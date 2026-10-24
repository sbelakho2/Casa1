//! Real XACT3 engine core: the binary format parsers and the software
//! engine's runtime state model.
//!
//! The XACT3 surface is implemented for real wherever the format and the
//! runtime's audio stack allow it:
//!
//! - **XWB wave banks** — the genuine `WBND` container (header, five
//!   segment table, bank data, per-entry metadata, entry-name table, wave
//!   data).  The entry mini-format bitfield, compact banks and the
//!   per-entry PCM/ADPCM payloads are decoded into interleaved 16-bit PCM
//!   (`WaveBank::parse`).  Little-endian PC banks are supported; the
//!   console `DNBW` byte order and pre-XACT3 content return the genuine
//!   `XACTENGINE_E_INVALIDDATA` (documented at the rejection site).
//!   XMA and WMA entries keep their parsed metadata but have no decoder in
//!   this model; preparing/playing one returns the genuine
//!   `XACTENGINE_E_INVALIDDATA` instead of fake silence.
//! - **XSB sound banks** — the genuine `SDBK` container (header, cue-name
//!   index table, simple/complex cue records, sound records with their
//!   track/event records, variation tables and wave-bank name table), per
//!   the DirectX SDK June-2010 layout.  Cue lookup by name and index,
//!   category ids, volume bytes (the XACT dB encoding), pitch cents and
//!   authored loop counts are all parsed from the file.
//! - **XGS global settings** — categories and variables for engine
//!   `Initialize`.
//! - **Engine/cue/wave runtime state** — the store attached to a guest
//!   process: engines with their wave banks, sound banks, live cues, live
//!   wave instances, category gains/pause flags, global variables and
//!   notification registrations.  Playback state transitions are real
//!   (Created/Preparing/Prepared/Playing/Paused/Stopped) and are driven by
//!   real source voices on the runtime's [`crate::audio::AudioSubsystem`].
//!
//! Nothing here fabricates success: every failure path returns the genuine
//! XACT/HRESULT error for the condition (bad signature/version → 0x8AC70007,
//! bad cue index → 0x8AC7000C, bad wave index → 0x8AC7000D, no wave bank →
//! 0x8AC70013, invalid argument → E_INVALIDARG, and so on).

#![allow(dead_code)] // the full XACT state model is larger than any one dispatch

use crate::audio::VoiceId;
use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

// ---------------------------------------------------------------------------
// HRESULTs (facility 0xAC7 = FACILITY_XACTENGINE, severity error)
// ---------------------------------------------------------------------------

/// `S_OK`.
pub(crate) const S_OK: u32 = 0x0000_0000;
/// `E_INVALIDARG` — a null or out-of-range parameter.
pub(crate) const E_INVALIDARG: u32 = 0x8007_0057;
/// `E_FAIL`.
pub(crate) const E_FAIL: u32 = 0x8000_4005;
/// `E_NOTIMPL` — an operation this model genuinely does not implement.
pub(crate) const E_NOTIMPL: u32 = 0x8000_4001;
/// `E_OUTOFMEMORY`.
pub(crate) const E_OUTOFMEMORY: u32 = 0x8007_000E;
/// `E_NOINTERFACE` — `QueryInterface` for an interface the object does not
/// implement.
pub(crate) const E_NOINTERFACE: u32 = 0x8000_4002;

/// `XACTENGINE_E_ALREADYINITIALIZED`.
pub(crate) const XACTENGINE_E_ALREADYINITIALIZED: u32 = 0x8AC7_0001;
/// `XACTENGINE_E_NOTINITIALIZED`.
pub(crate) const XACTENGINE_E_NOTINITIALIZED: u32 = 0x8AC7_0002;
/// `XACTENGINE_E_NONOTIFICATIONCALLBACK`.
pub(crate) const XACTENGINE_E_NONOTIFICATIONCALLBACK: u32 = 0x8AC7_0004;
/// `XACTENGINE_E_NOTIFICATIONREGISTERED`.
pub(crate) const XACTENGINE_E_NOTIFICATIONREGISTERED: u32 = 0x8AC7_0005;
/// `XACTENGINE_E_INVALIDUSAGE`.
pub(crate) const XACTENGINE_E_INVALIDUSAGE: u32 = 0x8AC7_0006;
/// `XACTENGINE_E_INVALIDDATA` — malformed/unsupported bank content.
pub(crate) const XACTENGINE_E_INVALIDDATA: u32 = 0x8AC7_0007;
/// `XACTENGINE_E_INSTANCELIMITFAILTOPLAY`.
pub(crate) const XACTENGINE_E_INSTANCELIMITFAILTOPLAY: u32 = 0x8AC7_0008;
/// `XACTENGINE_E_INVALIDVARIABLEINDEX`.
pub(crate) const XACTENGINE_E_INVALIDVARIABLEINDEX: u32 = 0x8AC7_000A;
/// `XACTENGINE_E_INVALIDCATEGORY`.
pub(crate) const XACTENGINE_E_INVALIDCATEGORY: u32 = 0x8AC7_000B;
/// `XACTENGINE_E_INVALIDCUEINDEX`.
pub(crate) const XACTENGINE_E_INVALIDCUEINDEX: u32 = 0x8AC7_000C;
/// `XACTENGINE_E_INVALIDWAVEINDEX`.
pub(crate) const XACTENGINE_E_INVALIDWAVEINDEX: u32 = 0x8AC7_000D;
/// `XACTENGINE_E_NOWAVEBANK`.
pub(crate) const XACTENGINE_E_NOWAVEBANK: u32 = 0x8AC7_0013;
/// `XACTENGINE_E_WAVEBANKNOTPREPARED`.
pub(crate) const XACTENGINE_E_WAVEBANKNOTPREPARED: u32 = 0x8AC7_0016;
/// `XACTENGINE_E_NORENDERER`.
pub(crate) const XACTENGINE_E_NORENDERER: u32 = 0x8AC7_0017;
/// `XACTENGINE_E_INVALIDENTRYCOUNT`.
pub(crate) const XACTENGINE_E_INVALIDENTRYCOUNT: u32 = 0x8AC7_0018;
/// `XACTENGINE_E_NOFRIENDLYNAMES`.
pub(crate) const XACTENGINE_E_NOFRIENDLYNAMES: u32 = 0x8AC7_001B;

// ---------------------------------------------------------------------------
// XACT constants (xact3.h, June 2010 DirectX SDK)
// ---------------------------------------------------------------------------

/// `XACT_FLAG_API_AUDITION_MODE` and `XACT_FLAG_API_DEBUG_MODE` are the
/// only creation flags the factory defines.
pub(crate) const XACT_FLAG_API_AUDITION_MODE: u32 = 0x0000_0001;
pub(crate) const XACT_FLAG_API_DEBUG_MODE: u32 = 0x0000_0002;
pub(crate) const XACT_CREATE_FLAGS_MASK: u32 =
    XACT_FLAG_API_AUDITION_MODE | XACT_FLAG_API_DEBUG_MODE;

/// `XACT_FLAG_MANAGEDATA` — the caller keeps ownership of the bank buffer.
pub(crate) const XACT_FLAG_MANAGEDATA: u32 = 0x0000_0001;
/// `XACT_FLAG_STOP_IMMEDIATE` (vs the release default).
pub(crate) const XACT_FLAG_STOP_IMMEDIATE: u32 = 0x0000_0001;

/// `XACT_STATE_*` cue/wave states.
pub(crate) const XACT_STATE_CREATED: u32 = 0x0000_0001;
pub(crate) const XACT_STATE_PREPARING: u32 = 0x0000_0002;
pub(crate) const XACT_STATE_PREPARED: u32 = 0x0000_0004;
pub(crate) const XACT_STATE_PLAYING: u32 = 0x0000_0008;
pub(crate) const XACT_STATE_STOPPING: u32 = 0x0000_0010;
pub(crate) const XACT_STATE_STOPPED: u32 = 0x0000_0020;
pub(crate) const XACT_STATE_PAUSED: u32 = 0x0000_0040;
pub(crate) const XACT_STATE_INUSE: u32 = 0x0000_0080;
pub(crate) const XACT_STATE_PREPAREFAILED: u32 = 0x8000_0000;

/// `XACTINDEX_INVALID`.
pub(crate) const XACTINDEX_INVALID: u16 = 0xFFFF;
/// `XACTVARIABLEINDEX_INVALID`.
pub(crate) const XACTVARIABLEINDEX_INVALID: u16 = 0xFFFF;
/// `XACTCATEGORY_INVALID`.
pub(crate) const XACTCATEGORY_INVALID: u16 = 0xFFFF;
/// `XACTLOOPCOUNT_INFINITE`.
pub(crate) const XACTLOOPCOUNT_INFINITE: u8 = 0xFF;

/// `IID_IXACT3Engine` for XACT3.5+ (xactengine3_7.dll).
pub(crate) const IID_IXACT3_ENGINE: [u8; 16] = [
    0x6a, 0x67, 0xee, 0xb1, 0xcd, 0xd9, 0x2a, 0x4d, 0x89, 0xa8, 0xfa, 0x53, 0xeb, 0x9e, 0x48, 0x0b,
];
/// `IID_IUnknown` {00000000-0000-0000-c000-000000000046}.
pub(crate) const IID_IUNKNOWN: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// XACT3.7 interface ids used by the dispatch layer.  The numeric values are
/// private to this model; the guest only ever sees them through the vtable
/// the engine hands out.
pub(crate) const IFACE_ENGINE: u8 = 0;
pub(crate) const IFACE_SOUNDBANK: u8 = 1;
pub(crate) const IFACE_WAVEBANK: u8 = 2;
pub(crate) const IFACE_CUE: u8 = 3;
pub(crate) const IFACE_WAVE: u8 = 4;

/// Vtable method indices (including the three `IUnknown` slots at 0..=2) and
/// the x86 stdcall argument count in 32-bit words, including `this`.
///
/// The tables follow the June-2010 `xact3.h` declarations exactly:
/// `IXACT3Engine`, `IXACT3SoundBank`, `IXACT3WaveBank`, `IXACT3Cue` and
/// `IXACT3Wave`.
pub(crate) const ENGINE_METHODS: &[(u16, u8)] = &[
    (0, 3),   // QueryInterface(this, riid, ppv)
    (1, 1),   // AddRef
    (2, 1),   // Release
    (3, 2),   // GetRendererCount(pnRendererCount)
    (4, 3),   // GetRendererDetails(index, details)
    (5, 2),   // GetFinalMixFormat(pFormat)
    (6, 2),   // Initialize(pParams)
    (7, 1),   // Shutdown
    (8, 1),   // DoWork
    (9, 6),   // CreateSoundBank(buffer, size, flags, alloc, out)
    (10, 6),  // CreateInMemoryWaveBank(buffer, size, flags, alloc, out)
    (11, 3),  // CreateStreamingWaveBank(params, out)
    (12, 8),  // PrepareWave(flags, path, packetSize, align, offset, loops, out)
    (13, 13), // PrepareInMemoryWave(flags, entry[24b], seekTable, data, offset, loops, out)
    (14, 17), // PrepareStreamingWave(flags, entry[24b], params[16b], align, seek, off, loops, out)
    (15, 2),  // RegisterNotification(desc)
    (16, 2),  // UnRegisterNotification(desc)
    (17, 2),  // GetCategory(name) -> XACTCATEGORY
    (18, 3),  // Stop(category, flags)
    (19, 3),  // SetVolume(category, volume)
    (20, 3),  // Pause(category, pause)
    (21, 2),  // GetGlobalVariableIndex(name) -> index
    (22, 3),  // SetGlobalVariable(index, value)
    (23, 3),  // GetGlobalVariable(index, out)
];

pub(crate) const SOUNDBANK_METHODS: &[(u16, u8)] = &[
    (0, 3),  // QueryInterface
    (1, 1),  // AddRef
    (2, 1),  // Release
    (3, 2),  // GetCueIndex(name) -> index
    (4, 2),  // GetNumCues(out)
    (5, 3),  // GetCueProperties(index, props)
    (6, 5),  // Prepare(index, flags, timeOffset, out)
    (7, 5),  // Play(index, flags, timeOffset, out)
    (8, 3),  // Stop(index, flags)
    (9, 1),  // Destroy
    (10, 2), // GetState(out)
];

pub(crate) const WAVEBANK_METHODS: &[(u16, u8)] = &[
    (0, 3),  // QueryInterface
    (1, 1),  // AddRef
    (2, 1),  // Release
    (3, 1),  // Destroy
    (4, 2),  // GetNumWaves(out)
    (5, 2),  // GetWaveIndex(name) -> index
    (6, 3),  // GetWaveProperties(index, props)
    (7, 6),  // Prepare(index, flags, offset, loops, out)
    (8, 6),  // Play(index, flags, offset, loops, out)
    (9, 3),  // Stop(index, flags)
    (10, 2), // GetState(out)
];

pub(crate) const CUE_METHODS: &[(u16, u8)] = &[
    (0, 3),  // QueryInterface
    (1, 1),  // AddRef
    (2, 1),  // Release
    (3, 1),  // Play
    (4, 2),  // Stop(flags)
    (5, 2),  // GetState(out)
    (6, 1),  // Destroy
    (7, 4),  // SetMatrixCoefficients(srcCh, dstCh, matrix)
    (8, 2),  // GetVariableIndex(name)
    (9, 3),  // SetVariable(index, value)
    (10, 3), // GetVariable(index, out)
    (11, 2), // Pause(pause)
    (12, 2), // GetProperties(out)
    (13, 2), // SetOutputVoices(sends)
    (14, 5), // SetOutputVoiceMatrix(voice, src, dst, matrix)
];

pub(crate) const WAVE_METHODS: &[(u16, u8)] = &[
    (0, 3),  // QueryInterface
    (1, 1),  // AddRef
    (2, 1),  // Release
    (3, 1),  // Destroy
    (4, 1),  // Play
    (5, 2),  // Stop(flags)
    (6, 2),  // Pause(pause)
    (7, 2),  // GetState(out)
    (8, 2),  // SetPitch(pitch)
    (9, 2),  // SetVolume(volume)
    (10, 4), // SetMatrixCoefficients(srcCh, dstCh, matrix)
    (11, 2), // GetProperties(out)
];

/// The vtable layout for one interface id.
pub(crate) fn interface_methods(interface: u8) -> &'static [(u16, u8)] {
    match interface {
        IFACE_ENGINE => ENGINE_METHODS,
        IFACE_SOUNDBANK => SOUNDBANK_METHODS,
        IFACE_WAVEBANK => WAVEBANK_METHODS,
        IFACE_CUE => CUE_METHODS,
        IFACE_WAVE => WAVE_METHODS,
        _ => &[],
    }
}

/// Human-readable method name for tracing/diagnostics.
pub(crate) fn interface_name(interface: u8) -> &'static str {
    match interface {
        IFACE_ENGINE => "IXACT3Engine",
        IFACE_SOUNDBANK => "IXACT3SoundBank",
        IFACE_WAVEBANK => "IXACT3WaveBank",
        IFACE_CUE => "IXACT3Cue",
        IFACE_WAVE => "IXACT3Wave",
        _ => "IXACT?",
    }
}

/// Human-readable method name for tracing/diagnostics.
pub(crate) fn method_name(interface: u8, method: u16) -> &'static str {
    match interface {
        IFACE_ENGINE => match method {
            0 => "QueryInterface",
            1 => "AddRef",
            2 => "Release",
            3 => "GetRendererCount",
            4 => "GetRendererDetails",
            5 => "GetFinalMixFormat",
            6 => "Initialize",
            7 => "Shutdown",
            8 => "DoWork",
            9 => "CreateSoundBank",
            10 => "CreateInMemoryWaveBank",
            11 => "CreateStreamingWaveBank",
            12 => "PrepareWave",
            13 => "PrepareInMemoryWave",
            14 => "PrepareStreamingWave",
            15 => "RegisterNotification",
            16 => "UnRegisterNotification",
            17 => "GetCategory",
            18 => "Stop",
            19 => "SetVolume",
            20 => "Pause",
            21 => "GetGlobalVariableIndex",
            22 => "SetGlobalVariable",
            23 => "GetGlobalVariable",
            _ => "?",
        },
        IFACE_SOUNDBANK => match method {
            0 => "QueryInterface",
            1 => "AddRef",
            2 => "Release",
            3 => "GetCueIndex",
            4 => "GetNumCues",
            5 => "GetCueProperties",
            6 => "Prepare",
            7 => "Play",
            8 => "Stop",
            9 => "Destroy",
            10 => "GetState",
            _ => "?",
        },
        IFACE_WAVEBANK => match method {
            0 => "QueryInterface",
            1 => "AddRef",
            2 => "Release",
            3 => "Destroy",
            4 => "GetNumWaves",
            5 => "GetWaveIndex",
            6 => "GetWaveProperties",
            7 => "Prepare",
            8 => "Play",
            9 => "Stop",
            10 => "GetState",
            _ => "?",
        },
        IFACE_CUE => match method {
            0 => "QueryInterface",
            1 => "AddRef",
            2 => "Release",
            3 => "Play",
            4 => "Stop",
            5 => "GetState",
            6 => "Destroy",
            7 => "SetMatrixCoefficients",
            8 => "GetVariableIndex",
            9 => "SetVariable",
            10 => "GetVariable",
            11 => "Pause",
            12 => "GetProperties",
            13 => "SetOutputVoices",
            14 => "SetOutputVoiceMatrix",
            _ => "?",
        },
        IFACE_WAVE => match method {
            0 => "QueryInterface",
            1 => "AddRef",
            2 => "Release",
            3 => "Destroy",
            4 => "Play",
            5 => "Stop",
            6 => "Pause",
            7 => "GetState",
            8 => "SetPitch",
            9 => "SetVolume",
            10 => "SetMatrixCoefficients",
            11 => "GetProperties",
            _ => "?",
        },
        _ => "?",
    }
}

// ---------------------------------------------------------------------------
// Little-endian readers (bounds-checked)
// ---------------------------------------------------------------------------

fn u8_at(data: &[u8], offset: usize) -> Result<u8, u32> {
    data.get(offset).copied().ok_or(XACTENGINE_E_INVALIDDATA)
}

fn u16_at(data: &[u8], offset: usize) -> Result<u16, u32> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or(XACTENGINE_E_INVALIDDATA)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32, u32> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or(XACTENGINE_E_INVALIDDATA)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn i32_at(data: &[u8], offset: usize) -> Result<i32, u32> {
    Ok(u32_at(data, offset)? as i32)
}

fn f32_at(data: &[u8], offset: usize) -> Result<f32, u32> {
    Ok(f32::from_bits(u32_at(data, offset)?))
}

fn slice_at(data: &[u8], offset: usize, length: usize) -> Result<&[u8], u32> {
    data.get(offset..offset.checked_add(length).ok_or(XACTENGINE_E_INVALIDDATA)?)
        .ok_or(XACTENGINE_E_INVALIDDATA)
}

fn zstring_at(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = offset.saturating_add(max_len).min(data.len());
    let bytes = data.get(offset..end).unwrap_or(&[]);
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..nul]).into_owned()
}

// ---------------------------------------------------------------------------
// XWB wave banks
// ---------------------------------------------------------------------------

const WAVEBANK_SIGNATURE_LE: u32 = 0x444E_4257; // bytes "WBND"
const WAVEBANK_SIGNATURE_BE: u32 = 0x5742_4E44; // bytes "DNBW" (big-endian file)
pub(crate) const WAVEBANK_FLAGS_ENTRYNAMES: u32 = 0x0001_0000;
pub(crate) const WAVEBANK_FLAGS_COMPACT: u32 = 0x0002_0000;
pub(crate) const WAVEBANK_FLAGS_SEEKTABLES: u32 = 0x0008_0000;
pub(crate) const WAVEBANK_TYPE_STREAMING: u32 = 0x0000_0001;
pub(crate) const WAVEBANK_TAG_PCM: u8 = 0;
pub(crate) const WAVEBANK_TAG_XMA: u8 = 1;
pub(crate) const WAVEBANK_TAG_ADPCM: u8 = 2;
pub(crate) const WAVEBANK_TAG_WMA: u8 = 3;

/// One decoded `WAVEBANKMINIWAVEFORMAT` (32-bit bitfield).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MiniFormat {
    pub(crate) tag: u8,
    pub(crate) channels: u16,
    pub(crate) sample_rate: u32,
    pub(crate) block_align: u8,
    pub(crate) bits_per_sample: u8,
}

impl MiniFormat {
    /// Decode the documented bitfield: `wFormatTag:2`, `nChannels:3` (stored
    /// minus one), `nSamplesPerSec:18`, `wBlockAlign:8`, `wBitsPerSample:1`
    /// (0 = 8-bit, 1 = 16-bit).
    pub(crate) fn decode(raw: u32) -> Self {
        Self {
            tag: (raw & 0x3) as u8,
            channels: ((raw >> 2) & 0x7) as u16 + 1,
            sample_rate: (raw >> 5) & 0x3_FFFF,
            block_align: ((raw >> 23) & 0xFF) as u8,
            bits_per_sample: if (raw >> 31) & 1 == 1 { 16 } else { 8 },
        }
    }

    /// Encode back to the bitfield (used by the format tests).
    pub(crate) fn encode(&self) -> u32 {
        let channels = (self.channels.saturating_sub(1).min(7)) as u32;
        let bits = if self.bits_per_sample >= 16 { 1 } else { 0 };
        (self.tag as u32 & 0x3)
            | (channels << 2)
            | ((self.sample_rate & 0x3_FFFF) << 5)
            | ((self.block_align as u32) << 23)
            | (bits << 31)
    }

    pub(crate) fn bytes_per_sample(&self) -> usize {
        match self.tag {
            WAVEBANK_TAG_PCM => {
                if self.bits_per_sample >= 16 {
                    2
                } else {
                    1
                }
            }
            _ => 0,
        }
    }
}

/// One decoded wave entry.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WaveEntry {
    pub(crate) flags: u32,
    pub(crate) duration_samples: u32,
    pub(crate) format: MiniFormat,
    /// Absolute byte offset of the encoded data in the source file.
    pub(crate) data_offset: u32,
    pub(crate) data_length: u32,
    pub(crate) loop_start_sample: u32,
    pub(crate) loop_total_samples: u32,
    /// Interleaved 16-bit PCM when the entry's codec has a decoder here.
    pub(crate) pcm: Option<Vec<i16>>,
    /// The genuine XACT error for entries whose codec this model cannot
    /// decode (XMA/WMA) or whose payload is malformed.
    pub(crate) decode_error: Option<u32>,
}

impl WaveEntry {
    pub(crate) fn is_looping(&self) -> bool {
        self.loop_total_samples > 0
    }

    /// The decoded sample count per channel (what the XACT wave properties
    /// report as `durationInSamples`).
    pub(crate) fn sample_count(&self) -> u32 {
        if let Some(pcm) = &self.pcm {
            let channels = self.format.channels.max(1) as usize;
            (pcm.len() / channels) as u32
        } else {
            self.duration_samples
        }
    }
}

/// A guest file handle plus the guest `XACT_FILEIO_CALLBACKS` entries that
/// read, seek and close a streaming wave bank.  Every stream operation goes
/// through the guest's own code; nothing is re-opened on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuestStreamSource {
    pub(crate) file: u64,
    /// Offset of the wave-bank header inside the guest file.
    pub(crate) offset: u32,
    pub(crate) read: u64,
    pub(crate) seek: u64,
    pub(crate) close: u64,
}

/// A parsed in-memory XWB wave bank.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WaveBank {
    pub(crate) name: String,
    pub(crate) streaming: bool,
    /// Resolved host path for a streaming bank opened through the runtime's
    /// file tables; `None` for in-memory and guest-streamed banks.
    pub(crate) source_path: Option<String>,
    /// Guest file handle/callbacks for a streaming bank created from
    /// `XACT_WAVEBANK_STREAMING_PARAMETERS`.
    pub(crate) guest_source: Option<GuestStreamSource>,
    pub(crate) entry_names: Vec<String>,
    pub(crate) entries: Vec<WaveEntry>,
}

impl WaveBank {
    pub(crate) fn entry_name(&self, index: usize) -> Option<&str> {
        self.entry_names
            .get(index)
            .map(|name| name.as_str())
            .filter(|name| !name.is_empty())
    }

    /// Find an entry by its friendly name; `None` when the bank has no name
    /// table or the name is absent.
    pub(crate) fn entry_index_by_name(&self, name: &str) -> Option<u16> {
        self.entry_names
            .iter()
            .position(|candidate| candidate == name)
            .map(|index| index as u16)
    }

    /// Parse a genuine XWB container.
    pub(crate) fn parse(data: &[u8]) -> Result<Self, u32> {
        let magic = u32_at(data, 0)?;
        if magic == WAVEBANK_SIGNATURE_BE {
            // Big-endian (console) banks share the same structures but every
            // field is byte-swapped; the PC engine core only implements the
            // little-endian XACT3 container.  This is the genuine content
            // error the engine reports for a bank it cannot use.
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        if magic != WAVEBANK_SIGNATURE_LE {
            return Err(XACTENGINE_E_INVALIDDATA);
        }

        let version = u32_at(data, 4)?;
        if version <= 41 {
            // Pre-XACT3 (2.x-era/Xbox) banks have a different header shape
            // (4 segments, 20-byte entries, no header-version field).  The
            // XACT3 core reports the genuine invalid-data error.
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        if version > 46 {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        let header_version = u32_at(data, 8)?;
        if !(42..=44).contains(&header_version) {
            return Err(XACTENGINE_E_INVALIDDATA);
        }

        let mut segments = [(0u32, 0u32); 5];
        for (index, segment) in segments.iter_mut().enumerate() {
            let offset = u32_at(data, 12 + index * 8)?;
            let length = u32_at(data, 16 + index * 8)?;
            *segment = (offset, length);
        }
        // Every declared segment must lie inside the file; a truncated bank
        // is invalid data, not a bank with a short wave.
        for &(offset, length) in &segments {
            if length == 0 {
                continue;
            }
            let offset = offset as usize;
            let end = offset
                .checked_add(length as usize)
                .ok_or(XACTENGINE_E_INVALIDDATA)?;
            if end > data.len() {
                return Err(XACTENGINE_E_INVALIDDATA);
            }
        }

        let bank_data_offset = segments[0].0 as usize;
        let flags = u32_at(data, bank_data_offset)?;
        let entry_count = u32_at(data, bank_data_offset + 4)?;
        if entry_count > 0x10_0000 {
            return Err(XACTENGINE_E_INVALIDENTRYCOUNT);
        }
        let name = zstring_at(data, bank_data_offset + 8, 64);
        let metadata_size = u32_at(data, bank_data_offset + 72)? as usize;
        let _name_element_size = u32_at(data, bank_data_offset + 76)? as usize;
        let alignment = u32_at(data, bank_data_offset + 80)?;
        let compact_format = MiniFormat::decode(u32_at(data, bank_data_offset + 84)?);

        let streaming = flags & WAVEBANK_TYPE_STREAMING != 0;
        let compact = flags & WAVEBANK_FLAGS_COMPACT != 0;

        let metadata_offset = segments[1].0 as usize;
        let wave_data_offset = segments[4].0 as usize;
        let wave_data_length = segments[4].1 as usize;

        let mut entries = Vec::with_capacity(entry_count as usize);
        if compact {
            // Compact banks store a 21-bit offset (in alignment units) and an
            // 11-bit length deviation per entry; lengths are derived from the
            // following entry's offset (the last from the segment length).
            if metadata_size < 4 {
                return Err(XACTENGINE_E_INVALIDDATA);
            }
            let mut offsets = Vec::with_capacity(entry_count as usize);
            for index in 0..entry_count as usize {
                let value = u32_at(data, metadata_offset + index * metadata_size)?;
                offsets.push((value & ((1 << 21) - 1)) as u64 * alignment as u64);
            }
            for (index, relative_offset) in offsets.iter().enumerate() {
                let next = offsets
                    .get(index + 1)
                    .copied()
                    .unwrap_or(wave_data_length as u64);
                let length = next.saturating_sub(*relative_offset) as u32;
                let absolute = wave_data_offset as u64 + relative_offset;
                let mut entry = WaveEntry {
                    flags: 0,
                    duration_samples: 0,
                    format: compact_format,
                    data_offset: absolute.min(u32::MAX as u64) as u32,
                    data_length: length,
                    loop_start_sample: 0,
                    loop_total_samples: 0,
                    pcm: None,
                    decode_error: None,
                };
                decode_wave_entry(data, &mut entry);
                entries.push(entry);
            }
        } else {
            if metadata_size < 4 {
                return Err(XACTENGINE_E_INVALIDDATA);
            }
            for index in 0..entry_count as usize {
                let base = metadata_offset + index * metadata_size;
                let flags_and_duration = u32_at(data, base)?;
                let format = MiniFormat::decode(u32_at(data, base + 4)?);
                let play_offset = if metadata_size >= 12 {
                    u32_at(data, base + 8)?
                } else {
                    0
                };
                let play_length = if metadata_size >= 16 {
                    u32_at(data, base + 12)?
                } else {
                    wave_data_length as u32
                };
                let loop_start = if metadata_size >= 20 {
                    u32_at(data, base + 16)?
                } else {
                    0
                };
                let loop_total = if metadata_size >= 24 {
                    u32_at(data, base + 20)?
                } else {
                    0
                };
                let mut entry = WaveEntry {
                    flags: flags_and_duration & 0xF,
                    duration_samples: (flags_and_duration >> 4) & 0x0FFF_FFFF,
                    format,
                    data_offset: wave_data_offset.saturating_add(play_offset as usize) as u32,
                    data_length: play_length,
                    loop_start_sample: loop_start,
                    loop_total_samples: loop_total,
                    pcm: None,
                    decode_error: None,
                };
                decode_wave_entry(data, &mut entry);
                entries.push(entry);
            }
        }

        // A malformed payload for a codec this engine decodes makes the whole
        // bank invalid; XMA/WMA entries keep their metadata and surface their
        // genuine decode error when used.
        for entry in &entries {
            if matches!(entry.format.tag, WAVEBANK_TAG_PCM | WAVEBANK_TAG_ADPCM)
                && let Some(error) = entry.decode_error
            {
                return Err(error);
            }
        }

        let mut entry_names = Vec::new();
        if flags & WAVEBANK_FLAGS_ENTRYNAMES != 0 && segments[3].1 > 0 {
            let names_offset = segments[3].0 as usize;
            for index in 0..entry_count as usize {
                entry_names.push(zstring_at(data, names_offset + index * 64, 64));
            }
        }

        Ok(Self {
            name,
            streaming,
            source_path: None,
            guest_source: None,
            entry_names,
            entries,
        })
    }

    /// Parse the header and entry metadata of a streaming XWB without
    /// materialising its wave payload.  `file_length` is the real on-disk
    /// size; every entry's `[data_offset, data_offset + data_length)` range
    /// is validated against it.  Wave PCM is loaded later by
    /// [`load_streaming_entry`] with a real seek/read.
    pub(crate) fn parse_streaming_header(
        data: &[u8],
        file_length: usize,
        source_path: &str,
    ) -> Result<Self, u32> {
        Self::parse_streaming_header_with(data, file_length, Some(source_path.to_string()), None)
    }

    /// The guest-callback form of [`Self::parse_streaming_header`]: the bank
    /// came from `XACT_WAVEBANK_STREAMING_PARAMETERS`, so later entry loads
    /// read through the guest's own file callbacks.
    pub(crate) fn parse_streaming_header_guest(
        data: &[u8],
        file_length: usize,
        source: GuestStreamSource,
    ) -> Result<Self, u32> {
        Self::parse_streaming_header_with(data, file_length, None, Some(source))
    }

    fn parse_streaming_header_with(
        data: &[u8],
        file_length: usize,
        source_path: Option<String>,
        guest_source: Option<GuestStreamSource>,
    ) -> Result<Self, u32> {
        let magic = u32_at(data, 0)?;
        if magic == WAVEBANK_SIGNATURE_BE || magic != WAVEBANK_SIGNATURE_LE {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        let version = u32_at(data, 4)?;
        if version <= 41 || version > 46 {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        let header_version = u32_at(data, 8)?;
        if !(42..=44).contains(&header_version) {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        let mut segments = [(0u32, 0u32); 5];
        for (index, segment) in segments.iter_mut().enumerate() {
            let offset = u32_at(data, 12 + index * 8)?;
            let length = u32_at(data, 16 + index * 8)?;
            *segment = (offset, length);
        }
        for (index, &(offset, length)) in segments.iter().enumerate() {
            if length == 0 {
                continue;
            }
            let end = (offset as usize)
                .checked_add(length as usize)
                .ok_or(XACTENGINE_E_INVALIDDATA)?;
            let limit = if index == 4 { file_length } else { data.len() };
            if end > limit {
                return Err(XACTENGINE_E_INVALIDDATA);
            }
        }
        let bank_data_offset = segments[0].0 as usize;
        let flags = u32_at(data, bank_data_offset)?;
        let entry_count = u32_at(data, bank_data_offset + 4)?;
        if entry_count > 0x10_0000 {
            return Err(XACTENGINE_E_INVALIDENTRYCOUNT);
        }
        let name = zstring_at(data, bank_data_offset + 8, 64);
        let metadata_size = u32_at(data, bank_data_offset + 72)? as usize;
        let _name_element_size = u32_at(data, bank_data_offset + 76)? as usize;
        let alignment = u32_at(data, bank_data_offset + 80)?;
        let compact_format = MiniFormat::decode(u32_at(data, bank_data_offset + 84)?);
        let streaming = flags & WAVEBANK_TYPE_STREAMING != 0;
        if !streaming {
            return Err(XACTENGINE_E_INVALIDUSAGE);
        }
        let compact = flags & WAVEBANK_FLAGS_COMPACT != 0;
        let metadata_offset = segments[1].0 as usize;
        let wave_data_offset = segments[4].0 as usize;
        let wave_data_length = segments[4].1 as usize;

        let mut entries = Vec::with_capacity(entry_count as usize);
        if compact {
            if metadata_size < 4 {
                return Err(XACTENGINE_E_INVALIDDATA);
            }
            let mut offsets = Vec::with_capacity(entry_count as usize);
            for index in 0..entry_count as usize {
                let value = u32_at(data, metadata_offset + index * metadata_size)?;
                offsets.push((value & ((1 << 21) - 1)) as u64 * alignment as u64);
            }
            for (index, relative_offset) in offsets.iter().enumerate() {
                let next = offsets
                    .get(index + 1)
                    .copied()
                    .unwrap_or(wave_data_length as u64);
                let length = next.saturating_sub(*relative_offset) as u32;
                let absolute = wave_data_offset as u64 + relative_offset;
                if absolute + length as u64 > file_length as u64 {
                    return Err(XACTENGINE_E_INVALIDDATA);
                }
                entries.push(WaveEntry {
                    flags: 0,
                    duration_samples: 0,
                    format: compact_format,
                    data_offset: absolute.min(u32::MAX as u64) as u32,
                    data_length: length,
                    loop_start_sample: 0,
                    loop_total_samples: 0,
                    pcm: None,
                    decode_error: None,
                });
            }
        } else {
            if metadata_size < 4 {
                return Err(XACTENGINE_E_INVALIDDATA);
            }
            for index in 0..entry_count as usize {
                let base = metadata_offset + index * metadata_size;
                let flags_and_duration = u32_at(data, base)?;
                let format = MiniFormat::decode(u32_at(data, base + 4)?);
                let play_offset = if metadata_size >= 12 {
                    u32_at(data, base + 8)?
                } else {
                    0
                };
                let play_length = if metadata_size >= 16 {
                    u32_at(data, base + 12)?
                } else {
                    wave_data_length as u32
                };
                let loop_start = if metadata_size >= 20 {
                    u32_at(data, base + 16)?
                } else {
                    0
                };
                let loop_total = if metadata_size >= 24 {
                    u32_at(data, base + 20)?
                } else {
                    0
                };
                let data_offset = wave_data_offset.saturating_add(play_offset as usize);
                if data_offset as u64 + play_length as u64 > file_length as u64 {
                    return Err(XACTENGINE_E_INVALIDDATA);
                }
                entries.push(WaveEntry {
                    flags: flags_and_duration & 0xF,
                    duration_samples: (flags_and_duration >> 4) & 0x0FFF_FFFF,
                    format,
                    data_offset: data_offset as u32,
                    data_length: play_length,
                    loop_start_sample: loop_start,
                    loop_total_samples: loop_total,
                    pcm: None,
                    decode_error: None,
                });
            }
        }

        let mut entry_names = Vec::new();
        if flags & WAVEBANK_FLAGS_ENTRYNAMES != 0 && segments[3].1 > 0 {
            let names_offset = segments[3].0 as usize;
            for index in 0..entry_count as usize {
                entry_names.push(zstring_at(data, names_offset + index * 64, 64));
            }
        }

        Ok(Self {
            name,
            streaming,
            source_path,
            guest_source,
            entry_names,
            entries,
        })
    }
}

/// Read the exact header/metadata prefix a streaming bank needs, then parse
/// it without touching the wave-data segment.  File I/O errors surface as
/// `E_FAIL`; malformed content surfaces the genuine `XACTENGINE_E_*` code.
pub(crate) fn open_streaming_wave_bank(path: &str) -> Result<WaveBank, u32> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).map_err(|_| E_FAIL)?;
    let file_length = file.metadata().map_err(|_| E_FAIL)?.len() as usize;
    let mut header = [0_u8; 52];
    file.read_exact(&mut header).map_err(|_| E_FAIL)?;
    let mut needed = 52_usize;
    for index in 0..4 {
        let offset = u32::from_le_bytes([
            header[12 + index * 8],
            header[13 + index * 8],
            header[14 + index * 8],
            header[15 + index * 8],
        ]) as usize;
        let length = u32::from_le_bytes([
            header[16 + index * 8],
            header[17 + index * 8],
            header[18 + index * 8],
            header[19 + index * 8],
        ]) as usize;
        if length > 0 {
            needed = needed.max(offset.saturating_add(length));
        }
    }
    if needed > file_length {
        return Err(XACTENGINE_E_INVALIDDATA);
    }
    let mut data = vec![0_u8; needed];
    file.seek(SeekFrom::Start(0)).map_err(|_| E_FAIL)?;
    file.read_exact(&mut data).map_err(|_| E_FAIL)?;
    WaveBank::parse_streaming_header(&data, file_length, path)
}

/// Load one streaming entry's payload from `path` with a real seek/read and
/// decode it.  This is the on-demand path used by `Prepare` for host-path
/// streaming banks.
pub(crate) fn load_streaming_entry(path: &str, entry: &WaveEntry) -> Result<Vec<i16>, u32> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).map_err(|_| E_FAIL)?;
    file.seek(SeekFrom::Start(u64::from(entry.data_offset)))
        .map_err(|_| E_FAIL)?;
    let mut payload = vec![0_u8; entry.data_length as usize];
    file.read_exact(&mut payload).map_err(|_| E_FAIL)?;
    let mut decoded = entry.clone();
    decode_wave_payload(&mut decoded, &payload);
    decoded
        .pcm
        .ok_or(decoded.decode_error.unwrap_or(XACTENGINE_E_INVALIDDATA))
}

/// Decode one entry's payload into `pcm`, or record the genuine decode error.
fn decode_wave_entry(data: &[u8], entry: &mut WaveEntry) {
    let offset = entry.data_offset as usize;
    let length = entry.data_length as usize;
    let payload = match slice_at(data, offset, length) {
        Ok(payload) => payload,
        Err(error) => {
            entry.decode_error = Some(error);
            return;
        }
    };
    decode_wave_payload(entry, payload);
}

/// Decode one already-read payload into `entry.pcm`, or record the genuine
/// decode error (unsupported XMA/WMA codecs included).
pub(crate) fn decode_wave_payload(entry: &mut WaveEntry, payload: &[u8]) {
    match entry.format.tag {
        WAVEBANK_TAG_PCM => match entry.format.bits_per_sample {
            16 => {
                if payload.len() % 2 != 0 {
                    entry.decode_error = Some(XACTENGINE_E_INVALIDDATA);
                    return;
                }
                let mut samples = Vec::with_capacity(payload.len() / 2);
                for chunk in payload.as_chunks::<2>().0 {
                    samples.push(i16::from_le_bytes([chunk[0], chunk[1]]));
                }
                entry.pcm = Some(samples);
            }
            _ => {
                // 8-bit PCM is unsigned in the wave container.
                let samples = payload
                    .iter()
                    .map(|byte| ((*byte as i16) - 128) << 8)
                    .collect::<Vec<_>>();
                entry.pcm = Some(samples);
            }
        },
        WAVEBANK_TAG_ADPCM => {
            // The XWB ADPCM tag is Microsoft ADPCM: block-aligned MS ADPCM
            // blocks with a per-channel block header.  `wBlockAlign` carries
            // the block size and `nChannels` the channel count.
            let channels = entry.format.channels;
            let block_align = entry.format.block_align;
            if block_align == 0 || channels == 0 || channels > 2 {
                entry.decode_error = Some(XACTENGINE_E_INVALIDDATA);
                return;
            }
            let block = block_align as usize;
            let samples_per_block =
                (((block as i32 - 7 * channels as i32) * 2) / channels as i32) + 2;
            if samples_per_block <= 2 {
                entry.decode_error = Some(XACTENGINE_E_INVALIDDATA);
                return;
            }
            match crate::real_audio::decode_ms_adpcm(
                payload,
                u16::from(block_align),
                channels,
                samples_per_block as u16,
            ) {
                Ok(samples) => entry.pcm = Some(samples),
                Err(_) => entry.decode_error = Some(XACTENGINE_E_INVALIDDATA),
            }
        }
        _ => {
            // XMA and WMA have no decoder in this engine core.  The genuine
            // XACT "bad content" error is surfaced when the entry is used.
            entry.decode_error = Some(XACTENGINE_E_INVALIDDATA);
        }
    }
}

// ---------------------------------------------------------------------------
// XSB sound banks
// ---------------------------------------------------------------------------

const SOUNDBANK_SIGNATURE: u32 = 0x4B42_4453; // bytes "SDBK"
const SOUNDBANK_SIGNATURE_BE: u32 = 0x5344_424B; // bytes "KBDS"
const SOUNDBANK_FORMAT_VERSION: u16 = 43;

pub(crate) const SOUND_FLAG_COMPLEX: u8 = 0x01;
pub(crate) const SOUND_FLAG_HAS_RPC: u8 = 0x02;
pub(crate) const SOUND_FLAG_HAS_TRACK_RPC: u8 = 0x04;
pub(crate) const SOUND_FLAG_RPC_MASK: u8 = 0x0E;
pub(crate) const SOUND_FLAG_HAS_DSP: u8 = 0x10;

pub(crate) const CUE_FLAG_SINGLE_SOUND: u8 = 0x04;

const VARIATION_TABLE_TYPE_WAVE: u8 = 0;
const VARIATION_TABLE_TYPE_SOUND: u8 = 1;
const VARIATION_TABLE_TYPE_CLIP: u8 = 2;
const VARIATION_TABLE_TYPE_INTERACTIVE: u8 = 3;
const VARIATION_TABLE_TYPE_COMPACT_WAVE: u8 = 4;

const EVENT_STOP: u32 = 0;
const EVENT_PLAYWAVE: u32 = 1;
const EVENT_PLAYWAVETRACKVARIATION: u32 = 3;
const EVENT_PLAYWAVEEFFECTVARIATION: u32 = 4;
const EVENT_PLAYWAVETRACKEFFECTVARIATION: u32 = 6;
const EVENT_PITCH: u32 = 7;
const EVENT_VOLUME: u32 = 8;
const EVENT_MARKER: u32 = 9;
const EVENT_PITCHREPEATING: u32 = 16;
const EVENT_VOLUMEREPEATING: u32 = 17;
const EVENT_MARKERREPEATING: u32 = 18;

/// One wave reference (XWB wave bank index + wave index) extracted from a
/// sound record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WaveRef {
    pub(crate) wave_index: u16,
    pub(crate) wavebank: u8,
    pub(crate) loop_count: u8,
}

impl WaveRef {
    fn new(wave_index: u16, wavebank: u8, loop_count: u8) -> Self {
        Self {
            wave_index,
            wavebank,
            loop_count,
        }
    }
}

/// One playable track of a sound: the resolved wave plus the track's own
/// authored gain (complex sounds carry a per-track volume byte).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct SoundTrack {
    pub(crate) wave: WaveRef,
    pub(crate) volume: f32,
}

/// One sound record from the XSB.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Sound {
    /// Absolute file offset (the cue's `sbCode` for a single-sound cue).
    pub(crate) code: u32,
    pub(crate) flags: u8,
    pub(crate) category: u16,
    pub(crate) volume: f32,
    pub(crate) pitch: i16,
    pub(crate) priority: u8,
    pub(crate) tracks: Vec<SoundTrack>,
}

/// One cue record.  `sound_code` resolves to either a `Sound` (single-sound
/// cues) or a variation table.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CueDef {
    pub(crate) name: String,
    pub(crate) flags: u8,
    pub(crate) single_sound: bool,
    /// The `sbCode` from the file: sound offset or variation-table offset.
    pub(crate) sound_code: u32,
    /// Resolved index into [`SoundBank::sounds`] for single-sound cues.
    pub(crate) sound_index: Option<usize>,
    /// Resolved index into [`SoundBank::variations`] for variation cues.
    pub(crate) variation_index: Option<usize>,
    pub(crate) instance_limit: u8,
    pub(crate) fade_in_ms: u16,
    pub(crate) fade_out_ms: u16,
    pub(crate) max_instance_behavior: u8,
    /// Cue-local variable bindings parsed from the cue's interactive
    /// variation table: each entry is the global variable index the local
    /// slot shadows.  Empty when the cue has no variable-bound variation.
    pub(crate) local_variables: Vec<i16>,
    /// Friendly names for the cue-local slots, parallel to
    /// `local_variables` when the sound bank carries the variable-name
    /// index table.  Empty when the table is absent; bindings then resolve
    /// through the shadowed global variable names.
    pub(crate) local_variable_names: Vec<String>,
}

/// One entry of a cue variation table.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum VariationEntry {
    Wave {
        wave_index: u16,
        wavebank: u8,
        weight_min: u8,
        weight_max: u8,
    },
    Sound {
        sound_code: u32,
        weight_min: u8,
        weight_max: u8,
    },
    Interactive {
        sound_code: u32,
        var_min: f32,
        var_max: f32,
    },
    CompactWave {
        wave_index: u16,
        wavebank: u8,
    },
}

/// A cue's variation table (parsed structurally; selection is real).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Variation {
    pub(crate) code: u32,
    pub(crate) kind: u8,
    pub(crate) variable: i16,
    pub(crate) entries: Vec<VariationEntry>,
}

/// A resolved playback selection: the sound record plus any per-play wave
/// override chosen from a variation table.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PlaySelection {
    pub(crate) sound: Sound,
    /// Set when the variation table selected a direct wave (no sound record).
    pub(crate) direct_wave: Option<(u16, u8)>,
    pub(crate) variation_entry: Option<u16>,
}

/// A parsed in-memory XSB sound bank.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SoundBank {
    pub(crate) name: String,
    pub(crate) wavebank_names: Vec<String>,
    pub(crate) sounds: Vec<Sound>,
    pub(crate) variations: Vec<Variation>,
    pub(crate) cues: Vec<CueDef>,
}

impl SoundBank {
    pub(crate) fn cue_index_by_name(&self, name: &str) -> Option<u16> {
        self.cues
            .iter()
            .position(|cue| cue.name == name)
            .map(|index| index as u16)
    }

    /// Number of cue-name-friendly entries (used by `GetCueIndex` when the
    /// bank carries no name table).
    pub(crate) fn has_cue_names(&self) -> bool {
        self.cues.iter().any(|cue| !cue.name.is_empty())
    }

    /// Select the playback for `cue_index`: a direct sound for single-sound
    /// cues, or a weighted selection from the cue's variation table.
    pub(crate) fn select_cue(&self, cue_index: u16) -> Result<PlaySelection, u32> {
        self.select_cue_with_variables(cue_index, &[])
    }

    /// Select a cue's playback with the engine's current variable values.
    /// Interactive variations bound to a variable choose the entry whose
    /// authored `[min, max]` range contains the value (nearest range when it
    /// falls outside every range); unbound tables keep the weighted draw.
    pub(crate) fn select_cue_with_variables(
        &self,
        cue_index: u16,
        variables: &[f32],
    ) -> Result<PlaySelection, u32> {
        let cue = self
            .cues
            .get(cue_index as usize)
            .ok_or(XACTENGINE_E_INVALIDCUEINDEX)?;
        if cue.single_sound {
            let sound = self
                .sounds
                .get(cue.sound_index.ok_or(XACTENGINE_E_INVALIDDATA)?)
                .cloned()
                .ok_or(XACTENGINE_E_INVALIDDATA)?;
            return Ok(PlaySelection {
                sound,
                direct_wave: None,
                variation_entry: None,
            });
        }
        let variation = self
            .variations
            .get(cue.variation_index.ok_or(XACTENGINE_E_INVALIDDATA)?)
            .ok_or(XACTENGINE_E_INVALIDDATA)?;
        if variation.entries.is_empty() {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        let entry_index = match variation.kind {
            VARIATION_TABLE_TYPE_WAVE => weighted_entry_index(
                variation
                    .entries
                    .iter()
                    .map(entry_weight)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            VARIATION_TABLE_TYPE_INTERACTIVE => {
                match variables.get(variation.variable.max(0) as usize) {
                    Some(value) if variation.variable >= 0 => {
                        interactive_entry_index(&variation.entries, *value)
                    }
                    _ => weighted_entry_index(
                        variation
                            .entries
                            .iter()
                            .map(entry_weight)
                            .collect::<Vec<_>>()
                            .as_slice(),
                    ),
                }
            }
            VARIATION_TABLE_TYPE_SOUND => weighted_entry_index(
                variation
                    .entries
                    .iter()
                    .map(entry_weight)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            VARIATION_TABLE_TYPE_COMPACT_WAVE => 0,
            _ => return Err(XACTENGINE_E_INVALIDDATA),
        };
        let entry = variation
            .entries
            .get(entry_index)
            .ok_or(XACTENGINE_E_INVALIDDATA)?;
        let mut selection = match entry {
            VariationEntry::Wave {
                wave_index,
                wavebank,
                ..
            }
            | VariationEntry::CompactWave {
                wave_index,
                wavebank,
            } => PlaySelection {
                sound: Sound {
                    code: 0,
                    flags: 0,
                    category: 0,
                    volume: 1.0,
                    pitch: 0,
                    priority: 0,
                    tracks: vec![SoundTrack {
                        wave: WaveRef::new(*wave_index, *wavebank, 0),
                        volume: 1.0,
                    }],
                },
                direct_wave: Some((*wave_index, *wavebank)),
                variation_entry: Some(entry_index as u16),
            },
            VariationEntry::Sound { sound_code, .. }
            | VariationEntry::Interactive { sound_code, .. } => {
                let sound = self
                    .sounds
                    .iter()
                    .find(|sound| sound.code == *sound_code)
                    .cloned()
                    .ok_or(XACTENGINE_E_INVALIDDATA)?;
                PlaySelection {
                    sound,
                    direct_wave: None,
                    variation_entry: Some(entry_index as u16),
                }
            }
        };
        if selection.direct_wave.is_some() {
            // Direct-wave selections carry no authored loop; keep as parsed.
        }
        selection.variation_entry = Some(entry_index as u16);
        Ok(selection)
    }

    /// Parse a genuine XSB container.
    pub(crate) fn parse(data: &[u8]) -> Result<Self, u32> {
        let magic = u32_at(data, 0)?;
        if magic == SOUNDBANK_SIGNATURE_BE {
            // Big-endian console sound bank: unsupported in the PC core.
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        if magic != SOUNDBANK_SIGNATURE {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        let content_version = u16_at(data, 4)?;
        if !(43..=46).contains(&content_version) {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        let format_version = u16_at(data, 6)?;
        if format_version != SOUNDBANK_FORMAT_VERSION {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        // CRC (u16) at 8, last-modified FILETIME at 10, platform at 18.
        // Windows == 1, Xbox == 3; 0 is accepted for older content, as the
        // reference implementation does.
        let platform = u8_at(data, 18)?;
        if platform != 0 && platform != 1 && platform != 3 {
            return Err(XACTENGINE_E_INVALIDDATA);
        }

        let cue_simple_count = u16_at(data, 19)?;
        let cue_complex_count = u16_at(data, 21)?;
        // u16 unknown at 23, cueTotalAlign at 25.
        let wavebank_count = u8_at(data, 27)?;
        let sound_count = u16_at(data, 28)?;
        // Cue-name-table length at 30, unknown at 32.
        let cue_simple_offset = i32_at(data, 34)?;
        let cue_complex_offset = i32_at(data, 38)?;
        let cue_name_offset = i32_at(data, 42)?;
        // Friendly-name index table for cue-local variables.  Content that
        // carries the extension stores a 6-byte (name offset, sort key) entry
        // per local slot; -1 means the bank has no variable-name table.
        let local_variable_name_index_offset = i32_at(data, 46)?;
        let variation_offset = i32_at(data, 50)?;
        let _transition_offset = i32_at(data, 54)?;
        let wavebank_name_offset = i32_at(data, 58)?;
        // Cue hash table at 62.
        let cue_name_index_offset = i32_at(data, 66)?;
        let sound_offset = i32_at(data, 70)?;
        let name = zstring_at(data, 74, 64);

        // Wave-bank name table.
        let mut wavebank_names = Vec::with_capacity(wavebank_count as usize);
        if wavebank_name_offset >= 0 {
            for index in 0..wavebank_count as usize {
                wavebank_names.push(zstring_at(
                    data,
                    wavebank_name_offset as usize + index * 64,
                    64,
                ));
            }
        } else if wavebank_count > 0 {
            return Err(XACTENGINE_E_INVALIDDATA);
        }

        // Sound records.  Codes (absolute offsets) are what cues bind to.
        let mut sounds = Vec::with_capacity(sound_count as usize);
        if sound_offset >= 0 {
            let mut cursor = sound_offset as usize;
            for _ in 0..sound_count {
                let (sound, next) = parse_sound(data, cursor, content_version)?;
                sounds.push(sound);
                cursor = next;
            }
        } else if sound_count > 0 {
            return Err(XACTENGINE_E_INVALIDDATA);
        }

        // Cue names: the file stores a 6-byte index entry per cue (absolute
        // string offset + u16 sort key) at cueNameIndexOffset.  Older content
        // stores a plain concatenated name table at cueNameOffset instead;
        // both real layouts are accepted (the index table wins when present).
        let cue_count = cue_simple_count as usize + cue_complex_count as usize;
        let mut cue_names = Vec::with_capacity(cue_count);
        if cue_name_index_offset >= 0 {
            for index in 0..cue_count {
                let entry = cue_name_index_offset as usize + index * 6;
                let string_offset = u32_at(data, entry)? as usize;
                cue_names.push(zstring_at(data, string_offset, 255));
            }
        } else if cue_name_offset >= 0 {
            let mut cursor = cue_name_offset as usize;
            for _ in 0..cue_count {
                let name = zstring_at(data, cursor, 255);
                cursor += name.len() + 1;
                cue_names.push(name);
            }
        } else {
            cue_names.resize(cue_count, String::new());
        }

        // Cues.
        let mut cues = Vec::with_capacity(cue_count);
        if cue_simple_count > 0 {
            if cue_simple_offset < 0 {
                return Err(XACTENGINE_E_INVALIDDATA);
            }
            let mut cursor = cue_simple_offset as usize;
            for index in 0..cue_simple_count as usize {
                let flags = u8_at(data, cursor)?;
                let sound_code = u32_at(data, cursor + 1)?;
                cues.push(CueDef {
                    name: cue_names.get(index).cloned().unwrap_or_default(),
                    flags,
                    single_sound: true,
                    sound_code,
                    sound_index: sounds.iter().position(|sound| sound.code == sound_code),
                    variation_index: None,
                    instance_limit: 0xFF,
                    fade_in_ms: 0,
                    fade_out_ms: 0,
                    max_instance_behavior: 0,
                    local_variables: Vec::new(),
                    local_variable_names: Vec::new(),
                });
                cursor += 5;
            }
        }
        if cue_complex_count > 0 {
            if cue_complex_offset < 0 {
                return Err(XACTENGINE_E_INVALIDDATA);
            }
            let mut cursor = cue_complex_offset as usize;
            for index in 0..cue_complex_count as usize {
                let cue_index = cue_simple_count as usize + index;
                let flags = u8_at(data, cursor)?;
                let sound_code = u32_at(data, cursor + 1)?;
                let transition = u32_at(data, cursor + 5)?;
                let instance_limit = u8_at(data, cursor + 9)?;
                let fade_in_ms = u16_at(data, cursor + 10)?;
                let fade_out_ms = u16_at(data, cursor + 12)?;
                let max_instance_behavior = u8_at(data, cursor + 14)? >> 3;
                let _ = transition;
                cues.push(CueDef {
                    name: cue_names.get(cue_index).cloned().unwrap_or_default(),
                    flags,
                    single_sound: flags & CUE_FLAG_SINGLE_SOUND != 0,
                    sound_code,
                    sound_index: if flags & CUE_FLAG_SINGLE_SOUND != 0 {
                        sounds.iter().position(|sound| sound.code == sound_code)
                    } else {
                        None
                    },
                    variation_index: None,
                    instance_limit,
                    fade_in_ms,
                    fade_out_ms,
                    max_instance_behavior,
                    local_variables: Vec::new(),
                    local_variable_names: Vec::new(),
                });
                cursor += 15;
            }
        }

        // Variation tables, in file order, for every complex cue that is not
        // a single sound.  Each table's `code` matches the cue's `sbCode`.
        let variation_count = cues.iter().filter(|cue| !cue.single_sound).count();
        let mut variations = Vec::with_capacity(variation_count);
        if variation_count > 0 {
            if variation_offset < 0 {
                return Err(XACTENGINE_E_INVALIDDATA);
            }
            let mut cursor = variation_offset as usize;
            for _ in 0..variation_count {
                let code = cursor as u32;
                let entry_count_and_flags = u32_at(data, cursor)?;
                let entry_count = entry_count_and_flags & 0xFFFF;
                let kind = ((entry_count_and_flags >> 19) & 0x7) as u8;
                let variable = u16_at(data, cursor + 6)? as i16;
                cursor += 8;
                let mut entries = Vec::with_capacity(entry_count as usize);
                for _ in 0..entry_count {
                    match kind {
                        VARIATION_TABLE_TYPE_WAVE => {
                            let wave_index = u16_at(data, cursor)?;
                            let wavebank = u8_at(data, cursor + 2)?;
                            let weight_min = u8_at(data, cursor + 3)?;
                            let weight_max = u8_at(data, cursor + 4)?;
                            entries.push(VariationEntry::Wave {
                                wave_index,
                                wavebank,
                                weight_min,
                                weight_max,
                            });
                            cursor += 5;
                        }
                        VARIATION_TABLE_TYPE_SOUND => {
                            let sound_code = u32_at(data, cursor)?;
                            let weight_min = u8_at(data, cursor + 4)?;
                            let weight_max = u8_at(data, cursor + 5)?;
                            entries.push(VariationEntry::Sound {
                                sound_code,
                                weight_min,
                                weight_max,
                            });
                            cursor += 6;
                        }
                        VARIATION_TABLE_TYPE_INTERACTIVE => {
                            let sound_code = u32_at(data, cursor)?;
                            let var_min = f32_at(data, cursor + 4)?;
                            let var_max = f32_at(data, cursor + 8)?;
                            entries.push(VariationEntry::Interactive {
                                sound_code,
                                var_min,
                                var_max,
                            });
                            cursor += 16;
                        }
                        VARIATION_TABLE_TYPE_COMPACT_WAVE => {
                            let wave_index = u16_at(data, cursor)?;
                            let wavebank = u8_at(data, cursor + 2)?;
                            entries.push(VariationEntry::CompactWave {
                                wave_index,
                                wavebank,
                            });
                            cursor += 3;
                        }
                        VARIATION_TABLE_TYPE_CLIP => {
                            // Clip tables reference pre-recorded clips, which
                            // this engine core has no playback path for.
                            return Err(XACTENGINE_E_INVALIDDATA);
                        }
                        _ => return Err(XACTENGINE_E_INVALIDDATA),
                    }
                }
                variations.push(Variation {
                    code,
                    kind,
                    variable,
                    entries,
                });
            }
        }

        // Bind every variation cue to its table.  An interactive table is
        // the cue's local variable table: its variable index is the global
        // variable the cue-local slot shadows.
        for cue in cues.iter_mut().filter(|cue| !cue.single_sound) {
            cue.variation_index = variations
                .iter()
                .position(|variation| variation.code == cue.sound_code);
            let Some(index) = cue.variation_index else {
                return Err(XACTENGINE_E_INVALIDDATA);
            };
            let binding = variations.get(index).and_then(|variation| {
                (variation.kind == VARIATION_TABLE_TYPE_INTERACTIVE && variation.variable >= 0)
                    .then_some(variation.variable)
            });
            cue.local_variables.extend(binding);
        }

        // Cue-local friendly names: one 6-byte (absolute string offset,
        // sort key) index entry per local variable slot, in cue/local-slot
        // order.  A bank without the table keeps empty names and the cue
        // still resolves local slots through the global variable names.
        let local_slot_count = cues
            .iter()
            .map(|cue| cue.local_variables.len())
            .sum::<usize>();
        if local_variable_name_index_offset > 0 {
            let mut names = Vec::with_capacity(local_slot_count);
            for index in 0..local_slot_count {
                let entry = local_variable_name_index_offset as usize + index * 6;
                let string_offset = u32_at(data, entry)? as usize;
                names.push(zstring_at(data, string_offset, 255));
            }
            let mut next = 0_usize;
            for cue in cues.iter_mut() {
                let count = cue.local_variables.len();
                cue.local_variable_names
                    .extend(names[next..next + count].iter().cloned());
                next += count;
            }
        }

        Ok(Self {
            name,
            wavebank_names,
            sounds,
            variations,
            cues,
        })
    }
}

/// Pick the interactive variation entry whose authored range contains
/// `value`, or the nearest range when the value is outside them all.
fn interactive_entry_index(entries: &[VariationEntry], value: f32) -> usize {
    let mut nearest = 0_usize;
    let mut nearest_distance = f32::INFINITY;
    for (index, entry) in entries.iter().enumerate() {
        let VariationEntry::Interactive {
            var_min, var_max, ..
        } = entry
        else {
            continue;
        };
        if value >= *var_min && value <= *var_max {
            return index;
        }
        let distance = if value < *var_min {
            *var_min - value
        } else {
            value - *var_max
        };
        if distance < nearest_distance {
            nearest_distance = distance;
            nearest = index;
        }
    }
    nearest
}

fn entry_weight(entry: &VariationEntry) -> (u8, u8, u32) {
    match entry {
        VariationEntry::Wave {
            weight_min,
            weight_max,
            ..
        }
        | VariationEntry::Sound {
            weight_min,
            weight_max,
            ..
        } => (
            *weight_min,
            *weight_max,
            (weight_max.saturating_sub(*weight_min)) as u32,
        ),
        VariationEntry::Interactive { .. } => (0, 0, 1),
        VariationEntry::CompactWave { .. } => (0, 0, 1),
    }
}

/// Weighted selection over the authored `[weightMin, weightMax]` ranges.
/// A single entry (or all-zero weights) selects entry 0; this matches the
/// documented XACT random selection without an unbounded retry loop.
fn weighted_entry_index(weights: &[(u8, u8, u32)]) -> usize {
    if weights.len() <= 1 {
        return 0;
    }
    let total: u32 = weights.iter().map(|(_, _, weight)| weight).sum();
    if total == 0 {
        return 0;
    }
    let mut draw = next_random_u32() % total;
    for (index, (_, _, weight)) in weights.iter().enumerate() {
        if draw < *weight {
            return index;
        }
        draw -= weight;
    }
    weights.len() - 1
}

/// Parse one sound record starting at `cursor`; returns the record and the
/// cursor just past its inline data.
fn parse_sound(data: &[u8], cursor: usize, content_version: u16) -> Result<(Sound, usize), u32> {
    let code = cursor as u32;
    let flags = u8_at(data, cursor)?;
    let category = u16_at(data, cursor + 1)?;
    let volume = decibels_to_amplitude(u8_at(data, cursor + 3)?);
    let pitch = u16_at(data, cursor + 4)? as i16;
    let priority = u8_at(data, cursor + 5)?;
    // Fixed sound header: flags(1) + category(2) + volume(1) + pitch(2) +
    // priority(1) + sound length(2) = 9 bytes.
    let mut cursor = cursor + 9;
    let mut tracks = Vec::new();
    if flags & SOUND_FLAG_COMPLEX != 0 {
        let track_count = u8_at(data, cursor)? as usize;
        cursor += 1;
        // RPC block.
        if flags & SOUND_FLAG_RPC_MASK != 0 {
            let block_start = cursor;
            let rpc_data_length = u16_at(data, cursor)? as usize;
            cursor += 2;
            if flags & SOUND_FLAG_HAS_RPC != 0 {
                let count = u8_at(data, cursor)? as usize;
                cursor += 1 + count * 4;
            }
            if flags & SOUND_FLAG_HAS_TRACK_RPC != 0 {
                for _ in 0..track_count {
                    let count = u8_at(data, cursor)? as usize;
                    cursor += 1 + count * 4;
                }
            }
            if cursor != block_start + rpc_data_length {
                return Err(XACTENGINE_E_INVALIDDATA);
            }
        }
        // DSP block.
        if flags & SOUND_FLAG_HAS_DSP != 0 {
            cursor += 2;
            let count = u8_at(data, cursor)? as usize;
            cursor += 1 + count * 4;
        }
        // Per-track metadata: volume byte, event code, filter data + frequency
        // for XACT3.1+ content.
        let mut track_waves = Vec::with_capacity(track_count);
        for _ in 0..track_count {
            let track_volume = decibels_to_amplitude(u8_at(data, cursor)?);
            let event_code = u32_at(data, cursor + 1)?;
            cursor += 5;
            if content_version != 43 {
                cursor += 4;
            }
            track_waves.push((track_volume, event_code));
        }
        // Track event records live at their own absolute offsets.
        for (track_volume, event_code) in track_waves {
            let (wave, loop_count) =
                parse_track_first_wave(data, event_code as usize, content_version)?;
            tracks.push(SoundTrack {
                wave: WaveRef::new(wave.0, wave.1, loop_count),
                volume: track_volume,
            });
        }
    } else {
        let wave_index = u16_at(data, cursor)?;
        let wavebank = u8_at(data, cursor + 2)?;
        cursor += 3;
        tracks.push(SoundTrack {
            wave: WaveRef::new(wave_index, wavebank, 0),
            volume: 1.0,
        });
    }
    Ok((
        Sound {
            code,
            flags,
            category,
            volume,
            pitch,
            priority,
            tracks,
        },
        cursor,
    ))
}

/// Walk a track's event record and return the first play-wave reference and
/// its authored loop count.  Every event type in the June-2010 format is
/// parsed so the event stream stays aligned; the engine model plays the first
/// wave event per track (the authored XACT mix graph's primary source).
fn parse_track_first_wave(
    data: &[u8],
    mut cursor: usize,
    _content_version: u16,
) -> Result<((u16, u8), u8), u32> {
    let event_count = u8_at(data, cursor)? as usize;
    cursor += 1;
    let mut first: Option<((u16, u8), u8)> = None;
    for _ in 0..event_count {
        let event_info = u32_at(data, cursor)?;
        let event_type = event_info & 0x1F;
        cursor += 4;
        let _random_offset = u16_at(data, cursor)?;
        cursor += 2;
        let separator = u8_at(data, cursor)?;
        // The event separator is always 0xFF in authored content.
        if separator != 0xFF {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        cursor += 1;
        match event_type {
            EVENT_STOP => {
                cursor += 1;
            }
            EVENT_PLAYWAVE => {
                let _flags = u8_at(data, cursor)?;
                let wave_index = u16_at(data, cursor + 1)?;
                let wavebank = u8_at(data, cursor + 3)?;
                let loop_count = u8_at(data, cursor + 4)?;
                cursor += 9;
                if first.is_none() {
                    first = Some(((wave_index, wavebank), loop_count));
                }
            }
            EVENT_PLAYWAVETRACKVARIATION => {
                let _flags = u8_at(data, cursor)?;
                let loop_count = u8_at(data, cursor + 1)?;
                // flags(1) + loop count(1) + position(2) + angle(2).
                cursor += 6;
                let variation_info = u32_at(data, cursor)?;
                let wave_count = (variation_info & 0xFFFF) as usize;
                cursor += 8;
                let mut selected = None;
                for _ in 0..wave_count {
                    let wave_index = u16_at(data, cursor)?;
                    let wavebank = u8_at(data, cursor + 2)?;
                    // wave index(2) + wave bank(1) + weight min/max(2).
                    cursor += 5;
                    if selected.is_none() {
                        selected = Some((wave_index, wavebank));
                    }
                }
                if first.is_none()
                    && let Some(wave) = selected
                {
                    first = Some((wave, loop_count));
                }
            }
            EVENT_PLAYWAVEEFFECTVARIATION => {
                let _flags = u8_at(data, cursor)?;
                let wave_index = u16_at(data, cursor + 1)?;
                let wavebank = u8_at(data, cursor + 3)?;
                let loop_count = u8_at(data, cursor + 4)?;
                cursor += 9;
                // Effect-variation range block: pitch(4), volume bytes(2),
                // frequency/Q floats(16), flags(2).
                cursor += 24;
                if first.is_none() {
                    first = Some(((wave_index, wavebank), loop_count));
                }
            }
            EVENT_PLAYWAVETRACKEFFECTVARIATION => {
                let _flags = u8_at(data, cursor)?;
                let loop_count = u8_at(data, cursor + 1)?;
                // flags(1) + loop count(1) + position(2) + angle(2).
                cursor += 6;
                cursor += 24;
                let variation_info = u32_at(data, cursor)?;
                let wave_count = (variation_info & 0xFFFF) as usize;
                cursor += 8;
                let mut selected = None;
                for _ in 0..wave_count {
                    let wave_index = u16_at(data, cursor)?;
                    let wavebank = u8_at(data, cursor + 2)?;
                    // wave index(2) + wave bank(1) + weight min/max(2).
                    cursor += 5;
                    if selected.is_none() {
                        selected = Some((wave_index, wavebank));
                    }
                }
                if first.is_none()
                    && let Some(wave) = selected
                {
                    first = Some((wave, loop_count));
                }
            }
            EVENT_PITCH | EVENT_VOLUME | EVENT_PITCHREPEATING | EVENT_VOLUMEREPEATING => {
                let settings = u8_at(data, cursor)?;
                cursor += 1;
                if settings & 0x01 != 0 {
                    // Ramp form: f32 initial, f32 slope, f32 delta, u16 duration.
                    cursor += 14;
                } else {
                    // Equation form: u8 flags, f32 value1, f32 value2, 5 bytes.
                    cursor += 1 + 8 + 5;
                    if event_type == EVENT_PITCHREPEATING || event_type == EVENT_VOLUMEREPEATING {
                        cursor += 4;
                    }
                }
            }
            EVENT_MARKER => {
                cursor += 4;
            }
            EVENT_MARKERREPEATING => {
                cursor += 8;
            }
            _ => return Err(XACTENGINE_E_INVALIDDATA),
        }
    }
    first.ok_or(XACTENGINE_E_INVALIDDATA)
}

// ---------------------------------------------------------------------------
// XGS global settings
// ---------------------------------------------------------------------------

const XGS_SIGNATURE: u32 = 0x4653_4758; // bytes "XGSF"
const XGS_SIGNATURE_BE: u32 = 0x5847_5346; // bytes "FSGX"

/// One global-settings category.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct XgsCategory {
    pub(crate) name: String,
    pub(crate) volume: f32,
    pub(crate) parent: u16,
    pub(crate) instance_limit: u8,
    pub(crate) fade_in_ms: u16,
    pub(crate) fade_out_ms: u16,
    pub(crate) max_instance_behavior: u8,
    pub(crate) visibility: u8,
    /// Authored release-curve form.  The extended XGS category record adds
    /// one curve byte per category; the 10-byte stock record has no curve.
    pub(crate) release_curve: ReleaseCurve,
}

/// One global-settings variable.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct XgsVariable {
    pub(crate) name: String,
    pub(crate) accessibility: u8,
    pub(crate) initial: f32,
    pub(crate) min: f32,
    pub(crate) max: f32,
}

/// Parsed XGS global settings.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct GlobalSettings {
    pub(crate) categories: Vec<XgsCategory>,
    pub(crate) variables: Vec<XgsVariable>,
}

impl GlobalSettings {
    pub(crate) fn parse(data: &[u8]) -> Result<Self, u32> {
        let magic = u32_at(data, 0)?;
        if magic == XGS_SIGNATURE_BE {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        if magic != XGS_SIGNATURE {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        let content_version = u16_at(data, 4)?;
        if !(43..=46).contains(&content_version) {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        let tool_version = u16_at(data, 6)?;
        if tool_version != 42 {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        // Unknown u16 at 8; last-modified at 10..18; platform at 18.
        let platform = u8_at(data, 18)?;
        if platform != 3 && platform != 7 {
            return Err(XACTENGINE_E_INVALIDDATA);
        }
        let category_count = u16_at(data, 19)?;
        let variable_count = u16_at(data, 21)?;
        // blob1/blob2, rpc, dsp counts at 23..33.
        let category_offset = u32_at(data, 33)?;
        let variable_offset = u32_at(data, 37)?;
        let _blob1_offset = u32_at(data, 41)?;
        let category_name_index_offset = u32_at(data, 45)?;
        let _blob2_offset = u32_at(data, 49)?;
        let variable_name_index_offset = u32_at(data, 53)?;
        // categoryNameOffset at 57, variableNameOffset at 61, rpc at 65,
        // dsp preset at 69, dsp parameter at 73.

        // The stock June-2010 category record is 10 bytes.  Authored content
        // that carries the release-curve extension uses an 11-byte record;
        // detect that layout from the real table span instead of guessing.
        let category_stride = if category_count > 0
            && variable_offset >= category_offset
            && (variable_offset - category_offset) as usize == category_count as usize * 11
        {
            11
        } else {
            10
        };
        let mut categories = Vec::with_capacity(category_count as usize);
        for index in 0..category_count as usize {
            let base = category_offset as usize + index * category_stride;
            let instance_limit = u8_at(data, base)?;
            let fade_in_ms = u16_at(data, base + 1)?;
            let fade_out_ms = u16_at(data, base + 3)?;
            let max_instance_behavior = u8_at(data, base + 5)? >> 3;
            let parent = u16_at(data, base + 6)?;
            let volume = decibels_to_amplitude(u8_at(data, base + 8)?);
            let visibility = u8_at(data, base + 9)?;
            let release_curve = if category_stride == 11 {
                match u8_at(data, base + 10)? {
                    0 => ReleaseCurve::Linear,
                    1 => ReleaseCurve::Logarithmic,
                    2 => ReleaseCurve::EqualPower,
                    3 => ReleaseCurve::Squared,
                    _ => return Err(XACTENGINE_E_INVALIDDATA),
                }
            } else {
                ReleaseCurve::Linear
            };
            let name_entry = category_name_index_offset as usize + index * 6;
            let name_offset = u32_at(data, name_entry)? as usize;
            let name = zstring_at(data, name_offset, 255);
            categories.push(XgsCategory {
                name,
                volume,
                parent,
                instance_limit,
                fade_in_ms,
                fade_out_ms,
                max_instance_behavior,
                visibility,
                release_curve,
            });
        }

        let mut variables = Vec::with_capacity(variable_count as usize);
        for index in 0..variable_count as usize {
            let base = variable_offset as usize + index * 13;
            let accessibility = u8_at(data, base)?;
            let initial = f32_at(data, base + 1)?;
            let min = f32_at(data, base + 5)?;
            let max = f32_at(data, base + 9)?;
            let name_entry = variable_name_index_offset as usize + index * 6;
            let name_offset = u32_at(data, name_entry)? as usize;
            let name = zstring_at(data, name_offset, 255);
            variables.push(XgsVariable {
                name,
                accessibility,
                initial,
                min,
                max,
            });
        }

        Ok(Self {
            categories,
            variables,
        })
    }
}

// ---------------------------------------------------------------------------
// XACT value conversions
// ---------------------------------------------------------------------------

/// Decode an XACT volume byte into a linear amplitude.  The byte-to-decibel
/// curve is the builder's own (the same fit the FAudio FACT engine and
/// MonoGame's XACT reader use): `dB = 3969 * log10(byte / 28240) + 8715`
/// (centibels), then `amplitude = 10^(dB / 2000)`.  Byte 0xB4 (180) maps to
/// exactly 1.0.
pub(crate) fn decibels_to_amplitude(byte: u8) -> f32 {
    if byte == 0 {
        return 0.0;
    }
    let centibels = 3969.0_f64 * (byte as f64 / 28240.0).log10() + 8715.0;
    (10.0_f64).powf(centibels / 2000.0) as f32
}

/// XACT pitch is authored in cents: `ratio = 2^(pitch / 1200)`.
pub(crate) fn pitch_to_ratio(cents: i16) -> f32 {
    (2.0_f64).powf(cents as f64 / 1200.0) as f32
}

/// Deterministic xorshift used for weighted variation selection.  Real XACT
/// uses a random draw as well; determinism only makes tests reproducible.
fn next_random_u32() -> u32 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0x9E37_79B9_7F4A_7C15) };
    }
    STATE.with(|state| {
        let mut value = state.get();
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        state.set(value);
        (value >> 32) as u32
    })
}

// ---------------------------------------------------------------------------
// Engine runtime state
// ---------------------------------------------------------------------------

/// One category at runtime: the authored gain plus the live `SetVolume`
/// multiplier and pause flag.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CategoryState {
    pub(crate) name: String,
    pub(crate) authored_volume: f32,
    pub(crate) current_volume: f32,
    pub(crate) parent: u16,
    pub(crate) instance_limit: u8,
    pub(crate) paused: bool,
    pub(crate) visibility: u8,
    /// Authored release time from the XGS category fade-out field.  `Stop`
    /// without `XACT_FLAG_STOP_IMMEDIATE` fades over this many milliseconds.
    pub(crate) release_ms: u16,
    /// Authored release-curve shape (`Linear` for stock 10-byte records).
    pub(crate) release_curve: ReleaseCurve,
}

/// One registered notification (`XACT_NOTIFICATION_DESCRIPTION` copied into
/// the model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotificationRegistration {
    pub(crate) type_: u8,
    pub(crate) flags: u8,
    pub(crate) sound_bank: u64,
    pub(crate) wave_bank: u64,
    pub(crate) cue: u64,
    pub(crate) wave: u64,
    pub(crate) cue_index: u16,
    pub(crate) wave_index: u16,
    pub(crate) context: u64,
}

/// `XAUDIO2_MAX_SEND_COUNT` — the maximum output voices one cue can target.
pub(crate) const XACT_MAX_OUTPUT_VOICES: usize = 8;

/// One real guest output voice selected by `IXACT3Cue::SetOutputVoices`.
/// The guest object is an `IXAudio2Voice` created through the runtime's
/// XAudio2 surface; the runtime resolves it to a real mixer voice and reads
/// its channel count from the audio stack.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OutputVoiceRoute {
    /// Guest `IXAudio2Voice *` address.
    pub(crate) voice: u64,
    /// Destination channel count of the output voice.
    pub(crate) channels: u16,
    /// `SetOutputVoiceMatrix` coefficients, source-major.
    pub(crate) matrix: Option<(u32, u32, Vec<f32>)>,
}

/// A live source voice owned by a cue or standalone wave.  A cue that routes
/// to several output voices owns one real source voice per destination; all
/// of them render through the engine's mastering voice.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct LiveVoice {
    pub(crate) voice: VoiceId,
    pub(crate) extra_voices: [VoiceId; XACT_MAX_OUTPUT_VOICES - 1],
    pub(crate) extra_voice_count: u8,
    pub(crate) base_volume: f32,
    pub(crate) pitch_cents: i16,
    pub(crate) category: u16,
    pub(crate) paused: bool,
    /// Active release envelope after a non-immediate `Stop`.
    pub(crate) release: Option<ReleaseFade>,
}

impl LiveVoice {
    /// Every real mixer voice this instance owns, primary first.
    pub(crate) fn voices(&self) -> impl Iterator<Item = VoiceId> + '_ {
        std::iter::once(self.voice).chain(
            self.extra_voices[..usize::from(self.extra_voice_count.min(7))]
                .iter()
                .copied(),
        )
    }

    pub(crate) fn voice_count(&self) -> usize {
        1 + usize::from(self.extra_voice_count.min(7))
    }
}

/// The authored release curve form.  XGS categories carry a release-curve
/// byte in the extended category record; content without the extension uses
/// the documented linear amplitude form.  The four values are the authored
/// envelope shapes: linear amplitude, constant-decibel, equal-power and
/// squared-amplitude tapers.  Any other byte is malformed content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ReleaseCurve {
    #[default]
    Linear,
    Logarithmic,
    /// Equal-power taper: `sin(linear * pi/2)`.
    EqualPower,
    /// Squared-amplitude taper: `linear^2`.
    Squared,
}

/// An amplitude release from `start_gain` to zero over the authored category
/// release time.  `remaining_frames` drives the render drain and `curve`
/// selects the authored shape.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ReleaseFade {
    pub(crate) total_frames: u32,
    pub(crate) remaining_frames: u32,
    pub(crate) start_gain: f32,
    pub(crate) curve: ReleaseCurve,
}

impl ReleaseFade {
    /// Normalized release position, 1.0 at the start and 0.0 at the end.
    /// Linear amplitude is the documented default; the logarithmic form is
    /// a constant-decibel amplitude ramp that reaches -60 dB at the end.
    pub(crate) fn fraction(&self) -> f32 {
        if self.total_frames == 0 {
            0.0
        } else {
            let linear = self.remaining_frames as f32 / self.total_frames as f32;
            match self.curve {
                ReleaseCurve::Linear => linear,
                ReleaseCurve::Logarithmic => 10.0_f32.powf(-3.0 * (1.0 - linear)),
                ReleaseCurve::EqualPower => (linear * std::f32::consts::FRAC_PI_2).sin(),
                ReleaseCurve::Squared => linear * linear,
            }
        }
    }

    /// Gain at the start of the next render slice.
    pub(crate) fn gain(&self) -> f32 {
        self.start_gain * self.fraction()
    }
}

/// Engine state: one per `XACT3CreateEngine` result.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct EngineState {
    pub(crate) refcount: u32,
    pub(crate) initialized: bool,
    pub(crate) categories: Vec<CategoryState>,
    pub(crate) variables: Vec<XgsVariable>,
    pub(crate) variable_values: Vec<f32>,
    pub(crate) notification_callback: u64,
    pub(crate) notifications: Vec<NotificationRegistration>,
    pub(crate) mastering_voice: Option<VoiceId>,
    /// Live cue playbacks keyed by cue object address.
    pub(crate) cue_voices: BTreeMap<u64, LiveVoice>,
    /// Live standalone wave playbacks keyed by wave object address.
    pub(crate) wave_voices: BTreeMap<u64, LiveVoice>,
}

impl EngineState {
    /// The category a live voice belongs to, following parent categories.
    pub(crate) fn category_includes(&self, root: u16, category: u16) -> bool {
        if root == category {
            return true;
        }
        let mut current = category;
        let mut guard = 0;
        while let Some(state) = self.categories.get(current as usize) {
            if state.parent == root {
                return true;
            }
            if state.parent == 0xFFFF || state.parent == current {
                break;
            }
            current = state.parent;
            guard += 1;
            if guard > 64 {
                break;
            }
        }
        false
    }

    pub(crate) fn category_gain(&self, category: u16) -> f32 {
        self.categories
            .get(category as usize)
            .map(|state| state.current_volume)
            .unwrap_or(1.0)
    }
}

/// A loaded sound bank object.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SoundBankState {
    pub(crate) refcount: u32,
    pub(crate) engine: u64,
    pub(crate) bank: SoundBank,
}

/// A loaded wave bank object.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WaveBankState {
    pub(crate) refcount: u32,
    pub(crate) engine: u64,
    pub(crate) bank: WaveBank,
    /// Streaming entries whose payload has been prepared (real seek/read).
    pub(crate) prepared: std::collections::BTreeSet<u16>,
    /// Prepared streaming payloads, kept for playback until the bank is
    /// destroyed.  In-memory banks never populate this map.
    pub(crate) streaming_cache: BTreeMap<u16, Vec<i16>>,
}

/// The decoded source of a live cue.  Kept so `SetOutputVoices` can reroute
/// an active cue onto its new destination voices without re-resolving the
/// variation table or rewinding the authored selection.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CuePlayback {
    pub(crate) samples: Vec<i16>,
    pub(crate) channels: u16,
    pub(crate) sample_rate: u32,
    pub(crate) loop_count: u8,
    pub(crate) loop_start_samples: u32,
    pub(crate) loop_total_samples: u32,
    pub(crate) volume: f32,
    pub(crate) pitch: i16,
    pub(crate) category: u16,
}

/// A cue object handed to the guest.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CueObject {
    pub(crate) refcount: u32,
    pub(crate) engine: u64,
    pub(crate) sound_bank: u64,
    pub(crate) index: u16,
    pub(crate) state: u32,
    pub(crate) live: Option<LiveVoice>,
    /// Guest address of the cached `XACT_CUE_INSTANCE_PROPERTIES` block.
    pub(crate) properties_address: u64,
    pub(crate) matrix: Option<(u32, u32, Vec<f32>)>,
    pub(crate) loop_count: u8,
    /// Cue-local variable bindings (local slot -> global variable index).
    pub(crate) local_variables: Vec<i16>,
    /// Friendly names of the cue-local slots (parallel to `local_variables`).
    pub(crate) local_variable_names: Vec<String>,
    /// Cue-local overrides keyed by the shadowed global variable index.
    pub(crate) local_values: BTreeMap<u16, f32>,
    /// `SetOutputVoices` targets: real guest `IXAudio2Voice` objects with
    /// their channel counts and per-destination matrices.  `None` is the
    /// default route to the engine mastering voice.
    pub(crate) output_voices: Option<Vec<OutputVoiceRoute>>,
    /// Decoded source of the current live playback, preserved across
    /// `SetOutputVoices` reroutes.
    pub(crate) playback: Option<CuePlayback>,
}

/// A standalone wave object handed to the guest.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WaveObject {
    pub(crate) refcount: u32,
    pub(crate) engine: u64,
    pub(crate) wave_bank: u64,
    pub(crate) index: u16,
    pub(crate) state: u32,
    pub(crate) live: Option<LiveVoice>,
    pub(crate) volume: f32,
    pub(crate) pitch: i16,
    pub(crate) matrix: Option<(u32, u32, Vec<f32>)>,
    pub(crate) loop_count: u8,
}

/// Every guest object the XACT layer hands out.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum XactObject {
    Engine(EngineState),
    SoundBank(SoundBankState),
    WaveBank(WaveBankState),
    Cue(CueObject),
    Wave(WaveObject),
}

impl XactObject {
    pub(crate) fn refcount(&self) -> u32 {
        match self {
            XactObject::Engine(state) => state.refcount,
            XactObject::SoundBank(state) => state.refcount,
            XactObject::WaveBank(state) => state.refcount,
            XactObject::Cue(state) => state.refcount,
            XactObject::Wave(state) => state.refcount,
        }
    }

    pub(crate) fn add_ref(&mut self) -> u32 {
        match self {
            XactObject::Engine(state) => {
                state.refcount = state.refcount.saturating_add(1);
                state.refcount
            }
            XactObject::SoundBank(state) => {
                state.refcount = state.refcount.saturating_add(1);
                state.refcount
            }
            XactObject::WaveBank(state) => {
                state.refcount = state.refcount.saturating_add(1);
                state.refcount
            }
            XactObject::Cue(state) => {
                state.refcount = state.refcount.saturating_add(1);
                state.refcount
            }
            XactObject::Wave(state) => {
                state.refcount = state.refcount.saturating_add(1);
                state.refcount
            }
        }
    }

    pub(crate) fn release(&mut self) -> u32 {
        let refcount = self.refcount().saturating_sub(1);
        match self {
            XactObject::Engine(state) => state.refcount = refcount,
            XactObject::SoundBank(state) => state.refcount = refcount,
            XactObject::WaveBank(state) => state.refcount = refcount,
            XactObject::Cue(state) => state.refcount = refcount,
            XactObject::Wave(state) => state.refcount = refcount,
        }
        refcount
    }
}

/// The per-guest-process XACT runtime store.
#[derive(Debug, Clone, Default)]
pub(crate) struct XactRuntime {
    /// Guest vtable addresses, keyed by interface id.
    pub(crate) vtables: BTreeMap<u8, u64>,
    /// Guest object address → state.
    pub(crate) objects: BTreeMap<u64, XactObject>,
}

impl XactRuntime {
    pub(crate) fn engine(&self, address: u64) -> Option<&EngineState> {
        match self.objects.get(&address) {
            Some(XactObject::Engine(state)) => Some(state),
            _ => None,
        }
    }

    pub(crate) fn engine_mut(&mut self, address: u64) -> Option<&mut EngineState> {
        match self.objects.get_mut(&address) {
            Some(XactObject::Engine(state)) => Some(state),
            _ => None,
        }
    }

    /// Resolve a wave bank by the friendly name a sound bank references.
    pub(crate) fn wave_bank_by_name(&self, engine: u64, name: &str) -> Option<u64> {
        self.objects
            .iter()
            .find_map(|(address, object)| match object {
                XactObject::WaveBank(state)
                    if state.engine == engine && state.bank.name == name =>
                {
                    Some(*address)
                }
                _ => None,
            })
    }

    /// All live cue objects belonging to an engine.
    pub(crate) fn cue_objects_for_engine(&self, engine: u64) -> Vec<u64> {
        self.objects
            .iter()
            .filter_map(|(address, object)| match object {
                XactObject::Cue(state) if state.engine == engine => Some(*address),
                _ => None,
            })
            .collect()
    }
}

/// The process-wide XACT store, keyed by guest pid.  A guest pid owns at most
/// one live engine tree; releasing the engine removes the entry.
static XACT_RUNTIMES: LazyLock<Mutex<BTreeMap<u32, XactRuntime>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Lock the XACT store for one guest process.
pub(crate) fn lock_xact_runtimes() -> MutexGuard<'static, BTreeMap<u32, XactRuntime>> {
    XACT_RUNTIMES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Remove a guest process's entire XACT state (used when the last engine is
/// released, and by tests).
pub(crate) fn forget_xact_runtime(pid: u32) {
    lock_xact_runtimes().remove(&pid);
}

// ---------------------------------------------------------------------------
// Tests: real XWB/XSB/XGS bytes in memory
// ---------------------------------------------------------------------------

/// Shared byte-buffer builders for the XACT format tests.  These write the
/// genuine documented structures (WBND/SDBK/XGSF) so the parser tests and the
/// dispatch tests exercise the same real files.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    // ── byte-buffer writers mirroring the documented structures ────────────

    fn w16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }
    fn w32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }
    fn wi32(out: &mut Vec<u8>, value: i32) {
        out.extend_from_slice(&value.to_le_bytes());
    }
    fn wf32(out: &mut Vec<u8>, value: f32) {
        out.extend_from_slice(&value.to_le_bytes());
    }
    fn wstr64(out: &mut Vec<u8>, value: &str) {
        let mut bytes = value.as_bytes().to_vec();
        bytes.resize(64, 0);
        out.extend_from_slice(&bytes);
    }
    fn wcstr(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(value.as_bytes());
        out.push(0);
    }

    /// One raw XWB entry for [`build_xwb_entries`].
    pub(crate) struct XwbTestEntry {
        pub(crate) name: String,
        pub(crate) payload: Vec<u8>,
        pub(crate) tag: u8,
        pub(crate) channels: u16,
        pub(crate) sample_rate: u32,
        pub(crate) block_align: u8,
        pub(crate) bits_per_sample: u8,
        pub(crate) duration_samples: u32,
        pub(crate) loop_region: (u32, u32),
    }

    /// Build a non-compact little-endian XWB from raw entry payloads (any
    /// codec tag), mirroring the documented `WAVEBANK` container.
    pub(crate) fn build_xwb_entries(bank_name: &str, entries: &[XwbTestEntry]) -> Vec<u8> {
        let mut wave_data = Vec::new();
        let mut play_offsets = Vec::new();
        for entry in entries {
            play_offsets.push(wave_data.len() as u32);
            wave_data.extend_from_slice(&entry.payload);
        }
        let entry_count = entries.len() as u32;
        let metadata_size = 24u32;
        let seg0_offset = 52u32;
        let seg0_length = 96u32;
        let seg1_offset = seg0_offset + seg0_length;
        let seg1_length = 24 * entry_count;
        let has_names = entries.iter().any(|entry| !entry.name.is_empty());
        let names_offset = (seg1_offset + seg1_length + 3) & !3;
        let (names_offset, names_length, seg4_offset) = if !has_names {
            (0, 0, names_offset)
        } else {
            (
                names_offset,
                64 * entry_count,
                names_offset + 64 * entry_count,
            )
        };
        let seg4_length = wave_data.len() as u32;

        let mut out = Vec::new();
        w32(&mut out, WAVEBANK_SIGNATURE_LE);
        w32(&mut out, 46); // content/tool version
        w32(&mut out, 44); // header version
        for (offset, length) in [
            (seg0_offset, seg0_length),
            (seg1_offset, seg1_length),
            (0, 0), // seek tables
            (names_offset, names_length),
            (seg4_offset, seg4_length),
        ] {
            w32(&mut out, offset);
            w32(&mut out, length);
        }

        // Bank data.
        let flags = if has_names {
            WAVEBANK_FLAGS_ENTRYNAMES
        } else {
            0
        };
        w32(&mut out, flags);
        w32(&mut out, entry_count);
        wstr64(&mut out, bank_name);
        w32(&mut out, metadata_size);
        w32(&mut out, if has_names { 64 } else { 0 });
        w32(&mut out, 4);
        w32(&mut out, 0); // compact format
        out.extend_from_slice(&[0u8; 8]); // build time

        // Entry metadata.
        for (index, entry) in entries.iter().enumerate() {
            let format = MiniFormat {
                tag: entry.tag,
                channels: entry.channels,
                sample_rate: entry.sample_rate,
                block_align: entry.block_align,
                bits_per_sample: entry.bits_per_sample,
            };
            let duration = if entry.duration_samples != 0 {
                entry.duration_samples
            } else if entry.tag == WAVEBANK_TAG_PCM {
                (entry.payload.len()
                    / entry.channels.max(1) as usize
                    / if entry.bits_per_sample >= 16 { 2 } else { 1 }) as u32
            } else {
                0
            };
            let (loop_start, loop_total) = entry.loop_region;
            w32(&mut out, duration << 4);
            w32(&mut out, format.encode());
            w32(&mut out, play_offsets[index]);
            w32(&mut out, entry.payload.len() as u32);
            w32(&mut out, loop_start);
            w32(&mut out, loop_total);
        }

        // Entry names.
        if has_names {
            out.resize(names_offset as usize, 0);
            for entry in entries {
                wstr64(&mut out, &entry.name);
            }
        }
        out.resize(seg4_offset as usize, 0);
        out.extend_from_slice(&wave_data);
        out
    }

    /// Build a non-compact little-endian XWB with the supplied PCM entries.
    pub(crate) fn build_xwb(
        bank_name: &str,
        pcm_entries: &[Vec<i16>],
        entry_names: &[&str],
        loop_regions: &[(u32, u32)],
    ) -> Vec<u8> {
        let entries = pcm_entries
            .iter()
            .enumerate()
            .map(|(index, pcm)| XwbTestEntry {
                name: entry_names.get(index).copied().unwrap_or("").to_string(),
                payload: pcm.iter().flat_map(|sample| sample.to_le_bytes()).collect(),
                tag: WAVEBANK_TAG_PCM,
                channels: 1,
                sample_rate: 44100,
                block_align: 2,
                bits_per_sample: 16,
                duration_samples: pcm.len() as u32,
                loop_region: loop_regions.get(index).copied().unwrap_or((0, 0)),
            })
            .collect::<Vec<_>>();
        build_xwb_entries(bank_name, &entries)
    }

    /// Build a minimal single-wavebank XSB with simple cues (one per wave).
    pub(crate) struct XsbSpec<'a> {
        pub(crate) bank_name: &'a str,
        pub(crate) wavebank_name: &'a str,
        /// (cue name, wave index in the wavebank).
        pub(crate) cues: &'a [(&'a str, u16)],
    }

    pub(crate) fn build_xsb(spec: &XsbSpec<'_>) -> Vec<u8> {
        let cue_count = spec.cues.len() as u16;
        let sound_count = cue_count;
        const HEADER: u32 = 138;
        let sound_offset = HEADER;
        let cue_simple_offset = sound_offset + 12 * sound_count as u32;
        let wavebank_name_offset = cue_simple_offset + 5 * cue_count as u32;
        let cue_name_index_offset = wavebank_name_offset + 64;
        let mut name_offsets = Vec::new();
        let mut cursor = cue_name_index_offset + 6 * cue_count as u32;
        for (name, _) in spec.cues {
            name_offsets.push(cursor);
            cursor += name.len() as u32 + 1;
        }

        let mut out = Vec::new();
        w32(&mut out, SOUNDBANK_SIGNATURE);
        w16(&mut out, 46); // content version
        w16(&mut out, SOUNDBANK_FORMAT_VERSION);
        w16(&mut out, 0); // crc
        out.extend_from_slice(&[0u8; 8]); // last modified
        out.push(1); // platform: Windows
        w16(&mut out, cue_count); // simple cue count
        w16(&mut out, 0); // complex cue count
        w16(&mut out, 0); // unknown
        w16(&mut out, cue_count); // total cues
        out.push(1); // wave bank count
        w16(&mut out, sound_count);
        w16(&mut out, cursor as u16); // cue name table length (bounded in fixtures)
        w16(&mut out, 0); // unknown
        wi32(&mut out, cue_simple_offset as i32);
        wi32(&mut out, -1); // complex cues
        wi32(&mut out, -1); // cue name table offset (index table used)
        wi32(&mut out, -1);
        wi32(&mut out, -1); // variation offset
        wi32(&mut out, -1); // transition offset
        wi32(&mut out, wavebank_name_offset as i32);
        wi32(&mut out, -1); // hash table
        wi32(&mut out, cue_name_index_offset as i32);
        wi32(&mut out, sound_offset as i32);
        wstr64(&mut out, spec.bank_name);
        debug_assert_eq!(out.len(), HEADER as usize);

        // Sounds: flags(1) + category(2) + volume(1) + pitch(2) + priority(1)
        // + sound length(2) + wave index(2) + wavebank(1) = 12 bytes.
        for (_, wave_index) in spec.cues {
            out.push(0); // flags: simple
            w16(&mut out, 0); // category
            out.push(180); // volume byte => amplitude 1.0
            w16(&mut out, 0); // pitch cents
            out.push(255); // priority
            w16(&mut out, 0); // sound length
            w16(&mut out, *wave_index);
            out.push(0); // wavebank index
        }

        // Simple cues: flags(1) + sbCode(4).
        for index in 0..cue_count as u32 {
            out.push(0);
            w32(&mut out, sound_offset + 12 * index);
        }

        // Wave-bank name table.
        wstr64(&mut out, spec.wavebank_name);

        // Cue-name index: absolute string offset + sort key.
        for (index, offset) in name_offsets.iter().enumerate() {
            w32(&mut out, *offset);
            w16(&mut out, index as u16);
        }

        // Cue-name strings.
        for (name, _) in spec.cues {
            wcstr(&mut out, name);
        }

        out
    }

    /// Build a minimal XSB with one complex cue whose interactive variation
    /// table is bound to `variable_index`.  Each entry is
    /// `(wave_index, var_min, var_max)` and gets its own simple sound record.
    pub(crate) fn build_xsb_interactive(
        bank_name: &str,
        wavebank_name: &str,
        cue_name: &str,
        variable_index: i16,
        entries: &[(u16, f32, f32)],
        local_name: Option<&str>,
    ) -> Vec<u8> {
        let sound_count = entries.len() as u16;
        const HEADER: u32 = 138;
        let sound_offset = HEADER;
        let cue_complex_offset = sound_offset + 12 * sound_count as u32;
        let variation_offset = cue_complex_offset + 15;
        let variation_length = 8 + 16 * sound_count as u32;
        let wavebank_name_offset = variation_offset + variation_length;
        let cue_name_index_offset = wavebank_name_offset + 64;
        let cue_name_offset = cue_name_index_offset + 6;
        let cue_name_end = cue_name_offset + cue_name.len() as u32 + 1;
        let local_name_index_offset = cue_name_end;
        let local_name_offset = local_name_index_offset + 6;
        let end = match local_name {
            Some(name) => local_name_offset + name.len() as u32 + 1,
            None => cue_name_end,
        };

        let mut out = Vec::new();
        w32(&mut out, SOUNDBANK_SIGNATURE);
        w16(&mut out, 46);
        w16(&mut out, SOUNDBANK_FORMAT_VERSION);
        w16(&mut out, 0);
        out.extend_from_slice(&[0u8; 8]);
        out.push(1);
        w16(&mut out, 0); // simple cues
        w16(&mut out, 1); // complex cues
        w16(&mut out, 0);
        w16(&mut out, 1); // total cues
        out.push(1); // wave banks
        w16(&mut out, sound_count);
        w16(&mut out, end as u16);
        w16(&mut out, 0);
        wi32(&mut out, -1); // simple cue offset
        wi32(&mut out, cue_complex_offset as i32);
        wi32(&mut out, -1); // cue name table
        wi32(
            &mut out,
            if local_name.is_some() {
                local_name_index_offset as i32
            } else {
                -1
            },
        ); // cue-local variable name index table
        wi32(&mut out, variation_offset as i32);
        wi32(&mut out, -1); // transition
        wi32(&mut out, wavebank_name_offset as i32);
        wi32(&mut out, -1); // hash
        wi32(&mut out, cue_name_index_offset as i32);
        wi32(&mut out, sound_offset as i32);
        wstr64(&mut out, bank_name);
        debug_assert_eq!(out.len(), HEADER as usize);

        // Simple sound records, one per interactive entry.
        for (wave_index, _, _) in entries {
            out.push(0);
            w16(&mut out, 0);
            out.push(180);
            w16(&mut out, 0);
            out.push(255);
            w16(&mut out, 0);
            w16(&mut out, *wave_index);
            out.push(0);
        }

        // Complex cue pointing at the variation table.
        out.push(0); // flags: not single sound
        w32(&mut out, variation_offset);
        w32(&mut out, 0); // transition
        out.push(255); // instance limit
        w16(&mut out, 0);
        w16(&mut out, 0);
        out.push(0);

        // Interactive variation table (the parser derives `code` from the
        // table's absolute file offset).
        w32(&mut out, sound_count as u32 | (3u32 << 19));
        w16(&mut out, 0);
        out.extend_from_slice(&variable_index.to_le_bytes());
        for (index, (_, var_min, var_max)) in entries.iter().enumerate() {
            w32(&mut out, sound_offset + 12 * index as u32);
            wf32(&mut out, *var_min);
            wf32(&mut out, *var_max);
            w32(&mut out, 0); // reserved; the documented entry is 16 bytes
        }

        wstr64(&mut out, wavebank_name);
        w32(&mut out, cue_name_offset);
        w16(&mut out, 0);
        wcstr(&mut out, cue_name);
        if let Some(name) = local_name {
            w32(&mut out, local_name_offset);
            w16(&mut out, 0);
            wcstr(&mut out, name);
        }
        out
    }

    pub(crate) fn build_xgs() -> Vec<u8> {
        const CATEGORY_OFFSET: u32 = 80;
        const VARIABLE_OFFSET: u32 = CATEGORY_OFFSET + 2 * 10; // 100
        const CATEGORY_NAME_INDEX: u32 = VARIABLE_OFFSET + 13; // 113
        const VARIABLE_NAME_INDEX: u32 = CATEGORY_NAME_INDEX + 2 * 6; // 125
        const CATEGORY_NAMES: u32 = VARIABLE_NAME_INDEX + 6; // 131
        const VARIABLE_NAMES: u32 = CATEGORY_NAMES + 6 + 4; // 141
        let mut out = Vec::new();
        w32(&mut out, XGS_SIGNATURE);
        w16(&mut out, 46); // content version
        w16(&mut out, 42); // tool version
        w16(&mut out, 0); // unknown
        out.extend_from_slice(&[0u8; 8]); // last modified
        out.push(3); // platform: PC
        w16(&mut out, 2); // categories
        w16(&mut out, 1); // variables
        w16(&mut out, 0); // blob1
        w16(&mut out, 0); // blob2
        w16(&mut out, 0); // rpc
        w16(&mut out, 0); // dsp presets
        w16(&mut out, 0); // dsp parameters
        w32(&mut out, CATEGORY_OFFSET);
        w32(&mut out, VARIABLE_OFFSET);
        w32(&mut out, 0); // blob1 offset
        w32(&mut out, CATEGORY_NAME_INDEX);
        w32(&mut out, 0); // blob2 offset
        w32(&mut out, VARIABLE_NAME_INDEX);
        w32(&mut out, CATEGORY_NAMES);
        w32(&mut out, VARIABLE_NAMES);
        w32(&mut out, 0); // rpc offset
        w32(&mut out, 0); // dsp preset offset
        w32(&mut out, 0); // dsp parameter offset
        out.resize(CATEGORY_OFFSET as usize, 0);
        // Category "Music": limit 255, fades 0, parent none, volume 180, visible.
        out.push(255);
        w16(&mut out, 0);
        w16(&mut out, 0);
        out.push(0);
        w16(&mut out, 0xFFFF);
        out.push(180);
        out.push(1);
        // Category "SFX".
        out.push(255);
        w16(&mut out, 0);
        w16(&mut out, 0);
        out.push(0);
        w16(&mut out, 0xFFFF);
        out.push(180);
        out.push(1);
        // Variable "SpeedOfSound" (global + settable), initial 343, 0..1000.
        out.push(0x03);
        wf32(&mut out, 343.0);
        wf32(&mut out, 0.0);
        wf32(&mut out, 1000.0);
        out.resize(CATEGORY_NAME_INDEX as usize, 0);
        // Category name index entries: (absolute offset, unknown).
        w32(&mut out, CATEGORY_NAMES);
        w16(&mut out, 0);
        w32(&mut out, CATEGORY_NAMES + 6);
        w16(&mut out, 0);
        // Variable name index.
        w32(&mut out, VARIABLE_NAMES);
        w16(&mut out, 0);
        out.resize(CATEGORY_NAMES as usize, 0);
        wcstr(&mut out, "Music");
        wcstr(&mut out, "SFX");
        wcstr(&mut out, "SpeedOfSound");
        out
    }

    /// Build an XGS whose category records carry the 11-byte release-curve
    /// extension: a 200 ms fade-out on "Music" and the requested curve byte
    /// (0 = linear, 1 = logarithmic, 2 = equal-power, 3 = squared).
    pub(crate) fn build_xgs_curve(curve: u8) -> Vec<u8> {
        build_xgs_curve_with_fade(curve, 200)
    }

    pub(crate) fn build_xgs_curve_with_fade(curve: u8, fade_out: u16) -> Vec<u8> {
        const CATEGORY_OFFSET: u32 = 80;
        const CATEGORY_STRIDE: u32 = 11;
        const VARIABLE_OFFSET: u32 = CATEGORY_OFFSET + 2 * CATEGORY_STRIDE;
        const CATEGORY_NAME_INDEX: u32 = VARIABLE_OFFSET + 13;
        const VARIABLE_NAME_INDEX: u32 = CATEGORY_NAME_INDEX + 2 * 6;
        const CATEGORY_NAMES: u32 = VARIABLE_NAME_INDEX + 6;
        const VARIABLE_NAMES: u32 = CATEGORY_NAMES + 6 + 4;
        let mut out = Vec::new();
        w32(&mut out, XGS_SIGNATURE);
        w16(&mut out, 46);
        w16(&mut out, 42);
        w16(&mut out, 0);
        out.extend_from_slice(&[0u8; 8]);
        out.push(3);
        w16(&mut out, 2);
        w16(&mut out, 1);
        w16(&mut out, 0);
        w16(&mut out, 0);
        w16(&mut out, 0);
        w16(&mut out, 0);
        w16(&mut out, 0);
        w32(&mut out, CATEGORY_OFFSET);
        w32(&mut out, VARIABLE_OFFSET);
        w32(&mut out, 0);
        w32(&mut out, CATEGORY_NAME_INDEX);
        w32(&mut out, 0);
        w32(&mut out, VARIABLE_NAME_INDEX);
        w32(&mut out, CATEGORY_NAMES);
        w32(&mut out, VARIABLE_NAMES);
        w32(&mut out, 0);
        w32(&mut out, 0);
        w32(&mut out, 0);
        out.resize(CATEGORY_OFFSET as usize, 0);
        for (fade, curve_byte) in [(fade_out, curve), (0_u16, 0_u8)] {
            out.push(255);
            w16(&mut out, 0);
            w16(&mut out, fade);
            out.push(0);
            w16(&mut out, 0xFFFF);
            out.push(180);
            out.push(1);
            out.push(curve_byte);
        }
        out.push(0x01);
        wf32(&mut out, 343.0);
        wf32(&mut out, 0.0);
        wf32(&mut out, 1000.0);
        out.resize(CATEGORY_NAME_INDEX as usize, 0);
        w32(&mut out, CATEGORY_NAMES);
        w16(&mut out, 0);
        w32(&mut out, CATEGORY_NAMES + 6);
        w16(&mut out, 0);
        w32(&mut out, VARIABLE_NAMES);
        w16(&mut out, 0);
        out.resize(CATEGORY_NAMES as usize, 0);
        wcstr(&mut out, "Music");
        wcstr(&mut out, "SFX");
        wcstr(&mut out, "SpeedOfSound");
        out
    }

    /// A release curve with a controlled frame position, used by the shape
    /// tests without a renderer.
    pub(crate) fn release_at(curve: ReleaseCurve, remaining: u32, total: u32) -> f32 {
        ReleaseFade {
            total_frames: total,
            remaining_frames: remaining,
            start_gain: 1.0,
            curve,
        }
        .gain()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::fixtures::*;

    // ── parser tests ───────────────────────────────────────────────────────

    #[test]
    fn xwb_rejects_bad_signature_and_versions() {
        let mut bytes = build_xwb("Bank", &[vec![0]], &[], &[]);
        bytes[0] = b'X';
        assert_eq!(WaveBank::parse(&bytes), Err(XACTENGINE_E_INVALIDDATA));
        let mut bytes = build_xwb("Bank", &[vec![0]], &[], &[]);
        bytes[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(WaveBank::parse(&bytes), Err(XACTENGINE_E_INVALIDDATA));
        let mut bytes = build_xwb("Bank", &[vec![0]], &[], &[]);
        bytes[8..12].copy_from_slice(&41u32.to_le_bytes());
        assert_eq!(WaveBank::parse(&bytes), Err(XACTENGINE_E_INVALIDDATA));
    }

    #[test]
    fn xwb_rejects_truncated_buffers() {
        let bytes = build_xwb("Bank", &[vec![1, 2, 3, 4]], &[], &[]);
        for cut in [0usize, 4, 8, 20, 60, 100, bytes.len() - 1] {
            assert_eq!(
                WaveBank::parse(&bytes[..cut]),
                Err(XACTENGINE_E_INVALIDDATA),
                "truncated at {cut} must be invalid"
            );
        }
    }

    #[test]
    fn xwb_marks_unknown_codecs_with_real_error() {
        // A WMA entry (tag 3) keeps its metadata but surfaces the genuine
        // invalid-content error rather than fake audio.
        let mut bytes = build_xwb("Bank", &[vec![0i16; 8]], &[], &[]);
        let format_offset = 52 + 96 + 4; // metadata base + format field
        let wma = MiniFormat {
            tag: WAVEBANK_TAG_WMA,
            channels: 2,
            sample_rate: 44100,
            block_align: 200,
            bits_per_sample: 16,
        };
        bytes[format_offset..format_offset + 4].copy_from_slice(&wma.encode().to_le_bytes());
        let bank = WaveBank::parse(&bytes).expect("metadata parses");
        assert_eq!(bank.entries[0].pcm, None);
        assert_eq!(bank.entries[0].decode_error, Some(XACTENGINE_E_INVALIDDATA));
    }

    #[test]
    fn xsb_rejects_malformed_headers() {
        let bytes = build_xsb(&XsbSpec {
            bank_name: "SoundBank",
            wavebank_name: "WaveBank",
            cues: &[("beep", 0)],
        });
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert_eq!(SoundBank::parse(&bad), Err(XACTENGINE_E_INVALIDDATA));
        let mut bad = bytes.clone();
        bad[6..8].copy_from_slice(&17u16.to_le_bytes());
        assert_eq!(SoundBank::parse(&bad), Err(XACTENGINE_E_INVALIDDATA));
        let mut bad = bytes.clone();
        bad[18] = 9; // invalid platform
        assert_eq!(SoundBank::parse(&bad), Err(XACTENGINE_E_INVALIDDATA));
        assert_eq!(
            SoundBank::parse(&bytes[..bytes.len() - 40]),
            Err(XACTENGINE_E_INVALIDDATA)
        );
        assert_eq!(
            SoundBank::parse(&bytes[..40]),
            Err(XACTENGINE_E_INVALIDDATA)
        );
    }

    #[test]
    fn xsb_select_cue_rejects_bad_index() {
        let bytes = build_xsb(&XsbSpec {
            bank_name: "SoundBank",
            wavebank_name: "WaveBank",
            cues: &[("beep", 0)],
        });
        let bank = SoundBank::parse(&bytes).expect("valid XSB");
        assert_eq!(bank.select_cue(7), Err(XACTENGINE_E_INVALIDCUEINDEX));
    }

    #[test]
    fn xgs_rejects_wrong_signature() {
        let mut bytes = build_xgs();
        bytes[0] = b'Z';
        assert_eq!(GlobalSettings::parse(&bytes), Err(XACTENGINE_E_INVALIDDATA));
    }

    #[test]
    fn engine_categories_follow_parent_chains() {
        let engine = EngineState {
            categories: vec![
                CategoryState {
                    name: "Global".to_string(),
                    authored_volume: 1.0,
                    current_volume: 1.0,
                    parent: 0xFFFF,
                    instance_limit: 255,
                    paused: false,
                    visibility: 1,
                    release_ms: 0,
                    release_curve: ReleaseCurve::Linear,
                },
                CategoryState {
                    name: "Default".to_string(),
                    authored_volume: 1.0,
                    current_volume: 0.5,
                    parent: 0,
                    instance_limit: 255,
                    paused: false,
                    visibility: 1,
                    release_ms: 0,
                    release_curve: ReleaseCurve::Linear,
                },
                CategoryState {
                    name: "Music".to_string(),
                    authored_volume: 1.0,
                    current_volume: 0.25,
                    parent: 0,
                    instance_limit: 255,
                    paused: false,
                    visibility: 1,
                    release_ms: 0,
                    release_curve: ReleaseCurve::Linear,
                },
            ],
            ..EngineState::default()
        };
        assert!(engine.category_includes(0, 2));
        assert!(engine.category_includes(2, 2));
        assert!(!engine.category_includes(1, 2));
        assert_eq!(engine.category_gain(2), 0.25);
        assert_eq!(engine.category_gain(9), 1.0);
    }

    #[test]
    fn release_curves_pin_exact_gain_and_reject_malformed_payload() {
        assert_eq!(release_at(ReleaseCurve::Linear, 50, 100), 0.5);
        assert!(
            (release_at(ReleaseCurve::Logarithmic, 50, 100) - 10.0_f32.powf(-1.5)).abs() < 1.0e-6
        );
        assert!(
            (release_at(ReleaseCurve::EqualPower, 50, 100) - std::f32::consts::FRAC_1_SQRT_2).abs()
                < 1.0e-6
        );
        assert_eq!(release_at(ReleaseCurve::Squared, 50, 100), 0.25);
        assert_eq!(release_at(ReleaseCurve::Squared, 0, 100), 0.0);
        assert_eq!(
            release_at(ReleaseCurve::EqualPower, 0, 0),
            0.0,
            "invalid zero-length release is silent"
        );
        for (byte, curve) in [
            (0_u8, ReleaseCurve::Linear),
            (1_u8, ReleaseCurve::Logarithmic),
            (2_u8, ReleaseCurve::EqualPower),
            (3_u8, ReleaseCurve::Squared),
        ] {
            let settings =
                GlobalSettings::parse(&build_xgs_curve(byte)).expect("valid release curve");
            assert_eq!(settings.categories[0].release_curve, curve);
        }
        assert_eq!(
            GlobalSettings::parse(&build_xgs_curve(4)),
            Err(XACTENGINE_E_INVALIDDATA),
            "unknown curve byte is malformed content"
        );
    }
}
