//! WinMM (Windows Multimedia) audio API implementation.
//!
//! Provides a synthetic `winmm.dll` subsystem that routes wave audio
//! calls through the macOS CoreAudio / AudioQueue infrastructure via
//! the existing [`AudioSubsystem`](crate::audio::AudioSubsystem).
//!
//! ## Supported APIs
//!
//! - **waveOut*** — waveform-audio output (open, close, prepare header,
//!   write, reset, volume, get position)
//! - **waveIn*** — waveform-audio input (open, close, prepare header,
//!   add buffer, start, stop, reset, get position)
//! - **midiOut*** / **midiIn*** — MIDI output and input via CoreMIDI
//! - **timeGetTime** / **timeBeginPeriod** / **timeEndPeriod** — timer
//! - **PlaySoundW** — real sound playback via CoreAudio/cpal
//! - **mmio*** — multimedia file I/O (RIFF/WAV real file access)

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── Audio subsystem imports ─────────────────────────────────────────────────
use crate::audio::{SampleFormat, WaveFormat};
use crate::midi;
use crate::real_audio::{pcm_bytes_to_float, RealAudioBackend};

// ── Wave message constants ──────────────────────────────────────────────────

/// Convert interleaved f32 samples to the device's PCM byte format
/// (8-bit unsigned, 16-bit signed LE, or 32-bit float LE).
fn capture_pcm_bytes(samples: &[f32], format: &WaveFormatEx) -> Vec<u8> {
    let bytes_per_sample = (format.w_bits_per_sample as usize / 8).max(1);
    let mut out = Vec::with_capacity(samples.len() * bytes_per_sample);
    match format.w_bits_per_sample {
        8 => {
            for &sample in samples {
                let value = (sample.clamp(-1.0, 1.0) * 127.0 + 128.0) as u8;
                out.push(value);
            }
        }
        32 => {
            for &sample in samples {
                out.extend_from_slice(&sample.clamp(-1.0, 1.0).to_le_bytes());
            }
        }
        _ => {
            // 16-bit (or unspecified) — signed little-endian PCM
            for &sample in samples {
                let value = if sample <= -1.0 {
                    i16::MIN
                } else {
                    (sample.clamp(-1.0, 1.0) * i16::MAX as f32) as i16
                };
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
    }
    out
}

/// Sent to the callback when a wave device is opened.
pub const WOM_OPEN: u32 = 0x3BB;
/// Sent to the callback when a wave device is closed.
pub const WOM_CLOSE: u32 = 0x3BC;
/// Sent to the callback when a buffer (WAVEHDR) has finished playing.
pub const WOM_DONE: u32 = 0x3BD;

/// Sent to the callback when a wave input device is opened.
pub const WIM_OPEN: u32 = 0x3BE;
/// Sent to the callback when a wave input device is closed.
pub const WIM_CLOSE: u32 = 0x3BF;
/// Sent to the callback when a wave input buffer is filled.
pub const WIM_DATA: u32 = 0x3C0;

/// Minimum (+0) and maximum (+1) wave mapper device IDs.
pub const WAVE_MAPPER: u32 = 0xFFFF;
pub const WAVE_MAPPER_MAX_DEVICES: u32 = 1;

/// Wave output error codes (MMSYSERR base).
pub const MMSYSERR_NOERROR: u32 = 0;
pub const MMSYSERR_ERROR: u32 = 1;
pub const MMSYSERR_BADDEVICEID: u32 = 2;
pub const MMSYSERR_NOTENABLED: u32 = 3;
pub const MMSYSERR_ALLOCATED: u32 = 4;
pub const MMSYSERR_INVALHANDLE: u32 = 5;
pub const MMSYSERR_NODRIVER: u32 = 6;
pub const MMSYSERR_NOMEM: u32 = 7;
pub const MMSYSERR_NOTSUPPORTED: u32 = 8;
pub const WAVERR_BADFORMAT: u32 = 0x20;
pub const WAVERR_STILLPLAYING: u32 = 0x21;
pub const WAVERR_UNPREPARED: u32 = 0x22;
pub const WAVERR_SYNC: u32 = 0x23;

// ── PlaySound flags ──────────────────────────────────────────────────────────

/// Play synchronously (default). The function does not return until the sound
/// finishes playing.
pub const SND_SYNC: u32 = 0x0000;
/// Play asynchronously. The function returns immediately and the sound plays
/// in a background thread.
pub const SND_ASYNC: u32 = 0x0001;
/// If the sound cannot be found, the function returns silently without playing
/// the default sound.
pub const SND_NODEFAULT: u32 = 0x0002;
/// The `pszSound` parameter is a memory pointer to the sound image.
pub const SND_MEMORY: u32 = 0x0004;
/// Play the sound repeatedly until `PlaySoundW` is called again with `pszSound=NULL`.
pub const SND_LOOP: u32 = 0x0008;
/// Don't stop any currently playing sound.
pub const SND_NOSTOP: u32 = 0x0010;
/// The `pszSound` parameter is a file name.
pub const SND_FILENAME: u32 = 0x00020000;
/// The `pszSound` parameter is a resource name.
pub const SND_RESOURCE: u32 = 0x00040004;
/// The sound is for an alert (e.g., MessageBox). Not functionally different.
pub const SND_ALIAS: u32 = 0x00010000;
/// The sound is an application-defined alias.
pub const SND_ALIAS_ID: u32 = 0x00110000;
/// Play the system-default sound unless SND_NODEFAULT is set.
pub const SND_DEFAULT: u32 = 0x00000000;

// ── mmio constants ───────────────────────────────────────────────────────────

/// Open file for reading only.
pub const MMIO_READ: u32 = 0x00000000;
/// Open file for writing only.
pub const MMIO_WRITE: u32 = 0x00000001;
/// Open file for both reading and writing.
pub const MMIO_READWRITE: u32 = 0x00000002;
/// Create a new file (truncate if exists).
pub const MMIO_CREATE: u32 = 0x00001000;
/// Compatibility mode (ignored on macOS).
pub const MMIO_COMPAT: u32 = 0x00002000;
/// Deny others read/write access.
pub const MMIO_EXCLUSIVE: u32 = 0x00004000;
/// Deny others read access.
pub const MMIO_DENYREAD: u32 = 0x00008000;
/// Deny others write access.
pub const MMIO_DENYWRITE: u32 = 0x00010000;
/// Preserve existing file (fail if exists).
pub const MMIO_EXIST: u32 = 0x00004000;
/// Parse the file for RIFF chunks on open.
pub const MMIO_PARSE: u32 = 0x00000100;
/// Allocate memory for a temporary file.
pub const MMIO_ALLOCBUF: u32 = 0x00010000;
/// Return MMSYSERR_INVALHANDLE on invalid handle.
pub const MMIO_INVALID_HANDLE: u32 = 0;

/// Chunk information not found.
pub const MMIOERR_CHUNKNOTFOUND: u32 = 25;
/// Unable to read the file.
pub const MMIOERR_CANNOTREAD: u32 = 26;
/// Unable to write the file.
pub const MMIOERR_CANNOTWRITE: u32 = 27;
/// Unable to open the file.
pub const MMIOERR_CANNOTOPEN: u32 = 28;
/// Unable to close the file.
pub const MMIOERR_CANNOTCLOSE: u32 = 29;
/// Out of memory.
pub const MMIOERR_OUTOFMEMORY: u32 = 30;
/// Access denied.
pub const MMIOERR_ACCESSDENIED: u32 = 31;
/// Invalid file handle.
pub const MMIOERR_INVALIDFILE: u32 = 32;
/// The file was not found.
pub const MMIOERR_PATHNOTFOUND: u32 = 33;
/// The file is not a valid RIFF file.
pub const MMIOERR_NOTRIFFFILE: u32 = 34;

/// Find a chunk by ID (ckid). Used with mmioDescend.
pub const MMIO_FIND_CHUNK: u32 = 0x0000;
/// Find a RIFF file by form type (fccType).
pub const MMIO_FIND_LIST: u32 = 0x0001;
/// Find a chunk by its form type (fccType).
pub const MMIO_FIND_RIFF: u32 = 0x0002;

// ── FOURCC helper ───────────────────────────────────────────────────────────

/// Build a FOURCC code from four ASCII characters.
#[inline]
pub const fn mmio_fourcc(c0: u8, c1: u8, c2: u8, c3: u8) -> u32 {
    (c0 as u32) | ((c1 as u32) << 8) | ((c2 as u32) << 16) | ((c3 as u32) << 24)
}

/// Standard FOURCC codes used in RIFF/WAV files.
pub const FOURCC_RIFF: u32 = mmio_fourcc(b'R', b'I', b'F', b'F');
pub const FOURCC_LIST: u32 = mmio_fourcc(b'L', b'I', b'S', b'T');
pub const FOURCC_WAVE: u32 = mmio_fourcc(b'W', b'A', b'V', b'E');
pub const FOURCC_FMT: u32 = mmio_fourcc(b'f', b'm', b't', b' ');
pub const FOURCC_DATA: u32 = mmio_fourcc(b'd', b'a', b't', b'a');
pub const FOURCC_INFO: u32 = mmio_fourcc(b'I', b'N', b'F', b'O');

// ── MmioChunkInfo (mirrors Windows MMCKINFO) ────────────────────────────────

/// RIFF chunk information structure, mirroring the Windows `MMCKINFO`.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct MmioChunkInfo {
    /// Chunk identifier (FOURCC).
    pub ckid: u32,
    /// Chunk size (number of bytes of data, excluding the header).
    pub cksize: u32,
    /// Form type or list type (FOURCC) — valid for `RIFF`/`LIST` chunks.
    pub fcc_type: u32,
    /// File offset from the start of the file to the beginning of the chunk's data.
    pub dw_data_offset: u32,
}

// ── MmioFile ────────────────────────────────────────────────────────────────

/// Chunk stack entry: the guest-visible [`MmioChunkInfo`] plus bookkeeping
/// about whether the chunk header was written by `mmioCreateChunk` (in which
/// case `mmioAscend` must patch the size field).
#[derive(Debug, Clone, Copy)]
pub(crate) struct MmioChunkEntry {
    info: MmioChunkInfo,
    created: bool,
}

/// An open multimedia I/O file, wrapping a [`std::fs::File`].
#[derive(Debug)]
pub struct MmioFile {
    /// The underlying OS file handle.
    pub file: File,
    /// Current file position (for read/write tracking).
    pub position: u64,
    /// The filename (for diagnostic purposes).
    pub filename: String,
    /// The flags the file was opened with.
    pub flags: u32,
    /// Current chunk stack for ascend/descend tracking.
    pub(crate) chunk_stack: Vec<MmioChunkEntry>,
    /// Total file size cached at open time.
    pub file_size: u64,
}

// SAFETY: `RealAudioBackend` must never be moved between threads while its
// cpal streams are live: cpal conservatively marks `Stream` as `!Send`
// across all platforms, but the CoreAudio APIs used on macOS (AudioUnit /
// AudioQueue) are thread-safe. Within Casa1 the backend is only ever
// accessed through `WINMM_REAL_AUDIO` — a global `Mutex<Option<RealAudioBackend>>`
// — so the streams are created, used, and dropped by whichever thread holds
// the lock, never concurrently, and the backend itself never crosses a
// thread boundary. Removing this impl would break the crate's lazy-static
// backend stores in `real_audio.rs` (out of scope for this change), so the
// invariant is documented and enforced by the mutex rather than by the type
// system. Treat the backend as single-threaded (mutex-guarded) at all times.
unsafe impl Send for crate::real_audio::RealAudioBackend {}

// ── Global real audio backend (lazy) ─────────────────────────────────────────

lazy_static::lazy_static! {
    /// Lazily-initialised cpal-based real audio output for WinMM.
    ///
    /// Used by `waveOutWrite`, `PlaySoundW`, and `waveIn` capture to
    /// route audio through the host's default output / input device
    /// without going through the XAudio2 / DirectSound pipeline.
    pub static ref WINMM_REAL_AUDIO: std::sync::Mutex<Option<RealAudioBackend>> =
        std::sync::Mutex::new(None);
}

/// Ensure the WinMM real audio backend is initialised, creating a cpal
/// output stream compatible with the requested format.
///
/// Returns the [`DeviceId`] of the default output device, or `None` if
/// initialisation failed.
fn ensure_winmm_audio(format: &WaveFormatEx) -> Option<u64> {
    let mut guard = WINMM_REAL_AUDIO.lock().unwrap();
    if guard.is_none() {
        match RealAudioBackend::new() {
            Ok(backend) => {
                *guard = Some(backend);
            }
            Err(e) => {
                eprintln!("[winmm] failed to initialise real audio backend: {e}");
                return None;
            }
        }
    }
    let backend = guard.as_mut()?;
    let device_id = backend.default_device_id().ok()?;

    // Build a WaveFormat from the WinMM format descriptor and ensure a
    // cpal output stream is running for this device.
    let sample_format = if format.w_bits_per_sample <= 16 {
        SampleFormat::Pcm16
    } else {
        SampleFormat::Float32
    };
    let wf = WaveFormat {
        channels: format.n_channels,
        sample_rate: format.n_samples_per_sec,
        sample_format,
    };
    let buffer_frames = (format.n_samples_per_sec / 100).max(256) as usize;
    let _ = backend.open_wasapi_client(&wf, buffer_frames, false);

    Some(device_id)
}

// ── PlayingSound tracking ───────────────────────────────────────────────────

/// Global flag that tells a looping async playback thread to stop.
static PLAY_SOUND_STOP: AtomicBool = AtomicBool::new(false);

/// Wave output device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaveOutState {
    Stopped,
    Playing,
    Paused,
}

impl WaveOutState {
    pub fn is_active(self) -> bool {
        matches!(self, WaveOutState::Playing | WaveOutState::Paused)
    }
}

// ── C-compatible packed structs ─────────────────────────────────────────────

/// PCM waveform-audio format (reduced set of [`WAVEFORMATEX`]).
///
/// This is the standard format descriptor used by `waveOutOpen` and friends.
/// Fields are in the order defined by the Windows SDK header `mmeapi.h`.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct WaveFormatEx {
    /// Format type (`WAVE_FORMAT_PCM = 1`, `WAVE_FORMAT_IEEE_FLOAT = 3`, …).
    pub w_format_tag: u16,
    /// Number of channels (1 = mono, 2 = stereo).
    pub n_channels: u16,
    /// Sample rate in Hz (e.g. 44100, 48000).
    pub n_samples_per_sec: u32,
    /// Average bytes per second (nSamplesPerSec × nBlockAlign).
    pub n_avg_bytes_per_sec: u32,
    /// Block alignment (nChannels × wBitsPerSample / 8).
    pub n_block_align: u16,
    /// Bits per sample (8, 16, 32 for float).
    pub w_bits_per_sample: u16,
    /// Size of extra format bytes (0 for PCM).
    pub cb_size: u16,
}

impl WaveFormatEx {
    pub const WAVE_FORMAT_PCM: u16 = 1;
    pub const WAVE_FORMAT_ADPCM: u16 = 2;
    pub const WAVE_FORMAT_IEEE_FLOAT: u16 = 3;
    pub const WAVE_FORMAT_ALAW: u16 = 6;
    pub const WAVE_FORMAT_MULAW: u16 = 7;
    pub const WAVE_FORMAT_IMA_ADPCM: u16 = 0x0011;
    pub const WAVE_FORMAT_MPEG: u16 = 0x0050;

    /// Create a standard PCM format descriptor.
    pub fn pcm(channels: u16, samples_per_sec: u32, bits_per_sample: u16) -> Self {
        let block_align = channels * (bits_per_sample / 8);
        let avg_bytes_per_sec = samples_per_sec * block_align as u32;
        Self {
            w_format_tag: Self::WAVE_FORMAT_PCM,
            n_channels: channels,
            n_samples_per_sec: samples_per_sec,
            n_avg_bytes_per_sec: avg_bytes_per_sec,
            n_block_align: block_align,
            w_bits_per_sample: bits_per_sample,
            cb_size: 0,
        }
    }

    /// Returns the number of bytes per audio frame (one sample per channel).
    pub fn frame_size(&self) -> u16 {
        self.n_channels * (self.w_bits_per_sample / 8)
    }
}

/// Validate a WAVEFORMATEX for use with waveOut/waveIn.
///
/// Every subsequent operation divides guest data by `frame_size()`, so a
/// zero frame size (channels == 0 or bits per sample < 8) or a zero sample
/// rate would panic or produce garbage; reject such formats up front.
fn is_valid_wave_format(format: &WaveFormatEx) -> bool {
    format.n_channels >= 1
        && format.n_channels <= 8
        && format.n_samples_per_sec > 0
        && format.w_bits_per_sample >= 8
        && format.w_bits_per_sample.is_multiple_of(8)
}

/// Waveform-audio output device capabilities (`WAVEOUTCAPSW`).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct WaveOutCapsW {
    /// Manufacturer identifier.
    pub w_mid: u16,
    /// Product identifier.
    pub w_pid: u16,
    /// Version number of the device driver.
    pub v_driver_version: u32,
    /// Product name in Unicode (null-terminated).
    pub sz_pname: [u16; 32],
    /// Supported formats (bitmask of `WAVE_FORMAT_*`).
    pub dw_formats: u32,
    /// Number of channels supported (1 = mono only, 2 = stereo).
    pub w_channels: u16,
    /// Reserved.
    pub w_reserved1: u16,
    /// Optional functionality supported.
    pub dw_support: u32,
}

impl Default for WaveOutCapsW {
    fn default() -> Self {
        let mut name = [0u16; 32];
        let default_name = "Casa1 Audio Output\0";
        for (i, c) in default_name.encode_utf16().enumerate().take(32) {
            name[i] = c;
        }
        Self {
            w_mid: 1,
            w_pid: 1,
            v_driver_version: 0x0100,
            sz_pname: name,
            dw_formats: 0x000100FF, // supports 8-bit through 32-bit at various rates
            w_channels: 2,
            w_reserved1: 0,
            dw_support: 0,
        }
    }
}

/// Waveform-audio buffer header (`WAVEHDR`).
///
/// **Note:** This is the **guest** view. Casa1 stores queued buffers
/// separately in [`WaveOutDevice::buffers`].
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct WaveHdr {
    /// Pointer to the wave data buffer.
    pub lp_data: u64,
    /// Length of the data buffer in bytes.
    pub dw_buffer_length: u32,
    /// Bytes already played / recorded into the buffer.
    pub dw_bytes_recorded: u32,
    /// User-specific data (not touched by the driver).
    pub dw_user: u64, // 64-bit on x64, 32-bit on x86 — we use 64 throughout
    /// Flags (see `WHDR_*` constants below).
    pub dw_flags: u32,
    /// Number of times to loop the buffer (0 = play once).
    pub dw_loops: u32,
    /// Reserved for the driver.
    pub lp_next: u64,
    /// Reserved.
    pub reserved: u64,
}

impl WaveHdr {
    pub const WHDR_DONE: u32 = 0x00000001;
    pub const WHDR_PREPARED: u32 = 0x00000002;
    pub const WHDR_BEGINLOOP: u32 = 0x00000004;
    pub const WHDR_ENDLOOP: u32 = 0x00000008;
    pub const WHDR_INQUEUE: u32 = 0x00000010;
}

/// Multimedia time structure (`MMTIME`).
#[derive(Clone, Copy)]
#[repr(C)]
pub union MmtTime {
    /// Total time in milliseconds.
    pub ms: u32,
    /// Total number of sample frames.
    pub sample: u32,
    /// Total bytes processed.
    pub cb: u32,
    /// SMPTE time components packed as `(hours << 24) | (minutes << 16) | (seconds << 8) | frames`.
    pub smpte: u32,
    /// MIDI song-pointer position.
    pub midi_song_ptr_pos: u32,
}

impl MmtTime {
    pub const TIME_MS: u32 = 0x0001;
    pub const TIME_SAMPLES: u32 = 0x0002;
    pub const TIME_BYTES: u32 = 0x0004;
    pub const TIME_SMPTE: u32 = 0x0008;
    pub const TIME_MIDI: u32 = 0x0010;
    pub const TIME_TICKS: u32 = 0x0020;
}

// ── Audio queue entry ───────────────────────────────────────────────────────

/// A buffer queued for playback on a wave output device.
///
/// Stores a copy of the guest's audio data in a host-side `Vec<u8>`
/// so that the guest is free to reuse or free its original buffer
/// as soon as `waveOutWrite` returns.
#[derive(Debug, Clone)]
pub struct QueuedWaveBuffer {
    /// Copy of the audio data (PCM bytes).
    pub data: Vec<u8>,
    /// Original `WAVEHDR` flags.
    pub flags: u32,
    /// Original `WAVEHDR` loop count.
    pub loops: u32,
    /// Whether this buffer has been fully consumed.
    pub done: bool,
    /// How many bytes from this buffer have been consumed by the audio backend.
    pub bytes_consumed: usize,
}

// ── Wave output device ──────────────────────────────────────────────────────

/// Waveform-audio input device capabilities (`WAVEINCAPSW`).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct WaveInCapsW {
    /// Manufacturer identifier.
    pub w_mid: u16,
    /// Product identifier.
    pub w_pid: u16,
    /// Version number of the device driver.
    pub v_driver_version: u32,
    /// Product name in Unicode (null-terminated).
    pub sz_pname: [u16; 32],
    /// Supported formats (bitmask of `WAVE_FORMAT_*`).
    pub dw_formats: u32,
    /// Number of channels supported (bitmask of valid channel counts).
    pub w_channels: u16,
    /// Reserved.
    pub w_reserved1: u16,
}

impl Default for WaveInCapsW {
    fn default() -> Self {
        let mut name = [0u16; 32];
        let default_name = "Default Microphone\0";
        for (i, c) in default_name.encode_utf16().enumerate().take(32) {
            name[i] = c;
        }
        Self {
            w_mid: 0,
            w_pid: 0,
            v_driver_version: 0x0100,
            sz_pname: name,
            // WAVE_FORMAT_1M08 | WAVE_FORMAT_1M16 | WAVE_FORMAT_2M08 |
            // WAVE_FORMAT_2M16 | WAVE_FORMAT_4M08 | WAVE_FORMAT_4M16
            dw_formats: 0x00000555,
            w_channels: 0x000F, // supports 1–4 channels
            w_reserved1: 0,
        }
    }
}

/// A single buffer queued for capture on a wave input device.
#[derive(Debug, Clone)]
pub struct WaveInBuffer {
    /// Guest pointer to the `WAVEHDR` structure.
    pub header_ptr: u32,
    /// Guest pointer to the buffer data (`WAVEHDR.lpData`).
    pub data_ptr: u32,
    /// Size of the buffer in bytes.
    pub buffer_size: u32,
    /// Whether the header has been prepared.
    pub is_prepared: bool,
    /// Whether the buffer is currently queued for capture.
    pub is_queued: bool,
}

/// A single open waveform-audio input device.
#[derive(Debug, Clone)]
pub struct WaveInDevice {
    /// Monotonic device ID (returned as the handle from `waveInOpen`).
    pub handle: u32,
    /// Capture format agreed at open time.
    pub format: WaveFormatEx,
    /// Queued capture buffers.
    pub buffers: Vec<WaveInBuffer>,
    /// Optional callback: `(callback_addr, instance_data)`.
    pub callback: Option<(u64, u64)>,
    /// Guest callback instance data.
    pub callback_instance: u32,
    /// Whether the device is open.
    pub is_open: bool,
    /// Whether capture is currently active.
    pub is_capturing: bool,
    /// cpal device index.
    pub device_id: u32,
    /// Bytes captured so far (for position reporting).
    pub bytes_captured: u64,
}

impl WaveInDevice {
    pub fn new(
        handle: u32,
        format: WaveFormatEx,
        callback: Option<(u64, u64)>,
        callback_instance: u32,
        device_id: u32,
    ) -> Self {
        Self {
            handle,
            format,
            buffers: Vec::new(),
            callback,
            callback_instance,
            is_open: true,
            is_capturing: false,
            device_id,
            bytes_captured: 0,
        }
    }
}

/// A single open waveform-audio output device.
#[derive(Debug, Clone)]
pub struct WaveOutDevice {
    /// Monotonic device ID (returned as the handle from `waveOutOpen`).
    pub device_id: u32,
    /// Device format agreed at open time.
    pub format: WaveFormatEx,
    /// Current state of the device.
    pub state: WaveOutState,
    /// Queued audio buffers (prepared + written).
    pub buffers: Vec<QueuedWaveBuffer>,
    /// Optional callback: `(callback_addr, user_data)`.
    pub callback: Option<(u64, u64)>,
    /// Left / right volume (each channel is 16 bits; low word = left, high word = right).
    pub volume: u32,
    /// The cpal device ID from the real audio backend.
    pub real_device_id: Option<u64>,
    /// Total bytes consumed by the audio backend across all buffers.
    /// Used to report playback position via `waveOutGetPosition`.
    pub total_bytes_consumed: u64,
    /// Total sample frames consumed (derived from bytes + format).
    /// Used for TIME_SAMPLES position queries.
    pub total_frames_consumed: u64,
}

impl WaveOutDevice {
    /// Default volume (full: 0xFFFF_FFFF).
    const DEFAULT_VOLUME: u32 = 0xFFFF_FFFF;

    pub fn new(
        device_id: u32,
        format: WaveFormatEx,
        callback: Option<(u64, u64)>,
        real_device_id: Option<u64>,
    ) -> Self {
        Self {
            device_id,
            format,
            state: WaveOutState::Stopped,
            buffers: Vec::new(),
            callback,
            volume: Self::DEFAULT_VOLUME,
            real_device_id,
            total_bytes_consumed: 0,
            total_frames_consumed: 0,
        }
    }
}

// ── MIDI constants ──────────────────────────────────────────────────────────

/// MIDI Mapper device ID.
pub const MIDI_MAPPER: u32 = 0xFFFF;

/// Maximum number of MIDI output devices.
pub const MIDI_OUT_MAX_DEVICES: u32 = 1;

/// MIDI error codes.
pub const MIDIERR_UNPREPARED: u32 = 64;
pub const MIDIERR_STILLPLAYING: u32 = 65;
pub const MIDIERR_NOMAP: u32 = 66;
pub const MIDIERR_NOTREADY: u32 = 67;
pub const MIDIERR_NODEVICE: u32 = 68;
pub const MIDIERR_INVALIDSETUP: u32 = 69;
pub const MIDIERR_BADOPENMODE: u32 = 70;
pub const MIDIERR_DONT_CONTINUE: u32 = 71;
pub const MIDIERR_LASTERROR: u32 = 72;

/// MIDI output device technology constants.
pub const MOD_MIDIPORT: u16 = 1;
pub const MOD_SYNTH: u16 = 2;
pub const MOD_SQSYNTH: u16 = 3;
pub const MOD_FMSYNTH: u16 = 4;
pub const MOD_MAPPER: u16 = 5;
pub const MOD_WAVETABLE: u16 = 6;
pub const MOD_SWSYNTH: u16 = 7;

/// MIDI input device state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidiInState {
    Stopped,
    Started,
}

/// A single open MIDI output device.
#[derive(Debug, Clone)]
pub struct MidiOutputDevice {
    /// Monotonic device handle (returned to the caller).
    pub device_id: u32,
    /// The handle returned from `midi::midi_out_open()`.
    pub midi_handle: crate::midi::MidiHandle,
    /// Optional callback: `(callback_addr, user_data)`.
    pub callback: Option<(u64, u64)>,
}

/// MIDI output device capabilities (`MIDIOUTCAPSW`).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MidiOutCapsW {
    /// Manufacturer identifier.
    pub w_mid: u16,
    /// Product identifier.
    pub w_pid: u16,
    /// Version number of the device driver.
    pub v_driver_version: u32,
    /// Product name in Unicode (null-terminated).
    pub sz_pname: [u16; 32],
    /// Supported technology (MOD_*).
    pub w_technology: u16,
    /// Voices (0 = unspecified).
    pub w_voices: u16,
    /// Notes (0 = unspecified).
    pub w_notes: u16,
    /// Channel mask (bitmask of valid channels).
    pub w_channel_mask: u16,
    /// Optional functionality supported.
    pub dw_support: u32,
    /// Extended driver data.
    pub ext_driver_data: u64,
}

impl Default for MidiOutCapsW {
    fn default() -> Self {
        let mut name = [0u16; 32];
        let default_name = "Casa1 MIDI Synthesizer\0";
        for (i, c) in default_name.encode_utf16().enumerate().take(32) {
            name[i] = c;
        }
        Self {
            w_mid: 1,
            w_pid: 2,
            v_driver_version: 0x0100,
            sz_pname: name,
            w_technology: MOD_SWSYNTH,
            w_voices: 16,
            w_notes: 64,
            w_channel_mask: 0xFFFF,
            dw_support: 0,
            ext_driver_data: 0,
        }
    }
}

/// MIDI header (`MIDIHDR`).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MidiHdr {
    /// Pointer to the MIDI data buffer.
    pub lp_data: u64,
    /// Length of the data buffer in bytes.
    pub dw_buffer_length: u32,
    /// Bytes used (for recording).
    pub dw_bytes_recorded: u32,
    /// User-specific data.
    pub dw_user: u64,
    /// Flags (see `MHDR_*` constants below).
    pub dw_flags: u32,
    /// Reserved for the driver.
    pub lp_next: u64,
    /// Reserved.
    pub reserved: u64,
    /// Reserved for the driver (offset into buffer for stream buffers).
    pub dw_offset: u32,
    /// Reserved for the driver.
    pub dw_reserved: [u32; 8],
}

impl MidiHdr {
    pub const MHDR_DONE: u32 = 0x00000001;
    pub const MHDR_PREPARED: u32 = 0x00000002;
    pub const MHDR_INQUEUE: u32 = 0x00000004;
    pub const MHDR_ISSTRM: u32 = 0x00000008;
}

/// A single open MIDI input device.
#[derive(Debug)]
pub struct MidiInputDevice {
    /// Monotonic device handle.
    pub device_id: u32,
    /// State of the input device.
    pub state: MidiInState,
    /// Optional callback: `(callback_addr, user_data)`.
    pub callback: Option<(u64, u64)>,
    /// Background thread that polls CoreMIDI and delivers messages.
    pub midi_thread: Option<JoinHandle<()>>,
    /// Shared stop signal for the MIDI polling thread.
    pub midi_thread_stop: Arc<AtomicBool>,
    /// Shared buffer for received MIDI messages (pushed by polling thread).
    pub midi_buffer: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl Clone for MidiInputDevice {
    fn clone(&self) -> Self {
        Self {
            device_id: self.device_id,
            state: self.state,
            callback: self.callback,
            // Don't clone the running thread — the clone gets a fresh stopped state.
            midi_thread: None,
            midi_thread_stop: Arc::new(AtomicBool::new(true)),
            midi_buffer: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

/// Shared per-device MIDI subscriber buffer (device handle → message queue).
type MidiSubscriberBuffer = Arc<Mutex<VecDeque<Vec<u8>>>>;

/// Shared CoreMIDI input poller.
///
/// A single background thread drains the global CoreMIDI input buffer and
/// fans the messages out to every open MIDI input device. Without this,
/// each device would spawn its own thread calling `drain_core_midi_input`,
/// and with ≥ 2 open devices the messages would be split arbitrarily
/// between them.
#[derive(Default)]
struct MidiInPoller {
    thread: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    subscribers: Vec<(u32, MidiSubscriberBuffer)>,
}

lazy_static::lazy_static! {
    static ref MIDI_IN_POLLER: Mutex<MidiInPoller> = Mutex::new(MidiInPoller::default());
}

/// Unregister a MIDI input device from the shared poller, stopping the
/// poller thread once the last subscriber leaves.
///
/// The join happens without holding the poller lock, so the poller thread
/// (which takes the lock while fanning out) can always exit.
fn unregister_midi_in_device(device_handle: u32) {
    let joined = if let Ok(mut poller) = MIDI_IN_POLLER.lock() {
        poller.subscribers.retain(|&(id, _)| id != device_handle);
        if poller.subscribers.is_empty() {
            poller.stop.store(true, Ordering::SeqCst);
            poller.thread.take()
        } else {
            None
        }
    } else {
        None
    };
    if let Some(thread) = joined {
        let _ = thread.join();
    }
}

// ── WinMM Subsystem ─────────────────────────────────────────────────────────

/// Top-level WinMM subsystem state.
///
/// This is stored inside [`AudioSubsystem`](crate::audio::AudioSubsystem)
/// behind a `RwLock` for interior-mutability access from the PE runtime
/// dispatch functions (which hold `&mut self` on the runtime but need
/// shared access to the audio subsystem).
#[derive(Debug)]
pub struct WinMmSubsystem {
    /// List of open wave output devices.
    pub wave_out_devices: Vec<WaveOutDevice>,
    /// Monotonic ID counter for device handles.
    pub next_device_id: u32,
    /// Reference `Instant` used by `timeGetTime` (in milliseconds since
    /// subsystem creation).
    pub time_get_time_ref: u64,
    /// Open MIDI output devices.
    pub midi_out_devices: Vec<MidiOutputDevice>,
    /// Open MIDI input devices.
    pub midi_in_devices: Vec<MidiInputDevice>,
    /// List of open wave input (capture) devices.
    pub wave_in_devices: Vec<WaveInDevice>,
    /// Monotonic handle counter for wave input devices.
    pub next_wave_in_handle: u32,
    /// Open multimedia I/O files (mmio), keyed by handle.
    pub mmio_files: HashMap<u32, MmioFile>,
    /// Monotonic handle counter for mmio files.
    pub next_mmio_handle: u32,
    /// Optional join handle for an async PlaySound thread.
    pub play_sound_thread: Option<JoinHandle<()>>,
    /// Stop flags for wave-in capture threads, keyed by device handle.
    pub wave_in_thread_stop: HashMap<u32, Arc<AtomicBool>>,
    /// Join handles for wave-in capture threads, keyed by device handle.
    pub wave_in_threads: HashMap<u32, JoinHandle<()>>,
    /// Per-device capture sessions (PCM bytes + byte count) shared with the
    /// wave-in polling threads, keyed by device handle.
    pub wave_in_capture_data: HashMap<u32, Arc<Mutex<WaveInCaptureSession>>>,
}

/// Captured audio pending guest delivery for a single wave-in device.
///
/// Filled by the wave-in polling thread (which reads the real backend's
/// input stream) and consumed by `waveInGetPosition`; the dispatch layer
/// copies `data` into guest WAVEHDR buffers and fires WIM_DATA.
#[derive(Debug, Clone, Default)]
pub struct WaveInCaptureSession {
    /// Captured PCM bytes in the device's format (host-side, bounded).
    pub data: Vec<u8>,
    /// Total bytes captured since the session started.
    pub bytes_captured: u64,
}

impl Default for WinMmSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WinMmSubsystem {
    fn drop(&mut self) {
        // Signal and join all capture threads and the async PlaySound thread
        // so no background threads outlive the subsystem.
        for stop in self.wave_in_thread_stop.values() {
            stop.store(true, Ordering::SeqCst);
        }
        for (_, thread) in self.wave_in_threads.drain() {
            let _ = thread.join();
        }
        self.wave_in_thread_stop.clear();
        self.wave_in_capture_data.clear();
        if let Some(thread) = self.play_sound_thread.take() {
            PLAY_SOUND_STOP.store(true, Ordering::SeqCst);
            let _ = thread.join();
        }
    }
}

impl WinMmSubsystem {
    /// Create a new WinMM subsystem with a single WAVE_MAPPER device available.
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            wave_out_devices: Vec::new(),
            next_device_id: 1,
            time_get_time_ref: now,
            midi_out_devices: Vec::new(),
            midi_in_devices: Vec::new(),
            wave_in_devices: Vec::new(),
            next_wave_in_handle: 1,
            mmio_files: HashMap::new(),
            next_mmio_handle: 1,
            play_sound_thread: None,
            wave_in_thread_stop: HashMap::new(),
            wave_in_threads: HashMap::new(),
            wave_in_capture_data: HashMap::new(),
        }
    }

    /// Returns the number of wave output devices available.
    ///
    /// Always returns at least 1 (the WAVE_MAPPER device).
    pub fn wave_out_get_num_devs(&self) -> u32 {
        1
    }

    /// Returns device capabilities for `device_id`.
    ///
    /// `device_id` may be `WAVE_MAPPER` (0xFFFF) which maps to device 0.
    pub fn wave_out_get_dev_caps(&self, device_id: u32, caps: &mut WaveOutCapsW) -> u32 {
        if device_id != WAVE_MAPPER && device_id != 0 {
            return MMSYSERR_BADDEVICEID;
        }
        *caps = WaveOutCapsW::default();
        MMSYSERR_NOERROR
    }

    /// Open a wave output device.
    ///
    /// `device_id` should be `WAVE_MAPPER` (0xFFFF) or 0.
    /// Returns `(mmresult, handle)` where handle is the device handle on success.
    pub fn wave_out_open(
        &mut self,
        device_id: u32,
        format: &WaveFormatEx,
        callback: Option<(u64, u64)>,
    ) -> (u32, u32) {
        // Validate device ID
        if device_id != WAVE_MAPPER && device_id != 0 {
            return (MMSYSERR_BADDEVICEID, 0);
        }

        // Validate format — must be PCM / IEEE float with a sane geometry.
        // `frame_size()` divides guest data on every write, so a zero frame
        // size (n_channels == 0 or bits per sample < 8) must be rejected.
        if format.w_format_tag != WaveFormatEx::WAVE_FORMAT_PCM
            && format.w_format_tag != WaveFormatEx::WAVE_FORMAT_IEEE_FLOAT
        {
            return (WAVERR_BADFORMAT, 0);
        }
        if !is_valid_wave_format(format) {
            return (WAVERR_BADFORMAT, 0);
        }

        // Initialise the real audio backend and create a cpal output stream.
        let real_device_id = ensure_winmm_audio(format);

        let device_handle = self.next_device_id;
        self.next_device_id += 1;

        let device = WaveOutDevice::new(device_handle, *format, callback, real_device_id);
        self.wave_out_devices.push(device);

        (MMSYSERR_NOERROR, device_handle)
    }

    /// Close a wave output device.
    pub fn wave_out_close(&mut self, device_handle: u32) -> u32 {
        let pos = self
            .wave_out_devices
            .iter()
            .position(|d| d.device_id == device_handle);
        match pos {
            Some(idx) => {
                self.wave_out_devices.swap_remove(idx);
                MMSYSERR_NOERROR
            }
            None => MMSYSERR_INVALHANDLE,
        }
    }

    /// Prepare a WAVEHDR for playback.
    ///
    /// In Casa1 this is largely a validation step; the actual data copy
    /// happens in `wave_out_write`. The header's `WHDR_PREPARED` flag
    /// is set.
    pub fn wave_out_prepare_header(&mut self, device_handle: u32, _header: &WaveHdr) -> u32 {
        if !self
            .wave_out_devices
            .iter()
            .any(|d| d.device_id == device_handle)
        {
            return MMSYSERR_INVALHANDLE;
        }
        MMSYSERR_NOERROR
    }

    /// Unprepare a WAVEHDR.
    pub fn wave_out_unprepare_header(&mut self, device_handle: u32, _header: &WaveHdr) -> u32 {
        if !self
            .wave_out_devices
            .iter()
            .any(|d| d.device_id == device_handle)
        {
            return MMSYSERR_INVALHANDLE;
        }
        MMSYSERR_NOERROR
    }

    /// Write (queue) a buffer for playback.
    ///
    /// Copies the audio data from guest memory into a [`QueuedWaveBuffer`]
    /// and appends it to the device's queue.
    ///
    /// Returns `MMSYSERR_NOERROR` on success.
    pub fn wave_out_write(
        &mut self,
        device_handle: u32,
        data: &[u8],
        flags: u32,
        loops: u32,
    ) -> u32 {
        let device = match self
            .wave_out_devices
            .iter_mut()
            .find(|d| d.device_id == device_handle)
        {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };

        // Drop fully-consumed buffers so the queue stays bounded over a
        // long session (WOM_DONE delivery is handled by the dispatch layer).
        device.buffers.retain(|b| !b.done);

        let buf = QueuedWaveBuffer {
            data: data.to_vec(),
            flags,
            loops,
            done: false,
            bytes_consumed: 0,
        };
        device.buffers.push(buf);
        device.state = WaveOutState::Playing;

        // ── Push audio data to the real cpal output stream ────────────────
        if data.is_empty() {
            // An empty buffer is trivially consumed.
            if let Some(last) = device.buffers.last_mut() {
                last.done = true;
            }
            return MMSYSERR_NOERROR;
        }

        let Some(real_id) = device.real_device_id else {
            eprintln!("[winmm] wave_out_write: no real_device_id for handle {device_handle}");
            device.buffers.pop();
            return MMSYSERR_ERROR;
        };

        let push_result = WINMM_REAL_AUDIO.lock().map(|mut guard| {
            guard.as_mut().map(|backend| {
                // Convert guest PCM bytes to host f32 samples
                let samples = pcm_bytes_to_float(
                    data,
                    device.format.w_format_tag,
                    device.format.w_bits_per_sample,
                    device.format.n_channels,
                );
                // Push the samples to the output stream's lock-free queue
                backend.push_wasapi_frames(
                    real_id,
                    &samples,
                    device.format.n_channels,
                    device.format.n_samples_per_sec,
                )
            })
        });

        match push_result {
            Ok(Some(Ok(()))) => {
                // Only count and complete the buffer when the backend
                // actually accepted the data, so position queries
                // (TIME_BYTES/TIME_SAMPLES/TIME_MS) do not lie.
                device.total_bytes_consumed += data.len() as u64;
                let frame_size = device.format.frame_size().max(1) as u64;
                device.total_frames_consumed += (data.len() as u64) / frame_size;
                if let Some(last) = device.buffers.last_mut() {
                    last.done = true;
                }
            }
            Ok(_) => {
                // Backend unavailable or push failed: the buffer was never
                // queued, so remove it and report failure to the guest.
                eprintln!("[winmm] wave_out_write: backend could not accept buffer");
                device.buffers.pop();
                return MMSYSERR_ERROR;
            }
            Err(e) => {
                eprintln!("[winmm] WINMM_REAL_AUDIO lock poisoned: {e}");
                device.buffers.pop();
                return MMSYSERR_ERROR;
            }
        }

        MMSYSERR_NOERROR
    }

    /// Reset (stop) playback and drain all queued buffers.
    ///
    /// All pending buffers are marked as done and the device state
    /// is set to `Stopped`.
    pub fn wave_out_reset(&mut self, device_handle: u32) -> u32 {
        let device = match self
            .wave_out_devices
            .iter_mut()
            .find(|d| d.device_id == device_handle)
        {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };

        for buf in &mut device.buffers {
            buf.done = true;
        }
        device.buffers.clear();
        device.state = WaveOutState::Stopped;
        MMSYSERR_NOERROR
    }

    /// Get the volume for a wave output device.
    ///
    /// Volume is packed as `(right << 16) | left`.
    pub fn wave_out_get_volume(&self, device_handle: u32, volume_out: &mut u32) -> u32 {
        let device = match self
            .wave_out_devices
            .iter()
            .find(|d| d.device_id == device_handle)
        {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };
        *volume_out = device.volume;
        MMSYSERR_NOERROR
    }

    /// Set the volume for a wave output device.
    ///
    /// Volume is packed as `(right << 16) | left`.
    pub fn wave_out_set_volume(&mut self, device_handle: u32, volume: u32) -> u32 {
        let device = match self
            .wave_out_devices
            .iter_mut()
            .find(|d| d.device_id == device_handle)
        {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };
        device.volume = volume;
        MMSYSERR_NOERROR
    }

    /// Get the current playback position for a wave output device.
    ///
    /// Returns `(MMRESULT, position_value)` where `position_value` is
    /// the position in the requested `time_format` (TIME_BYTES, TIME_SAMPLES,
    /// or TIME_MS). The PE runtime dispatch layer is responsible for writing
    /// the MMTIME struct into guest memory.
    ///
    /// Position counters are kept as `u64` internally; they are truncated to
    /// `u32` here at the guest boundary, matching Windows' DWORD MMTIME
    /// semantics.
    ///
    /// Returns `MMSYSERR_INVALHANDLE` if the handle is invalid.
    pub fn wave_out_get_position(
        &self,
        device_handle: u32,
        time_format: u32,
    ) -> (u32, u32) {
        let device = match self
            .wave_out_devices
            .iter()
            .find(|d| d.device_id == device_handle)
        {
            Some(d) => d,
            None => return (MMSYSERR_INVALHANDLE, 0),
        };

        let value = match time_format {
            MmtTime::TIME_BYTES => device.total_bytes_consumed as u32,
            MmtTime::TIME_SAMPLES => device.total_frames_consumed as u32,
            MmtTime::TIME_MS => {
                if device.format.n_samples_per_sec > 0 {
                    (device
                        .total_frames_consumed
                        .saturating_mul(1000)
                        / device.format.n_samples_per_sec as u64) as u32
                } else {
                    0
                }
            }
            _ => {
                // Unsupported time format — fall back to TIME_BYTES
                device.total_bytes_consumed as u32
            }
        };

        (MMSYSERR_NOERROR, value)
    }

    // ── Time functions ──────────────────────────────────────────────────────

    /// Returns the current time in milliseconds since the subsystem was created.
    ///
    /// Corresponds to `timeGetTime()`.
    pub fn time_get_time(&self) -> u32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        (now.saturating_sub(self.time_get_time_ref)) as u32
    }

    /// Returns the system time as a high-resolution count.
    ///
    /// Corresponds to `timeGetSystemTime()`.
    pub fn time_get_system_time(&self, mmtime: &mut MmtTime) -> u32 {
        let ms = self.time_get_time() as u64;
        mmtime.ms = ms as u32;
        MMSYSERR_NOERROR
    }

    /// `timeBeginPeriod` — no-op on macOS where timer resolution is managed by the kernel.
    pub fn time_begin_period(_period: u32) -> u32 {
        MMSYSERR_NOERROR
    }

    /// `timeEndPeriod` — no-op on macOS where timer resolution is managed by the kernel.
    pub fn time_end_period(_period: u32) -> u32 {
        MMSYSERR_NOERROR
    }

    // ── Wave In functions ────────────────────────────────────────────────────

    /// Returns the number of wave input devices available.
    ///
    /// Reports the number of *available* devices (1, matching
    /// `wave_in_get_dev_caps` / `wave_in_open`), not the number of
    /// currently-open devices.
    pub fn wave_in_get_num_devs(&self) -> u32 {
        1
    }

    /// Returns device capabilities for a wave input device.
    pub fn wave_in_get_dev_caps(&self, dev_id: u32, caps: &mut WaveInCapsW) -> u32 {
        if dev_id != WAVE_MAPPER && dev_id != 0 {
            return MMSYSERR_BADDEVICEID;
        }
        *caps = WaveInCapsW::default();
        MMSYSERR_NOERROR
    }

    /// Open a wave input device for audio capture.
    ///
    /// `dev_id` should be `WAVE_MAPPER` (0xFFFF) or 0.
    /// Returns `(mmresult, handle)` where handle is the device handle on success.
    pub fn wave_in_open(
        &mut self,
        dev_id: u32,
        format: &WaveFormatEx,
        callback: Option<(u64, u64)>,
    ) -> (u32, u32) {
        if dev_id != WAVE_MAPPER && dev_id != 0 {
            return (MMSYSERR_BADDEVICEID, 0);
        }

        if format.w_format_tag != WaveFormatEx::WAVE_FORMAT_PCM
            && format.w_format_tag != WaveFormatEx::WAVE_FORMAT_IEEE_FLOAT
        {
            return (WAVERR_BADFORMAT, 0);
        }
        if !is_valid_wave_format(format) {
            return (WAVERR_BADFORMAT, 0);
        }

        let handle = self.next_wave_in_handle;
        self.next_wave_in_handle += 1;

        let cb_instance = callback.map(|(_, inst)| inst as u32).unwrap_or(0);
        let device = WaveInDevice::new(handle, *format, callback, cb_instance, dev_id);
        self.wave_in_devices.push(device);

        (MMSYSERR_NOERROR, handle)
    }

    /// Close a wave input device.
    pub fn wave_in_close(&mut self, handle: u32) -> u32 {
        let device = match self.wave_in_devices.iter_mut().find(|d| d.handle == handle) {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };
        device.is_open = false;
        device.is_capturing = false;
        // Tear down the capture polling thread and the real input stream,
        // mirroring wave_in_stop so open/close cycles do not leak threads
        // or streams.
        if let Some(stop) = self.wave_in_thread_stop.remove(&handle) {
            stop.store(true, Ordering::SeqCst);
        }
        if let Some(thread) = self.wave_in_threads.remove(&handle) {
            let _ = thread.join();
        }
        if let Ok(mut guard) = WINMM_REAL_AUDIO.lock()
            && let Some(backend) = guard.as_mut()
        {
            backend.stop_input_stream();
        }
        self.wave_in_capture_data.remove(&handle);
        MMSYSERR_NOERROR
    }

    /// Prepare a WAVEHDR for capture.
    ///
    /// Reads the WAVEHDR from the guest pointer, adds a buffer entry with the
    /// caller-provided `data_ptr` and `buffer_size` (extracted from the WAVEHDR
    /// in guest memory by the PE runtime dispatch), and sets the `WHDR_PREPARED`
    /// flag.
    pub fn wave_in_prepare_header(
        &mut self,
        handle: u32,
        hdr_ptr: u32,
        _hdr_size: u32,
        data_ptr: u32,
        buffer_size: u32,
    ) -> u32 {
        let device = match self.wave_in_devices.iter_mut().find(|d| d.handle == handle) {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };

        device.buffers.push(WaveInBuffer {
            header_ptr: hdr_ptr,
            data_ptr,
            buffer_size,
            is_prepared: true,
            is_queued: false,
        });

        MMSYSERR_NOERROR
    }

    /// Unprepare a WAVEHDR.
    pub fn wave_in_unprepare_header(&mut self, handle: u32, hdr_ptr: u32, hdr_size: u32) -> u32 {
        let _hdr_size = hdr_size;
        let device = match self.wave_in_devices.iter_mut().find(|d| d.handle == handle) {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };

        let pos = device.buffers.iter().position(|b| b.header_ptr == hdr_ptr);
        match pos {
            Some(idx) => {
                if device.buffers[idx].is_queued {
                    return WAVERR_STILLPLAYING;
                }
                device.buffers.swap_remove(idx);
                MMSYSERR_NOERROR
            }
            None => MMSYSERR_INVALHANDLE,
        }
    }

    /// Add (queue) a prepared buffer for capture.
    pub fn wave_in_add_buffer(&mut self, handle: u32, hdr_ptr: u32, hdr_size: u32) -> u32 {
        let _hdr_size = hdr_size;
        let device = match self.wave_in_devices.iter_mut().find(|d| d.handle == handle) {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };

        let buf = match device.buffers.iter_mut().find(|b| b.header_ptr == hdr_ptr) {
            Some(b) => b,
            None => return MMSYSERR_INVALHANDLE,
        };

        buf.is_queued = true;
        MMSYSERR_NOERROR
    }

    /// Start capture on a wave input device.
    ///
    /// Initialises the real audio backend's input stream (if not already
    /// running) and begins filling queued WAVEHDR buffers with captured
    /// PCM data.
    pub fn wave_in_start(&mut self, handle: u32) -> u32 {
        let device = match self.wave_in_devices.iter_mut().find(|d| d.handle == handle) {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };

        if device.is_capturing {
            return MMSYSERR_NOERROR;
        }

        // Initialise the real audio backend if needed so that an input
        // stream can be created.
        {
            let mut guard = WINMM_REAL_AUDIO.lock().unwrap();
            if guard.is_none() {
                match RealAudioBackend::new() {
                    Ok(backend) => {
                        *guard = Some(backend);
                    }
                    Err(e) => {
                        eprintln!("[winmm] wave_in_start: failed to init audio backend: {e}");
                        return MMSYSERR_ERROR;
                    }
                }
            }
            if let Some(backend) = guard.as_mut() {
                // Start the input (capture) stream on the default device
                let sr = device.format.n_samples_per_sec;
                let ch = device.format.n_channels;
                if let Err(e) = backend.start_input_stream(sr, ch) {
                    eprintln!("[winmm] wave_in_start: start_input_stream error: {e}");
                    // Non-fatal — we still mark capturing so the polling
                    // thread will try again each cycle.
                }
            }
        }

        device.is_capturing = true;

        // Spawn a background polling thread that pulls captured audio from
        // the real backend, converts it to the device's PCM format, and
        // accumulates it for guest delivery.
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = stop.clone();
        let session = Arc::new(Mutex::new(WaveInCaptureSession::default()));
        let session_clone = session.clone();
        let format = device.format; // Copy
        let thread_builder = std::thread::Builder::new().name(format!("winmm-wavein-{handle}"));
        let join_handle = match thread_builder.spawn(move || {
            let poll_interval = Duration::from_millis(20);
            while !stop_clone.load(Ordering::SeqCst) {
                // Read captured audio data from the real backend and convert
                // it to PCM bytes in the device's format.
                if let Ok(mut guard) = WINMM_REAL_AUDIO.lock()
                    && let Some(backend) = guard.as_mut()
                {
                    let captured = backend.read_capture_data();
                    if !captured.is_empty()
                        && let Ok(mut sess) = session_clone.lock()
                    {
                        let bytes = capture_pcm_bytes(&captured, &format);
                        sess.data.extend_from_slice(&bytes);
                        sess.bytes_captured += bytes.len() as u64;
                        // Bound the pending data (~4 seconds of PCM);
                        // guest delivery drains it via the dispatch layer.
                        let max_bytes = (format.n_samples_per_sec as usize
                            * format.n_channels as usize
                            * (format.w_bits_per_sample as usize / 8))
                            .saturating_mul(4)
                            .max(1024);
                        if sess.data.len() > max_bytes {
                            let excess = sess.data.len() - max_bytes;
                            sess.data.drain(0..excess);
                        }
                    }
                }
                std::thread::sleep(poll_interval);
            }
        }) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[winmm] wave_in_start: failed to spawn capture thread: {e}");
                device.is_capturing = false;
                return MMSYSERR_ERROR;
            }
        };

        // Store the stop flag, thread handle, and capture session so that
        // wave_in_stop / wave_in_reset / wave_in_close can tear them down.
        self.wave_in_thread_stop.insert(handle, stop);
        self.wave_in_threads.insert(handle, join_handle);
        self.wave_in_capture_data.insert(handle, session);

        MMSYSERR_NOERROR
    }

    /// Stop capture on a wave input device.
    ///
    /// Stops the capture polling thread and marks all queued buffers as done.
    pub fn wave_in_stop(&mut self, handle: u32) -> u32 {
        if !self.wave_in_devices.iter().any(|d| d.handle == handle) {
            return MMSYSERR_INVALHANDLE;
        }

        // Signal the capture thread to stop and join it
        if let Some(stop) = self.wave_in_thread_stop.remove(&handle) {
            stop.store(true, Ordering::SeqCst);
        }
        if let Some(thread) = self.wave_in_threads.remove(&handle) {
            let _ = thread.join();
        }
        self.wave_in_capture_data.remove(&handle);

        // Stop the real audio input stream
        if let Ok(mut guard) = WINMM_REAL_AUDIO.lock()
            && let Some(backend) = guard.as_mut()
        {
            backend.stop_input_stream();
        }

        // Mark the device as not capturing and mark all queued buffers as done
        if let Some(device) = self.wave_in_devices.iter_mut().find(|d| d.handle == handle) {
            device.is_capturing = false;
            for buf in &mut device.buffers {
                if buf.is_queued {
                    buf.is_queued = false;
                }
            }
        }

        MMSYSERR_NOERROR
    }

    /// Reset a wave input device — stop capture and mark all buffers done.
    pub fn wave_in_reset(&mut self, handle: u32) -> u32 {
        if !self.wave_in_devices.iter().any(|d| d.handle == handle) {
            return MMSYSERR_INVALHANDLE;
        }

        // Signal the capture thread to stop and join it
        if let Some(stop) = self.wave_in_thread_stop.remove(&handle) {
            stop.store(true, Ordering::SeqCst);
        }
        if let Some(thread) = self.wave_in_threads.remove(&handle) {
            let _ = thread.join();
        }
        self.wave_in_capture_data.remove(&handle);

        // Stop the real audio input stream
        if let Ok(mut guard) = WINMM_REAL_AUDIO.lock()
            && let Some(backend) = guard.as_mut()
        {
            backend.stop_input_stream();
        }

        if let Some(device) = self.wave_in_devices.iter_mut().find(|d| d.handle == handle) {
            device.is_capturing = false;
            for buf in &mut device.buffers {
                buf.is_queued = false;
            }
            device.bytes_captured = 0;
        }

        MMSYSERR_NOERROR
    }

    /// Get the capture position for a wave input device.
    ///
    /// Returns `(MMRESULT, bytes_captured)` so the PE runtime dispatch can
    /// write the MMTIME struct into guest memory. The byte count reflects
    /// the live value accumulated by the capture polling thread.
    pub fn wave_in_get_position(&mut self, handle: u32) -> (u32, u32) {
        let device = match self.wave_in_devices.iter_mut().find(|d| d.handle == handle) {
            Some(d) => d,
            None => return (MMSYSERR_INVALHANDLE, 0),
        };

        if let Some(session) = self.wave_in_capture_data.get(&handle)
            && let Ok(sess) = session.lock()
        {
            device.bytes_captured = sess.bytes_captured;
        }

        (MMSYSERR_NOERROR, device.bytes_captured as u32)
    }

    // ── MIDI Out ────────────────────────────────────────────────────────────

    /// Open a MIDI output device.
    ///
    /// `device_id` should be 0 or `MIDI_MAPPER` (0xFFFF).
    /// Creates / accesses the global MIDI synthesizer and returns a device handle.
    pub fn midi_out_open(&mut self, device_id: u32, callback: Option<(u64, u64)>) -> u32 {
        if device_id != 0 && device_id != MIDI_MAPPER {
            return MMSYSERR_BADDEVICEID;
        }

        // The synthesizer is lazily initialized via midi.rs lazy_static.
        let midi_handle = match midi::midi_out_open() {
            Ok(h) => h,
            Err(_) => return MMSYSERR_ERROR,
        };

        let device_handle = self.next_device_id;
        self.next_device_id += 1;

        self.midi_out_devices.push(MidiOutputDevice {
            device_id: device_handle,
            midi_handle,
            callback,
        });

        MMSYSERR_NOERROR
    }

    /// Close a MIDI output device.
    ///
    /// Cleans up the device entry. The global synthesizer persists
    /// (other open devices may still use it).
    pub fn midi_out_close(&mut self, device_handle: u32) -> u32 {
        let pos = self
            .midi_out_devices
            .iter()
            .position(|d| d.device_id == device_handle);
        match pos {
            Some(idx) => {
                let dev = &self.midi_out_devices[idx];
                if let Err(e) = midi::midi_out_close(dev.midi_handle) {
                    eprintln!(
                        "[WinMM] midi_out_close failed for device {}: {e}",
                        dev.device_id
                    );
                }
                self.midi_out_devices.swap_remove(idx);
                MMSYSERR_NOERROR
            }
            None => MMSYSERR_INVALHANDLE,
        }
    }

    /// Send a short MIDI message to the synthesizer.
    ///
    /// `msg` is packed as: `(data2 << 16) | (data1 << 8) | status`.
    pub fn midi_out_short_msg(&mut self, device_handle: u32, msg: u32) -> u32 {
        let dev = match self
            .midi_out_devices
            .iter()
            .find(|d| d.device_id == device_handle)
        {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };
        match midi::midi_out_short_msg(dev.midi_handle, msg) {
            Ok(_) => MMSYSERR_NOERROR,
            Err(_) => MMSYSERR_ERROR,
        }
    }

    /// Send a long MIDI message (system exclusive) to the synthesizer.
    ///
    /// `data` is the raw SysEx bytes read from guest memory.
    pub fn midi_out_long_msg(&mut self, device_handle: u32, data: &[u8]) -> u32 {
        let dev = match self
            .midi_out_devices
            .iter()
            .find(|d| d.device_id == device_handle)
        {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };
        match midi::midi_out_long_msg(dev.midi_handle, data) {
            Ok(_) => MMSYSERR_NOERROR,
            Err(_) => MMSYSERR_ERROR,
        }
    }

    /// Reset a MIDI output device (all notes off, reset controllers).
    pub fn midi_out_reset(&mut self, device_handle: u32) -> u32 {
        let dev = match self
            .midi_out_devices
            .iter()
            .find(|d| d.device_id == device_handle)
        {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };
        match midi::midi_out_reset(dev.midi_handle) {
            Ok(_) => MMSYSERR_NOERROR,
            Err(_) => MMSYSERR_ERROR,
        }
    }

    /// Returns the number of MIDI output devices available (always 1).
    pub fn midi_out_get_num_devs(&self) -> u32 {
        1
    }

    /// Returns device capabilities for the MIDI output device.
    pub fn midi_out_get_dev_caps(&self, device_id: u32, caps: &mut MidiOutCapsW) -> u32 {
        if device_id != 0 && device_id != MIDI_MAPPER {
            return MMSYSERR_BADDEVICEID;
        }
        *caps = MidiOutCapsW::default();
        MMSYSERR_NOERROR
    }

    // ── MIDI In ─────────────────────────────────────────────────────────────

    /// Open a MIDI input device.
    ///
    /// Accepts device parameters and initialises the thread / buffer fields
    /// needed for CoreMIDI polling. The actual polling thread is spawned
    /// by [`midi_in_start`].
    ///
    /// Returns `MMSYSERR_NOERROR` with a valid handle.
    pub fn midi_in_open(&mut self, device_id: u32, callback: Option<(u64, u64)>) -> u32 {
        if device_id != 0 && device_id != MIDI_MAPPER {
            return MMSYSERR_BADDEVICEID;
        }

        let device_handle = self.next_device_id;
        self.next_device_id += 1;

        self.midi_in_devices.push(MidiInputDevice {
            device_id: device_handle,
            state: MidiInState::Stopped,
            callback,
            midi_thread: None,
            midi_thread_stop: Arc::new(AtomicBool::new(true)),
            midi_buffer: Arc::new(Mutex::new(VecDeque::new())),
        });

        MMSYSERR_NOERROR
    }

    /// Close a MIDI input device.
    ///
    /// Stops the background polling thread (if running) before removing
    /// the device.
    pub fn midi_in_close(&mut self, device_handle: u32) -> u32 {
        let pos = self
            .midi_in_devices
            .iter()
            .position(|d| d.device_id == device_handle);
        match pos {
            Some(idx) => {
                // Unregister from the shared CoreMIDI poller first
                unregister_midi_in_device(device_handle);
                // Stop the per-device thread (if one exists)
                let dev = &mut self.midi_in_devices[idx];
                dev.midi_thread_stop.store(true, Ordering::SeqCst);
                if let Some(handle) = dev.midi_thread.take() {
                    let _ = handle.join();
                }
                self.midi_in_devices.swap_remove(idx);
                MMSYSERR_NOERROR
            }
            None => MMSYSERR_INVALHANDLE,
        }
    }

    /// Start MIDI input capture.
    ///
    /// Registers this device with the shared CoreMIDI poller (a single
    /// background thread that drains the global CoreMIDI buffer and fans
    /// messages out to every open input device). The PE runtime dispatch
    /// layer can then read the device's buffer and deliver MIM_DATA
    /// callbacks in guest context.
    pub fn midi_in_start(&mut self, device_handle: u32) -> u32 {
        let dev = match self
            .midi_in_devices
            .iter_mut()
            .find(|d| d.device_id == device_handle)
        {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };

        if dev.state == MidiInState::Started {
            return MMSYSERR_NOERROR;
        }
        dev.state = MidiInState::Started;

        // Register this device as a subscriber of the shared poller.
        let buffer = dev.midi_buffer.clone();
        if let Ok(mut poller) = MIDI_IN_POLLER.lock() {
            poller.subscribers.retain(|&(id, _)| id != device_handle);
            poller.subscribers.push((device_handle, buffer));

            // Spawn the shared poller thread on first use.
            if poller.thread.is_none() {
                let stop = Arc::new(AtomicBool::new(false));
                let stop_clone = stop.clone();
                poller.stop = stop.clone();
                let spawned = std::thread::Builder::new()
                    .name("winmm-midi-in-poller".to_string())
                    .spawn(move || {
                        while !stop_clone.load(Ordering::SeqCst) {
                            // Poll CoreMIDI for incoming messages
                            let messages = crate::midi::drain_core_midi_input();
                            if !messages.is_empty()
                                && let Ok(poller) = MIDI_IN_POLLER.lock()
                            {
                                for msg in &messages {
                                    for (_, buf) in &poller.subscribers {
                                        if let Ok(mut b) = buf.lock() {
                                            b.push_back(msg.data.clone());
                                            if b.len() > 1024 {
                                                b.pop_front();
                                            }
                                        }
                                    }
                                }
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    });
                match spawned {
                    Ok(h) => {
                        poller.thread = Some(h);
                    }
                    Err(e) => {
                        eprintln!("[winmm] failed to spawn MIDI poller thread: {e}");
                        poller.subscribers.retain(|&(id, _)| id != device_handle);
                        poller.stop = Arc::new(AtomicBool::new(true));
                        dev.state = MidiInState::Stopped;
                        return MMSYSERR_ERROR;
                    }
                }
            }
        }
        MMSYSERR_NOERROR
    }

    /// Stop MIDI input capture.
    ///
    /// Unregisters the device from the shared poller and stops its
    /// per-device thread (if any).
    pub fn midi_in_stop(&mut self, device_handle: u32) -> u32 {
        let dev = match self
            .midi_in_devices
            .iter_mut()
            .find(|d| d.device_id == device_handle)
        {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };

        dev.state = MidiInState::Stopped;
        unregister_midi_in_device(device_handle);
        dev.midi_thread_stop.store(true, Ordering::SeqCst);
        if let Some(handle) = dev.midi_thread.take() {
            let _ = handle.join();
        }
        MMSYSERR_NOERROR
    }

    /// Reset a MIDI input device.
    ///
    /// Stops capture and clears any pending MIDI data in the buffer.
    pub fn midi_in_reset(&mut self, device_handle: u32) -> u32 {
        let dev = match self
            .midi_in_devices
            .iter_mut()
            .find(|d| d.device_id == device_handle)
        {
            Some(d) => d,
            None => return MMSYSERR_INVALHANDLE,
        };

        dev.state = MidiInState::Stopped;
        unregister_midi_in_device(device_handle);
        dev.midi_thread_stop.store(true, Ordering::SeqCst);
        if let Some(handle) = dev.midi_thread.take() {
            let _ = handle.join();
        }
        // Clear any buffered MIDI data
        if let Ok(mut buf) = dev.midi_buffer.lock() {
            buf.clear();
        }
        MMSYSERR_NOERROR
    }

    /// Returns the number of MIDI input devices available (always 1).
    pub fn midi_in_get_num_devs(&self) -> u32 {
        1
    }

    /// Returns device capabilities for a MIDI input device (basic stub).
    pub fn midi_in_get_dev_caps(&self) -> u32 {
        MMSYSERR_NOERROR
    }

    /// Get MIDI output device volume.
    ///
    /// Volume is packed as `(right << 16) | left`.
    pub fn midi_out_get_volume(&self, _device_handle: u32) -> (u32, u32) {
        let vol = crate::midi::midi_out_get_volume();
        (MMSYSERR_NOERROR, vol)
    }

    /// Set MIDI output device volume.
    ///
    /// Volume is packed as `(right << 16) | left`.
    pub fn midi_out_set_volume(&mut self, _device_handle: u32, volume: u32) -> u32 {
        crate::midi::midi_out_set_volume(volume);
        MMSYSERR_NOERROR
    }

    // ── PlaySound implementation (cpal-based) ─────────────────────────────────

    /// Parse a RIFF/WAV file and push its PCM audio data to the cpal backend.
    ///
    /// Returns the duration of the queued audio in seconds on success, or
    /// `None` if the file could not be read/parsed or queued.
    fn play_sound_file_cpal(path: &str) -> Option<f64> {
        let file_data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[winmm] play_sound_file_cpal: cannot read '{path}': {e}");
                return None;
            }
        };

        if file_data.len() < 12 {
            eprintln!("[winmm] play_sound_file_cpal: '{path}' too short for RIFF header");
            return None;
        }

        // Validate RIFF header
        let riff = u32::from_le_bytes([file_data[0], file_data[1], file_data[2], file_data[3]]);
        let wave = u32::from_le_bytes([file_data[8], file_data[9], file_data[10], file_data[11]]);
        if riff != FOURCC_RIFF || wave != FOURCC_WAVE {
            eprintln!("[winmm] play_sound_file_cpal: '{path}' not a RIFF/WAV file");
            return None;
        }

        // Walk chunks to find fmt and data
        let mut offset: usize = 12;
        let mut channels: u16 = 2;
        let mut sample_rate: u32 = 44100;
        let mut bits_per_sample: u16 = 16;
        let mut format_tag: u16 = 1; // PCM
        let mut pcm_data: Vec<u8> = Vec::new();

        while offset + 8 <= file_data.len() {
            let ckid = u32::from_le_bytes([
                file_data[offset],
                file_data[offset + 1],
                file_data[offset + 2],
                file_data[offset + 3],
            ]);
            let cksize = u32::from_le_bytes([
                file_data[offset + 4],
                file_data[offset + 5],
                file_data[offset + 6],
                file_data[offset + 7],
            ]) as usize;

            if ckid == FOURCC_FMT && offset + 8 + cksize <= file_data.len() {
                let fmt_data = &file_data[offset + 8..offset + 8 + cksize];
                if fmt_data.len() >= 16 {
                    format_tag = u16::from_le_bytes([fmt_data[0], fmt_data[1]]);
                    channels = u16::from_le_bytes([fmt_data[2], fmt_data[3]]);
                    sample_rate = u32::from_le_bytes([fmt_data[4], fmt_data[5], fmt_data[6], fmt_data[7]]);
                    bits_per_sample = u16::from_le_bytes([fmt_data[14], fmt_data[15]]);
                }
            } else if ckid == FOURCC_DATA && offset + 8 + cksize <= file_data.len() {
                pcm_data = file_data[offset + 8..offset + 8 + cksize].to_vec();
            }

            // Move to next chunk (chunks are WORD-aligned)
            let chunk_total = 8 + cksize + (cksize % 2);
            offset += chunk_total;
        }

        if pcm_data.is_empty() {
            eprintln!("[winmm] play_sound_file_cpal: no data chunk found in '{path}'");
            return None;
        }
        // Guard against malformed headers that would divide by zero later.
        if channels == 0 || sample_rate == 0 || bits_per_sample == 0 {
            eprintln!("[winmm] play_sound_file_cpal: malformed format in '{path}'");
            return None;
        }

        // Push to the cpal backend
        let wav_format = WaveFormatEx {
            w_format_tag: format_tag,
            n_channels: channels,
            n_samples_per_sec: sample_rate,
            n_avg_bytes_per_sec: sample_rate * channels as u32 * (bits_per_sample as u32 / 8),
            n_block_align: channels * (bits_per_sample / 8),
            w_bits_per_sample: bits_per_sample,
            cb_size: 0,
        };

        // Ensure audio backend is initialised for this format
        let real_id = match ensure_winmm_audio(&wav_format) {
            Some(id) => id,
            None => {
                eprintln!("[winmm] play_sound_file_cpal: failed to init audio backend");
                return None;
            }
        };

        let pushed = if let Ok(mut guard) = WINMM_REAL_AUDIO.lock()
            && let Some(backend) = guard.as_mut()
        {
            let samples = pcm_bytes_to_float(&pcm_data, format_tag, bits_per_sample, channels);
            backend
                .push_wasapi_frames(real_id, &samples, channels, sample_rate)
                .is_ok()
        } else {
            false
        };
        if !pushed {
            eprintln!("[winmm] play_sound_file_cpal: failed to queue audio");
            return None;
        }

        // Duration of the queued audio in seconds (for SND_SYNC blocking).
        let bytes_per_frame = (bits_per_sample as usize / 8) * channels as usize;
        let frames = pcm_data.len() / bytes_per_frame.max(1);
        Some(frames as f64 / sample_rate as f64)
    }

    pub fn play_sound_w(&mut self, sound_name: Option<String>, _hmod: u64, flags: u32) -> u32 {
        // SND_MEMORY means pszSound is a pointer to a sound image in guest
        // memory, which this subsystem cannot dereference — reject it.
        if flags & SND_MEMORY != 0 {
            return 0; // FALSE
        }

        // If no sound name provided and SND_NODEFAULT is set, return silently.
        let name = match sound_name {
            Some(ref n) if !n.is_empty() => n.clone(),
            _ => {
                if flags & SND_NODEFAULT != 0 {
                    return 0; // FALSE
                }
                // Play a synthesized system beep
                return Self::play_system_beep();
            }
        };

        // Resolve the path. SND_ALIAS maps a small set of system aliases to
        // the built-in beep; otherwise the name is treated as a file path.
        let path = if flags & SND_ALIAS != 0 && flags & SND_FILENAME == 0 {
            match name.to_ascii_lowercase().as_str() {
                "systemasterisk" | "systemexclamation" | "systemhand" | "systemquestion"
                | "systemdefault" | "systembeep" => {
                    return Self::play_system_beep();
                }
                _ => return 0, // FALSE — unknown alias
            }
        } else {
            std::path::PathBuf::from(&name)
        };

        if !path.exists() {
            if flags & SND_NODEFAULT != 0 {
                return 0; // FALSE
            }
            // Fall back to a synthesized beep instead of a system AIFF file,
            // which the WAV-only parser cannot play.
            return Self::play_system_beep();
        }

        // Stop any currently playing async sound, joining the old thread so
        // it cannot push audio after the new sound starts.
        if let Some(thread) = self.play_sound_thread.take() {
            PLAY_SOUND_STOP.store(true, Ordering::SeqCst);
            let _ = thread.join();
        }

        let async_mode = flags & SND_ASYNC != 0;
        let loop_mode = flags & SND_LOOP != 0;

        if async_mode {
            // Play on background thread
            let path_str = path.to_string_lossy().to_string();
            PLAY_SOUND_STOP.store(false, Ordering::SeqCst);
            let handle = std::thread::spawn(move || {
                if loop_mode {
                    while !PLAY_SOUND_STOP.load(Ordering::SeqCst) {
                        if Self::play_sound_file_cpal(&path_str).is_none() {
                            break;
                        }
                    }
                } else {
                    Self::play_sound_file_cpal(&path_str);
                }
            });
            self.play_sound_thread = Some(handle);
            1 // TRUE
        } else {
            // SND_SYNC: block until the queued audio has played out.
            let duration = Self::play_sound_file_cpal(path.to_string_lossy().as_ref());
            match duration {
                Some(secs) => {
                    std::thread::sleep(Duration::from_secs_f64(secs + 0.05));
                    1 // TRUE
                }
                None => 0, // FALSE — could not play
            }
        }
    }

    /// Play a short synthesized system beep through the real audio backend.
    ///
    /// Used for `PlaySoundW` default/alias/fallback paths, replacing the
    /// previous AIFF file that the WAV-only parser could never play.
    fn play_system_beep() -> u32 {
        let fmt = WaveFormatEx::pcm(1, 44100, 16);
        let real_id = match ensure_winmm_audio(&fmt) {
            Some(id) => id,
            None => {
                eprintln!("[winmm] play_system_beep: failed to init audio backend");
                return 0;
            }
        };

        // Synthesize an 880 Hz beep (~150 ms with a short decay envelope).
        let sample_rate = 44100.0f32;
        let frames = (sample_rate * 0.15) as usize;
        let samples: Vec<f32> = (0..frames)
            .map(|i| {
                let t = i as f32 / sample_rate;
                let envelope = if t < 0.01 {
                    t / 0.01
                } else {
                    (-(t - 0.01) * 12.0).exp()
                };
                (2.0 * std::f32::consts::PI * 880.0 * t).sin() * envelope * 0.5
            })
            .collect();

        let Ok(mut guard) = WINMM_REAL_AUDIO.lock() else {
            return 0;
        };
        match guard.as_mut() {
            Some(backend) => backend
                .push_wasapi_frames(real_id, &samples, 1, 44100)
                .is_ok() as u32,
            None => 0,
        }
    }

    // ── mmio implementation ──────────────────────────────────────────────────

    /// Open a multimedia file for I/O (mmioOpenW).
    ///
    /// Returns a handle (HMMIO) on success, or 0 on failure.
    pub fn mmio_open_w(&mut self, filename: String, flags: u32) -> u32 {
        let path = std::path::PathBuf::from(&filename);

        // Determine the correct file open mode based on flags
        let file = if (flags & MMIO_WRITE) != 0 || (flags & MMIO_READWRITE) != 0 {
            let create = (flags & MMIO_CREATE) != 0;
            if create {
                std::fs::OpenOptions::new()
                    .write(true)
                    .read(true)
                    .create(true)
                    .truncate(true)
                    .open(&path)
            } else {
                std::fs::OpenOptions::new()
                    .write(true)
                    .read(true)
                    .open(&path)
            }
        } else {
            // MMIO_READ or default
            std::fs::OpenOptions::new().read(true).open(&path)
        };

        let file = match file {
            Ok(f) => f,
            Err(_) => return 0, // NULL handle
        };

        let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);

        let handle = self.next_mmio_handle;
        self.next_mmio_handle += 1;

        self.mmio_files.insert(
            handle,
            MmioFile {
                file,
                position: 0,
                filename,
                flags,
                chunk_stack: Vec::new(),
                file_size,
            },
        );

        handle
    }

    /// Close a multimedia file (mmioClose).
    pub fn mmio_close(&mut self, handle: u32, _flags: u32) -> u32 {
        if self.mmio_files.remove(&handle).is_some() {
            MMSYSERR_NOERROR
        } else {
            MMSYSERR_INVALHANDLE
        }
    }

    /// Read bytes from a multimedia file (mmioRead).
    ///
    /// Returns the number of bytes read, or 0 at EOF.
    pub fn mmio_read(&mut self, handle: u32, buf: &mut [u8], count: u32) -> u32 {
        let mmio = match self.mmio_files.get_mut(&handle) {
            Some(f) => f,
            None => return 0,
        };

        let count = (count as usize).min(buf.len());
        match mmio.file.read(&mut buf[..count]) {
            Ok(n) => {
                mmio.position += n as u64;
                n as u32
            }
            Err(_) => 0,
        }
    }

    /// Write bytes to a multimedia file (mmioWrite).
    ///
    /// Returns the number of bytes written.
    pub fn mmio_write(&mut self, handle: u32, data: &[u8], count: u32) -> u32 {
        let mmio = match self.mmio_files.get_mut(&handle) {
            Some(f) => f,
            None => return 0,
        };

        let count = (count as usize).min(data.len());
        match mmio.file.write(&data[..count]) {
            Ok(n) => {
                mmio.position += n as u64;
                if mmio.position > mmio.file_size {
                    mmio.file_size = mmio.position;
                }
                n as u32
            }
            Err(_) => 0,
        }
    }

    /// Reposition the file pointer within a multimedia file (mmioSeek).
    ///
    /// `origin` is `MMIO_SEEK_SET` (0), `MMIO_SEEK_CUR` (1), or
    /// `MMIO_SEEK_END` (2). Returns the new file offset, or `-1` on failure
    /// (invalid handle, unknown origin, negative target, or I/O error).
    ///
    /// Note: the guest-facing dispatch thunk must be wired in `pe_runtime.rs`
    /// (outside this file's scope) for guests to call `mmioSeekW`.
    pub fn mmio_seek(&mut self, handle: u32, offset: i32, origin: u32) -> i64 {
        const MMIO_SEEK_SET: u32 = 0;
        const MMIO_SEEK_CUR: u32 = 1;
        const MMIO_SEEK_END: u32 = 2;

        let mmio = match self.mmio_files.get_mut(&handle) {
            Some(f) => f,
            None => return -1,
        };

        let base = match origin {
            MMIO_SEEK_SET => 0i64,
            MMIO_SEEK_CUR => mmio.position as i64,
            MMIO_SEEK_END => mmio.file_size as i64,
            _ => return -1,
        };
        let target = base.saturating_add(offset as i64);
        if target < 0 {
            return -1;
        }
        match mmio.file.seek(SeekFrom::Start(target as u64)) {
            Ok(pos) => {
                mmio.position = pos;
                pos as i64
            }
            Err(_) => -1,
        }
    }

    /// Ascend from a RIFF chunk (mmioAscend).
    ///
    /// For chunks created with `mmioCreateChunk` (which wrote a placeholder
    /// size of 0), the real chunk size is patched back into the file header.
    /// Then the file pointer is moved past the end of the chunk (aligned to
    /// WORD).
    pub fn mmio_ascend(&mut self, handle: u32, _chunk: &MmioChunkInfo) -> u32 {
        let mmio = match self.mmio_files.get_mut(&handle) {
            Some(f) => f,
            None => return MMSYSERR_INVALHANDLE,
        };

        // Pop the chunk from the stack (if any)
        if let Some(entry) = mmio.chunk_stack.pop() {
            let chunk = entry.info;
            // If the chunk header was written by mmioCreateChunk, patch the
            // placeholder cksize with the actual data size. The data ends at
            // the current file position; the size region starts right after
            // the 8-byte chunk header (the 4-byte form type of RIFF/LIST
            // chunks is *inside* the size region).
            let actual_data_end = if entry.created {
                mmio.position
            } else {
                chunk.dw_data_offset as u64 + chunk.cksize as u64
            };
            if entry.created {
                // The size region starts right after the 8-byte chunk header
                // and runs to the current file position (the 4-byte form
                // type of RIFF/LIST chunks is inside the size region).
                let header_start = chunk.dw_data_offset as u64 - 8;
                let cksize = actual_data_end.saturating_sub(header_start + 8) as u32;
                if mmio.file.seek(SeekFrom::Start(header_start + 4)).is_err() {
                    return MMIOERR_CANNOTWRITE;
                }
                if mmio.file.write_all(&cksize.to_le_bytes()).is_err() {
                    return MMIOERR_CANNOTWRITE;
                }
            }
            // Seek to the end of this chunk's data
            // Align to WORD (2-byte) boundary
            let aligned_end = (actual_data_end + 1) & !1u64;
            if aligned_end > mmio.file_size {
                // Extend the file if needed (writing case)
                // We can't easily extend, but we can pad
                let pad = aligned_end - mmio.file_size;
                if pad > 0 {
                    if mmio.file.seek(SeekFrom::End(0)).is_err() {
                        return MMIOERR_CANNOTWRITE;
                    }
                    let padding = vec![0u8; pad as usize];
                    if mmio.file.write(&padding).is_err() {
                        return MMIOERR_CANNOTWRITE;
                    }
                }
            }
            if let Ok(pos) = mmio.file.seek(SeekFrom::Start(aligned_end)) {
                mmio.position = pos;
            } else {
                return MMIOERR_CANNOTWRITE;
            }
            MMSYSERR_NOERROR
        } else {
            // No chunk to ascend from; seek to end of file (write) or stay put
            MMSYSERR_NOERROR
        }
    }

    /// Descend into a RIFF chunk (mmioDescend).
    ///
    /// Searches for the chunk identified by `chunk.ckid` (if `flags` is
    /// `MMIO_FIND_CHUNK`) starting from the current file position. If `parent`
    /// is `Some`, the search is constrained to the parent chunk's data region.
    pub fn mmio_descend(
        &mut self,
        handle: u32,
        chunk: &mut MmioChunkInfo,
        parent: Option<&MmioChunkInfo>,
        _flags: u32,
    ) -> u32 {
        let mmio = match self.mmio_files.get_mut(&handle) {
            Some(f) => f,
            None => return MMSYSERR_INVALHANDLE,
        };

        // Determine the search range. For a parent chunk, children start
        // after the parent's 4-byte form type (RIFF/LIST) or directly at the
        // data offset, and end at the parent's data end.
        let (search_start, search_end) = if let Some(p) = parent {
            let is_riff_like = p.ckid == FOURCC_RIFF || p.ckid == FOURCC_LIST;
            let form_type_len = if is_riff_like { 4u64 } else { 0 };
            (
                p.dw_data_offset as u64 + form_type_len,
                p.dw_data_offset as u64 + p.cksize as u64,
            )
        } else {
            (mmio.position, mmio.file_size)
        };

        // Seek to search start
        if mmio.file.seek(SeekFrom::Start(search_start)).is_err() {
            return MMIOERR_CHUNKNOTFOUND;
        }
        mmio.position = search_start;

        // Search for the chunk with matching ckid
        let mut pos = search_start;
        while pos + 8 <= search_end {
            // Read chunk header: ckid (4 bytes) + cksize (4 bytes)
            let mut header = [0u8; 8];
            if mmio.file.seek(SeekFrom::Start(pos)).is_err() {
                return MMIOERR_CHUNKNOTFOUND;
            }
            if mmio.file.read_exact(&mut header).is_err() {
                return MMIOERR_CHUNKNOTFOUND;
            }
            let ckid = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            let cksize = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

            // Align chunk size to WORD boundary
            let aligned_size = if cksize % 2 == 1 { cksize + 1 } else { cksize };

            if ckid == chunk.ckid || (chunk.ckid == FOURCC_RIFF && ckid == FOURCC_RIFF) {
                // Found the chunk
                chunk.ckid = ckid;
                chunk.cksize = cksize;
                chunk.dw_data_offset = (pos + 8) as u32;

                // For RIFF/LIST chunks, read the form type
                if ckid == FOURCC_RIFF || ckid == FOURCC_LIST {
                    let mut fcc = [0u8; 4];
                    if mmio.file.read_exact(&mut fcc).is_ok() {
                        chunk.fcc_type = u32::from_le_bytes(fcc);
                    }
                }

                // Push onto chunk stack
                mmio.chunk_stack.push(MmioChunkEntry {
                    info: *chunk,
                    created: false,
                });

                // Move position to start of chunk data
                mmio.position = pos + 8;
                if mmio.file.seek(SeekFrom::Start(mmio.position)).is_err() {
                    return MMIOERR_CANNOTREAD;
                }

                return MMSYSERR_NOERROR;
            }

            // Move to the next chunk
            pos += 8 + aligned_size as u64;
        }

        MMIOERR_CHUNKNOTFOUND
    }

    /// Create a new RIFF chunk (mmioCreateChunk).
    ///
    /// Writes a chunk header at the current file position. The caller should
    /// then write the chunk data and call `mmio_ascend` to finalise.
    pub fn mmio_create_chunk(
        &mut self,
        handle: u32,
        chunk: &mut MmioChunkInfo,
        _flags: u32,
    ) -> u32 {
        let mmio = match self.mmio_files.get_mut(&handle) {
            Some(f) => f,
            None => return MMSYSERR_INVALHANDLE,
        };

        // Record the data offset (right after the 8-byte header). For
        // RIFF/LIST chunks this points at the form type, matching the
        // MMCKINFO.dwDataOffset semantics used by mmioDescend.
        chunk.dw_data_offset = mmio.position as u32 + 8;

        // Write chunk header: ckid (4 bytes) + placeholder cksize (4 bytes)
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&chunk.ckid.to_le_bytes());
        header[4..8].copy_from_slice(&0u32.to_le_bytes()); // placeholder size
        if mmio.file.write_all(&header).is_err() {
            return MMIOERR_CANNOTWRITE;
        }

        // For RIFF/LIST chunks, write the form type
        if chunk.ckid == FOURCC_RIFF || chunk.ckid == FOURCC_LIST {
            let mut fcc = [0u8; 4];
            fcc.copy_from_slice(&chunk.fcc_type.to_le_bytes());
            if mmio.file.write_all(&fcc).is_err() {
                return MMIOERR_CANNOTWRITE;
            }
        }

        mmio.position = chunk.dw_data_offset as u64 + if chunk.ckid == FOURCC_RIFF || chunk.ckid == FOURCC_LIST { 4 } else { 0 };

        // Push onto stack so mmio_ascend can finalise the size
        mmio.chunk_stack.push(MmioChunkEntry {
            info: *chunk,
            created: true,
        });

        MMSYSERR_NOERROR
    }

    /// Convert a four-character string to a FOURCC code (mmioStringToFOURCCW).
    ///
    /// The string may be up to 4 characters long. Shorter strings are padded
    /// with spaces.
    pub fn mmio_string_to_fourcc_w(&self, s: String, _flags: u32) -> u32 {
        let bytes = s.as_bytes();
        let c0 = bytes.first().copied().unwrap_or(b' ');
        let c1 = bytes.get(1).copied().unwrap_or(b' ');
        let c2 = bytes.get(2).copied().unwrap_or(b' ');
        let c3 = bytes.get(3).copied().unwrap_or(b' ');
        mmio_fourcc(c0, c1, c2, c3)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wave_out_open_close() {
        let mut mm = WinMmSubsystem::new();
        let fmt = WaveFormatEx::pcm(2, 44100, 16);

        let (rc, handle) = mm.wave_out_open(WAVE_MAPPER, &fmt, None);
        assert_eq!(rc, MMSYSERR_NOERROR, "waveOutOpen should succeed");
        assert!(handle > 0, "should get a nonzero handle");

        let rc = mm.wave_out_close(handle);
        assert_eq!(rc, MMSYSERR_NOERROR, "waveOutClose should succeed");
    }

    #[test]
    fn test_wave_out_write() {
        let mut mm = WinMmSubsystem::new();
        let fmt = WaveFormatEx::pcm(2, 44100, 16);

        let (rc, handle) = mm.wave_out_open(WAVE_MAPPER, &fmt, None);
        assert_eq!(rc, MMSYSERR_NOERROR);

        // Write sample PCM data (silence)
        let sample_data = vec![0u8; 1024];

        let rc = mm.wave_out_write(handle, &sample_data, 0, 0);
        assert_eq!(rc, MMSYSERR_NOERROR, "waveOutWrite should succeed");

        // Verify the data was stored correctly
        let device = mm
            .wave_out_devices
            .iter()
            .find(|d| d.device_id == handle)
            .unwrap();
        assert_eq!(device.buffers.len(), 1);
        assert_eq!(device.buffers[0].data, sample_data);

        mm.wave_out_close(handle);
    }

    #[test]
    fn test_time_get_time() {
        let mm = WinMmSubsystem::new();
        let t1 = mm.time_get_time();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = mm.time_get_time();
        assert!(t2 >= t1, "timeGetTime should increase monotonically");
    }

    #[test]
    fn test_wave_out_get_num_devs() {
        let mm = WinMmSubsystem::new();
        let n = mm.wave_out_get_num_devs();
        assert!(n >= 1, "at least 1 device should be available");
    }

    #[test]
    fn test_wave_out_get_volume() {
        let mut mm = WinMmSubsystem::new();
        let fmt = WaveFormatEx::pcm(2, 44100, 16);
        let (rc, handle) = mm.wave_out_open(WAVE_MAPPER, &fmt, None);
        assert_eq!(rc, MMSYSERR_NOERROR);

        let mut vol = 0;
        let rc = mm.wave_out_get_volume(handle, &mut vol);
        assert_eq!(rc, MMSYSERR_NOERROR);
        assert_eq!(vol, 0xFFFF_FFFF, "default volume should be max");

        mm.wave_out_close(handle);
    }

    #[test]
    fn test_wave_out_set_volume() {
        let mut mm = WinMmSubsystem::new();
        let fmt = WaveFormatEx::pcm(2, 44100, 16);
        let (rc, handle) = mm.wave_out_open(WAVE_MAPPER, &fmt, None);
        assert_eq!(rc, MMSYSERR_NOERROR);

        let rc = mm.wave_out_set_volume(handle, 0x8000_8000);
        assert_eq!(rc, MMSYSERR_NOERROR);

        let mut vol = 0;
        let rc = mm.wave_out_get_volume(handle, &mut vol);
        assert_eq!(rc, MMSYSERR_NOERROR);
        assert_eq!(vol, 0x8000_8000);

        mm.wave_out_close(handle);
    }

    #[test]
    fn test_wave_out_reset() {
        let mut mm = WinMmSubsystem::new();
        let fmt = WaveFormatEx::pcm(2, 44100, 16);
        let (rc, handle) = mm.wave_out_open(WAVE_MAPPER, &fmt, None);
        assert_eq!(rc, MMSYSERR_NOERROR);

        let sample_data = vec![0u8; 256];
        let rc = mm.wave_out_write(handle, &sample_data, 0, 0);
        assert_eq!(rc, MMSYSERR_NOERROR);

        let rc = mm.wave_out_reset(handle);
        assert_eq!(rc, MMSYSERR_NOERROR);

        let device = mm.wave_out_devices.iter().find(|d| d.device_id == handle);
        assert!(device.is_some());
        assert_eq!(device.unwrap().state, WaveOutState::Stopped);
        assert!(device.unwrap().buffers.is_empty());

        mm.wave_out_close(handle);
    }

    #[test]
    fn test_wave_out_get_dev_caps() {
        let mm = WinMmSubsystem::new();
        let mut caps = WaveOutCapsW::default();
        let rc = mm.wave_out_get_dev_caps(WAVE_MAPPER, &mut caps);
        assert_eq!(rc, MMSYSERR_NOERROR);
        assert_eq!(caps.w_channels, 2);
    }

    #[test]
    fn test_wave_out_bad_device_id() {
        let mut mm = WinMmSubsystem::new();
        let fmt = WaveFormatEx::pcm(2, 44100, 16);
        let (rc, _) = mm.wave_out_open(999, &fmt, None);
        assert_eq!(rc, MMSYSERR_BADDEVICEID);
    }

    #[test]
    fn test_invalid_handle_returns_error() {
        let mut mm = WinMmSubsystem::new();
        assert_eq!(mm.wave_out_close(0xFFFFFFFF), MMSYSERR_INVALHANDLE);
        assert_eq!(mm.wave_out_reset(0xFFFFFFFF), MMSYSERR_INVALHANDLE);
    }

    // ── MIDI tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_midi_out_open_close() {
        let mut mm = WinMmSubsystem::new();
        let rc = mm.midi_out_open(0, None);
        assert_eq!(rc, MMSYSERR_NOERROR, "midiOutOpen should succeed");

        // Should have one device
        assert_eq!(mm.midi_out_devices.len(), 1);
        let dev_id = mm.midi_out_devices[0].device_id;

        let rc = mm.midi_out_close(dev_id);
        assert_eq!(rc, MMSYSERR_NOERROR, "midiOutClose should succeed");
        assert!(mm.midi_out_devices.is_empty());
    }

    #[test]
    fn test_midi_out_open_with_mapper() {
        let mut mm = WinMmSubsystem::new();
        let rc = mm.midi_out_open(MIDI_MAPPER, None);
        assert_eq!(
            rc, MMSYSERR_NOERROR,
            "midiOutOpen with MIDI_MAPPER should succeed"
        );
    }

    #[test]
    fn test_midi_out_bad_device_id() {
        let mut mm = WinMmSubsystem::new();
        let rc = mm.midi_out_open(999, None);
        assert_eq!(rc, MMSYSERR_BADDEVICEID);
    }

    #[test]
    fn test_midi_out_short_msg() {
        let mut mm = WinMmSubsystem::new();
        let rc = mm.midi_out_open(0, None);
        assert_eq!(rc, MMSYSERR_NOERROR);
        let dev_id = mm.midi_out_devices[0].device_id;

        // Note On, channel 0, note 60, velocity 100
        let msg = 0x90u32 | (60u32 << 8) | (100u32 << 16);
        let rc = mm.midi_out_short_msg(dev_id, msg);
        assert_eq!(
            rc, MMSYSERR_NOERROR,
            "midiOutShortMsg (NoteOn) should succeed"
        );

        // Note Off, channel 0, note 60
        let msg_off = 0x80u32 | (60u32 << 8);
        let rc = mm.midi_out_short_msg(dev_id, msg_off);
        assert_eq!(
            rc, MMSYSERR_NOERROR,
            "midiOutShortMsg (NoteOff) should succeed"
        );

        mm.midi_out_close(dev_id);
    }

    #[test]
    fn test_midi_out_short_msg_invalid_handle() {
        let mut mm = WinMmSubsystem::new();
        let rc = mm.midi_out_short_msg(0xFFFFFFFF, 0);
        assert_eq!(rc, MMSYSERR_INVALHANDLE);
    }

    #[test]
    fn test_midi_out_long_msg() {
        let mut mm = WinMmSubsystem::new();
        let rc = mm.midi_out_open(0, None);
        assert_eq!(rc, MMSYSERR_NOERROR);
        let dev_id = mm.midi_out_devices[0].device_id;

        // Send a SysEx message
        let sysex = vec![0xF0, 0x7E, 0x7F, 0x09, 0x01, 0xF7];
        let rc = mm.midi_out_long_msg(dev_id, &sysex);
        assert_eq!(rc, MMSYSERR_NOERROR, "midiOutLongMsg should succeed");

        mm.midi_out_close(dev_id);
    }

    #[test]
    fn test_midi_out_reset() {
        let mut mm = WinMmSubsystem::new();
        let rc = mm.midi_out_open(0, None);
        assert_eq!(rc, MMSYSERR_NOERROR);
        let dev_id = mm.midi_out_devices[0].device_id;

        // Send some notes, then reset
        let msg = 0x90u32 | (60u32 << 8) | (100u32 << 16);
        let rc = mm.midi_out_short_msg(dev_id, msg);
        assert_eq!(rc, MMSYSERR_NOERROR);

        let rc = mm.midi_out_reset(dev_id);
        assert_eq!(rc, MMSYSERR_NOERROR, "midiOutReset should succeed");

        mm.midi_out_close(dev_id);
    }

    #[test]
    fn test_midi_out_get_num_devs() {
        let mm = WinMmSubsystem::new();
        assert_eq!(mm.midi_out_get_num_devs(), 1);
    }

    #[test]
    fn test_midi_out_get_dev_caps() {
        let mm = WinMmSubsystem::new();
        let mut caps = MidiOutCapsW::default();
        let rc = mm.midi_out_get_dev_caps(0, &mut caps);
        assert_eq!(rc, MMSYSERR_NOERROR);
        assert_eq!(caps.w_technology, MOD_SWSYNTH);
    }

    #[test]
    fn test_midi_in_open_close() {
        let mut mm = WinMmSubsystem::new();
        let rc = mm.midi_in_open(0, None);
        assert_eq!(rc, MMSYSERR_NOERROR, "midiInOpen should succeed");
        assert_eq!(mm.midi_in_devices.len(), 1);
        let dev_id = mm.midi_in_devices[0].device_id;

        let rc = mm.midi_in_close(dev_id);
        assert_eq!(rc, MMSYSERR_NOERROR, "midiInClose should succeed");
        assert!(mm.midi_in_devices.is_empty());
    }

    #[test]
    fn test_midi_in_start_stop() {
        let mut mm = WinMmSubsystem::new();
        let rc = mm.midi_in_open(0, None);
        assert_eq!(rc, MMSYSERR_NOERROR);
        let dev_id = mm.midi_in_devices[0].device_id;

        let rc = mm.midi_in_start(dev_id);
        assert_eq!(rc, MMSYSERR_NOERROR, "midiInStart should succeed");
        assert_eq!(mm.midi_in_devices[0].state, MidiInState::Started);

        let rc = mm.midi_in_stop(dev_id);
        assert_eq!(rc, MMSYSERR_NOERROR, "midiInStop should succeed");
        assert_eq!(mm.midi_in_devices[0].state, MidiInState::Stopped);

        mm.midi_in_close(dev_id);
    }

    #[test]
    fn test_midi_in_reset() {
        let mut mm = WinMmSubsystem::new();
        let rc = mm.midi_in_open(0, None);
        assert_eq!(rc, MMSYSERR_NOERROR);
        let dev_id = mm.midi_in_devices[0].device_id;

        let rc = mm.midi_in_start(dev_id);
        assert_eq!(rc, MMSYSERR_NOERROR);

        let rc = mm.midi_in_reset(dev_id);
        assert_eq!(rc, MMSYSERR_NOERROR, "midiInReset should succeed");
        assert_eq!(mm.midi_in_devices[0].state, MidiInState::Stopped);

        mm.midi_in_close(dev_id);
    }

    #[test]
    fn test_midi_in_get_num_devs() {
        let mm = WinMmSubsystem::new();
        assert_eq!(mm.midi_in_get_num_devs(), 1);
    }

    #[test]
    fn test_mmio_create_ascend_patches_chunk_sizes() {
        let mut mm = WinMmSubsystem::new();
        let path = std::env::temp_dir().join(format!(
            "casa1-mmio-ascend-{}.wav",
            std::process::id()
        ));
        let path_str = path.to_string_lossy().to_string();

        let handle = mm.mmio_open_w(path_str.clone(), MMIO_WRITE | MMIO_CREATE);
        assert_ne!(handle, 0, "mmioOpen for writing should succeed");

        let mut riff = MmioChunkInfo {
            ckid: FOURCC_RIFF,
            fcc_type: FOURCC_WAVE,
            ..Default::default()
        };
        assert_eq!(
            mm.mmio_create_chunk(handle, &mut riff, 0),
            MMSYSERR_NOERROR
        );
        let mut data = MmioChunkInfo {
            ckid: FOURCC_DATA,
            ..Default::default()
        };
        assert_eq!(
            mm.mmio_create_chunk(handle, &mut data, 0),
            MMSYSERR_NOERROR
        );

        let payload = [0xABu8; 32];
        assert_eq!(
            mm.mmio_write(handle, &payload, payload.len() as u32),
            payload.len() as u32
        );
        assert_eq!(mm.mmio_ascend(handle, &data), MMSYSERR_NOERROR);
        assert_eq!(mm.mmio_ascend(handle, &riff), MMSYSERR_NOERROR);
        assert_eq!(mm.mmio_close(handle, 0), MMSYSERR_NOERROR);

        // Re-open read-only and verify the patched sizes.
        let handle = mm.mmio_open_w(path_str.clone(), MMIO_READ);
        assert_ne!(handle, 0, "mmioOpen for reading should succeed");
        let mut chunk = MmioChunkInfo {
            ckid: FOURCC_RIFF,
            ..Default::default()
        };
        assert_eq!(
            mm.mmio_descend(handle, &mut chunk, None, MMIO_FIND_RIFF),
            MMSYSERR_NOERROR
        );
        assert_eq!(chunk.ckid, FOURCC_RIFF);
        assert_eq!(chunk.fcc_type, FOURCC_WAVE);
        // 8 (RIFF hdr) + 4 (WAVE) + 8 (data hdr) + 32 (payload) - 8 = 44
        assert_eq!(chunk.cksize, 44, "RIFF cksize must be patched");
        let mut data = MmioChunkInfo {
            ckid: FOURCC_DATA,
            ..Default::default()
        };
        assert_eq!(
            mm.mmio_descend(handle, &mut data, Some(&chunk), MMIO_FIND_CHUNK),
            MMSYSERR_NOERROR
        );
        assert_eq!(data.cksize, 32, "data cksize must be patched");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_mmio_seek_positions() {
        let mut mm = WinMmSubsystem::new();
        let path = std::env::temp_dir().join(format!(
            "casa1-mmio-seek-{}.bin",
            std::process::id()
        ));
        let path_str = path.to_string_lossy().to_string();
        let handle = mm.mmio_open_w(path_str.clone(), MMIO_WRITE | MMIO_CREATE);
        assert_ne!(handle, 0);
        assert_eq!(mm.mmio_write(handle, b"abcdefgh", 8), 8);

        // SEEK_SET
        assert_eq!(mm.mmio_seek(handle, 2, 0), 2);
        // SEEK_CUR
        assert_eq!(mm.mmio_seek(handle, 3, 1), 5);
        // SEEK_END
        assert_eq!(mm.mmio_seek(handle, -2, 2), 6);
        // Negative target fails
        assert_eq!(mm.mmio_seek(handle, -100, 0), -1);
        // Unknown origin fails
        assert_eq!(mm.mmio_seek(handle, 0, 99), -1);
        // Invalid handle fails
        assert_eq!(mm.mmio_seek(0xFFFF_FFFF, 0, 0), -1);

        mm.mmio_close(handle, 0);
        let _ = std::fs::remove_file(&path);
    }
}
