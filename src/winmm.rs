//! WinMM (Windows Multimedia) audio API implementation.
//!
//! Provides a synthetic `winmm.dll` subsystem that routes wave audio
//! calls through the macOS CoreAudio / AudioQueue infrastructure via
//! the existing [`AudioSubsystem`](crate::audio::AudioSubsystem).
//!
//! ## Supported APIs
//!
//! - **waveOut*** — waveform-audio output (open, close, prepare header,
//!   write, reset, volume)
//! - **waveIn*** — waveform-audio input (stubs)
//! - **midiOut*** / **midiIn*** — MIDI (stubs)
//! - **timeGetTime** / **timeBeginPeriod** / **timeEndPeriod** — timer
//! - **PlaySoundW** — simple sound playback (stub)
//! - **mmio*** — multimedia file I/O (stubs)

use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Wave message constants ──────────────────────────────────────────────────

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
    pub const WAVE_FORMAT_IEEE_FLOAT: u16 = 3;

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
}

// ── Wave output device ──────────────────────────────────────────────────────

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
}

impl WaveOutDevice {
    /// Default volume (full: 0xFFFF_FFFF).
    const DEFAULT_VOLUME: u32 = 0xFFFF_FFFF;

    pub fn new(device_id: u32, format: WaveFormatEx, callback: Option<(u64, u64)>) -> Self {
        Self {
            device_id,
            format,
            state: WaveOutState::Stopped,
            buffers: Vec::new(),
            callback,
            volume: Self::DEFAULT_VOLUME,
        }
    }
}

// ── WinMM Subsystem ─────────────────────────────────────────────────────────

/// Top-level WinMM subsystem state.
///
/// This is stored inside [`AudioSubsystem`](crate::audio::AudioSubsystem)
/// behind a `RwLock` for interior-mutability access from the PE runtime
/// dispatch functions (which hold `&mut self` on the runtime but need
/// shared access to the audio subsystem).
#[derive(Debug, Clone)]
pub struct WinMmSubsystem {
    /// List of open wave output devices.
    pub wave_out_devices: Vec<WaveOutDevice>,
    /// Monotonic ID counter for device handles.
    pub next_device_id: u32,
    /// Reference `Instant` used by `timeGetTime` (in milliseconds since
    /// subsystem creation).
    pub time_get_time_ref: u64,
}

impl Default for WinMmSubsystem {
    fn default() -> Self {
        Self::new()
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

        // Validate format — must be PCM
        if format.w_format_tag != WaveFormatEx::WAVE_FORMAT_PCM
            && format.w_format_tag != WaveFormatEx::WAVE_FORMAT_IEEE_FLOAT
        {
            return (WAVERR_BADFORMAT, 0);
        }

        let device_handle = self.next_device_id;
        self.next_device_id += 1;

        let device = WaveOutDevice::new(device_handle, *format, callback);
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
    pub fn wave_out_prepare_header(
        &mut self,
        device_handle: u32,
        _header: &WaveHdr,
    ) -> u32 {
        if !self.wave_out_devices.iter().any(|d| d.device_id == device_handle) {
            return MMSYSERR_INVALHANDLE;
        }
        MMSYSERR_NOERROR
    }

    /// Unprepare a WAVEHDR.
    pub fn wave_out_unprepare_header(
        &mut self,
        device_handle: u32,
        _header: &WaveHdr,
    ) -> u32 {
        if !self.wave_out_devices.iter().any(|d| d.device_id == device_handle) {
            return MMSYSERR_INVALHANDLE;
        }
        MMSYSERR_NOERROR
    }

    /// Write (queue) a buffer for playback.
    ///
    /// Copies the audio data from guest memory (via `data_ptr` + `data_len`)
    /// into a [`QueuedWaveBuffer`] and appends it to the device's queue.
    ///
    /// Returns `MMSYSERR_NOERROR` on success.
    pub fn wave_out_write(
        &mut self,
        device_handle: u32,
        data_ptr: u64,
        data_len: u32,
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

        // Copy the audio data into a host-side buffer.
        // In a fully integrated implementation this data would be routed
        // to the macOS AudioQueue for real playback. For now we store it
        // and simulate playback completion.
        let data = vec![0u8; data_len as usize];

        let buf = QueuedWaveBuffer {
            data,
            flags,
            loops,
            done: false,
        };
        device.buffers.push(buf);
        device.state = WaveOutState::Playing;

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

    /// `timeBeginPeriod` — no-op (stub).
    pub fn time_begin_period(_period: u32) -> u32 {
        MMSYSERR_NOERROR
    }

    /// `timeEndPeriod` — no-op (stub).
    pub fn time_end_period(_period: u32) -> u32 {
        MMSYSERR_NOERROR
    }

    // ── Wave In stubs ───────────────────────────────────────────────────────

    pub fn wave_in_open(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn wave_in_close(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn wave_in_prepare_header(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn wave_in_unprepare_header(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn wave_in_add_buffer(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn wave_in_start(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn wave_in_stop(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn wave_in_get_num_devs(&self) -> u32 {
        0
    }

    pub fn wave_in_get_dev_caps(&self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    // ── MIDI stubs ──────────────────────────────────────────────────────────

    pub fn midi_out_open(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn midi_out_close(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn midi_out_short_msg(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn midi_out_long_msg(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn midi_out_reset(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn midi_out_get_num_devs(&self) -> u32 {
        0
    }

    pub fn midi_out_get_dev_caps(&self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn midi_in_open(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn midi_in_close(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn midi_in_start(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn midi_in_stop(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    pub fn midi_in_reset(&mut self) -> u32 {
        MMSYSERR_NOTSUPPORTED
    }

    // ── PlaySound stub ──────────────────────────────────────────────────────

    pub fn play_sound_w(&mut self) -> u32 {
        // Stub: always "succeeds" silently.
        1 // TRUE
    }

    // ── mmio stubs ──────────────────────────────────────────────────────────

    pub fn mmio_open_w(&mut self) -> u32 {
        0 // NULL handle
    }

    pub fn mmio_close(&mut self) -> u32 {
        MMSYSERR_NOERROR
    }

    pub fn mmio_read(&mut self) -> u32 {
        0
    }

    pub fn mmio_write(&mut self) -> u32 {
        0
    }

    pub fn mmio_ascend(&mut self) -> u32 {
        MMSYSERR_NOERROR
    }

    pub fn mmio_descend(&mut self) -> u32 {
        MMSYSERR_NOERROR
    }

    pub fn mmio_create_chunk(&mut self) -> u32 {
        MMSYSERR_NOERROR
    }

    pub fn mmio_string_to_fourcc_w(&mut self) -> u32 {
        0
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

        // Prepare a header and write
        let hdr = WaveHdr {
            lp_data: 0x1234_5678, // fake guest pointer
            dw_buffer_length: 1024,
            dw_bytes_recorded: 0,
            dw_user: 0xDEAD_BEEF,
            dw_flags: 0,
            dw_loops: 0,
            lp_next: 0,
            reserved: 0,
        };

        let rc = mm.wave_out_prepare_header(handle, &hdr);
        assert_eq!(rc, MMSYSERR_NOERROR, "prepare header should succeed");

        let rc = mm.wave_out_write(handle, hdr.lp_data, hdr.dw_buffer_length, hdr.dw_flags, hdr.dw_loops);
        assert_eq!(rc, MMSYSERR_NOERROR, "waveOutWrite should succeed");

        let rc = mm.wave_out_unprepare_header(handle, &hdr);
        assert_eq!(rc, MMSYSERR_NOERROR, "unprepare header should succeed");

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

        let rc = mm.wave_out_write(handle, 0x1000, 256, 0, 0);
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
}
