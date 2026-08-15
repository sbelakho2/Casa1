//! MIDI Synthesis for Casa1.
//!
//! Provides General MIDI wavetable synthesis for Windows `midiOut*` APIs.
//! Uses a simple sine-wave based synthesizer with basic instrument mapping.
//!
//! ## Supported Features
//! - `midiOutOpen` / `midiOutClose` / `midiOutShortMsg` / `midiOutLongMsg`
//! - General MIDI instrument map (128 instruments)
//! - Note On/Off, Program Change, Control Change, Pitch Bend
//! - Mixes output into Casa1 audio mixer

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::sync::Mutex;

/// MIDI status byte constants.
pub const MIDI_STATUS_NOTE_OFF: u8 = 0x80;
pub const MIDI_STATUS_NOTE_ON: u8 = 0x90;
pub const MIDI_STATUS_POLY_AFTERTOUCH: u8 = 0xA0;
pub const MIDI_STATUS_CONTROL_CHANGE: u8 = 0xB0;
pub const MIDI_STATUS_PROGRAM_CHANGE: u8 = 0xC0;
pub const MIDI_STATUS_CHANNEL_AFTERTOUCH: u8 = 0xD0;
pub const MIDI_STATUS_PITCH_BEND: u8 = 0xE0;
pub const MIDI_STATUS_SYSTEM: u8 = 0xF0;

/// MIDI controller numbers.
pub const MIDI_CTL_VOLUME: u8 = 7;
pub const MIDI_CTL_PAN: u8 = 10;
pub const MIDI_CTL_SUSTAIN: u8 = 64;
pub const MIDI_CTL_ALL_NOTES_OFF: u8 = 123;
pub const MIDI_CTL_ALL_SOUND_OFF: u8 = 120;

/// A single active note in the synthesizer.
#[derive(Debug, Clone)]
struct ActiveNote {
    channel: u8,
    note: u8,
    velocity: u8,
    sample_index: u64,
    frequency: f64,
    amplitude: f64,
    instrument: u8,
    /// True if note-off was received while sustain pedal was held.
    sustained: bool,
}

/// Per-channel state.
#[derive(Debug, Clone)]
struct ChannelState {
    instrument: u8,
    volume: u8,
    pan: u8,
    pitch_bend: i16, // -8192 to 8191
    sustain: bool,
    active_notes: Vec<ActiveNote>,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            instrument: 0, // Acoustic Grand Piano
            volume: 100,
            pan: 64, // center
            pitch_bend: 0,
            sustain: false,
            active_notes: Vec::new(),
        }
    }
}

/// The MIDI synthesizer state.
pub struct MidiSynthesizer {
    channels: [ChannelState; 16],
    sample_rate: u32,
    master_volume: f64,
    /// General MIDI instrument waveforms (harmonic content per instrument).
    /// Each instrument is defined as a set of harmonic amplitudes.
    instrument_waveforms: Vec<Vec<f64>>,
}

impl MidiSynthesizer {
    /// Create a new MIDI synthesizer.
    pub fn new(sample_rate: u32) -> Self {
        let instrument_waveforms = build_instrument_waveforms();
        Self {
            channels: [(); 16].map(|_| ChannelState::default()),
            sample_rate,
            master_volume: 0.5,
            instrument_waveforms,
        }
    }

    /// Process a MIDI short message (packed into 3 bytes).
    pub fn process_short_msg(&mut self, msg: u32) {
        let status = (msg & 0xFF) as u8;
        let data1 = ((msg >> 8) & 0xFF) as u8;
        let data2 = ((msg >> 16) & 0xFF) as u8;

        let channel = status & 0x0F;
        if channel >= 16 {
            return;
        }

        match status & 0xF0 {
            MIDI_STATUS_NOTE_OFF => {
                self.note_off(channel, data1);
            }
            MIDI_STATUS_NOTE_ON => {
                if data2 == 0 {
                    self.note_off(channel, data1);
                } else {
                    self.note_on(channel, data1, data2);
                }
            }
            MIDI_STATUS_POLY_AFTERTOUCH => {
                // Polyphonic aftertouch — simplified, ignore
            }
            MIDI_STATUS_CONTROL_CHANGE => {
                self.control_change(channel, data1, data2);
            }
            MIDI_STATUS_PROGRAM_CHANGE => {
                self.program_change(channel, data1);
            }
            MIDI_STATUS_CHANNEL_AFTERTOUCH => {
                // Channel aftertouch — simplified, ignore
            }
            MIDI_STATUS_PITCH_BEND => {
                let value = (data1 as i16) | ((data2 as i16) << 7);
                self.pitch_bend(channel, value - 8192);
            }
            _ => {}
        }
    }

    /// Process a MIDI long message (system exclusive).
    pub fn process_long_msg(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match data[0] {
            0xF0 => {
                // System Exclusive — ignore for now
            }
            0xF1 => {
                // MIDI Time Code Quarter Frame
            }
            0xF2 => {
                // Song Position Pointer
            }
            0xF3 => {
                // Song Select
            }
            0xF6 => {
                // Tune Request
            }
            0xF8 => {
                // Timing Clock
            }
            0xFA => {
                // Start
            }
            0xFB => {
                // Continue
            }
            0xFC => {
                // Stop
            }
            0xFE => {
                // Active Sensing
            }
            0xFF => {
                // System Reset
            }
            _ => {}
        }
    }

    /// Note On event.
    pub fn note_on(&mut self, channel: u8, note: u8, velocity: u8) {
        let ch = &mut self.channels[channel as usize];
        let frequency = midi_note_to_frequency(note, ch.pitch_bend);
        let amplitude = (velocity as f64 / 127.0) * (ch.volume as f64 / 127.0) * self.master_volume;
        let instrument = ch.instrument;

        ch.active_notes.push(ActiveNote {
            channel,
            note,
            velocity,
            sample_index: 0,
            frequency,
            amplitude,
            instrument,
            sustained: false,
        });
    }

    /// Note Off event.
    pub fn note_off(&mut self, channel: u8, note: u8) {
        let ch = &mut self.channels[channel as usize];
        if ch.sustain {
            // Note is sustained — mark it but keep playing
            // When sustain pedal is released, sustained notes will be removed
            if let Some(n) = ch.active_notes.iter_mut().find(|n| n.note == note) {
                n.sustained = true;
            }
            return;
        }
        ch.active_notes.retain(|n| n.note != note);
    }

    /// Control Change event.
    pub fn control_change(&mut self, channel: u8, controller: u8, value: u8) {
        let ch = &mut self.channels[channel as usize];
        match controller {
            MIDI_CTL_VOLUME => {
                ch.volume = value;
                // Update amplitudes of active notes
                for note in &mut ch.active_notes {
                    note.amplitude = (note.velocity as f64 / 127.0)
                        * (value as f64 / 127.0)
                        * self.master_volume;
                }
            }
            MIDI_CTL_PAN => {
                ch.pan = value;
            }
            MIDI_CTL_SUSTAIN => {
                ch.sustain = value >= 64;
                if !ch.sustain {
                    // Release sustained notes (those that got note_off while sustain was held)
                    ch.active_notes.retain(|n| !n.sustained);
                }
            }
            MIDI_CTL_ALL_NOTES_OFF | MIDI_CTL_ALL_SOUND_OFF => {
                ch.active_notes.clear();
            }
            _ => {}
        }
    }

    /// Program Change event.
    pub fn program_change(&mut self, channel: u8, program: u8) {
        if program < 128 {
            self.channels[channel as usize].instrument = program;
        }
    }

    /// Pitch Bend event.
    pub fn pitch_bend(&mut self, channel: u8, value: i16) {
        let ch = &mut self.channels[channel as usize];
        ch.pitch_bend = value;
        // Update frequencies of active notes on this channel
        for note in &mut ch.active_notes {
            if note.channel == channel {
                note.frequency = midi_note_to_frequency(note.note, value);
            }
        }
    }

    /// Generate audio samples (interleaved stereo float32).
    /// Returns `(left_samples, right_samples)`.
    pub fn generate_samples(&mut self, num_samples: usize) -> (Vec<f32>, Vec<f32>) {
        let mut left = vec![0.0f32; num_samples];
        let mut right = vec![0.0f32; num_samples];

        for ch_idx in 0..16 {
            let ch = &self.channels[ch_idx];
            if ch.active_notes.is_empty() {
                continue;
            }

            // Constant-power pan: 0=left, 64=center, 127=right
            let pan_angle = ch.pan as f64 / 127.0 * std::f64::consts::FRAC_PI_2;
            let pan_left = pan_angle.cos();
            let pan_right = pan_angle.sin();

            for note in &ch.active_notes {
                let waveform = &self.instrument_waveforms[note.instrument as usize];
                for i in 0..num_samples {
                    let t = (note.sample_index + i as u64) as f64 / self.sample_rate as f64;
                    let phase = 2.0 * std::f64::consts::PI * note.frequency * t;

                    // Generate sample using harmonic synthesis
                    let mut sample = 0.0;
                    for (harm_idx, &harm_amp) in waveform.iter().enumerate() {
                        let harm = (harm_idx + 1) as f64;
                        sample += (phase * harm).sin() * harm_amp;
                    }

                    // Normalize
                    sample *= note.amplitude * 0.3;

                    // Apply envelope (simple adsr-like decay)
                    let note_age = (note.sample_index + i as u64) as f64 / self.sample_rate as f64;
                    let envelope = if note_age < 0.01 {
                        note_age / 0.01 // Attack: 10ms
                    } else {
                        (-note_age * 0.5).exp() // Exponential decay
                    };

                    sample *= envelope;

                    left[i] += (sample * pan_left) as f32;
                    right[i] += (sample * pan_right) as f32;
                }
            }
        }

        // Advance sample indices
        for ch_idx in 0..16 {
            for note in &mut self.channels[ch_idx].active_notes {
                note.sample_index += num_samples as u64;
            }
        }

        (left, right)
    }

    /// Reset all channels (all notes off, reset controllers).
    pub fn reset(&mut self) {
        for ch in &mut self.channels {
            ch.active_notes.clear();
            ch.volume = 100;
            ch.pan = 64;
            ch.pitch_bend = 0;
            ch.sustain = false;
        }
    }
}

/// Convert a MIDI note number to frequency in Hz.
fn midi_note_to_frequency(note: u8, pitch_bend: i16) -> f64 {
    let bend_semitones = pitch_bend as f64 / 8192.0 * 2.0; // +/- 2 semitones
    let adjusted_note = note as f64 + bend_semitones;
    440.0 * 2.0_f64.powf((adjusted_note - 69.0) / 12.0)
}

/// Build General MIDI instrument waveforms (harmonic amplitudes).
/// Each instrument is a vector of harmonic amplitudes for the first 8 harmonics.
fn build_instrument_waveforms() -> Vec<Vec<f64>> {
    let mut waveforms = Vec::with_capacity(128);

    // Piano (0-7)
    waveforms.push(vec![1.0, 0.5, 0.3, 0.1, 0.05, 0.02, 0.01, 0.005]); // 0: Acoustic Grand Piano
    waveforms.push(vec![1.0, 0.4, 0.2, 0.08, 0.04, 0.01, 0.008, 0.003]); // 1: Bright Acoustic Piano
    waveforms.push(vec![1.0, 0.5, 0.25, 0.12, 0.06, 0.03, 0.015, 0.008]); // 2: Electric Grand Piano
    waveforms.push(vec![1.0, 0.6, 0.2, 0.1, 0.05, 0.02, 0.01, 0.005]); // 3: Honky-tonk Piano
    waveforms.push(vec![1.0, 0.3, 0.15, 0.05, 0.02, 0.01, 0.005, 0.002]); // 4: Rhodes Piano
    waveforms.push(vec![1.0, 0.2, 0.1, 0.03, 0.01, 0.005, 0.002, 0.001]); // 5: Chorused Piano
    waveforms.push(vec![1.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]); // 6: Harpsichord
    waveforms.push(vec![1.0, 0.7, 0.4, 0.2, 0.1, 0.05, 0.02, 0.01]); // 7: Clavinet

    // Chromatic Percussion (8-15)
    for _ in 8..16 {
        waveforms.push(vec![1.0, 0.3, 0.1, 0.05, 0.02, 0.01, 0.005, 0.002]);
    }

    // Organ (16-23)
    for _ in 16..24 {
        waveforms.push(vec![1.0, 0.5, 0.5, 0.3, 0.3, 0.1, 0.1, 0.05]);
    }

    // Guitar (24-31)
    for _ in 24..32 {
        waveforms.push(vec![1.0, 0.4, 0.2, 0.15, 0.1, 0.05, 0.03, 0.02]);
    }

    // Bass (32-39)
    for _ in 32..40 {
        waveforms.push(vec![1.0, 0.3, 0.1, 0.05, 0.02, 0.01, 0.005, 0.002]);
    }

    // Strings (40-47)
    for _ in 40..48 {
        waveforms.push(vec![1.0, 0.2, 0.1, 0.05, 0.03, 0.02, 0.01, 0.005]);
    }

    // Ensemble (48-55)
    for _ in 48..56 {
        waveforms.push(vec![1.0, 0.3, 0.15, 0.08, 0.04, 0.02, 0.01, 0.005]);
    }

    // Brass (56-63)
    for _ in 56..64 {
        waveforms.push(vec![1.0, 0.6, 0.3, 0.2, 0.15, 0.1, 0.08, 0.05]);
    }

    // Reed (64-71)
    for _ in 64..72 {
        waveforms.push(vec![1.0, 0.5, 0.4, 0.3, 0.2, 0.1, 0.05, 0.03]);
    }

    // Pipe (72-79)
    for _ in 72..80 {
        waveforms.push(vec![1.0, 0.4, 0.2, 0.1, 0.05, 0.03, 0.02, 0.01]);
    }

    // Synth Lead (80-87)
    for _ in 80..88 {
        waveforms.push(vec![1.0, 0.6, 0.4, 0.3, 0.2, 0.1, 0.05, 0.03]);
    }

    // Synth Pad (88-95)
    for _ in 88..96 {
        waveforms.push(vec![1.0, 0.3, 0.2, 0.1, 0.05, 0.03, 0.02, 0.01]);
    }

    // Synth Effects (96-103)
    for _ in 96..104 {
        waveforms.push(vec![1.0, 0.5, 0.3, 0.2, 0.1, 0.05, 0.03, 0.02]);
    }

    // Ethnic (104-111)
    for _ in 104..112 {
        waveforms.push(vec![1.0, 0.4, 0.2, 0.15, 0.1, 0.05, 0.03, 0.02]);
    }

    // Percussive (112-119)
    for _ in 112..120 {
        waveforms.push(vec![1.0, 0.8, 0.6, 0.4, 0.2, 0.1, 0.05, 0.02]);
    }

    // Sound Effects (120-127)
    for _ in 120..128 {
        waveforms.push(vec![1.0, 0.3, 0.1, 0.05, 0.02, 0.01, 0.005, 0.002]);
    }

    waveforms
}

/// MIDI output device handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MidiHandle(u32);

static NEXT_MIDI_HANDLE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// Get a new unique MIDI handle.
pub fn new_midi_handle() -> MidiHandle {
    MidiHandle(NEXT_MIDI_HANDLE.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
}

// Global MIDI synthesizer instance (thread-safe).
lazy_static::lazy_static! {
    static ref MIDI_SYNTH: Mutex<MidiSynthesizer> = Mutex::new(MidiSynthesizer::new(44100));
}

/// midiOutOpen implementation.
pub fn midi_out_open() -> AppResult<MidiHandle> {
    let handle = new_midi_handle();
    Ok(handle)
}

/// midiOutClose implementation.
pub fn midi_out_close(_handle: MidiHandle) -> AppResult<()> {
    Ok(())
}

/// midiOutShortMsg implementation.
///
/// Sends the message to both the internal synthesizer and the real
/// CoreMIDI device (if available).
pub fn midi_out_short_msg(_handle: MidiHandle, msg: u32) -> AppResult<()> {
    let mut synth = MIDI_SYNTH.lock().map_err(|e| {
        AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!("MIDI synth lock: {}", e),
        )
    })?;
    synth.process_short_msg(msg);
    // Also send to real CoreMIDI device
    send_to_core_midi(msg);
    Ok(())
}

/// midiOutLongMsg implementation (system exclusive).
///
/// Sends the message to both the internal synthesizer and the real
/// CoreMIDI device (if available).
pub fn midi_out_long_msg(_handle: MidiHandle, data: &[u8]) -> AppResult<()> {
    let mut synth = MIDI_SYNTH.lock().map_err(|e| {
        AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!("MIDI synth lock: {}", e),
        )
    })?;
    synth.process_long_msg(data);
    // Also send to real CoreMIDI device
    send_sysex_to_core_midi(data);
    Ok(())
}

/// midiOutReset implementation.
///
/// Sends "All Notes Off" on all 16 channels and resets controllers.
pub fn midi_out_reset(_handle: MidiHandle) -> AppResult<()> {
    let mut synth = MIDI_SYNTH.lock().map_err(|e| {
        AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!("MIDI synth lock: {}", e),
        )
    })?;
    synth.reset();
    // Also send All Notes Off to real CoreMIDI device
    for channel in 0u8..16 {
        let msg =
            (0xB0 | (channel & 0x0F)) as u32 | ((MIDI_CTL_ALL_NOTES_OFF as u32) << 8) | (0 << 16);
        send_to_core_midi(msg);
        let msg2 =
            (0xB0 | (channel & 0x0F)) as u32 | ((MIDI_CTL_ALL_SOUND_OFF as u32) << 8) | (0 << 16);
        send_to_core_midi(msg2);
    }
    Ok(())
}

/// Global MIDI output volume (packed as low word = left, high word = right).
static MIDI_OUT_VOLUME: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0xFFFF_FFFF);

/// midiOutGetVolume implementation.
///
/// Returns the volume as `(left << 0) | (right << 16)`.
pub fn midi_out_get_volume() -> u32 {
    MIDI_OUT_VOLUME.load(std::sync::atomic::Ordering::SeqCst)
}

/// midiOutSetVolume implementation.
///
/// Sets the volume from packed `(left << 0) | (right << 16)`.
pub fn midi_out_set_volume(volume: u32) {
    MIDI_OUT_VOLUME.store(volume, std::sync::atomic::Ordering::SeqCst);
    // Update the synthesizer master volume from the average of L/R
    let left = (volume & 0xFFFF) as f32 / 0xFFFF as f32;
    let right = ((volume >> 16) & 0xFFFF) as f32 / 0xFFFF as f32;
    let avg = (left + right) * 0.5;
    if let Ok(mut synth) = MIDI_SYNTH.lock() {
        synth.master_volume = avg as f64;
    }
}

/// Get the current MIDI audio samples for mixing.
pub fn get_midi_samples(num_samples: usize) -> (Vec<f32>, Vec<f32>) {
    MIDI_SYNTH
        .lock()
        .map(|mut synth| synth.generate_samples(num_samples))
        .unwrap_or_else(|_| (vec![0.0; num_samples], vec![0.0; num_samples]))
}

/// Convert frequency to MIDI note number (for test verification).
pub fn frequency_to_midi_note(freq: f64) -> f64 {
    69.0 + 12.0 * (freq / 440.0).log2()
}

// ---------------------------------------------------------------------------
// CoreMIDI output — send MIDI messages to real MIDI devices on macOS
// ---------------------------------------------------------------------------

/// CoreMIDI FFI bindings for macOS.
///
/// These bindings allow sending MIDI messages to real MIDI endpoints
/// (hardware synthesizers, virtual MIDI ports, etc.) via the macOS
/// CoreMIDI framework.
#[cfg(target_os = "macos")]
mod core_midi {
    use std::ptr;

    /// Opaque CoreMIDI client handle.
    pub type MIDIClientRef = u64;
    /// Opaque CoreMIDI port handle.
    pub type MIDIPortRef = u64;
    /// Opaque CoreMIDI endpoint handle.
    pub type MIDIEndpointRef = u64;
    /// Opaque CoreFoundation string handle.
    pub type CFStringRef = *const std::ffi::c_void;
    /// Opaque CoreFoundation run loop handle.
    pub type CFRunLoopRef = *mut std::ffi::c_void;

    /// MIDI packet structure.
    #[repr(C)]
    pub struct MIDIPacket {
        pub timestamp: u64,
        pub length: u16,
        pub data: [u8; 256],
    }

    /// MIDI packet list structure.
    #[repr(C)]
    pub struct MIDIPacketList {
        pub num_packets: u32,
        pub packet: [MIDIPacket; 1],
    }

    /// MIDI notification structure (simplified).
    #[repr(C)]
    pub struct MIDINotifyStruct {
        pub message_id: u32,
        pub client: MIDIClientRef,
    }

    pub type MIDINotifyProc =
        Option<unsafe extern "C" fn(*const MIDINotifyStruct, *mut std::ffi::c_void)>;
    pub type MIDIReadProc = Option<
        unsafe extern "C" fn(*const MIDIPacketList, *mut std::ffi::c_void, *mut std::ffi::c_void),
    >;

    #[link(name = "CoreMIDI", kind = "framework")]
    unsafe extern "C" {
        pub fn MIDIClientCreate(
            name: CFStringRef,
            notify_proc: MIDINotifyProc,
            notify_ref_con: *mut std::ffi::c_void,
            out_client: *mut MIDIClientRef,
        ) -> i32;

        pub fn MIDIOutputPortCreate(
            client: MIDIClientRef,
            port_name: CFStringRef,
            out_port: *mut MIDIPortRef,
        ) -> i32;

        pub fn MIDISend(
            port: MIDIPortRef,
            dest: MIDIEndpointRef,
            pktlist: *const MIDIPacketList,
        ) -> i32;

        pub fn MIDIGetNumberOfDestinations() -> u32;

        pub fn MIDIGetDestination(index: u32) -> MIDIEndpointRef;

        pub fn MIDIObjectGetStringProperty(
            obj: u64,
            property_id: i32,
            str_out: *mut CFStringRef,
        ) -> i32;
    }

    /// CoreMIDI property IDs.
    pub const K_MIDI_PROPERTY_DISPLAY_NAME: i32 = 164_416_2816; // 'name'

    /// Create a CFString from a Rust string.
    pub fn cf_string_from_str(s: &str) -> CFStringRef {
        use std::ffi::c_void;
        unsafe {
            // Use the CoreFoundation CFStringCreateWithCString function
            #[link(name = "CoreFoundation", kind = "framework")]
            unsafe extern "C" {
                fn CFStringCreateWithCString(
                    allocator: *const c_void,
                    c_str: *const i8,
                    encoding: u32,
                ) -> CFStringRef;
            }
            CFStringCreateWithCString(ptr::null(), s.as_ptr() as *const i8, 0x08000100) // kCFStringEncodingUTF8
        }
    }
}

/// CoreMIDI output device manager.
///
/// Manages a CoreMIDI client and output port for sending MIDI messages
/// to real MIDI devices on macOS. Falls back to software synthesis when
/// no MIDI destinations are available.
#[cfg(target_os = "macos")]
pub struct CoreMidiOutput {
    client: core_midi::MIDIClientRef,
    port: core_midi::MIDIPortRef,
    destination: Option<core_midi::MIDIEndpointRef>,
    destination_name: String,
}

#[cfg(target_os = "macos")]
impl CoreMidiOutput {
    /// Create a new CoreMIDI output, connecting to the first available
    /// MIDI destination.
    pub fn new() -> Result<Self, String> {
        unsafe {
            let mut client: core_midi::MIDIClientRef = 0;
            let client_name = core_midi::cf_string_from_str("Casa1 MIDI Client");

            let status = core_midi::MIDIClientCreate(
                client_name,
                None, // No notification callback
                std::ptr::null_mut(),
                &mut client,
            );

            if status != 0 {
                return Err(format!("MIDIClientCreate failed with status {status}"));
            }

            let mut port: core_midi::MIDIPortRef = 0;
            let port_name = core_midi::cf_string_from_str("Casa1 MIDI Output");

            let status = core_midi::MIDIOutputPortCreate(client, port_name, &mut port);

            if status != 0 {
                return Err(format!("MIDIOutputPortCreate failed with status {status}"));
            }

            // Try to find the first available MIDI destination
            let num_destinations = core_midi::MIDIGetNumberOfDestinations();
            let (destination, destination_name) = if num_destinations > 0 {
                let dest = core_midi::MIDIGetDestination(0);
                let name = Self::get_endpoint_name(dest);
                (Some(dest), name)
            } else {
                (None, "No MIDI destination".to_string())
            };

            Ok(Self {
                client,
                port,
                destination,
                destination_name,
            })
        }
    }

    /// Get the display name of a MIDI endpoint.
    fn get_endpoint_name(endpoint: core_midi::MIDIEndpointRef) -> String {
        unsafe {
            let mut name_ref: core_midi::CFStringRef = std::ptr::null();
            let status = core_midi::MIDIObjectGetStringProperty(
                endpoint,
                core_midi::K_MIDI_PROPERTY_DISPLAY_NAME,
                &mut name_ref,
            );
            if status != 0 || name_ref.is_null() {
                return format!("MIDI Endpoint {endpoint}");
            }

            // Read the CFString as a C string
            #[link(name = "CoreFoundation", kind = "framework")]
            unsafe extern "C" {
                fn CFStringGetLength(the_string: core_midi::CFStringRef) -> isize;
                fn CFStringGetCStringPtr(
                    the_string: core_midi::CFStringRef,
                    encoding: u32,
                ) -> *const i8;
            }

            let c_ptr = CFStringGetCStringPtr(name_ref, 0x08000100); // kCFStringEncodingUTF8
            if c_ptr.is_null() {
                return format!("MIDI Endpoint {endpoint}");
            }
            std::ffi::CStr::from_ptr(c_ptr)
                .to_string_lossy()
                .into_owned()
        }
    }

    /// Send a MIDI short message (3 bytes) to the connected destination.
    pub fn send_short_msg(&self, msg: u32) -> Result<(), String> {
        let dest = self.destination.ok_or("No MIDI destination available")?;

        let status = (msg & 0xFF) as u8;
        let data1 = ((msg >> 8) & 0xFF) as u8;
        let data2 = ((msg >> 16) & 0xFF) as u8;

        // Determine message length based on status byte
        let length = match status & 0xF0 {
            0xC0..=0xDF => 2,               // Program Change, Channel Aftertouch
            0x80..=0xBF | 0xE0..=0xEF => 3, // Note On/Off, Poly Aftertouch, Control Change, Pitch Bend
            0xF0 => match status {
                0xF1 | 0xF3 => 2, // MTC Quarter Frame, Song Select
                0xF2 => 3,        // Song Position Pointer
                _ => 1,           // System Real-Time (single byte)
            },
            _ => 3,
        };

        let mut packet_list: core_midi::MIDIPacketList = unsafe { std::mem::zeroed() };
        packet_list.num_packets = 1;
        packet_list.packet[0].timestamp = 0; // Send immediately
        packet_list.packet[0].length = length as u16;
        packet_list.packet[0].data[0] = status;
        if length >= 2 {
            packet_list.packet[0].data[1] = data1;
        }
        if length >= 3 {
            packet_list.packet[0].data[2] = data2;
        }

        unsafe {
            let result = core_midi::MIDISend(self.port, dest, &packet_list);
            if result != 0 {
                return Err(format!("MIDISend failed with status {result}"));
            }
        }
        Ok(())
    }

    /// Send a MIDI long message (system exclusive) to the connected destination.
    pub fn send_long_msg(&self, data: &[u8]) -> Result<(), String> {
        let dest = self.destination.ok_or("No MIDI destination available")?;

        if data.is_empty() {
            return Ok(());
        }

        let mut packet_list: core_midi::MIDIPacketList = unsafe { std::mem::zeroed() };
        packet_list.num_packets = 1;
        packet_list.packet[0].timestamp = 0;
        packet_list.packet[0].length = data.len().min(256) as u16;
        packet_list.packet[0].data[..data.len().min(256)]
            .copy_from_slice(&data[..data.len().min(256)]);

        unsafe {
            let result = core_midi::MIDISend(self.port, dest, &packet_list);
            if result != 0 {
                return Err(format!("MIDISend (long) failed with status {result}"));
            }
        }
        Ok(())
    }

    /// Get the name of the connected destination.
    pub fn destination_name(&self) -> &str {
        &self.destination_name
    }

    /// Check if a MIDI destination is available.
    pub fn has_destination(&self) -> bool {
        self.destination.is_some()
    }

    /// Refresh the destination list, connecting to the first available.
    pub fn refresh_destinations(&mut self) {
        unsafe {
            let num_destinations = core_midi::MIDIGetNumberOfDestinations();
            if num_destinations > 0 {
                let dest = core_midi::MIDIGetDestination(0);
                self.destination_name = Self::get_endpoint_name(dest);
                self.destination = Some(dest);
            } else {
                self.destination = None;
                self.destination_name = "No MIDI destination".to_string();
            }
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for CoreMidiOutput {
    fn drop(&mut self) {
        // CoreMIDI handles cleanup when the client is released.
        // We don't need explicit cleanup as the handles are just u64 IDs.
    }
}

// ---------------------------------------------------------------------------
// CoreMIDI input — receive MIDI messages from real MIDI devices on macOS
// ---------------------------------------------------------------------------

/// Additional CoreMIDI FFI bindings for input.
#[cfg(target_os = "macos")]
mod core_midi_input {
    use super::core_midi::*;

    #[link(name = "CoreMIDI", kind = "framework")]
    unsafe extern "C" {
        pub fn MIDIInputPortCreate(
            client: MIDIClientRef,
            port_name: CFStringRef,
            read_proc: MIDIReadProc,
            ref_con: *mut std::ffi::c_void,
            out_port: *mut MIDIPortRef,
        ) -> i32;

        pub fn MIDIPortConnectSource(
            port: MIDIPortRef,
            source: MIDIEndpointRef,
            conn_ref_con: *mut std::ffi::c_void,
        ) -> i32;

        pub fn MIDIPortDisconnectSource(port: MIDIPortRef, source: MIDIEndpointRef) -> i32;

        pub fn MIDIGetNumberOfDevices() -> u32;

        pub fn MIDIGetDevice(index: u32) -> u64;

        pub fn MIDIEntityGetNumberOfSources(entity: u64) -> u32;

        pub fn MIDIDeviceGetNumberOfEntities(device: u64) -> u32;

        pub fn MIDIDeviceGetEntity(device: u64, index: u32) -> u64;

        pub fn MIDIEntityGetSource(entity: u64, source_index: u32) -> MIDIEndpointRef;

        pub fn MIDIGetNumberOfSources() -> u32;

        pub fn MIDIGetSource(index: u32) -> MIDIEndpointRef;
    }
}

/// A received MIDI message from a CoreMIDI input device.
#[derive(Debug, Clone)]
pub struct ReceivedMidiMessage {
    /// The raw MIDI message bytes.
    pub data: Vec<u8>,
    /// Timestamp in host time units.
    pub timestamp: u64,
}

/// CoreMIDI input device manager.
///
/// Manages a CoreMIDI client and input port for receiving MIDI messages
/// from real MIDI devices on macOS.
#[cfg(target_os = "macos")]
pub struct CoreMidiInput {
    client: core_midi::MIDIClientRef,
    port: core_midi::MIDIPortRef,
    /// Connected source endpoints.
    sources: Vec<core_midi::MIDIEndpointRef>,
}

#[cfg(target_os = "macos")]
impl CoreMidiInput {
    /// Create a new CoreMIDI input, connecting to all available MIDI sources.
    pub fn new() -> Result<Self, String> {
        unsafe {
            let mut client: core_midi::MIDIClientRef = 0;
            let client_name = core_midi::cf_string_from_str("Casa1 MIDI Input");

            let status =
                core_midi::MIDIClientCreate(client_name, None, std::ptr::null_mut(), &mut client);

            if status != 0 {
                return Err(format!("MIDIClientCreate failed with status {status}"));
            }

            let mut port: core_midi::MIDIPortRef = 0;
            let port_name = core_midi::cf_string_from_str("Casa1 MIDI Input Port");

            // The read proc callback stores received messages in the global buffer
            let read_proc: core_midi::MIDIReadProc = Some(midi_input_read_proc);

            let status = core_midi_input::MIDIInputPortCreate(
                client,
                port_name,
                read_proc,
                std::ptr::null_mut(),
                &mut port,
            );

            if status != 0 {
                return Err(format!("MIDIInputPortCreate failed with status {status}"));
            }

            // Connect to all available MIDI sources
            let num_sources = core_midi_input::MIDIGetNumberOfSources();
            let mut sources = Vec::new();
            for i in 0..num_sources {
                let source = core_midi_input::MIDIGetSource(i);
                let conn_status =
                    core_midi_input::MIDIPortConnectSource(port, source, std::ptr::null_mut());
                if conn_status == 0 {
                    sources.push(source);
                }
            }

            Ok(Self {
                client,
                port,
                sources,
            })
        }
    }

    /// Get all received MIDI messages since the last call, clearing the buffer.
    pub fn drain_received(&self) -> Vec<ReceivedMidiMessage> {
        if let Ok(mut buf) = MIDI_INPUT_BUFFER.lock() {
            std::mem::take(&mut *buf)
        } else {
            Vec::new()
        }
    }

    /// Get the number of connected MIDI sources.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Refresh the source list, connecting to any new MIDI sources.
    pub fn refresh_sources(&mut self) {
        unsafe {
            let num_sources = core_midi_input::MIDIGetNumberOfSources();
            for i in 0..num_sources {
                let source = core_midi_input::MIDIGetSource(i);
                if !self.sources.contains(&source) {
                    let status = core_midi_input::MIDIPortConnectSource(
                        self.port,
                        source,
                        std::ptr::null_mut(),
                    );
                    if status == 0 {
                        self.sources.push(source);
                    }
                }
            }
        }
    }
}

// Global buffer for received MIDI messages from CoreMIDI input.
#[cfg(target_os = "macos")]
lazy_static::lazy_static! {
    static ref MIDI_INPUT_BUFFER: Mutex<Vec<ReceivedMidiMessage>> = Mutex::new(Vec::new());
}

/// CoreMIDI input read callback.
///
/// Parses `MIDIPacketList` and stores received messages in the global buffer.
#[cfg(target_os = "macos")]
unsafe extern "C" fn midi_input_read_proc(
    pktlist: *const core_midi::MIDIPacketList,
    _ref_con: *mut std::ffi::c_void,
    _conn_ref_con: *mut std::ffi::c_void,
) {
    unsafe {
        if pktlist.is_null() {
            return;
        }

        let num_packets = (*pktlist).num_packets;
        let mut messages = Vec::with_capacity(num_packets as usize);

        let packet = &(*pktlist).packet[0];
        let mut packet_ptr = packet as *const core_midi::MIDIPacket;
        for _ in 0..num_packets {
            if packet_ptr.is_null() {
                break;
            }
            let pkt = &*packet_ptr;
            let len = pkt.length as usize;
            if len > 0 && len <= 256 {
                let data = pkt.data[..len].to_vec();
                messages.push(ReceivedMidiMessage {
                    data,
                    timestamp: pkt.timestamp,
                });
            }
            // Advance to next packet
            packet_ptr = ((packet_ptr as *const u8)
                .wrapping_add(std::mem::size_of::<u64>() + std::mem::size_of::<u16>())
                .wrapping_add((pkt.length as usize + 3) & !3))
                as *const core_midi::MIDIPacket;
        }

        // Store messages in the global buffer
        if let Ok(mut guard) = MIDI_INPUT_BUFFER.lock() {
            guard.extend(messages);
            // Keep buffer bounded
            if guard.len() > 10000 {
                guard.drain(0..5000);
            }
        }
    }
}

// Global CoreMIDI input instance (lazily initialized).
#[cfg(target_os = "macos")]
lazy_static::lazy_static! {
    static ref CORE_MIDI_INPUT: std::sync::Mutex<Option<CoreMidiInput>> = {
        std::sync::Mutex::new(CoreMidiInput::new().ok())
    };
}

/// Drain all received MIDI messages from the CoreMIDI input.
#[cfg(target_os = "macos")]
pub fn drain_core_midi_input() -> Vec<ReceivedMidiMessage> {
    CORE_MIDI_INPUT
        .lock()
        .ok()
        .and_then(|mut guard| guard.as_mut().map(|input| input.drain_received()))
        .unwrap_or_default()
}

/// Drain all received MIDI messages from the CoreMIDI input (non-macOS stub).
#[cfg(not(target_os = "macos"))]
pub fn drain_core_midi_input() -> Vec<ReceivedMidiMessage> {
    Vec::new()
}

/// Get the number of connected CoreMIDI input sources.
#[cfg(target_os = "macos")]
pub fn core_midi_input_source_count() -> usize {
    CORE_MIDI_INPUT
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|input| input.source_count()))
        .unwrap_or(0)
}

/// Get the number of connected CoreMIDI input sources (non-macOS stub).
#[cfg(not(target_os = "macos"))]
pub fn core_midi_input_source_count() -> usize {
    0
}

/// Enumerate all available MIDI input sources.
///
/// Returns a list of (device_index, source_name) pairs.
#[cfg(target_os = "macos")]
pub fn enumerate_midi_input_sources() -> Vec<(u32, String)> {
    let mut sources = Vec::new();
    unsafe {
        let num_sources = core_midi_input::MIDIGetNumberOfSources();
        for i in 0..num_sources {
            let source = core_midi_input::MIDIGetSource(i);
            let name = CoreMidiOutput::get_endpoint_name(source);
            sources.push((i, name));
        }
    }
    sources
}

/// Enumerate all available MIDI input sources (non-macOS stub).
#[cfg(not(target_os = "macos"))]
pub fn enumerate_midi_input_sources() -> Vec<(u32, String)> {
    Vec::new()
}

/// Enumerate all available MIDI output destinations.
#[cfg(target_os = "macos")]
pub fn enumerate_midi_output_destinations() -> Vec<(u32, String)> {
    let mut dests = Vec::new();
    unsafe {
        let num_dests = core_midi::MIDIGetNumberOfDestinations();
        for i in 0..num_dests {
            let dest = core_midi::MIDIGetDestination(i);
            let name = CoreMidiOutput::get_endpoint_name(dest);
            dests.push((i, name));
        }
    }
    dests
}

/// Enumerate all available MIDI output destinations (non-macOS stub).
#[cfg(not(target_os = "macos"))]
pub fn enumerate_midi_output_destinations() -> Vec<(u32, String)> {
    Vec::new()
}

/// MIDI streaming support for `midiStreamOpen` / `midiStreamOut`.
/// MIDI stream property tags (for `midiStreamProperty`).
pub const MIDIPROP_GET: u32 = 0x40000000;
pub const MIDIPROP_SET: u32 = 0x80000000;
pub const MIDIPROP_TIMEDIV: u32 = 0x00000001;
pub const MIDIPROP_TEMPO: u32 = 0x00000002;

/// MIDI stream position information.
#[derive(Debug, Clone)]
pub struct MidiStreamPosition {
    /// Current position in ticks.
    pub ticks: u32,
    /// Current position in milliseconds.
    pub ms: u32,
    /// Current song pointer position.
    pub song_ptr: u32,
}

/// MIDI stream properties.
#[derive(Debug, Clone)]
pub struct MidiStreamProperties {
    /// Time division (ticks per quarter note).
    pub time_division: u16,
    /// Tempo in microseconds per beat.
    pub tempo_us_per_beat: u32,
}

/// Manages a queue of MIDI events that are played back at specified timestamps.
pub struct MidiStreamPlayer {
    /// The MIDI synthesizer for audio generation.
    synth: MidiSynthesizer,
    /// Whether the stream is currently playing.
    playing: bool,
    /// Whether the stream is paused.
    paused: bool,
    /// The tempo in microseconds per beat (default 500000 = 120 BPM).
    tempo_us_per_beat: u32,
    /// The time division (ticks per quarter note, default 480).
    time_division: u16,
    /// Queued MIDI events with their absolute tick positions.
    event_queue: Vec<(u32, u32)>, // (absolute_tick, midi_msg)
    /// Current tick position.
    current_tick: u32,
    /// Total number of samples generated.
    total_samples: u64,
}

impl MidiStreamPlayer {
    /// Create a new MIDI stream player.
    pub fn new(sample_rate: u32) -> Self {
        Self {
            synth: MidiSynthesizer::new(sample_rate),
            playing: false,
            paused: false,
            tempo_us_per_beat: 500000, // 120 BPM
            time_division: 480,
            event_queue: Vec::new(),
            current_tick: 0,
            total_samples: 0,
        }
    }

    /// Start playback (midiStreamRestart).
    pub fn start(&mut self) {
        self.playing = true;
        self.paused = false;
    }

    /// Stop playback (midiStreamStop).
    pub fn stop(&mut self) {
        self.playing = false;
        self.paused = false;
        self.synth.reset();
    }

    /// Pause playback (midiStreamPause).
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// Restart playback from the beginning (midiStreamRestart).
    pub fn restart(&mut self) {
        self.current_tick = 0;
        self.total_samples = 0;
        self.playing = true;
        self.paused = false;
    }

    /// Set the tempo.
    pub fn set_tempo(&mut self, tempo_us_per_beat: u32) {
        self.tempo_us_per_beat = tempo_us_per_beat.max(1);
    }

    /// Get the current tempo.
    pub fn tempo(&self) -> u32 {
        self.tempo_us_per_beat
    }

    /// Set the time division.
    pub fn set_time_division(&mut self, division: u16) {
        self.time_division = division.max(1);
    }

    /// Get the time division.
    pub fn time_division(&self) -> u16 {
        self.time_division
    }

    /// Queue a MIDI event with a delta time in ticks.
    ///
    /// The delta is relative to the previous event in the buffer (Windows MIDIHDR
    /// `dwOffset` style). We convert to absolute ticks internally.
    pub fn queue_event(&mut self, delta_ticks: u32, msg: u32) {
        let absolute_tick = self.current_tick + delta_ticks;
        self.event_queue.push((absolute_tick, msg));
    }

    /// Queue a MIDI event with an absolute tick position.
    pub fn queue_event_absolute(&mut self, tick: u32, msg: u32) {
        self.event_queue.push((tick, msg));
    }

    /// Get the current stream position (midiStreamPosition).
    pub fn position(&self) -> MidiStreamPosition {
        let ticks = self.current_tick;
        // Convert ticks to milliseconds:
        // ms = ticks * tempo_us_per_beat / (time_division * 1000)
        let ms = if self.time_division > 0 {
            (ticks as u64 * self.tempo_us_per_beat as u64 / (self.time_division as u64 * 1000))
                as u32
        } else {
            0
        };
        // Song pointer position (in 16th notes)
        let song_ptr = ticks / (self.time_division.max(1) as u32 / 4);
        MidiStreamPosition {
            ticks,
            ms,
            song_ptr,
        }
    }

    /// Get or set stream properties (midiStreamProperty).
    ///
    /// `property_id` is one of `MIDIPROP_TIMEDIV` or `MIDIPROP_TEMPO`.
    /// `flags` is a combination of `MIDIPROP_GET` / `MIDIPROP_SET`.
    /// Returns the current property value after applying any set operation.
    pub fn stream_property(&mut self, property_id: u32, flags: u32, value: u32) -> u32 {
        match property_id {
            MIDIPROP_TIMEDIV => {
                if flags & MIDIPROP_SET != 0 {
                    self.time_division = value.max(1) as u16;
                }
                self.time_division as u32
            }
            MIDIPROP_TEMPO => {
                if flags & MIDIPROP_SET != 0 {
                    self.tempo_us_per_beat = value.max(1);
                }
                self.tempo_us_per_beat
            }
            _ => 0,
        }
    }

    /// Process all due events and generate audio samples.
    ///
    /// Returns interleaved stereo f32 samples for the given duration.
    pub fn generate_samples(&mut self, num_samples: usize) -> (Vec<f32>, Vec<f32>) {
        if !self.playing || self.paused {
            return (vec![0.0; num_samples], vec![0.0; num_samples]);
        }

        // Process any due events
        let events_to_process: Vec<u32> = self
            .event_queue
            .iter()
            .filter(|(tick, _)| *tick <= self.current_tick)
            .map(|(_, msg)| *msg)
            .collect();

        // Remove processed events
        self.event_queue
            .retain(|(tick, _)| *tick > self.current_tick);

        // Process events through the synthesizer
        for msg in events_to_process {
            self.synth.process_short_msg(msg);
            // Also send to CoreMIDI
            send_to_core_midi(msg);
        }

        // Advance tick counter based on the number of samples and tempo
        // ticks_per_sample = time_division / (tempo_us_per_beat * sample_rate / 1000000)
        let ticks_per_sample = self.time_division as f64
            / (self.tempo_us_per_beat as f64 * self.synth.sample_rate as f64 / 1_000_000.0);
        self.current_tick += (num_samples as f64 * ticks_per_sample).round() as u32;
        self.total_samples += num_samples as u64;

        // Generate audio
        self.synth.generate_samples(num_samples)
    }

    /// Check if there are remaining events to process.
    pub fn has_events(&self) -> bool {
        !self.event_queue.is_empty()
    }

    /// Get the number of queued events.
    pub fn event_count(&self) -> usize {
        self.event_queue.len()
    }

    /// Clear all queued events.
    pub fn clear_events(&mut self) {
        self.event_queue.clear();
    }
}

// Global CoreMIDI output instance (lazily initialized).
#[cfg(target_os = "macos")]
lazy_static::lazy_static! {
    static ref CORE_MIDI_OUTPUT: std::sync::Mutex<Option<CoreMidiOutput>> = {
        std::sync::Mutex::new(CoreMidiOutput::new().ok())
    };
}

/// Send a MIDI short message to the real CoreMIDI device (if available).
///
/// This sends the message to the first available MIDI destination on macOS.
/// If no MIDI device is available, the message is only processed by the
/// internal synthesizer.
#[cfg(target_os = "macos")]
pub fn send_to_core_midi(msg: u32) -> bool {
    if let Ok(output) = CORE_MIDI_OUTPUT.lock() {
        if let Some(ref midi_out) = *output {
            return midi_out.send_short_msg(msg).is_ok();
        }
    }
    false
}

/// Send a MIDI short message to the real CoreMIDI device (stub for non-macOS).
#[cfg(not(target_os = "macos"))]
pub fn send_to_core_midi(_msg: u32) -> bool {
    false
}

/// Send a MIDI long message (SysEx) to the real CoreMIDI device (if available).
#[cfg(target_os = "macos")]
pub fn send_sysex_to_core_midi(data: &[u8]) -> bool {
    if let Ok(output) = CORE_MIDI_OUTPUT.lock() {
        if let Some(ref midi_out) = *output {
            return midi_out.send_long_msg(data).is_ok();
        }
    }
    false
}

/// Send a MIDI long message (SysEx) to the real CoreMIDI device (stub for non-macOS).
#[cfg(not(target_os = "macos"))]
pub fn send_sysex_to_core_midi(_data: &[u8]) -> bool {
    false
}

/// Get the name of the connected CoreMIDI destination.
#[cfg(target_os = "macos")]
pub fn core_midi_destination_name() -> Option<String> {
    CORE_MIDI_OUTPUT.lock().ok().and_then(|guard| {
        guard
            .as_ref()
            .map(|output| output.destination_name().to_string())
    })
}

/// Get the name of the connected CoreMIDI destination (stub for non-macOS).
#[cfg(not(target_os = "macos"))]
pub fn core_midi_destination_name() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_midi_note_to_frequency() {
        // A4 (MIDI 69) = 440 Hz
        let freq = midi_note_to_frequency(69, 0);
        assert!((freq - 440.0).abs() < 1.0);

        // C4 (MIDI 60) = 261.63 Hz
        let freq = midi_note_to_frequency(60, 0);
        assert!((freq - 261.63).abs() < 1.0);
    }

    #[test]
    fn test_note_on_off() {
        let mut synth = MidiSynthesizer::new(44100);
        synth.note_on(0, 60, 100);
        assert!(synth.channels[0].active_notes.len() == 1);
        synth.note_off(0, 60);
        assert!(synth.channels[0].active_notes.is_empty());
    }

    #[test]
    fn test_program_change() {
        let mut synth = MidiSynthesizer::new(44100);
        synth.program_change(0, 56); // Trumpet
        assert_eq!(synth.channels[0].instrument, 56);
    }

    #[test]
    fn test_control_change_volume() {
        let mut synth = MidiSynthesizer::new(44100);
        synth.control_change(0, MIDI_CTL_VOLUME, 127);
        assert_eq!(synth.channels[0].volume, 127);
    }

    #[test]
    fn test_generate_samples() {
        let mut synth = MidiSynthesizer::new(44100);
        synth.note_on(0, 60, 100);
        let (left, right) = synth.generate_samples(441);
        assert_eq!(left.len(), 441);
        assert_eq!(right.len(), 441);
        // Should have non-zero samples
        let max_sample = left
            .iter()
            .chain(right.iter())
            .map(|s| s.abs())
            .fold(0.0f32, f32::max);
        assert!(max_sample > 0.0);
    }

    #[test]
    fn test_short_msg_note_on() {
        let mut synth = MidiSynthesizer::new(44100);
        // Note On, channel 0, note 60, velocity 100
        let msg = 0x90u32 | (60u32 << 8) | (100u32 << 16);
        synth.process_short_msg(msg);
        assert_eq!(synth.channels[0].active_notes.len(), 1);
    }

    #[test]
    fn test_short_msg_note_off() {
        let mut synth = MidiSynthesizer::new(44100);
        let msg_on = 0x90u32 | (60u32 << 8) | (100u32 << 16);
        synth.process_short_msg(msg_on);
        let msg_off = 0x80u32 | (60u32 << 8) | (0u32 << 16);
        synth.process_short_msg(msg_off);
        assert!(synth.channels[0].active_notes.is_empty());
    }

    #[test]
    fn test_short_msg_program_change() {
        let mut synth = MidiSynthesizer::new(44100);
        let msg = 0xC0u32 | (56u32 << 8); // Program Change, channel 0, program 56
        synth.process_short_msg(msg);
        assert_eq!(synth.channels[0].instrument, 56);
    }

    #[test]
    fn test_reset() {
        let mut synth = MidiSynthesizer::new(44100);
        synth.note_on(0, 60, 100);
        synth.note_on(1, 64, 100);
        assert_eq!(synth.channels[0].active_notes.len(), 1);
        synth.reset();
        assert!(synth.channels[0].active_notes.is_empty());
        assert!(synth.channels[1].active_notes.is_empty());
    }

    #[test]
    fn test_pitch_bend() {
        let mut synth = MidiSynthesizer::new(44100);
        synth.note_on(0, 69, 100); // A4 = 440 Hz
        let freq_before = synth.channels[0].active_notes[0].frequency;
        synth.pitch_bend(0, 4096); // Bend up ~1 semitone
        let freq_after = synth.channels[0].active_notes[0].frequency;
        assert!(freq_after > freq_before); // Pitch should go up
    }

    #[test]
    fn test_sustain_pedal() {
        let mut synth = MidiSynthesizer::new(44100);
        synth.note_on(0, 60, 100);
        synth.control_change(0, MIDI_CTL_SUSTAIN, 127); // Press sustain
        synth.note_off(0, 60); // Release note
        // Note should still be active (sustained)
        assert_eq!(synth.channels[0].active_notes.len(), 1);
        synth.control_change(0, MIDI_CTL_SUSTAIN, 0); // Release sustain
        // Note should now be removed
        assert!(synth.channels[0].active_notes.is_empty());
    }

    #[test]
    fn test_all_notes_off() {
        let mut synth = MidiSynthesizer::new(44100);
        synth.note_on(0, 60, 100);
        synth.note_on(0, 64, 100);
        synth.note_on(0, 67, 100);
        assert_eq!(synth.channels[0].active_notes.len(), 3);
        synth.control_change(0, MIDI_CTL_ALL_NOTES_OFF, 0);
        assert!(synth.channels[0].active_notes.is_empty());
    }

    #[test]
    fn test_frequency_to_midi_note() {
        let note = frequency_to_midi_note(440.0);
        assert!((note - 69.0).abs() < 0.1);
    }

    // -----------------------------------------------------------------------
    // Malformed / edge-case MIDI message tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_long_msg_empty_sysex() {
        // SysEx with only the start byte F0 and no data — should not panic
        let mut synth = MidiSynthesizer::new(44100);
        synth.process_long_msg(&[0xF0]);
        // No crash is sufficient; state should be unchanged
        assert!(synth.channels[0].active_notes.is_empty());
    }

    #[test]
    fn test_process_long_msg_sysex_missing_eox() {
        // SysEx that starts with F0 but never sends F7 (missing End of Exclusive)
        let mut synth = MidiSynthesizer::new(44100);
        synth.process_long_msg(&[0xF0, 0x41, 0x10, 0x42, 0x12]);
        // Should not panic; the incomplete SysEx is simply ignored
        assert!(synth.channels[0].active_notes.is_empty());
    }

    #[test]
    fn test_process_long_msg_sysex_complete() {
        // Well-formed SysEx: F0 ... F7
        let mut synth = MidiSynthesizer::new(44100);
        synth.process_long_msg(&[0xF0, 0x41, 0x10, 0x42, 0x12, 0xF7]);
        // Should not panic
        assert!(synth.channels[0].active_notes.is_empty());
    }

    #[test]
    fn test_process_long_msg_very_long_sysex() {
        // SysEx with a large payload (e.g., 4096 bytes)
        let mut synth = MidiSynthesizer::new(44100);
        let mut data = vec![0xF0u8];
        data.extend(std::iter::repeat(0x41u8).take(4096));
        data.push(0xF7);
        synth.process_long_msg(&data);
        // Should not panic
    }

    #[test]
    fn test_process_long_msg_non_sysex_status() {
        // Long message starting with a non-SysEx status byte (e.g., 0x80)
        let mut synth = MidiSynthesizer::new(44100);
        synth.process_long_msg(&[0x80, 0x3C, 0x00]);
        // Should not panic; unknown long message types are ignored
    }

    #[test]
    fn test_process_short_msg_invalid_status_0xf0() {
        // Status byte 0xF0 (SysEx start) sent as a short message — should not panic
        let mut synth = MidiSynthesizer::new(44100);
        synth.process_short_msg(0xF0);
    }

    #[test]
    fn test_process_short_msg_invalid_status_0xff() {
        // Status byte 0xFF (Meta event / reset) sent as a short message
        let mut synth = MidiSynthesizer::new(44100);
        synth.process_short_msg(0xFF);
    }

    #[test]
    fn test_process_short_msg_running_status_note_on() {
        // Simulate running status: send a Note On, then re-send without status byte
        // In process_short_msg the status is always present (u32), so we test
        // that repeated same-status messages work correctly.
        let mut synth = MidiSynthesizer::new(44100);
        let msg_on = 0x90u32 | (60u32 << 8) | (100u32 << 16);
        synth.process_short_msg(msg_on);
        assert_eq!(synth.channels[0].active_notes.len(), 1);

        // Send another note on the same channel (running status simulation)
        let msg_on2 = 0x90u32 | (64u32 << 8) | (80u32 << 16);
        synth.process_short_msg(msg_on2);
        assert_eq!(synth.channels[0].active_notes.len(), 2);
    }

    #[test]
    fn test_process_short_msg_zero_velocity_note_on_is_note_off() {
        // MIDI convention: Note On with velocity 0 = Note Off
        let mut synth = MidiSynthesizer::new(44100);
        synth.note_on(0, 60, 100);
        assert_eq!(synth.channels[0].active_notes.len(), 1);

        // Note On with velocity 0 should act as Note Off
        let msg = 0x90u32 | (60u32 << 8) | (0u32 << 16);
        synth.process_short_msg(msg);
        assert!(
            synth.channels[0].active_notes.is_empty(),
            "Note On with velocity 0 should release the note"
        );
    }

    #[test]
    fn test_process_short_msg_channel_15() {
        // Ensure high channel numbers work (channel 15 = status byte 0x9F)
        let mut synth = MidiSynthesizer::new(44100);
        let msg = 0x9Fu32 | (60u32 << 8) | (100u32 << 16);
        synth.process_short_msg(msg);
        assert_eq!(synth.channels[15].active_notes.len(), 1);
    }

    #[test]
    fn test_process_long_msg_single_byte_f7() {
        // A lone F7 (End of Exclusive) with no preceding F0
        let mut synth = MidiSynthesizer::new(44100);
        synth.process_long_msg(&[0xF7]);
        // Should not panic
    }
}
