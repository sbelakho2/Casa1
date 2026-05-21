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
use std::collections::HashMap;
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
    pitch_bend: i16,     // -8192 to 8191
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
                    note.amplitude = (note.velocity as f64 / 127.0) * (value as f64 / 127.0) * self.master_volume;
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
    waveforms.push(vec![1.0, 0.5, 0.3, 0.1, 0.05, 0.02, 0.01, 0.005]);  // 0: Acoustic Grand Piano
    waveforms.push(vec![1.0, 0.4, 0.2, 0.08, 0.04, 0.01, 0.008, 0.003]); // 1: Bright Acoustic Piano
    waveforms.push(vec![1.0, 0.5, 0.25, 0.12, 0.06, 0.03, 0.015, 0.008]); // 2: Electric Grand Piano
    waveforms.push(vec![1.0, 0.6, 0.2, 0.1, 0.05, 0.02, 0.01, 0.005]);    // 3: Honky-tonk Piano
    waveforms.push(vec![1.0, 0.3, 0.15, 0.05, 0.02, 0.01, 0.005, 0.002]); // 4: Rhodes Piano
    waveforms.push(vec![1.0, 0.2, 0.1, 0.03, 0.01, 0.005, 0.002, 0.001]); // 5: Chorused Piano
    waveforms.push(vec![1.0, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);        // 6: Harpsichord
    waveforms.push(vec![1.0, 0.7, 0.4, 0.2, 0.1, 0.05, 0.02, 0.01]);      // 7: Clavinet

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

/// Global MIDI synthesizer instance (thread-safe).
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
pub fn midi_out_short_msg(_handle: MidiHandle, msg: u32) -> AppResult<()> {
    let mut synth = MIDI_SYNTH.lock().map_err(|e| {
        AppError::new(ReasonCode::RcAudioUnsupported, format!("MIDI synth lock: {}", e))
    })?;
    synth.process_short_msg(msg);
    Ok(())
}

/// midiOutLongMsg implementation (system exclusive).
pub fn midi_out_long_msg(_handle: MidiHandle, data: &[u8]) -> AppResult<()> {
    let mut synth = MIDI_SYNTH.lock().map_err(|e| {
        AppError::new(ReasonCode::RcAudioUnsupported, format!("MIDI synth lock: {}", e))
    })?;
    synth.process_long_msg(data);
    Ok(())
}

/// midiOutReset implementation.
pub fn midi_out_reset(_handle: MidiHandle) -> AppResult<()> {
    let mut synth = MIDI_SYNTH.lock().map_err(|e| {
        AppError::new(ReasonCode::RcAudioUnsupported, format!("MIDI synth lock: {}", e))
    })?;
    synth.reset();
    Ok(())
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
        let max_sample = left.iter().chain(right.iter()).map(|s| s.abs()).fold(0.0f32, f32::max);
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
}
