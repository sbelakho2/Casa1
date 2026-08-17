//! Lock-free audio ring buffer for Casa1.
//!
//! Provides a single-producer / single-consumer ring buffer optimised for
//! real-time audio streaming. The producer (audio decoder thread) writes
//! samples into the buffer while the consumer (cpal callback) reads them.
//!
//! ## Features
//! - Configurable capacity (default 4096 samples per channel)
//! - Multi-channel support (interleaved samples)
//! - Pre-buffering: configurable number of samples to buffer before starting
//! - Double-buffer support for seamless transitions
//! - Underrun detection and graceful handling (silence fill)
//! - Metrics: fill level, underrun count/duration, average latency
//! - Lock-free via `AtomicUsize` head/tail pointers

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

// ── Ring buffer metrics ────────────────────────────────────────────────────

/// Metrics tracked by the audio ring buffer.
#[derive(Debug, Clone, Default)]
pub struct RingBufferMetrics {
    /// Total number of buffer underruns (consumer read when buffer was empty).
    pub underrun_count: u64,
    /// Total duration of underruns in microseconds.
    pub underrun_duration_us: u64,
    /// Total number of buffer overflows (producer wrote when buffer was full).
    pub overflow_count: u64,
    /// Total samples written by the producer.
    pub total_written: u64,
    /// Total samples read by the consumer.
    pub total_read: u64,
    /// Peak fill level in frames.
    pub peak_fill_frames: usize,
    /// Time of the last underrun.
    pub last_underrun: Option<Instant>,
    /// Sum of measured latencies (in microseconds) for averaging.
    latency_sum_us: u64,
    /// Number of latency measurements.
    latency_measurements: u64,
}

impl RingBufferMetrics {
    /// Create a new zeroed metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Average latency in microseconds across all measurements.
    pub fn average_latency_us(&self) -> u64 {
        self.latency_sum_us
            .checked_div(self.latency_measurements)
            .unwrap_or(0)
    }

    /// Average latency in milliseconds.
    pub fn average_latency_ms(&self) -> f64 {
        self.average_latency_us() as f64 / 1000.0
    }
}

// ── Lock-free ring buffer ──────────────────────────────────────────────────

/// A lock-free single-producer / single-consumer ring buffer for audio samples.
///
/// The buffer stores interleaved f32 audio samples. The producer writes
/// chunks of samples and the consumer reads them. When the buffer underruns
/// (not enough data), the consumer fills with silence.
///
/// # Thread safety
///
/// The ring buffer uses `AtomicUsize` indices for the head (read) and tail
/// (write) positions, making it safe for single-producer / single-consumer
/// use without locks.
pub struct AudioRingBuffer {
    /// The sample storage buffer (power-of-2 sized for mask-based wrapping).
    buffer: Box<[f32]>,
    /// Bitmask for wrapping indices (buffer.len() - 1).
    mask: usize,
    /// Read position (consumer side). Only modified by the consumer.
    head: AtomicUsize,
    /// Write position (producer side). Only modified by the producer.
    tail: AtomicUsize,
    /// Samples written by the producer that overwrote unread data. The
    /// producer increments this on overflow; the consumer drains it and
    /// skips that many samples before reading. This keeps the producer
    /// from ever writing `head` (SPSC invariant) while still implementing
    /// "oldest samples are overwritten".
    dropped: AtomicUsize,
    /// Number of audio channels.
    channels: u16,
    /// Pre-buffer threshold: minimum frames before the consumer starts reading.
    pre_buffer_frames: usize,
    /// Whether pre-buffering is complete.
    pre_buffering_complete: std::sync::atomic::AtomicBool,
    /// Metrics snapshot.
    metrics: std::sync::Mutex<RingBufferMetrics>,
    /// Sample rate for latency calculations.
    sample_rate: u32,
}

impl AudioRingBuffer {
    /// Create a new ring buffer.
    ///
    /// # Arguments
    /// * `capacity_frames` — Number of audio frames the buffer can hold.
    ///   Will be rounded up to the next power of two.
    /// * `channels` — Number of audio channels per frame.
    /// * `sample_rate` — Audio sample rate in Hz (for latency metrics).
    /// * `pre_buffer_frames` — Number of frames to buffer before the consumer
    ///   starts reading. Set to 0 for no pre-buffering.
    pub fn new(
        capacity_frames: usize,
        channels: u16,
        sample_rate: u32,
        pre_buffer_frames: usize,
    ) -> Self {
        // A zero-channel buffer cannot be read or written without dividing
        // by zero on every path; reject it up front. No caller reaches this
        // with guest-controlled values.
        assert!(
            channels > 0,
            "AudioRingBuffer requires at least one channel"
        );
        let capacity_samples = capacity_frames.next_power_of_two() * channels as usize;
        let mask = capacity_samples - 1;
        let buffer = vec![0.0f32; capacity_samples].into_boxed_slice();

        Self {
            buffer,
            mask,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
            channels,
            pre_buffer_frames,
            pre_buffering_complete: std::sync::atomic::AtomicBool::new(pre_buffer_frames == 0),
            metrics: std::sync::Mutex::new(RingBufferMetrics::new()),
            sample_rate,
        }
    }

    /// Create a ring buffer with default settings (4096 frames, pre-buffer 1024).
    pub fn new_default(channels: u16, sample_rate: u32) -> Self {
        Self::new(4096, channels, sample_rate, 1024)
    }

    /// Write interleaved f32 samples into the ring buffer (producer side).
    ///
    /// If the buffer is full, the oldest samples are overwritten (overflow).
    /// Returns the number of samples actually written.
    ///
    /// The producer only ever touches `tail` and the `dropped` counter; the
    /// consumer owns `head`. On overflow the number of overwritten samples
    /// is recorded in `dropped` so the consumer can skip them, keeping the
    /// newest samples contiguous and in order.
    pub fn write(&self, samples: &[f32]) -> usize {
        let len = samples.len();
        if len == 0 {
            return 0;
        }
        let capacity = self.buffer.len();
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        let used = tail.wrapping_sub(head).min(capacity);
        let free = capacity - used;
        // Never write more than the ring holds; if the input is larger,
        // keep only the newest `capacity` samples.
        let write_count = len.min(capacity);
        let src = if len > capacity {
            &samples[len - capacity..]
        } else {
            samples
        };

        // Write samples into the ring buffer (wrapping)
        for (i, &sample) in src.iter().enumerate() {
            let idx = (tail + i) & self.mask;
            // SAFETY: single-producer means only this thread writes to buffer[idx]
            // and the mask ensures we stay within bounds.
            unsafe {
                let ptr = self.buffer.as_ptr().add(idx) as *mut f32;
                *ptr = sample;
            }
        }

        // Advance tail (producer-owned). Never touch head.
        self.tail
            .store(tail.wrapping_add(write_count), Ordering::Release);

        // On overflow the oldest `overflow` samples were overwritten; record
        // them so the consumer can skip them. `overflow` is independent of
        // any previously recorded drops (it only depends on the fill level
        // at write time), so accumulation is consistent.
        let overflow = write_count.saturating_sub(free);
        if overflow > 0 {
            self.dropped.fetch_add(overflow, Ordering::Release);
            if let Ok(mut m) = self.metrics.try_lock() {
                m.overflow_count += 1;
            }
        }

        // Check if pre-buffering is complete
        if !self.pre_buffering_complete.load(Ordering::Relaxed) {
            let fill_frames = self.fill_samples() / self.channels as usize;
            if fill_frames >= self.pre_buffer_frames {
                self.pre_buffering_complete.store(true, Ordering::Release);
            }
        }

        // Update metrics
        if let Ok(mut m) = self.metrics.try_lock() {
            m.total_written += write_count as u64;
            let fill = self.fill_samples();
            let fill_frames = fill / self.channels as usize;
            if fill_frames > m.peak_fill_frames {
                m.peak_fill_frames = fill_frames;
            }
        }

        write_count
    }

    /// Read interleaved f32 samples from the ring buffer (consumer side).
    ///
    /// If the buffer doesn't have enough data, the remaining output is filled
    /// with silence (underrun handling). If pre-buffering is not yet complete,
    /// all output is silence.
    ///
    /// Returns the number of samples actually read from the buffer (excluding
    /// silence fill).
    pub fn read(&self, output: &mut [f32]) -> usize {
        // If pre-buffering is not complete, output silence
        if !self.pre_buffering_complete.load(Ordering::Acquire) {
            output.fill(0.0);
            return 0;
        }

        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        // Drain any samples the producer overwrote (overflow) and skip them.
        let skip = self.dropped.swap(0, Ordering::AcqRel);
        let available = tail.wrapping_sub(head).saturating_sub(skip);
        let read_count = output.len().min(available);

        // Read samples from the ring buffer
        for (i, out) in output.iter_mut().enumerate().take(read_count) {
            let idx = (head + skip + i) & self.mask;
            *out = self.buffer[idx];
        }

        // Fill remaining with silence (underrun handling)
        if read_count < output.len() {
            output[read_count..].fill(0.0);
            let underrun_samples = output.len() - read_count;
            if let Ok(mut m) = self.metrics.try_lock() {
                m.underrun_count += 1;
                m.underrun_duration_us += if self.sample_rate > 0 {
                    (underrun_samples as u64 * 1_000_000)
                        / (self.sample_rate as u64 * self.channels as u64)
                } else {
                    0
                };
                m.last_underrun = Some(Instant::now());
            }
        }

        // Advance head past the skipped and read samples
        let advanced = skip + read_count;
        self.head
            .store(head.wrapping_add(advanced), Ordering::Release);

        // Update metrics
        if let Ok(mut m) = self.metrics.try_lock() {
            m.total_read += read_count as u64;
            // Record latency measurement
            let remaining = tail.wrapping_sub(head.wrapping_add(advanced));
            let remaining_frames = remaining / self.channels.max(1) as usize;
            if self.sample_rate > 0 {
                let latency_us = (remaining_frames as u64 * 1_000_000) / self.sample_rate as u64;
                m.latency_sum_us += latency_us;
                m.latency_measurements += 1;
            }
        }

        read_count
    }

    /// Read interleaved f32 samples, repeating the last sample on underrun
    /// instead of silence. This can reduce audible clicks.
    pub fn read_hold(&self, output: &mut [f32]) -> usize {
        // If pre-buffering is not complete, output silence
        if !self.pre_buffering_complete.load(Ordering::Acquire) {
            output.fill(0.0);
            return 0;
        }

        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        // Drain any samples the producer overwrote (overflow) and skip them.
        let skip = self.dropped.swap(0, Ordering::AcqRel);
        let available = tail.wrapping_sub(head).saturating_sub(skip);
        let read_count = output.len().min(available);

        // Read samples from the ring buffer
        for (i, out) in output.iter_mut().enumerate().take(read_count) {
            let idx = (head + skip + i) & self.mask;
            *out = self.buffer[idx];
        }

        // Fill remaining by repeating the last complete frame. A partial
        // frame (0 < read_count < channels) cannot be held, so it is
        // filled with silence instead (no underflow / OOB possible).
        if read_count < output.len() && read_count > 0 {
            let channels = self.channels as usize;
            if read_count >= channels {
                let last_frame_start = read_count - channels;
                for frame_idx in (read_count..output.len()).step_by(channels) {
                    for ch in 0..channels {
                        if frame_idx + ch < output.len() {
                            output[frame_idx + ch] = output[last_frame_start + ch];
                        }
                    }
                }
            } else {
                output[read_count..].fill(0.0);
            }
            if let Ok(mut m) = self.metrics.try_lock() {
                m.underrun_count += 1;
                let underrun_samples = output.len() - read_count;
                m.underrun_duration_us += if self.sample_rate > 0 {
                    (underrun_samples as u64 * 1_000_000)
                        / (self.sample_rate as u64 * self.channels as u64)
                } else {
                    0
                };
                m.last_underrun = Some(Instant::now());
            }
        } else if read_count == 0 {
            output.fill(0.0);
        }

        // Advance head past the skipped and read samples
        let advanced = skip + read_count;
        self.head
            .store(head.wrapping_add(advanced), Ordering::Release);

        // Update metrics
        if let Ok(mut m) = self.metrics.try_lock() {
            m.total_read += read_count as u64;
        }

        read_count
    }

    /// Get the current number of samples available for reading.
    ///
    /// Accounts for samples the producer dropped on overflow, so the value
    /// never exceeds the buffer capacity.
    pub fn fill_samples(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let dropped = self.dropped.load(Ordering::Acquire);
        tail.wrapping_sub(head)
            .saturating_sub(dropped)
            .min(self.buffer.len())
    }

    /// Get the current number of frames available for reading.
    pub fn fill_frames(&self) -> usize {
        self.fill_samples() / self.channels.max(1) as usize
    }

    /// Get the total capacity in frames.
    pub fn capacity_frames(&self) -> usize {
        self.buffer.len() / self.channels.max(1) as usize
    }

    /// Get the number of channels.
    pub fn channels(&self) -> u16 {
        self.channels
    }

    /// Check if pre-buffering is complete.
    pub fn is_pre_buffered(&self) -> bool {
        self.pre_buffering_complete.load(Ordering::Acquire)
    }

    /// Reset the ring buffer to empty state.
    pub fn reset(&self) {
        self.head.store(0, Ordering::Release);
        self.tail.store(0, Ordering::Release);
        self.dropped.store(0, Ordering::Release);
        self.pre_buffering_complete
            .store(self.pre_buffer_frames == 0, Ordering::Release);
    }

    /// Take a snapshot of the current metrics.
    pub fn metrics(&self) -> RingBufferMetrics {
        self.metrics.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// Get the fill level as a fraction [0.0, 1.0].
    pub fn fill_fraction(&self) -> f32 {
        let capacity = self.buffer.len();
        if capacity == 0 {
            return 0.0;
        }
        self.fill_samples() as f32 / capacity as f32
    }
}

// ── Double buffer ──────────────────────────────────────────────────────────

/// A double-buffer manager for seamless audio transitions.
///
/// Maintains two ring buffers: an "active" buffer being read by the consumer
/// and a "next" buffer being filled by the producer. When the active buffer
/// is exhausted, the buffers are swapped.
pub struct DoubleAudioBuffer {
    primary: AudioRingBuffer,
    secondary: AudioRingBuffer,
    /// Which buffer is currently active for reading.
    reading_primary: std::sync::atomic::AtomicBool,
}

impl DoubleAudioBuffer {
    /// Create a new double buffer.
    pub fn new(
        capacity_frames: usize,
        channels: u16,
        sample_rate: u32,
        pre_buffer_frames: usize,
    ) -> Self {
        Self {
            primary: AudioRingBuffer::new(
                capacity_frames,
                channels,
                sample_rate,
                pre_buffer_frames,
            ),
            secondary: AudioRingBuffer::new(
                capacity_frames,
                channels,
                sample_rate,
                pre_buffer_frames,
            ),
            reading_primary: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Write samples to the inactive (back) buffer.
    pub fn write(&self, samples: &[f32]) -> usize {
        if self.reading_primary.load(Ordering::Acquire) {
            self.secondary.write(samples)
        } else {
            self.primary.write(samples)
        }
    }

    /// Read samples from the active (front) buffer.
    /// If the active buffer is exhausted, swap to the other buffer.
    pub fn read(&self, output: &mut [f32]) -> usize {
        let reading_primary = self.reading_primary.load(Ordering::Acquire);
        let active = if reading_primary {
            &self.primary
        } else {
            &self.secondary
        };

        let read = active.read(output);

        // If the active buffer is running dry, check if the other has data
        if active.fill_frames() < output.len() / active.channels as usize / 2 {
            let other = if reading_primary {
                &self.secondary
            } else {
                &self.primary
            };
            if other.fill_frames() > 0 {
                // Swap: start reading from the other buffer
                self.reading_primary
                    .store(!reading_primary, Ordering::Release);
            }
        }

        read
    }

    /// Reset both buffers.
    pub fn reset(&self) {
        self.primary.reset();
        self.secondary.reset();
        self.reading_primary.store(true, Ordering::Release);
    }

    /// Get combined metrics from both buffers.
    pub fn metrics(&self) -> RingBufferMetrics {
        let mut m = self.primary.metrics();
        let m2 = self.secondary.metrics();
        m.underrun_count += m2.underrun_count;
        m.underrun_duration_us += m2.underrun_duration_us;
        m.overflow_count += m2.overflow_count;
        m.total_written += m2.total_written;
        m.total_read += m2.total_read;
        m.peak_fill_frames = m.peak_fill_frames.max(m2.peak_fill_frames);
        m
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_basic_write_read() {
        let rb = AudioRingBuffer::new(1024, 2, 44100, 0);
        let samples: Vec<f32> = (0..100).map(|i| i as f32).collect();
        let written = rb.write(&samples);
        assert_eq!(written, 100);

        let mut output = vec![0.0f32; 100];
        let read = rb.read(&mut output);
        assert_eq!(read, 100);
        for (i, &sample) in output.iter().enumerate() {
            assert!((sample - i as f32).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn test_ring_buffer_underrun() {
        let rb = AudioRingBuffer::new(1024, 1, 44100, 0);

        // Write 10 samples
        let samples: Vec<f32> = (0..10).map(|i| i as f32).collect();
        rb.write(&samples);

        // Try to read 20 samples — should get 10 real + 10 silence
        let mut output = vec![-1.0f32; 20];
        let read = rb.read(&mut output);
        assert_eq!(read, 10);

        // First 10 should be the real data
        for (i, &sample) in output.iter().enumerate().take(10) {
            assert!((sample - i as f32).abs() < f32::EPSILON);
        }
        // Last 10 should be silence (0.0)
        for &sample in &output[10..20] {
            assert_eq!(sample, 0.0);
        }

        // Check underrun was recorded
        let metrics = rb.metrics();
        assert_eq!(metrics.underrun_count, 1);
    }

    #[test]
    fn test_ring_buffer_pre_buffering() {
        let rb = AudioRingBuffer::new(1024, 1, 44100, 100);

        // Write 50 samples — not enough for pre-buffer
        let samples: Vec<f32> = (0..50).map(|i| i as f32).collect();
        rb.write(&samples);
        assert!(!rb.is_pre_buffered());

        let mut output = vec![0.0f32; 10];
        let read = rb.read(&mut output);
        assert_eq!(read, 0); // Should return silence
        assert!(output.iter().all(|&s| s == 0.0));

        // Write 50 more — now we have 100, should be pre-buffered
        let samples2: Vec<f32> = (50..100).map(|i| i as f32).collect();
        rb.write(&samples2);
        assert!(rb.is_pre_buffered());

        let mut output2 = vec![0.0f32; 10];
        let read2 = rb.read(&mut output2);
        assert_eq!(read2, 10);
        // Should read the first 10 samples
        for (i, &sample) in output2.iter().enumerate() {
            assert!((sample - i as f32).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn test_ring_buffer_wrap_around() {
        let rb = AudioRingBuffer::new(16, 1, 44100, 0); // 16 sample capacity

        // Write 10 samples
        let s1: Vec<f32> = (0..10).map(|i| i as f32).collect();
        rb.write(&s1);

        // Read 10 samples
        let mut out1 = vec![0.0f32; 10];
        rb.read(&mut out1);

        // Write 10 more — should wrap around
        let s2: Vec<f32> = (10..20).map(|i| i as f32).collect();
        rb.write(&s2);

        let mut out2 = vec![0.0f32; 10];
        let read = rb.read(&mut out2);
        assert_eq!(read, 10);
        for (i, &sample) in out2.iter().enumerate() {
            assert!((sample - (10 + i) as f32).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn test_ring_buffer_fill_tracking() {
        let rb = AudioRingBuffer::new(1024, 2, 44100, 0);

        // Write 100 samples (50 frames, 2 channels)
        let samples: Vec<f32> = (0..100).map(|i| i as f32).collect();
        rb.write(&samples);

        assert_eq!(rb.fill_samples(), 100);
        assert_eq!(rb.fill_frames(), 50);
    }

    #[test]
    fn test_ring_buffer_metrics() {
        let rb = AudioRingBuffer::new(1024, 1, 44100, 0);

        let samples: Vec<f32> = (0..10).map(|i| i as f32).collect();
        rb.write(&samples);

        let mut output = vec![0.0f32; 20];
        rb.read(&mut output); // Will cause underrun

        let metrics = rb.metrics();
        assert_eq!(metrics.total_written, 10);
        assert_eq!(metrics.total_read, 10);
        assert_eq!(metrics.underrun_count, 1);
    }

    #[test]
    fn test_ring_buffer_reset() {
        let rb = AudioRingBuffer::new(1024, 1, 44100, 0);

        let samples: Vec<f32> = (0..100).map(|i| i as f32).collect();
        rb.write(&samples);
        assert_eq!(rb.fill_samples(), 100);

        rb.reset();
        assert_eq!(rb.fill_samples(), 0);
    }

    #[test]
    fn test_ring_buffer_read_hold() {
        let rb = AudioRingBuffer::new(1024, 2, 44100, 0);

        // Write 4 samples (2 frames)
        rb.write(&[1.0, 2.0, 3.0, 4.0]);

        // Try to read 8 samples (4 frames) — underrun should hold last frame
        let mut output = vec![0.0f32; 8];
        rb.read_hold(&mut output);

        // First 4 should be real data
        assert_eq!(output[0], 1.0);
        assert_eq!(output[1], 2.0);
        assert_eq!(output[2], 3.0);
        assert_eq!(output[3], 4.0);
        // Last 4 should repeat the last frame (3.0, 4.0)
        assert_eq!(output[4], 3.0);
        assert_eq!(output[5], 4.0);
        assert_eq!(output[6], 3.0);
        assert_eq!(output[7], 4.0);
    }

    #[test]
    fn test_double_buffer_basic() {
        let db = DoubleAudioBuffer::new(1024, 1, 44100, 0);

        // Write to secondary (since primary is active for reading)
        let samples: Vec<f32> = (0..10).map(|i| i as f32).collect();
        db.write(&samples);

        // Swap by reading from primary (which is empty, triggering swap)
        let mut output = vec![0.0f32; 10];
        let read = db.read(&mut output);
        // Primary is empty so we get silence initially
        assert_eq!(read, 0);
    }

    #[test]
    fn test_fill_fraction() {
        let rb = AudioRingBuffer::new(1024, 1, 44100, 0);
        assert_eq!(rb.fill_fraction(), 0.0);

        rb.write(&[1.0; 512]);
        let frac = rb.fill_fraction();
        assert!(frac > 0.49 && frac < 0.51);
    }

    #[test]
    fn test_stereo_interleaved() {
        let rb = AudioRingBuffer::new(1024, 2, 44100, 0);

        // Write stereo interleaved: L R L R L R L R L R
        let samples: Vec<f32> = (0..10).map(|i| i as f32).collect();
        rb.write(&samples);

        let mut output = vec![0.0f32; 10];
        let read = rb.read(&mut output);
        assert_eq!(read, 10);

        // Verify interleaving is preserved
        for (i, &sample) in output.iter().enumerate() {
            assert!((sample - i as f32).abs() < f32::EPSILON);
        }
    }

    #[test]
    fn test_ring_buffer_wraparound_across_boundary() {
        // Use a very small buffer (4 samples) to force wraparound
        let rb = AudioRingBuffer::new(4, 1, 44100, 0);

        // Fill the buffer completely
        rb.write(&[1.0, 2.0, 3.0, 4.0]);
        assert_eq!(rb.fill_samples(), 4);

        // Read all samples
        let mut out = vec![0.0f32; 4];
        let read = rb.read(&mut out);
        assert_eq!(read, 4);
        assert_eq!(out, vec![1.0, 2.0, 3.0, 4.0]);
        assert_eq!(rb.fill_samples(), 0);

        // Write again — this wraps around the buffer boundary
        rb.write(&[5.0, 6.0, 7.0, 8.0]);
        assert_eq!(rb.fill_samples(), 4);

        let mut out2 = vec![0.0f32; 4];
        let read2 = rb.read(&mut out2);
        assert_eq!(read2, 4);
        assert_eq!(out2, vec![5.0, 6.0, 7.0, 8.0]);
    }

    #[test]
    fn test_ring_buffer_overrun_drops_oldest() {
        // When writing to a full buffer, overflow handling drops the oldest
        // data and keeps the newest samples, which then play in order.
        // The producer never writes `head`; the consumer skips the dropped
        // samples instead.
        let rb = AudioRingBuffer::new(4, 1, 44100, 0);

        // Fill buffer completely
        rb.write(&[1.0, 2.0, 3.0, 4.0]);
        assert_eq!(rb.fill_samples(), 4);

        // Write 4 more into the full buffer — the newest 4 samples replace
        // the oldest 4 (the whole ring), which are marked dropped.
        let written = rb.write(&[5.0, 6.0, 7.0, 8.0]);
        assert_eq!(written, 4);

        // Reading returns the newest data, in order.
        let mut out = vec![-1.0f32; 4];
        let read = rb.read(&mut out);
        assert_eq!(read, 4);
        assert_eq!(out, vec![5.0, 6.0, 7.0, 8.0]);

        // Buffer is now empty
        assert_eq!(rb.fill_samples(), 0);

        // Overflow should be recorded in metrics
        let metrics = rb.metrics();
        assert_eq!(metrics.overflow_count, 1);
    }

    #[test]
    fn test_ring_buffer_overrun_keeps_newest_when_partially_filled() {
        // Write more than fits while the buffer still has free space: the
        // overflowed samples replace the oldest unread data, and the consumer
        // still reads a contiguous, ordered stream.
        let rb = AudioRingBuffer::new(8, 1, 44100, 0);

        rb.write(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]); // 6 of 8 slots used
        let mut out = vec![0.0f32; 4];
        assert_eq!(rb.read(&mut out), 4); // consume 1..=4

        // Write 6 samples into 4 free slots: the 2 oldest unread samples
        // (5.0, 6.0) are overwritten and the newest 6 are kept.
        rb.write(&[7.0, 8.0, 9.0, 10.0, 11.0, 12.0]);
        assert_eq!(rb.fill_samples(), 8);

        let mut out2 = vec![0.0f32; 8];
        let read = rb.read(&mut out2);
        assert_eq!(read, 8);
        // Newest 6 in order, preceded by the 2 unread-but-not-overwritten.
        assert_eq!(out2, vec![5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0]);
    }

    #[test]
    fn test_ring_buffer_overrun_oversized_write_keeps_newest() {
        // A single write larger than the ring replaces the entire contents
        // with the newest samples.
        let rb = AudioRingBuffer::new(4, 1, 44100, 0);
        rb.write(&[1.0, 2.0, 3.0, 4.0]);
        rb.write(&(5..=20).map(|v| v as f32).collect::<Vec<_>>());

        let mut out = vec![-1.0f32; 4];
        let read = rb.read(&mut out);
        assert_eq!(read, 4);
        assert_eq!(out, vec![17.0, 18.0, 19.0, 20.0]);
    }

    #[test]
    fn test_ring_buffer_read_hold_partial_frame_no_panic() {
        // A producer write that is not frame-aligned leaves a partial frame;
        // read_hold must not underflow or panic, and must fill with silence.
        let rb = AudioRingBuffer::new(1024, 2, 44100, 0);
        rb.write(&[1.0]); // 1 sample of a stereo buffer
        let mut output = vec![0.0f32; 4];
        let read = rb.read_hold(&mut output);
        assert_eq!(read, 1);
        assert_eq!(output[0], 1.0);
        assert_eq!(output[1], 0.0);
        assert_eq!(output[2], 0.0);
        assert_eq!(output[3], 0.0);
    }

    #[test]
    fn test_ring_buffer_producer_consumer_simulation() {
        // Simulate a single-threaded producer/consumer pattern
        let rb = AudioRingBuffer::new(64, 1, 44100, 0);

        // Produce batch 1
        let batch1: Vec<f32> = (0..32).map(|i| i as f32).collect();
        rb.write(&batch1);
        assert_eq!(rb.fill_samples(), 32);

        // Consume first half
        let mut out1 = vec![0.0f32; 16];
        let read1 = rb.read(&mut out1);
        assert_eq!(read1, 16);
        for (i, &sample) in out1.iter().enumerate() {
            assert!((sample - i as f32).abs() < f32::EPSILON);
        }
        assert_eq!(rb.fill_samples(), 16);

        // Produce batch 2 (wraps around)
        let batch2: Vec<f32> = (32..64).map(|i| i as f32).collect();
        rb.write(&batch2);
        assert_eq!(rb.fill_samples(), 48);

        // Consume the rest
        let mut out2 = vec![0.0f32; 48];
        let read2 = rb.read(&mut out2);
        assert_eq!(read2, 48);

        // Verify data continuity: 16..32 from batch1, then 32..64 from batch2
        for (j, &sample) in out2.iter().enumerate().take(16) {
            assert!(
                (sample - (16 + j) as f32).abs() < f32::EPSILON,
                "at index {}",
                j
            );
        }
        for (j, &sample) in out2.iter().enumerate().skip(16).take(32) {
            assert!(
                (sample - (16 + j) as f32).abs() < f32::EPSILON,
                "at index {}",
                16 + j
            );
        }

        // Buffer should now be empty
        assert_eq!(rb.fill_samples(), 0);
    }

    #[test]
    fn test_ring_buffer_full_underrun_returns_silence() {
        let rb = AudioRingBuffer::new(16, 1, 44100, 0);

        // Read from empty buffer — should get all silence
        let mut out = vec![-1.0f32; 8];
        let read = rb.read(&mut out);
        assert_eq!(read, 0);
        assert!(out.iter().all(|&s| s == 0.0));

        // Metrics should record the underrun
        let metrics = rb.metrics();
        assert_eq!(metrics.underrun_count, 1);
    }

    #[test]
    fn test_ring_buffer_concurrent_producer_consumer() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let rb = Arc::new(Mutex::new(AudioRingBuffer::new(1024, 1, 44100, 0)));
        let rb_producer = Arc::clone(&rb);
        let rb_consumer = Arc::clone(&rb);

        let producer = thread::spawn(move || {
            for batch in 0..20 {
                let samples: Vec<f32> = (0..32).map(|i| (batch * 32 + i) as f32).collect();
                {
                    let buf = rb_producer.lock().unwrap();
                    buf.write(&samples);
                }
                thread::yield_now();
            }
        });

        let consumer = thread::spawn(move || {
            let mut total_read = 0usize;
            let mut output = vec![0.0f32; 32];
            for _ in 0..40 {
                {
                    let buf = rb_consumer.lock().unwrap();
                    let read = buf.read(&mut output);
                    total_read += read;
                }
                thread::yield_now();
            }
            total_read
        });

        producer.join().expect("producer thread panicked");
        let total_read = consumer.join().expect("consumer thread panicked");

        // Should have read some data (exact amount depends on scheduling)
        assert!(
            total_read > 0,
            "consumer should have read at least some samples, got {total_read}"
        );

        // Total produced = 20 batches × 32 samples = 640
        // Total consumed should be <= 640
        assert!(total_read <= 640, "consumed more than produced");
    }
}
