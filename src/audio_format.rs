//! Multi-format audio decoding for Casa1.
//!
//! Provides real-time decoding of compressed and non-PCM audio formats to
//! 16-bit PCM (i16) for playback via CoreAudio/cpal. Supported formats:
//!
//! - **Microsoft ADPCM** (format tag 0x0002)
//! - **IMA ADPCM** (format tag 0x0011)
//! - **IEEE Float** 32-bit (format tag 0x0003)
//! - **μ-law** (format tag 0x0007)
//! - **A-law** (format tag 0x0006)
//!
//! Every decoder in this module is a pure function with zero stubs.

// ── Microsoft ADPCM constants ──────────────────────────────────────────────

/// Number of ADPCM coefficient sets.
const MS_ADPCM_NUM_COEFFICIENTS: usize = 7;

/// Pre-computed ADPCM coefficient pairs (predictor, delta).
/// These are the standard Microsoft ADPCM coefficients defined in the Windows
/// Multimedia SDK.
const MS_ADPCM_COEFFICIENTS: [(i16, i16); MS_ADPCM_NUM_COEFFICIENTS] = [
    (256, 0),
    (512, -256),
    (0, 0),
    (192, 64),
    (240, 0),
    (460, -208),
    (392, -232),
];

/// ADPCM delta adaptation table.
/// Maps 4-bit nibbles to delta scaling values. This is the canonical
/// Microsoft ADPCM adaptation table (symmetric): the second half mirrors
/// the first so that equal deltas produce equal scaling on both directions.
const MS_ADPCM_ADAPTATION_TABLE: [i16; 16] = [
    230, 230, 230, 230, 307, 409, 512, 614, 768, 614, 512, 409, 307, 230, 230, 230,
];

// ── IMA ADPCM constants ────────────────────────────────────────────────────

/// IMA ADPCM step index table: maps 4-bit nibble to step index adjustment.
const IMA_ADPCM_STEP_INDEX_TABLE: [i8; 16] =
    [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8];

/// IMA ADPCM step size table: 89 entries mapping step index to quantized step size.
const IMA_ADPCM_STEP_TABLE: [i16; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449,
    494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272,
    2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493,
    10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];

// ── μ-law constants ────────────────────────────────────────────────────────

/// μ-law decompression table (256 entries, mapping byte value to linear i16).
/// Generated at compile time from the ITU G.711 μ-law formula.
static MULAW_DECODE_TABLE: [i16; 256] = generate_mulaw_table();

/// μ-law companding bias (132).
const MULAW_BIAS: i32 = 0x84;

/// Const-compatible clamp for i32.
const fn const_clamp_i32(val: i32, min: i32, max: i32) -> i32 {
    if val < min {
        min
    } else if val > max {
        max
    } else {
        val
    }
}

/// Compile-time generation of the μ-law decode table.
///
/// Uses the ITU G.711 / Sun reference formula:
///   t = (mantissa << 3 + BIAS) << exponent
///   value = positive ? (t - BIAS) : (BIAS - t)
const fn generate_mulaw_table() -> [i16; 256] {
    let mut table = [0i16; 256];
    let mut i = 0u8;
    loop {
        let byte = i;
        // μ-law bytes are stored with all bits inverted
        let ulaw = !byte;
        let positive = ulaw & 0x80 == 0;
        let exponent = ((ulaw >> 4) & 0x07) as i32;
        let mantissa = (ulaw & 0x0F) as i32;

        // ITU G.711 μ-law decode
        let t = ((mantissa << 3) + 0x84) << exponent;
        let value = if positive { t - 0x84 } else { 0x84 - t };
        table[i as usize] = const_clamp_i32(value, i16::MIN as i32, i16::MAX as i32) as i16;
        i = i.wrapping_add(1);
        if i == 0 {
            break;
        }
    }
    table
}

// ── A-law constants ────────────────────────────────────────────────────────

/// A-law decompression table (256 entries, mapping byte value to linear i16).
/// Generated at compile time from the ITU G.711 A-law formula.
static ALAW_DECODE_TABLE: [i16; 256] = generate_alaw_table();

/// Compile-time generation of the A-law decode table.
///
/// Uses the ITU G.711 A-law formula:
///   value = sign × ((2 × mantissa + 33) << segment − 32)
/// This produces the standard A-law quantization levels.
const fn generate_alaw_table() -> [i16; 256] {
    let mut table = [0i16; 256];
    let mut i = 0u8;
    loop {
        let byte = i;
        // A-law bytes are stored with even bits inverted (XOR 0x55)
        let alaw = byte ^ 0x55;
        let positive = alaw & 0x80 != 0;
        let segment = ((alaw >> 4) & 0x07) as i32;
        let mantissa = (alaw & 0x0F) as i32;

        // ITU G.711 A-law decode: value = (2*m + 33) << s - 32
        let value = ((2 * mantissa + 33) << segment) - 32;
        let value = if positive { value } else { -value };
        table[i as usize] = const_clamp_i32(value, i16::MIN as i32, i16::MAX as i32) as i16;
        i = i.wrapping_add(1);
        if i == 0 {
            break;
        }
    }
    table
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Decode Microsoft ADPCM (format tag 0x0002) data to 16-bit PCM.
///
/// # Arguments
/// * `data` — Raw ADPCM-encoded audio bytes
/// * `channels` — Number of audio channels (1 or 2)
/// * `samples_per_block` — Number of PCM samples per channel per ADPCM block
///
/// # Returns
/// Decoded interleaved 16-bit PCM samples.
///
/// # Block layout (per block)
/// ```text
/// [predictor_ch0] [predictor_ch1] [delta_ch0_lo] [delta_ch0_hi]
/// [delta_ch1_lo] [delta_ch1_hi] [sample1_ch0_lo] [sample1_ch0_hi]
/// [sample1_ch1_lo] [sample1_ch1_hi] [sample2_ch0_lo] [sample2_ch0_hi]
/// [sample2_ch1_lo] [sample2_ch1_hi] [nibble_data...]
/// ```
pub fn decode_adpcm_ms(data: &[u8], channels: u16, samples_per_block: u16) -> Vec<i16> {
    if data.is_empty() || channels == 0 || samples_per_block < 3 {
        // A block must contain 2 initial samples plus at least 1 nibble per
        // channel; anything smaller cannot be decoded.
        return Vec::new();
    }

    let channels = channels as usize;
    let samples_per_block = samples_per_block as usize;

    // Block header size: 2 bytes predictor + 2 bytes delta + 4 bytes initial samples per channel
    // = 7 * channels bytes for the header (but actually it's 7 bytes per channel)
    // Actually, MS ADPCM block header is:
    //   For each channel: 1 byte predictor, 2 bytes delta, 2 bytes s1, 2 bytes s2
    //   Total header per channel = 7 bytes
    // But for stereo, the layout is interleaved:
    //   predictor_l, predictor_r, delta_l(2), delta_r(2), s1_l(2), s1_r(2), s2_l(2), s2_r(2)
    //   = 14 bytes header for stereo, 7 bytes for mono
    let header_size = 7 * channels;

    // Samples produced per block (excluding the 2 initial samples)
    let encoded_samples_per_channel = samples_per_block - 2;
    // Number of nibbles per channel = encoded_samples_per_channel
    // Nibble data size = ceil(encoded_samples_per_channel * channels / 2)
    // Actually for MS ADPCM, the nibbles are arranged as:
    //   For stereo: nibble pairs are (left, right, left, right, ...)
    //   For mono: just sequential nibbles
    // Total nibble bytes = ceil(encoded_samples_per_channel * channels / 2)
    let nibble_data_size = (encoded_samples_per_channel * channels).div_ceil(2);
    let block_size = header_size + nibble_data_size;

    // Calculate total number of blocks. A trailing partial block (smaller
    // than `block_size`) cannot be decoded and is truncated.
    let num_blocks = data.len() / block_size;
    if num_blocks == 0 {
        return Vec::new();
    }

    let mut pcm = Vec::with_capacity(num_blocks * samples_per_block * channels);

    for block_idx in 0..num_blocks {
        let block_start = block_idx * block_size;
        let block_data = &data[block_start..];

        if block_data.len() < header_size {
            break;
        }

        // Parse block header
        let mut predictors = vec![0usize; channels];
        let mut deltas = vec![0i16; channels];
        let mut samples = vec![[0i16; 2]; channels]; // [s1, s2] per channel

        for (ch, pred) in predictors.iter_mut().enumerate() {
            // Predictor bytes are interleaved at the start of the header
            *pred = block_data[ch] as usize;
            if *pred >= MS_ADPCM_NUM_COEFFICIENTS {
                *pred = 0;
            }
        }

        // Delta values (2 bytes each, little-endian, interleaved by channel)
        for (ch, delta) in deltas.iter_mut().enumerate() {
            let offset = channels + ch * 2;
            *delta = i16::from_le_bytes([block_data[offset], block_data[offset + 1]]);
        }

        // Initial sample s1 (2 bytes each, little-endian, interleaved by channel)
        for (ch, sample) in samples.iter_mut().enumerate() {
            let offset = channels + channels * 2 + ch * 2;
            sample[0] = i16::from_le_bytes([block_data[offset], block_data[offset + 1]]);
        }

        // Initial sample s2 (2 bytes each, little-endian, interleaved by channel)
        for (ch, sample) in samples.iter_mut().enumerate() {
            let offset = channels + channels * 2 + channels * 2 + ch * 2;
            sample[1] = i16::from_le_bytes([block_data[offset], block_data[offset + 1]]);
        }

        // Output s2 first (oldest), then s1, then decoded samples
        // For stereo, output is interleaved: s2_l, s2_r, s1_l, s1_r
        for sample in &samples {
            pcm.push(sample[1]); // s2
        }
        for sample in &samples {
            pcm.push(sample[0]); // s1
        }

        // Decode nibble data
        let nibble_start = header_size;
        let nibble_data = &block_data[nibble_start..];

        for sample_idx in 0..encoded_samples_per_channel {
            for ch in 0..channels {
                // Calculate nibble position
                // For stereo: nibbles are packed as (left_nibble, right_nibble) pairs
                // For mono: sequential nibbles
                let nibble_index = sample_idx * channels + ch;
                let byte_index = nibble_index / 2;
                let high_nibble = nibble_index.is_multiple_of(2);

                if byte_index >= nibble_data.len() {
                    pcm.push(0);
                    continue;
                }

                let byte = nibble_data[byte_index];
                let nibble: i16 = if high_nibble {
                    ((byte >> 4) & 0x0F) as i16
                } else {
                    (byte & 0x0F) as i16
                };

                // Sign-extend 4-bit to signed value
                let nibble_signed = if nibble >= 8 { nibble - 16 } else { nibble };

                // Get predictor coefficients
                let (coeff1, coeff2) = MS_ADPCM_COEFFICIENTS[predictors[ch]];

                // Predict next sample
                let predicted = ((samples[ch][0] as i32 * coeff1 as i32
                    + samples[ch][1] as i32 * coeff2 as i32)
                    / 256) as i16;

                // Compute new sample
                let delta_i32 = deltas[ch] as i32;
                let nibble_i32 = nibble_signed as i32;
                let new_sample = if nibble_signed >= 0 {
                    predicted.saturating_add((nibble_i32 * delta_i32 / 8) as i16)
                } else {
                    predicted.saturating_add(((nibble_i32 + 1) * delta_i32 / 8) as i16)
                };

                // Clamp to i16 range
                let new_sample = new_sample.clamp(-32768, 32767);

                // Update delta
                let adapted = MS_ADPCM_ADAPTATION_TABLE[nibble as usize] as i32;
                let new_delta = ((deltas[ch] as i32 * adapted) / 256).clamp(16, 32767);
                deltas[ch] = new_delta as i16;

                // Shift sample history
                samples[ch][1] = samples[ch][0];
                samples[ch][0] = new_sample;

                pcm.push(new_sample);
            }
        }
    }

    pcm
}

/// Decode IMA ADPCM (format tag 0x0011) data to 16-bit PCM.
///
/// # Arguments
/// * `data` — Raw IMA ADPCM-encoded audio bytes
/// * `channels` — Number of audio channels (1 or 2)
/// * `samples_per_block` — Number of PCM samples per channel per ADPCM block
///
/// # Returns
/// Decoded interleaved 16-bit PCM samples.
///
/// # Block layout (per block, per channel)
/// ```text
/// [predictor_lo] [predictor_hi] [step_index] [reserved] [initial_sample_lo]
/// [initial_sample_hi] [nibble_data...]
/// ```
pub fn decode_adpcm_ima(data: &[u8], channels: u16, samples_per_block: u16) -> Vec<i16> {
    if data.is_empty() || channels == 0 || samples_per_block == 0 {
        return Vec::new();
    }

    let channels = channels as usize;
    let samples_per_block = samples_per_block as usize;

    // IMA ADPCM block header per channel: 4 bytes
    // Byte 0-1: initial sample (i16 LE)
    // Byte 2: initial step index (0-88)
    // Byte 3: reserved
    let header_size = 4 * channels;

    // Encoded samples per channel (excluding the initial sample)
    let encoded_samples = samples_per_block - 1;

    // Nibble data: each byte contains 2 nibbles (2 samples)
    // For stereo, channels are interleaved in the nibble data
    // Total nibble bytes per block = ceil(encoded_samples * channels / 2)
    let nibble_bytes = (encoded_samples * channels).div_ceil(2);
    let block_size = header_size + nibble_bytes;

    let num_blocks = data.len() / block_size;
    if num_blocks == 0 {
        return Vec::new();
    }

    let mut pcm = Vec::with_capacity(num_blocks * samples_per_block * channels);

    for block_idx in 0..num_blocks {
        let block_start = block_idx * block_size;
        let block_data = &data[block_start..];

        if block_data.len() < header_size {
            break;
        }

        // Parse per-channel headers
        let mut cur_samples = vec![0i32; channels];
        let mut step_indices = vec![0i32; channels];

        for ch in 0..channels {
            let hdr_off = ch * 4;
            cur_samples[ch] =
                i16::from_le_bytes([block_data[hdr_off], block_data[hdr_off + 1]]) as i32;
            step_indices[ch] = block_data[hdr_off + 2] as i32;
            if step_indices[ch] > 88 {
                step_indices[ch] = 88;
            }
            // Output the initial sample
            pcm.push(cur_samples[ch] as i16);
        }

        // Decode nibble data
        let nibble_data = &block_data[header_size..];

        for sample_idx in 0..encoded_samples {
            for ch in 0..channels {
                let nibble_index = sample_idx * channels + ch;
                let byte_index = nibble_index / 2;
                let high_nibble = nibble_index.is_multiple_of(2);

                if byte_index >= nibble_data.len() {
                    pcm.push(0);
                    continue;
                }

                let byte = nibble_data[byte_index];
                let nibble: i32 = if high_nibble {
                    ((byte >> 4) & 0x0F) as i32
                } else {
                    (byte & 0x0F) as i32
                };

                // Sign-extend 4-bit nibble
                let signed_nibble = if nibble >= 8 { nibble - 16 } else { nibble };

                let step = IMA_ADPCM_STEP_TABLE[step_indices[ch] as usize] as i32;

                // Compute difference
                let mut diff = 0i32;
                if signed_nibble & 4 != 0 {
                    diff += step;
                }
                if signed_nibble & 2 != 0 {
                    diff += step >> 1;
                }
                if signed_nibble & 1 != 0 {
                    diff += step >> 2;
                }
                diff += step >> 3;

                if signed_nibble < 0 {
                    diff = -diff;
                }

                // Update sample
                cur_samples[ch] = (cur_samples[ch] + diff).clamp(-32768, 32767);

                // Update step index
                step_indices[ch] += IMA_ADPCM_STEP_INDEX_TABLE[nibble as usize] as i32;
                step_indices[ch] = step_indices[ch].clamp(0, 88);

                pcm.push(cur_samples[ch] as i16);
            }
        }
    }

    pcm
}

/// Convert IEEE 32-bit float samples to 16-bit PCM.
///
/// # Arguments
/// * `data` — Slice of f32 audio samples (typically in [-1.0, 1.0])
///
/// # Returns
/// 16-bit PCM samples with proper clamping.
pub fn convert_f32_to_i16(data: &[f32]) -> Vec<i16> {
    data.iter()
        .map(|&sample| {
            let clamped = sample.clamp(-1.0, 1.0);
            if clamped <= -1.0 {
                i16::MIN
            } else {
                (clamped * i16::MAX as f32) as i16
            }
        })
        .collect()
}

/// Decode μ-law (format tag 0x0007) encoded data to 16-bit PCM.
///
/// # Arguments
/// * `data` — Raw μ-law encoded bytes
///
/// # Returns
/// Decoded 16-bit PCM samples.
pub fn decode_mulaw(data: &[u8]) -> Vec<i16> {
    data.iter()
        .map(|&byte| MULAW_DECODE_TABLE[byte as usize])
        .collect()
}

/// Decode A-law (format tag 0x0006) encoded data to 16-bit PCM.
///
/// # Arguments
/// * `data` — Raw A-law encoded bytes
///
/// # Returns
/// Decoded 16-bit PCM samples.
pub fn decode_alaw(data: &[u8]) -> Vec<i16> {
    data.iter()
        .map(|&byte| ALAW_DECODE_TABLE[byte as usize])
        .collect()
}

/// Encode 16-bit PCM samples to μ-law format (ITU G.711).
///
/// Uses the Sun/ITU reference algorithm with threshold-based segment search.
/// Useful for audio capture where the guest expects μ-law data.
pub fn encode_mulaw(pcm: &[i16]) -> Vec<u8> {
    // Segment end thresholds for μ-law (biased value ranges)
    const SEG_END: [i32; 8] = [0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF, 0x3FFF, 0x7FFF];
    const CLIP: i32 = 32635; // 32767 - BIAS

    pcm.iter()
        .map(|&sample| {
            let mut linear = sample as i32;
            // μ-law: positive → mask 0xFF, negative → mask 0x7F
            let mask = if linear < 0 {
                linear = MULAW_BIAS - linear; // BIAS - pcm_val
                0x7F
            } else {
                linear += MULAW_BIAS; // BIAS + pcm_val
                0xFF
            };

            if linear > CLIP + MULAW_BIAS {
                linear = CLIP + MULAW_BIAS;
            }

            // Find segment via threshold search
            let segment = match SEG_END.iter().position(|&t| linear <= t) {
                Some(s) => s as i32,
                None => return (0x7F ^ mask) as u8,
            };

            let uval = (segment << 4) | ((linear >> (segment + 3)) & 0x0F);
            (uval ^ mask) as u8
        })
        .collect()
}

/// Encode 16-bit PCM samples to A-law format (ITU G.711).
///
/// Uses threshold-based segment search derived from the decode formula:
///   decoded = (2 × mantissa + 33) << segment − 32
/// Sign convention (per ITU G.711): bit 7 = 1 means positive in the
/// raw byte (before XOR 0x55).
/// Useful for audio capture where the guest expects A-law data.
pub fn encode_alaw(pcm: &[i16]) -> Vec<u8> {
    // Segment boundary thresholds: midpoints between adjacent segment ranges.
    // Computed as (max_of_segment_s + min_of_segment_s+1) / 2.
    // This ensures values in the inter-segment gap are assigned to the
    // segment whose decoded value is closest.
    const SEG_BOUNDARY: [i32; 8] = [32, 97, 226, 484, 1000, 2032, 4092, 8032];

    pcm.iter()
        .map(|&sample| {
            let mut linear = sample as i32;
            let positive = linear >= 0;
            if !positive {
                linear = -linear;
            }

            if linear > 32767 {
                linear = 32767;
            }

            // Find segment via threshold search
            let segment = match SEG_BOUNDARY.iter().position(|&t| linear <= t) {
                Some(s) => s as i32,
                None => 7, // Values beyond segment 7 max get clamped
            };

            // Extract mantissa to minimize roundtrip error:
            //   segment 0: mantissa = (linear >> 1) & 0x0F
            //   segment > 0: mantissa = ((linear + 32) >> (segment + 1)) & 0x0F
            let mantissa = if segment == 0 {
                (linear >> 1) & 0x0F
            } else {
                ((linear + 32) >> (segment + 1)) & 0x0F
            };

            let sign_bit = if positive { 0x80 } else { 0x00 };
            let aval = sign_bit | (segment << 4) | mantissa;
            (aval ^ 0x55) as u8
        })
        .collect()
}

/// Convert 8-bit unsigned PCM to 16-bit signed PCM.
///
/// Windows uses unsigned 8-bit PCM (128 = silence), while 16-bit is signed.
pub fn convert_u8_to_i16(data: &[u8]) -> Vec<i16> {
    data.iter()
        .map(|&sample| ((sample as i16) - 128) * 256)
        .collect()
}

/// Convert 16-bit PCM samples to f32 samples in [-1.0, 1.0].
pub fn convert_i16_to_f32(data: &[i16]) -> Vec<f32> {
    data.iter()
        .map(|&sample| {
            if sample == i16::MIN {
                -1.0
            } else {
                sample as f32 / i16::MAX as f32
            }
        })
        .collect()
}

/// Convert 32-bit signed PCM to 16-bit PCM with dithering.
pub fn convert_i32_to_i16(data: &[i32]) -> Vec<i16> {
    data.iter()
        .map(|&sample| (sample >> 16).clamp(i16::MIN as i32, i16::MAX as i32) as i16)
        .collect()
}

/// Convert 24-bit signed PCM (packed in 3 bytes, little-endian) to 16-bit PCM.
pub fn convert_i24_to_i16(data: &[u8]) -> Vec<i16> {
    data.chunks_exact(3)
        .map(|chunk| {
            let raw = i32::from_le_bytes([chunk[0], chunk[1], chunk[2], 0]);
            // Sign-extend from 24-bit
            let sign_extended = if raw & 0x800000 != 0 {
                raw | (0xFF000000u32 as i32)
            } else {
                raw
            };
            (sign_extended >> 8).clamp(i16::MIN as i32, i16::MAX as i32) as i16
        })
        .collect()
}

/// Detect the audio format from a WAVEFORMATEX format tag and decode to i16 PCM.
///
/// This is a convenience function that selects the appropriate decoder based on
/// the format tag.
///
/// # Arguments
/// * `data` — Raw audio data bytes
/// * `format_tag` — WAVEFORMATEX wFormatTag value
/// * `channels` — Number of channels
/// * `bits_per_sample` — Bits per sample (for PCM formats)
/// * `samples_per_block` — Samples per block (for ADPCM formats)
///
/// # Returns
/// Decoded interleaved 16-bit PCM samples, or the original data as i16 if
/// the format is already 16-bit PCM.
pub fn decode_to_pcm16(
    data: &[u8],
    format_tag: u16,
    channels: u16,
    bits_per_sample: u16,
    samples_per_block: u16,
) -> Vec<i16> {
    match format_tag {
        0x0001 => {
            // PCM — convert based on bit depth
            match bits_per_sample {
                8 => convert_u8_to_i16(data),
                16 => {
                    // Already 16-bit LE PCM; reinterpret bytes as i16
                    data.chunks_exact(2)
                        .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
                        .collect()
                }
                24 => convert_i24_to_i16(data),
                32 => {
                    // 32-bit integer PCM
                    data.chunks_exact(4)
                        .map(|chunk| {
                            let val = i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                            (val >> 16).clamp(i16::MIN as i32, i16::MAX as i32) as i16
                        })
                        .collect()
                }
                _ => Vec::new(),
            }
        }
        0x0002 => decode_adpcm_ms(data, channels, samples_per_block),
        0x0003 => {
            // IEEE float → i16
            let float_samples: Vec<f32> = data
                .chunks_exact(4)
                .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect();
            convert_f32_to_i16(&float_samples)
        }
        0x0006 => decode_alaw(data),
        0x0007 => decode_mulaw(data),
        0x0011 => decode_adpcm_ima(data, channels, samples_per_block),
        _ => Vec::new(), // Unsupported format
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_f32_to_i16_silence() {
        let result = convert_f32_to_i16(&[0.0]);
        assert_eq!(result[0], 0);
    }

    #[test]
    fn test_f32_to_i16_full_scale() {
        let result = convert_f32_to_i16(&[1.0]);
        assert_eq!(result[0], i16::MAX);
        let result = convert_f32_to_i16(&[-1.0]);
        assert_eq!(result[0], i16::MIN);
    }

    #[test]
    fn test_f32_to_i16_clamping() {
        let result = convert_f32_to_i16(&[2.0]);
        assert_eq!(result[0], i16::MAX);
        let result = convert_f32_to_i16(&[-2.0]);
        assert_eq!(result[0], i16::MIN);
    }

    #[test]
    fn test_f32_to_i16_midpoint() {
        let result = convert_f32_to_i16(&[0.5]);
        assert!((result[0] as f32 - i16::MAX as f32 * 0.5).abs() < 2.0);
    }

    #[test]
    fn test_mulaw_roundtrip() {
        // μ-law max representable magnitude is ~8031; test within dynamic range.
        // Quantization step size grows with magnitude; allow proportional tolerance.
        let test_values: &[i16] = &[
            0, 100, -100, 500, -500, 2000, -2000, 4000, -4000, 8000, -8000,
        ];
        for &original in test_values {
            let encoded = encode_mulaw(&[original]);
            let decoded = decode_mulaw(&encoded);
            // Allow ±4% tolerance (companding quantization error)
            let tolerance = ((original.unsigned_abs() as i32 / 25) + 4).max(8);
            let diff = (decoded[0] as i32 - original as i32).abs();
            assert!(
                diff <= tolerance,
                "μ-law roundtrip failed for {}: decoded={}, diff={}, tolerance={}",
                original,
                decoded[0],
                diff,
                tolerance
            );
        }
    }

    #[test]
    fn test_mulaw_encode_decode_zero() {
        // Encoding 0 should produce byte 0xFF (silence), which decodes back to 0
        let encoded = encode_mulaw(&[0i16]);
        assert_eq!(encoded[0], 0xFF);
        let decoded = decode_mulaw(&encoded);
        assert_eq!(decoded[0], 0);
    }

    #[test]
    fn test_alaw_roundtrip() {
        // A-law max representable magnitude is ~8064; test within dynamic range.
        let test_values: &[i16] = &[
            0, 100, -100, 500, -500, 2000, -2000, 4000, -4000, 8000, -8000,
        ];
        for &original in test_values {
            let encoded = encode_alaw(&[original]);
            let decoded = decode_alaw(&encoded);
            // Allow ±4% tolerance (companding quantization error)
            let tolerance = ((original.unsigned_abs() as i32 / 25) + 4).max(8);
            let diff = (decoded[0] as i32 - original as i32).abs();
            assert!(
                diff <= tolerance,
                "A-law roundtrip failed for {}: decoded={}, diff={}, tolerance={}",
                original,
                decoded[0],
                diff,
                tolerance
            );
        }
    }

    #[test]
    fn test_mulaw_decode_known_value() {
        // μ-law byte 0xFF: inverted = 0x00, positive, exp=0, mantissa=0
        // t = (0 << 3 + 132) << 0 = 132; value = 132 - 132 = 0
        let decoded = decode_mulaw(&[0xFF]);
        assert_eq!(decoded[0], 0);

        // μ-law byte 0x80: inverted = 0x7F, positive, exp=7, mantissa=15
        // t = (120 + 132) << 7 = 252 << 7 = 32256; value = 32256 - 132 = 32124
        let decoded = decode_mulaw(&[0x80]);
        assert_eq!(decoded[0], 32124);

        // μ-law byte 0x00: inverted = 0xFF, negative, exp=7, mantissa=15
        // t = (120 + 132) << 7 = 32256; value = 132 - 32256 = -32124
        let decoded = decode_mulaw(&[0x00]);
        assert_eq!(decoded[0], -32124);
    }

    #[test]
    fn test_alaw_decode_known_value() {
        // A-law byte 0xD5: XOR 0x55 = 0x80 → positive, seg=0, mantissa=0
        // value = (2*0 + 33) << 0 - 32 = 33 - 32 = 1
        let decoded = decode_alaw(&[0xD5]);
        assert_eq!(decoded[0], 1);

        // A-law byte 0xAA: XOR 0x55 = 0xFF → positive, seg=7, mantissa=15
        // value = (2*15 + 33) << 7 - 32 = 63*128 - 32 = 8064 - 32 = 8032
        let decoded = decode_alaw(&[0xAA]);
        assert_eq!(decoded[0], 8032);
    }

    #[test]
    fn test_u8_to_i16() {
        let result = convert_u8_to_i16(&[128]); // silence
        assert_eq!(result[0], 0);

        let result = convert_u8_to_i16(&[255]); // max
        assert!(result[0] > 32000);

        let result = convert_u8_to_i16(&[0]); // min
        assert!(result[0] < -32000);
    }

    #[test]
    fn test_i16_to_f32_roundtrip() {
        let original = vec![0i16, 1000, -1000, i16::MAX, i16::MIN];
        let f32_samples = convert_i16_to_f32(&original);
        let i16_samples = convert_f32_to_i16(&f32_samples);
        for (orig, conv) in original.iter().zip(i16_samples.iter()) {
            let diff = (orig - conv).abs();
            assert!(
                diff <= 1,
                "roundtrip mismatch: {} vs {} (diff={})",
                orig,
                conv,
                diff
            );
        }
    }

    #[test]
    fn test_i32_to_i16() {
        let result = convert_i32_to_i16(&[0]);
        assert_eq!(result[0], 0);

        let result = convert_i32_to_i16(&[0x7FFF0000]);
        assert_eq!(result[0], i16::MAX);

        let result = convert_i32_to_i16(&[0x80000000u32 as i32]);
        assert_eq!(result[0], i16::MIN);
    }

    #[test]
    fn test_i24_to_i16() {
        // Zero
        let result = convert_i24_to_i16(&[0x00, 0x00, 0x00]);
        assert_eq!(result[0], 0);

        // Max positive 24-bit: 0x7FFFFF = 8388607
        let result = convert_i24_to_i16(&[0xFF, 0xFF, 0x7F]);
        assert!(result[0] > 32000);

        // Min negative 24-bit: 0x800000 = -8388608
        let result = convert_i24_to_i16(&[0x00, 0x00, 0x80]);
        assert!(result[0] < -32000);
    }

    #[test]
    fn test_adpcm_ms_mono_silence() {
        // Create a minimal MS ADPCM block with silence (all zeros)
        // Block: predictor(1) + delta(2) + s1(2) + s2(2) = 7 bytes header
        // Then nibble data for (samples_per_block - 2) samples
        let samples_per_block = 8u16;
        let channels = 1u16;
        let header_size = 7;
        let nibble_count = (samples_per_block - 2) as usize * channels as usize;
        let nibble_bytes = nibble_count.div_ceil(2);
        let block_size = header_size + nibble_bytes;

        let mut block = vec![0u8; block_size];
        // predictor = 0
        block[0] = 0;
        // delta = 16 (minimum)
        block[1] = 16;
        block[2] = 0;
        // s1 = 0 (silence)
        block[3] = 0;
        block[4] = 0;
        // s2 = 0 (silence)
        block[5] = 0;
        block[6] = 0;
        // Nibbles = 0 (silence)

        let result = decode_adpcm_ms(&block, channels, samples_per_block);
        assert_eq!(result.len(), samples_per_block as usize * channels as usize);
        // All samples should be near zero for silence input
        for &sample in &result {
            assert!(sample.abs() < 100, "Expected near-silence, got {}", sample);
        }
    }

    #[test]
    fn test_adpcm_ima_mono_silence() {
        let samples_per_block = 9u16;
        let channels = 1u16;
        let header_size = 4;
        let encoded_samples = (samples_per_block - 1) as usize;
        let nibble_bytes = encoded_samples.div_ceil(2);
        let block_size = header_size + nibble_bytes;

        let mut block = vec![0u8; block_size];
        // Initial sample = 0 (silence)
        block[0] = 0;
        block[1] = 0;
        // Step index = 0
        block[2] = 0;
        block[3] = 0;
        // Nibbles = 0 (silence)

        let result = decode_adpcm_ima(&block, channels, samples_per_block);
        assert_eq!(result.len(), samples_per_block as usize * channels as usize);
        // All samples should be zero for silence input
        for &sample in &result {
            assert_eq!(sample, 0, "Expected silence, got {}", sample);
        }
    }

    #[test]
    fn test_adpcm_ms_tiny_samples_per_block_no_panic() {
        // Malformed WAVE data with samples_per_block == 1 or 2 used to
        // underflow on `samples_per_block - 2`; it must decode to nothing
        // instead of panicking.
        let result = decode_adpcm_ms(&[0u8; 16], 1, 1);
        assert!(result.is_empty());
        let result = decode_adpcm_ms(&[0u8; 16], 2, 2);
        assert!(result.is_empty());
    }

    #[test]
    fn test_decode_to_pcm16_float() {
        // 4 bytes of f32 = 1.0
        let data = 1.0f32.to_le_bytes().to_vec();
        let result = decode_to_pcm16(&data, 0x0003, 1, 32, 0);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], i16::MAX);
    }

    #[test]
    fn test_decode_to_pcm16_mulaw() {
        let encoded = encode_mulaw(&[0i16]);
        let result = decode_to_pcm16(&encoded, 0x0007, 1, 8, 0);
        assert_eq!(result.len(), 1);
        let diff = (result[0] as i32).abs();
        assert!(diff < 512);
    }

    #[test]
    fn test_decode_to_pcm16_pcm16() {
        let data = i16::to_le_bytes(1234).to_vec();
        let result = decode_to_pcm16(&data, 0x0001, 1, 16, 0);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 1234);
    }

    #[test]
    fn test_decode_to_pcm16_pcm8() {
        let result = decode_to_pcm16(&[128], 0x0001, 1, 8, 0);
        assert_eq!(result[0], 0);
    }

    #[test]
    fn test_decode_to_pcm16_unsupported() {
        let result = decode_to_pcm16(&[0u8; 4], 0x0050, 1, 16, 0);
        assert!(result.is_empty());
    }
}
