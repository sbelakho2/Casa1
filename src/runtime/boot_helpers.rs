//! Boot-time environment, keyboard-replay, and XAudio helpers.

use super::*;

pub(crate) fn load_keyboard_replay(
    env: &BTreeMap<String, String>,
) -> AppResult<Vec<KeyboardReplayEvent>> {
    let Some(raw) = env.get(KEYBOARD_REPLAY_ENV) else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<KeyboardReplayEvent>>(raw).map_err(|error| {
        AppError::new(
            ReasonCode::RcCliInvalid,
            format!("invalid {KEYBOARD_REPLAY_ENV} payload"),
        )
        .with_hint(error.to_string())
    })
}

pub(crate) fn load_trace_categories(env: &BTreeMap<String, String>) -> Option<BTreeSet<String>> {
    let raw = env.get(TRACE_CATEGORIES_ENV)?;
    Some(
        raw.split(',')
            .map(str::trim)
            .filter(|category| !category.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
    )
}

pub(crate) fn read_wave_format(memory: &MemoryImage, address: u64) -> AppResult<WaveFormat> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            "source voice format pointer must not be null",
        ));
    }
    let format_tag = read_guest_u16(memory, address)?;
    let channels = read_guest_u16(memory, address + 2)?;
    let sample_rate = read_guest_u32(memory, address + 4)?;
    let block_align = read_guest_u16(memory, address + 12)?;
    let bits_per_sample = read_guest_u16(memory, address + 14)?;
    let sample_format = match (format_tag, bits_per_sample) {
        (1, 16) => SampleFormat::Pcm16,
        (3, 32) => SampleFormat::Float32,
        _ => {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!(
                    "unsupported WAVEFORMATEX tag={format_tag} bits_per_sample={bits_per_sample}"
                ),
            ));
        }
    };
    let expected_block_align = channels as usize
        * match sample_format {
            SampleFormat::Pcm16 => 2,
            SampleFormat::Float32 => 4,
        };
    if block_align as usize != expected_block_align {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!(
                "invalid WAVEFORMATEX block align {block_align}; expected {expected_block_align}"
            ),
        ));
    }
    Ok(WaveFormat {
        channels,
        sample_rate,
        sample_format,
    })
}

pub(crate) fn read_xaudio2_buffer(
    memory: &MemoryImage,
    address: u64,
    format: &WaveFormat,
) -> AppResult<(AudioSamples, u32)> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            "XAUDIO2_BUFFER pointer must not be null",
        ));
    }
    let audio_bytes = read_guest_u32(memory, address + 4)?;
    let audio_data = memory.read_u64(address + 8)?;
    let play_begin = read_guest_u32(memory, address + 16)?;
    let play_length = read_guest_u32(memory, address + 20)?;
    let loop_begin = read_guest_u32(memory, address + 24)?;
    let loop_length = read_guest_u32(memory, address + 28)?;
    let loop_count = read_guest_u32(memory, address + 32)?;
    if audio_bytes == 0
        || audio_data == 0
        || play_begin != 0
        || play_length != 0
        || loop_begin != 0
        || loop_length != 0
        || loop_count != 0
    {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            "only full, non-looping XAUDIO2_BUFFER payloads are currently supported",
        ));
    }
    let bytes = read_guest_bytes(memory, audio_data, audio_bytes as usize)?;
    let samples = match format.sample_format {
        SampleFormat::Pcm16 => {
            if bytes.len() % 2 != 0 {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!(
                        "PCM16 source buffer length {} is not sample-aligned",
                        bytes.len()
                    ),
                ));
            }
            let values = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            AudioSamples::Pcm16(values)
        }
        SampleFormat::Float32 => {
            if bytes.len() % 4 != 0 {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!(
                        "float32 source buffer length {} is not sample-aligned",
                        bytes.len()
                    ),
                ));
            }
            let values = bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect::<Vec<_>>();
            AudioSamples::Float32(values)
        }
    };
    Ok((samples, audio_bytes))
}

/// Collect the decoded blocks of a hot function starting at `entry` by
/// following decoded static jump targets.  Returns `None` unless at least two
/// blocks are available (a single block has nothing for whole-function Tier-2
/// to add over the per-block tiers).
pub(crate) fn collect_tier2_function_blocks(
    cache: &U64Map<CachedBlockEntry>,
    entry: u64,
) -> Option<Vec<crate::jit_ssa::FunctionBlock>> {
    const MAX_FUNCTION_BLOCKS: usize = 16;
    let mut blocks = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut queue = std::collections::VecDeque::from([entry]);
    while let Some(address) = queue.pop_front() {
        if blocks.len() >= MAX_FUNCTION_BLOCKS || !seen.insert(address) {
            continue;
        }
        let Some(cached) = cache.get(&address) else {
            continue;
        };
        let ir = cached.cached.translated.ir.clone();
        if ir.is_empty() {
            continue;
        }
        if let Some(last) = ir.last() {
            match last {
                crate::cpu::IrInstruction::Jump { target } => queue.push_back(*target),
                crate::cpu::IrInstruction::JumpIf {
                    target,
                    fallthrough,
                    ..
                } => {
                    queue.push_back(*target);
                    queue.push_back(*fallthrough);
                }
                _ => {}
            }
        }
        blocks.push(crate::jit_ssa::FunctionBlock::new(address, ir));
    }
    (blocks.len() > 1).then_some(blocks)
}
