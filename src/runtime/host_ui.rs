//! Host message-box/beep and trace helpers.

use super::*;

pub(crate) fn show_host_message_box(title: &str, text: &str, dtm: bool) -> AppResult<()> {
    if dtm {
        return Ok(());
    }
    let status = Command::new("osascript")
        .arg("-e")
        .arg(format!(
            "display dialog {} with title {} buttons {{\"OK\"}} default button \"OK\" giving up after 1",
            apple_script_string(text),
            apple_script_string(title),
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| AppError::from_io(ReasonCode::RcIo, "failed to launch osascript for MessageBoxW", &error))?;
    if !status.success() {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!("osascript failed while showing MessageBoxW: {status}"),
        ));
    }
    Ok(())
}

pub(crate) fn play_host_beep(frequency_hz: u32, duration_ms: u32, dtm: bool) -> AppResult<()> {
    if dtm {
        return Ok(());
    }
    let temp_path = std::env::temp_dir().join(format!(
        "casa1-beep-{}-{}.wav",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0)
    ));
    let wav = synthesize_beep_wav(frequency_hz.max(37), duration_ms.max(10));
    fs::write(&temp_path, wav).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to write host beep WAV {}", temp_path.display()),
            &error,
        )
    })?;
    let status = Command::new("afplay")
        .arg(&temp_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| {
            AppError::from_io(ReasonCode::RcIo, "failed to launch afplay for Beep", &error)
        })?;
    let _ = fs::remove_file(&temp_path);
    if !status.success() {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!("afplay failed while playing Beep: {status}"),
        ));
    }
    Ok(())
}

pub(crate) fn synthesize_beep_wav(frequency_hz: u32, duration_ms: u32) -> Vec<u8> {
    let sample_rate = 44_100_u32;
    let samples = ((sample_rate as u64 * duration_ms as u64) / 1000) as usize;
    let mut pcm = Vec::with_capacity(samples * 2);
    let amplitude = i16::MAX as f32 * 0.2;
    for index in 0..samples {
        let phase =
            (index as f32 * frequency_hz as f32 * std::f32::consts::TAU) / sample_rate as f32;
        let sample = (phase.sin() * amplitude) as i16;
        pcm.extend_from_slice(&sample.to_le_bytes());
    }

    let data_len = pcm.len() as u32;
    let mut wav = Vec::with_capacity(44 + pcm.len());
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + data_len).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16_u32.to_le_bytes());
    wav.extend_from_slice(&1_u16.to_le_bytes());
    wav.extend_from_slice(&1_u16.to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&(sample_rate * 2).to_le_bytes());
    wav.extend_from_slice(&2_u16.to_le_bytes());
    wav.extend_from_slice(&16_u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_len.to_le_bytes());
    wav.extend_from_slice(&pcm);
    wav
}

pub(crate) fn apple_script_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

pub(crate) fn trace_event(
    event_index: u64,
    category: &str,
    call_id: &str,
    parameters: BTreeMap<String, Value>,
    return_value: Value,
    side_effect_hashes: Vec<String>,
) -> TraceEvent {
    TraceEvent {
        event_index,
        category: category.to_string(),
        call_id: call_id.to_string(),
        parameters,
        return_value,
        get_last_error: None,
        side_effect_hashes,
    }
}
