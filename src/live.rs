use crate::audio::WaveFormat;
use crate::error::{AppError, AppResult};
use crate::gfx::DxgiFormat;
use crate::reason::ReasonCode;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use minifb::{Key, KeyRepeat, Scale, Window, WindowOptions};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct LiveFrame {
    pub width: u32,
    pub height: u32,
    pub format: DxgiFormat,
    pub bytes: Vec<u8>,
    pub displayed_frame_index: u64,
}

#[derive(Debug, Clone)]
pub struct LiveAudioChunk {
    pub format: WaveFormat,
    pub samples: Vec<f32>,
}

#[derive(Debug, Clone)]
pub enum LiveInputEvent {
    KeyDown {
        scancode: u16,
        shift: bool,
        altgr: bool,
    },
    CloseRequested,
}

#[derive(Debug)]
pub struct LivePeSession {
    pub frame_tx: Sender<LiveFrame>,
    pub audio_tx: Sender<LiveAudioChunk>,
    pub input_rx: Receiver<LiveInputEvent>,
}

#[derive(Debug)]
pub struct LiveHostSession {
    pub frame_rx: Receiver<LiveFrame>,
    pub audio_rx: Receiver<LiveAudioChunk>,
    pub input_tx: Sender<LiveInputEvent>,
}

pub fn new_live_session() -> (LiveHostSession, LivePeSession) {
    let (frame_tx, frame_rx) = bounded(4);
    let (audio_tx, audio_rx) = bounded(64);
    let (input_tx, input_rx) = unbounded();
    (
        LiveHostSession {
            frame_rx,
            audio_rx,
            input_tx,
        },
        LivePeSession {
            frame_tx,
            audio_tx,
            input_rx,
        },
    )
}

pub fn run_live_host_session<T>(
    title: &str,
    session: LiveHostSession,
    worker: JoinHandle<AppResult<T>>,
) -> AppResult<T> {
    let audio = LiveAudioOutput::new()?;
    let mut window: Option<Window> = None;
    let mut frame_buffer = Vec::new();
    let mut frame_width = 0_usize;
    let mut frame_height = 0_usize;
    let mut latest_frame: Option<LiveFrame> = None;
    let mut close_requested = false;

    loop {
        audio.drain(&session.audio_rx);
        while let Ok(frame) = session.frame_rx.try_recv() {
            latest_frame = Some(frame);
        }

        if window.is_none() {
            if latest_frame.is_none() {
                if worker.is_finished() {
                    break;
                }
                match session.frame_rx.recv_timeout(Duration::from_millis(16)) {
                    Ok(frame) => {
                        latest_frame = Some(frame);
                    }
                    Err(_) => continue,
                }
            }

            if let Some(frame) = latest_frame.take() {
                let mut created_window = create_window(title, frame.width as usize, frame.height as usize)?;
                frame_width = frame.width as usize;
                frame_height = frame.height as usize;
                frame_buffer = decode_frame_buffer(&frame)?;
                created_window
                    .update_with_buffer(&frame_buffer, frame_width, frame_height)
                    .map_err(|error| {
                        AppError::new(
                            ReasonCode::RcIo,
                            format!("failed to draw initial live frame: {error}"),
                        )
                    })?;
                window = Some(created_window);
            }
        }

        let Some(window_ref) = window.as_mut() else {
            continue;
        };

        if let Some(frame) = latest_frame.take() {
            if frame.width as usize != frame_width || frame.height as usize != frame_height {
                *window_ref = create_window(title, frame.width as usize, frame.height as usize)?;
                frame_width = frame.width as usize;
                frame_height = frame.height as usize;
            }
            frame_buffer = decode_frame_buffer(&frame)?;
        }

        pump_keyboard(window_ref, &session.input_tx);
        if window_ref.is_key_down(Key::Escape) && !close_requested {
            let _ = session.input_tx.send(LiveInputEvent::CloseRequested);
            close_requested = true;
        }

        if frame_width != 0 && frame_height != 0 {
            window_ref
                .update_with_buffer(&frame_buffer, frame_width, frame_height)
                .map_err(|error| {
                    AppError::new(
                        ReasonCode::RcIo,
                        format!("failed to present live frame: {error}"),
                    )
                })?;
        }

        if !window_ref.is_open() && !close_requested {
            let _ = session.input_tx.send(LiveInputEvent::CloseRequested);
            close_requested = true;
        }

        if worker.is_finished() {
            break;
        }
    }

    worker
        .join()
        .map_err(|_| AppError::new(ReasonCode::RcRunnerProtocolInvalid, "live PE worker panicked"))?
}

fn create_window(title: &str, width: usize, height: usize) -> AppResult<Window> {
    let mut window = Window::new(
        &format!(
            "{title}  |  A/D move  S soft drop  W/Q rotate  Space hard drop  Enter start  P pause  N/R new  Esc quit"
        ),
        width,
        height,
        WindowOptions {
            resize: true,
            scale: Scale::X8,
            ..WindowOptions::default()
        },
    )
    .map_err(|error| {
        AppError::new(
            ReasonCode::RcIo,
            format!("failed to create live play window: {error}"),
        )
    })?;
    #[cfg(target_os = "macos")]
    window.topmost(true);
    window.set_target_fps(60);
    Ok(window)
}

fn collect_scancodes_for_frame<F, I>(mut is_key_down: F, pressed_keys: I) -> Vec<u16>
where
    F: FnMut(Key) -> bool,
    I: IntoIterator<Item = Key>,
{
    let mut scancodes = Vec::new();

    if is_key_down(Key::A) || is_key_down(Key::Left) {
        scancodes.push(0x1e);
    }
    if is_key_down(Key::D) || is_key_down(Key::Right) {
        scancodes.push(0x20);
    }
    if is_key_down(Key::S) || is_key_down(Key::Down) {
        scancodes.push(0x1f);
    }

    for key in pressed_keys {
        let Some(scancode) = map_action_key_to_scancode(key) else {
            continue;
        };
        scancodes.push(scancode);
    }

    scancodes
}

fn pump_keyboard(window: &Window, input_tx: &Sender<LiveInputEvent>) {
    let shift = window.is_key_down(Key::LeftShift) || window.is_key_down(Key::RightShift);
    let altgr = window.is_key_down(Key::RightAlt);

    for scancode in collect_scancodes_for_frame(
        |key| window.is_key_down(key),
        window.get_keys_pressed(KeyRepeat::No),
    ) {
        send_key(input_tx, scancode, shift, altgr);
    }
}

fn send_key(input_tx: &Sender<LiveInputEvent>, scancode: u16, shift: bool, altgr: bool) {
    let _ = input_tx.send(LiveInputEvent::KeyDown {
        scancode,
        shift,
        altgr,
    });
}

fn map_action_key_to_scancode(key: Key) -> Option<u16> {
    match key {
        Key::W | Key::Up => Some(0x11),
        Key::Q => Some(0x10),
        Key::P => Some(0x19),
        Key::N => Some(0x31),
        Key::R => Some(0x13),
        Key::Enter => Some(0x1c),
        Key::Space => Some(0x39),
        _ => None,
    }
}

fn decode_frame_buffer(frame: &LiveFrame) -> AppResult<Vec<u32>> {
    let expected_bytes = (frame.width as usize)
        .checked_mul(frame.height as usize)
        .and_then(|pixel_count| pixel_count.checked_mul(4))
        .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "live frame dimensions overflow"))?;
    if frame.bytes.len() < expected_bytes {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!(
                "live frame buffer is too small for {}x{} {:?}",
                frame.width, frame.height, frame.format
            ),
        ));
    }

    let mut buffer = Vec::with_capacity(frame.width as usize * frame.height as usize);
    match frame.format {
        DxgiFormat::B8G8R8A8Unorm => {
            for chunk in frame.bytes[..expected_bytes].chunks_exact(4) {
                buffer.push(((chunk[2] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[0] as u32);
            }
        }
        DxgiFormat::R8G8B8A8Unorm => {
            for chunk in frame.bytes[..expected_bytes].chunks_exact(4) {
                buffer.push(((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32);
            }
        }
        other => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("live frame presentation does not support {other:?}"),
            ))
        }
    }
    Ok(buffer)
}

struct LiveAudioOutput {
    _stream: cpal::Stream,
    sample_rate: u32,
    channels: u16,
    queue: Arc<Mutex<VecDeque<f32>>>,
}

impl LiveAudioOutput {
    fn new() -> AppResult<Self> {
        let host = cpal::default_host();
        let device = host.default_output_device().ok_or_else(|| {
            AppError::new(ReasonCode::RcAudioUnsupported, "no host audio output device is available")
        })?;
        let supported_config = device.default_output_config().map_err(|error| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to read the host audio output config: {error}"),
            )
        })?;
        let sample_rate = supported_config.sample_rate().0;
        let channels = supported_config.channels();
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let callback_queue = Arc::clone(&queue);
        let error_callback = |error| {
            eprintln!("{{\"reason_code\":1017,\"reason_name\":\"RC_AUDIO_UNSUPPORTED\",\"message\":\"live audio stream error: {error}\",\"reproduction_hints\":[]}}");
        };
        let stream_config = supported_config.config();
        let stream = match supported_config.sample_format() {
            cpal::SampleFormat::F32 => device.build_output_stream(
                &stream_config,
                move |data: &mut [f32], _| fill_output_f32(data, &callback_queue),
                error_callback,
                None,
            ),
            cpal::SampleFormat::I16 => device.build_output_stream(
                &stream_config,
                move |data: &mut [i16], _| fill_output_i16(data, &callback_queue),
                error_callback,
                None,
            ),
            cpal::SampleFormat::U16 => device.build_output_stream(
                &stream_config,
                move |data: &mut [u16], _| fill_output_u16(data, &callback_queue),
                error_callback,
                None,
            ),
            other => {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!("unsupported host audio sample format {other:?}"),
                ))
            }
        }
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to build the live audio output stream: {error}"),
            )
        })?;
        stream.play().map_err(|error| {
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!("failed to start the live audio output stream: {error}"),
            )
        })?;
        Ok(Self {
            _stream: stream,
            sample_rate,
            channels,
            queue,
        })
    }

    fn drain(&self, audio_rx: &Receiver<LiveAudioChunk>) {
        while let Ok(chunk) = audio_rx.try_recv() {
            self.push_chunk(chunk);
        }
    }

    fn push_chunk(&self, chunk: LiveAudioChunk) {
        let adapted = adapt_audio_chunk(
            &chunk.samples,
            chunk.format.channels,
            chunk.format.sample_rate,
            self.channels,
            self.sample_rate,
        );
        if let Ok(mut queue) = self.queue.lock() {
            queue.extend(adapted);
            let max_samples = self.sample_rate as usize * self.channels as usize * 4;
            while queue.len() > max_samples {
                queue.pop_front();
            }
        }
    }
}

fn fill_output_f32(output: &mut [f32], queue: &Arc<Mutex<VecDeque<f32>>>) {
    let Ok(mut samples) = queue.lock() else {
        output.fill(0.0);
        return;
    };
    for sample in output.iter_mut() {
        *sample = samples.pop_front().unwrap_or(0.0).clamp(-1.0, 1.0);
    }
}

fn fill_output_i16(output: &mut [i16], queue: &Arc<Mutex<VecDeque<f32>>>) {
    let Ok(mut samples) = queue.lock() else {
        output.fill(0);
        return;
    };
    for sample in output.iter_mut() {
        let value = samples.pop_front().unwrap_or(0.0).clamp(-1.0, 1.0);
        *sample = (value * i16::MAX as f32) as i16;
    }
}

fn fill_output_u16(output: &mut [u16], queue: &Arc<Mutex<VecDeque<f32>>>) {
    let Ok(mut samples) = queue.lock() else {
        output.fill(u16::MAX / 2);
        return;
    };
    for sample in output.iter_mut() {
        let value = samples.pop_front().unwrap_or(0.0).clamp(-1.0, 1.0);
        *sample = (((value + 1.0) * 0.5) * u16::MAX as f32) as u16;
    }
}

fn adapt_audio_chunk(
    samples: &[f32],
    input_channels: u16,
    input_sample_rate: u32,
    output_channels: u16,
    output_sample_rate: u32,
) -> Vec<f32> {
    let input_channels = input_channels.max(1) as usize;
    let output_channels = output_channels.max(1) as usize;
    if samples.is_empty() {
        return Vec::new();
    }
    let input_frames = samples.len() / input_channels;
    if input_frames == 0 {
        return Vec::new();
    }
    let output_frames = if input_sample_rate == output_sample_rate {
        input_frames
    } else {
        ((input_frames as u64 * output_sample_rate as u64) / input_sample_rate as u64).max(1) as usize
    };
    let mut output = vec![0.0; output_frames * output_channels];
    for output_frame in 0..output_frames {
        let input_frame = if input_sample_rate == output_sample_rate {
            output_frame.min(input_frames - 1)
        } else {
            ((output_frame as u64 * input_sample_rate as u64) / output_sample_rate as u64) as usize
        }
        .min(input_frames - 1);
        let source = &samples[input_frame * input_channels..(input_frame + 1) * input_channels];
        for channel in 0..output_channels {
            output[output_frame * output_channels + channel] = remap_channel(source, channel, output_channels);
        }
    }
    output
}

fn remap_channel(source: &[f32], channel: usize, output_channels: usize) -> f32 {
    match (source.len(), output_channels) {
        (1, _) => source[0],
        (2, 1) => (source[0] + source[1]) * 0.5,
        (2, _) => source[channel.min(1)],
        (_, 1) => source.iter().copied().sum::<f32>() / source.len() as f32,
        _ => source.get(channel).copied().unwrap_or(0.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_scancodes_for_frame_emits_held_movement_and_pressed_actions() {
        let held = [Key::Left, Key::Down];
        let pressed = [Key::Space, Key::P];

        let scancodes = collect_scancodes_for_frame(|key| held.contains(&key), pressed);

        assert_eq!(scancodes, vec![0x1e, 0x1f, 0x39, 0x19]);
    }

    #[test]
    fn collect_scancodes_for_frame_keeps_rotate_one_shot() {
        let held = [Key::Up];

        let held_only = collect_scancodes_for_frame(|key| held.contains(&key), std::iter::empty());
        let pressed = collect_scancodes_for_frame(|_| false, [Key::Up]);

        assert!(held_only.is_empty());
        assert_eq!(pressed, vec![0x11]);
    }

    #[test]
    fn collect_scancodes_for_frame_supports_arrow_aliases_for_movement() {
        let held = [Key::Right];

        let scancodes = collect_scancodes_for_frame(|key| held.contains(&key), std::iter::empty());

        assert_eq!(scancodes, vec![0x20]);
    }
}