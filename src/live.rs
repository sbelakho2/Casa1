use crate::audio::WaveFormat;
use crate::error::{AppError, AppResult};
use crate::gfx::DxgiFormat;
#[cfg(target_os = "macos")]
use crate::mac_window;
use crate::reason::ReasonCode;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use crossbeam_channel::{Receiver, Sender, bounded, unbounded};
use minifb::{
    Key, KeyRepeat, MouseButton as MinifbMouseButton, MouseMode, Scale, Window, WindowOptions,
};
use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Diagnostic trace: append a line (with newline) to /tmp/casa1_trace.log.
/// Each open/close is deliberately per-call so the file is always flushed
/// and readable from another process in real time.
#[allow(dead_code)]
pub fn live_trace(_line: &str) {
    // Disabled — file I/O per call was a massive performance bottleneck.
}

const LIVE_WINDOW_OFFSET: isize = 32;

/// Maximum window dimension for live presentation. Guest-provided frame
/// dimensions are untrusted; anything beyond this is rejected before it
/// reaches minifb.
const MAX_WINDOW_DIM: usize = 16384;

/// Maximum total pixel count for live presentation (~100 MP).
const MAX_WINDOW_PIXELS: usize = 100 * 1024 * 1024;

/// Validate that guest-provided frame dimensions can be presented.
fn validate_presentable_dims(width: usize, height: usize) -> AppResult<()> {
    if width == 0
        || height == 0
        || width > MAX_WINDOW_DIM
        || height > MAX_WINDOW_DIM
        || width
            .checked_mul(height)
            .is_none_or(|pixels| pixels > MAX_WINDOW_PIXELS)
    {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("live frame dimensions {width}x{height} are not presentable"),
        ));
    }
    Ok(())
}

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
    KeyUp {
        scancode: u16,
        shift: bool,
        altgr: bool,
    },
    MouseInput {
        x: i32,
        y: i32,
        left_pressed: bool,
        left_released: bool,
        right_pressed: bool,
        right_released: bool,
        middle_pressed: bool,
        middle_released: bool,
    },
    MouseScroll {
        x: i32,
        y: i32,
        delta_x: i32,
        delta_y: i32,
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

const EXPORT_LIVE_FRAME_ENV: &str = "CASA1_EXPORT_LIVE_FRAME";

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
    let loop_result = run_live_host_loop(title, session, &worker);
    live_trace("[live] run_live_host_session exiting — joining worker thread");
    // The worker is always joined, even when the host loop returns early
    // (window creation, export, or decode failure), so it never keeps
    // running detached.
    let worker_result = worker.join().map_err(|_| {
        live_trace("[live] worker thread panicked!");
        AppError::new(
            ReasonCode::RcRunnerProtocolInvalid,
            "live PE worker panicked",
        )
    })?;
    loop_result?;
    worker_result
}

fn run_live_host_loop<T>(
    title: &str,
    session: LiveHostSession,
    worker: &JoinHandle<AppResult<T>>,
) -> AppResult<()> {
    let audio = LiveAudioOutput::new()?;
    let export_live_frame_path = std::env::var(EXPORT_LIVE_FRAME_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty());
    // No window is created at startup: the live window only exists once a
    // real guest frame arrives, and is sized to that frame's validated
    // dimensions.  If the worker finishes without ever producing a frame,
    // the loop exits cleanly below without creating any window.
    let mut window: Option<Window> = None;
    let mut frame_buffer = Vec::new();
    let mut frame_width = 0usize;
    let mut frame_height = 0usize;
    let mut latest_frame: Option<LiveFrame> = None;
    let mut close_requested = false;
    let mut held_scancodes = BTreeSet::new();
    let mut previous_mouse_pos = None;
    let mut left_mouse_down = false;
    let mut right_mouse_down = false;
    let mut middle_mouse_down = false;

    let mut trace_no_frame_counter: u64 = 0;
    let mut last_jit_watchdog = std::time::Instant::now();
    loop {
        // Pump pending main-thread work (AppKit calls queued by the PE
        // runtime worker via run_on_main).  This must happen before any
        // frame processing so that window creation, layer attachment, and
        // event polling dispatched from the worker thread are serviced
        // promptly.
        #[cfg(target_os = "macos")]
        mac_window::pump_main_queue();

        audio.drain(&session.audio_rx);
        let mut frames_this_iteration = drain_frames(&session.frame_rx, &mut latest_frame);

        if frames_this_iteration > 0 {
            live_trace(&format!(
                "[live] received {frames_this_iteration} frame(s) — showing content now"
            ));
            trace_no_frame_counter = 0;
        } else {
            trace_no_frame_counter += 1;
            if trace_no_frame_counter.is_multiple_of(1000) {
                live_trace(&format!(
                    "[live] no frames yet after {} loop iterations (worker_finished={})",
                    trace_no_frame_counter,
                    worker.is_finished(),
                ));
            }
        }

        // Worker finished with zero frames ever received: exit cleanly,
        // never having created a window.  One final drain first: a worker
        // that published its last frame and terminated between the drain
        // above and this check must not lose that frame.
        if latest_frame.is_none() && worker.is_finished() {
            frames_this_iteration += drain_frames(&session.frame_rx, &mut latest_frame);
            if latest_frame.is_none() {
                live_trace("[live] worker finished without producing any frames — exiting");
                break;
            }
        }

        let frame_changed = process_latest_frame(
            &mut latest_frame,
            &mut window,
            &mut frame_buffer,
            &mut frame_width,
            &mut frame_height,
            title,
            export_live_frame_path.as_deref().map(Path::new),
        )?;

        if let Some(window) = window.as_mut() {
            pump_keyboard(window, &session.input_tx, &mut held_scancodes);
            pump_mouse(
                window,
                &session.input_tx,
                &mut previous_mouse_pos,
                &mut left_mouse_down,
                &mut right_mouse_down,
                &mut middle_mouse_down,
            );
            if window.is_key_down(Key::Escape) && !close_requested {
                release_held_keys(&session.input_tx, &mut held_scancodes);
                if let Err(e) = session.input_tx.send(LiveInputEvent::CloseRequested) {
                    eprintln!("[live] failed to send CloseRequested (Escape): {e}");
                }
                close_requested = true;
            }

            if frame_changed {
                window
                    .update_with_buffer(&frame_buffer, frame_width, frame_height)
                    .map_err(|error| {
                        AppError::new(
                            ReasonCode::RcIo,
                            format!("failed to present live frame: {error}"),
                        )
                    })?;
            } else {
                window.update();
            }

            if !window.is_open() && !close_requested {
                release_held_keys(&session.input_tx, &mut held_scancodes);
                if let Err(e) = session.input_tx.send(LiveInputEvent::CloseRequested) {
                    eprintln!("[live] failed to send CloseRequested (window closed): {e}");
                }
                close_requested = true;
            }
        }

        // ── JIT watchdog: force chain-breaking across threads ────────────
        // Scheduling model: the HOST-SIDE block-dispatch safepoint (2 ms)
        // in pe_runtime.rs is the PRIMARY mechanism — every 2 ms of wall
        // time between dispatched blocks it pumps pending guest threads,
        // drains timer/APC queues and advances the guest clock, so a guest
        // spin can neither freeze the clock nor starve event sources.
        //
        // This watchdog remains as a JIT-chain FALLBACK for when chains
        // are re-enabled: if the PE runtime worker is stuck inside
        // JIT-compiled block chains (pure ARM64 B instructions that never
        // return to the dispatcher), neither the main loop's safepoint nor
        // the block-dispatch timer will ever fire.
        //
        // The watchdog calls `force_break_all_chains()` every ~500 ms,
        // which physically writes RET instructions over every chain patch
        // location in the compiled code.  On the next chained-block
        // boundary, execution will return to the dispatcher where the
        // safepoint and frame pipeline can run.
        //
        // Also set `JIT_CHAIN_BREAK_REQUESTED` so that `chain_blocks()`
        // (called from `get_or_compile`) refuses to form new chains
        // until the flag is cleared by the main loop.
        //
        // Behavior is intentionally unchanged: the host-side safepoint is
        // the active scheduler today (the JIT is dormant), and the
        // watchdog is dormant code that activates automatically when JIT
        // execution and chain formation are re-enabled.
        if last_jit_watchdog.elapsed().as_millis() >= 500 {
            crate::jit::JIT_CHAIN_BREAK_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
            crate::jit::force_break_all_chains();
            last_jit_watchdog = std::time::Instant::now();
            let sigbus_total =
                crate::jit::SIGBUS_TOTAL_EVENTS.load(std::sync::atomic::Ordering::Relaxed);
            let storm =
                crate::jit::JIT_FAULT_STORM_DISABLED.load(std::sync::atomic::Ordering::Relaxed);
            live_trace(&format!(
                "[live] jit watchdog: requested chain break (sigbus_total={sigbus_total} storm_disabled={storm})"
            ));
        }

        // Yield the CPU when no new frame is available to prevent
        // 99% CPU usage from tight polling in the live session loop.
        // An 8 ms sleep limits the idle poll rate to ~125 Hz, which
        // is more than enough for UI responsiveness while keeping
        // CPU usage near zero when Steam is rendering through its
        // own native windows (not through the live frame pipeline).
        if !frame_changed {
            std::thread::sleep(std::time::Duration::from_millis(8));
        }

        if worker.is_finished() {
            // Final drain before exiting: a worker that published its last
            // frame and terminated between the top-of-loop drain and this
            // check must not lose that frame (the run would otherwise exit
            // windowless with a real frame still pending).
            drain_frames(&session.frame_rx, &mut latest_frame);
            let final_changed = process_latest_frame(
                &mut latest_frame,
                &mut window,
                &mut frame_buffer,
                &mut frame_width,
                &mut frame_height,
                title,
                export_live_frame_path.as_deref().map(Path::new),
            )?;
            if final_changed && let Some(window) = window.as_mut() {
                window
                    .update_with_buffer(&frame_buffer, frame_width, frame_height)
                    .map_err(|error| {
                        AppError::new(
                            ReasonCode::RcIo,
                            format!("failed to present live frame: {error}"),
                        )
                    })?;
            }
            live_trace("[live] worker finished — exiting main loop");
            break;
        }
    }

    Ok(())
}

/// Drain every pending frame from the live channel into `latest_frame`.
/// Returns the number of frames consumed.  Extracted so the finish-path
/// final drain can reuse the exact same consume semantics as the main loop.
fn drain_frames(rx: &Receiver<LiveFrame>, latest_frame: &mut Option<LiveFrame>) -> u32 {
    let mut count = 0u32;
    while let Ok(frame) = rx.try_recv() {
        *latest_frame = Some(frame);
        count += 1;
    }
    count
}

/// Consume the latest frame, (re)creating the window and decoding the pixel
/// buffer as needed.  Returns true when the window should present the new
/// buffer.  Frame dimensions come from the guest pipeline and are untrusted,
/// so they are validated before reaching minifb.
#[allow(clippy::too_many_arguments)]
fn process_latest_frame(
    latest_frame: &mut Option<LiveFrame>,
    window: &mut Option<Window>,
    frame_buffer: &mut Vec<u32>,
    frame_width: &mut usize,
    frame_height: &mut usize,
    title: &str,
    export_live_frame_path: Option<&Path>,
) -> AppResult<bool> {
    let Some(frame) = latest_frame.take() else {
        return Ok(false);
    };
    if window.is_none()
        || frame.width as usize != *frame_width
        || frame.height as usize != *frame_height
    {
        let width = frame.width as usize;
        let height = frame.height as usize;
        validate_presentable_dims(width, height)?;
        *window = Some(create_window(title, width, height)?);
        *frame_width = width;
        *frame_height = height;
    }
    if let Some(path) = export_live_frame_path {
        export_live_frame(&frame, path)?;
    }
    decode_frame_buffer_into(&frame, frame_buffer)?;
    Ok(true)
}

fn create_window(title: &str, width: usize, height: usize) -> AppResult<Window> {
    let window_title = if title.is_empty() {
        "Casa1".to_string()
    } else {
        title.to_string()
    };
    let mut window = Window::new(
        &window_title,
        width,
        height,
        WindowOptions {
            resize: true,
            scale: Scale::FitScreen,
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
    {
        window.topmost(true);
        window.set_position(LIVE_WINDOW_OFFSET, LIVE_WINDOW_OFFSET);
    }
    Ok(window)
}

fn collect_scancodes_for_frame<F>(mut is_key_down: F) -> BTreeSet<u16>
where
    F: FnMut(Key) -> bool,
{
    let mut scancodes = BTreeSet::new();
    for key in ALL_MAPPED_KEYS {
        if is_key_down(*key)
            && let Some(scancode) = map_key_to_scancode(*key)
        {
            scancodes.insert(scancode);
        }
    }
    scancodes
}

fn collect_scancodes_from_keys<I>(keys: I) -> BTreeSet<u16>
where
    I: IntoIterator<Item = Key>,
{
    let keys = keys.into_iter().collect::<BTreeSet<_>>();
    collect_scancodes_for_frame(|key| keys.contains(&key))
}

fn scancode_transitions(previous: &BTreeSet<u16>, current: &BTreeSet<u16>) -> (Vec<u16>, Vec<u16>) {
    let pressed = current.difference(previous).copied().collect();
    let released = previous.difference(current).copied().collect();
    (pressed, released)
}

fn scancode_events_for_frame(
    previous: &BTreeSet<u16>,
    current: &BTreeSet<u16>,
    pressed_keys: &[Key],
    released_keys: &[Key],
) -> (Vec<u16>, Vec<u16>) {
    let (mut pressed, mut released) = scancode_transitions(previous, current);
    let mut pressed_set = pressed.iter().copied().collect::<BTreeSet<_>>();
    let mut released_set = released.iter().copied().collect::<BTreeSet<_>>();

    for scancode in collect_scancodes_from_keys(pressed_keys.iter().copied()) {
        if pressed_set.insert(scancode) {
            pressed.push(scancode);
        }
    }
    for scancode in collect_scancodes_from_keys(released_keys.iter().copied()) {
        if released_set.insert(scancode) {
            released.push(scancode);
        }
    }

    pressed.sort_unstable();
    released.sort_unstable();
    (pressed, released)
}

fn pump_keyboard(
    window: &Window,
    input_tx: &Sender<LiveInputEvent>,
    held_scancodes: &mut BTreeSet<u16>,
) {
    let shift = window.is_key_down(Key::LeftShift) || window.is_key_down(Key::RightShift);
    let altgr = window.is_key_down(Key::RightAlt);
    let current_scancodes = collect_scancodes_for_frame(|key| window.is_key_down(key));
    let pressed_keys = window.get_keys_pressed(KeyRepeat::No);
    let released_keys = window.get_keys_released();
    let (pressed, released) = scancode_events_for_frame(
        held_scancodes,
        &current_scancodes,
        &pressed_keys,
        &released_keys,
    );

    for scancode in pressed {
        send_key_down(input_tx, scancode, shift, altgr);
    }
    for scancode in released {
        send_key_up(input_tx, scancode, shift, altgr);
    }

    *held_scancodes = current_scancodes;
}

fn pump_mouse(
    window: &Window,
    input_tx: &Sender<LiveInputEvent>,
    previous_mouse_pos: &mut Option<(i32, i32)>,
    left_mouse_down: &mut bool,
    right_mouse_down: &mut bool,
    middle_mouse_down: &mut bool,
) {
    let current_mouse_pos = window
        .get_mouse_pos(MouseMode::Clamp)
        .map(|(x, y)| (x.round() as i32, y.round() as i32));
    let current_left_down = window.get_mouse_down(MinifbMouseButton::Left);
    let current_right_down = window.get_mouse_down(MinifbMouseButton::Right);
    let current_middle_down = window.get_mouse_down(MinifbMouseButton::Middle);
    let left_pressed = current_left_down && !*left_mouse_down;
    let left_released = !current_left_down && *left_mouse_down;
    let right_pressed = current_right_down && !*right_mouse_down;
    let right_released = !current_right_down && *right_mouse_down;
    let middle_pressed = current_middle_down && !*middle_mouse_down;
    let middle_released = !current_middle_down && *middle_mouse_down;

    // Scroll wheel: minifb reports the delta accumulated since the last
    // update, so forward it directly rather than treating it as a
    // cumulative position.
    if let Some(scroll) = window.get_scroll_wheel() {
        let scroll_delta_x = scroll.0 as i32;
        let scroll_delta_y = scroll.1 as i32;
        if (scroll_delta_x.abs() >= 1 || scroll_delta_y.abs() >= 1)
            && let Some((x, y)) = current_mouse_pos
            && let Err(e) = input_tx.send(LiveInputEvent::MouseScroll {
                x,
                y,
                delta_x: scroll_delta_x,
                delta_y: scroll_delta_y,
            })
        {
            eprintln!("[live] failed to send mouse scroll event: {e}");
        }
    }

    let mouse_changed = current_mouse_pos != *previous_mouse_pos
        || left_pressed
        || left_released
        || right_pressed
        || right_released
        || middle_pressed
        || middle_released;

    if let Some((x, y)) = current_mouse_pos
        && mouse_changed
        && let Err(e) = input_tx.send(LiveInputEvent::MouseInput {
            x,
            y,
            left_pressed,
            left_released,
            right_pressed,
            right_released,
            middle_pressed,
            middle_released,
        })
    {
        eprintln!("[live] failed to send mouse input event: {e}");
    }

    *previous_mouse_pos = current_mouse_pos;
    *left_mouse_down = current_left_down;
    *right_mouse_down = current_right_down;
    *middle_mouse_down = current_middle_down;
}

fn send_key_down(input_tx: &Sender<LiveInputEvent>, scancode: u16, shift: bool, altgr: bool) {
    if let Err(e) = input_tx.send(LiveInputEvent::KeyDown {
        scancode,
        shift,
        altgr,
    }) {
        eprintln!("[live] failed to send KeyDown scancode={scancode}: {e}");
    }
}

fn send_key_up(input_tx: &Sender<LiveInputEvent>, scancode: u16, shift: bool, altgr: bool) {
    if let Err(e) = input_tx.send(LiveInputEvent::KeyUp {
        scancode,
        shift,
        altgr,
    }) {
        eprintln!("[live] failed to send KeyUp scancode={scancode}: {e}");
    }
}

fn release_held_keys(input_tx: &Sender<LiveInputEvent>, held_scancodes: &mut BTreeSet<u16>) {
    for scancode in held_scancodes.iter().copied().collect::<Vec<_>>() {
        send_key_up(input_tx, scancode, false, false);
    }
    held_scancodes.clear();
}

/// All keys we track for scancode mapping.
const ALL_MAPPED_KEYS: &[Key] = &[
    // Letters
    Key::A,
    Key::B,
    Key::C,
    Key::D,
    Key::E,
    Key::F,
    Key::G,
    Key::H,
    Key::I,
    Key::J,
    Key::K,
    Key::L,
    Key::M,
    Key::N,
    Key::O,
    Key::P,
    Key::Q,
    Key::R,
    Key::S,
    Key::T,
    Key::U,
    Key::V,
    Key::W,
    Key::X,
    Key::Y,
    Key::Z,
    // Numbers (top row)
    Key::Key0,
    Key::Key1,
    Key::Key2,
    Key::Key3,
    Key::Key4,
    Key::Key5,
    Key::Key6,
    Key::Key7,
    Key::Key8,
    Key::Key9,
    // Function keys
    Key::F1,
    Key::F2,
    Key::F3,
    Key::F4,
    Key::F5,
    Key::F6,
    Key::F7,
    Key::F8,
    Key::F9,
    Key::F10,
    Key::F11,
    Key::F12,
    // Navigation
    Key::Up,
    Key::Down,
    Key::Left,
    Key::Right,
    Key::Home,
    Key::End,
    Key::PageUp,
    Key::PageDown,
    Key::Insert,
    Key::Delete,
    // Modifiers
    Key::LeftShift,
    Key::RightShift,
    Key::LeftCtrl,
    Key::RightCtrl,
    Key::LeftAlt,
    Key::RightAlt,
    // Punctuation / symbols
    Key::Space,
    Key::Enter,
    Key::Backspace,
    Key::Tab,
    Key::Escape,
    Key::Backquote,
    Key::Minus,
    Key::Equal,
    Key::LeftBracket,
    Key::RightBracket,
    Key::Backslash,
    Key::Semicolon,
    Key::Apostrophe,
    Key::Comma,
    Key::Period,
    Key::Slash,
    // Keypad
    Key::NumPad0,
    Key::NumPad1,
    Key::NumPad2,
    Key::NumPad3,
    Key::NumPad4,
    Key::NumPad5,
    Key::NumPad6,
    Key::NumPad7,
    Key::NumPad8,
    Key::NumPad9,
    Key::NumPadPlus,
    Key::NumPadMinus,
    Key::NumPadAsterisk,
    Key::NumPadSlash,
    Key::NumPadDot,
    Key::NumPadEnter,
    // Lock keys
    Key::CapsLock,
    Key::NumLock,
    Key::ScrollLock,
    // Misc
    Key::Pause,
    Key::Menu,
];

fn map_key_to_scancode(key: Key) -> Option<u16> {
    match key {
        // Letters (PC scancodes, set 1)
        Key::A => Some(0x1e),
        Key::B => Some(0x30),
        Key::C => Some(0x2e),
        Key::D => Some(0x20),
        Key::E => Some(0x12),
        Key::F => Some(0x21),
        Key::G => Some(0x22),
        Key::H => Some(0x23),
        Key::I => Some(0x17),
        Key::J => Some(0x24),
        Key::K => Some(0x25),
        Key::L => Some(0x26),
        Key::M => Some(0x32),
        Key::N => Some(0x31),
        Key::O => Some(0x18),
        Key::P => Some(0x19),
        Key::Q => Some(0x10),
        Key::R => Some(0x13),
        Key::S => Some(0x1f),
        Key::T => Some(0x14),
        Key::U => Some(0x16),
        Key::V => Some(0x2f),
        Key::W => Some(0x11),
        Key::X => Some(0x2d),
        Key::Y => Some(0x15),
        Key::Z => Some(0x2c),
        // Numbers (top row)
        Key::Key0 => Some(0x0b),
        Key::Key1 => Some(0x02),
        Key::Key2 => Some(0x03),
        Key::Key3 => Some(0x04),
        Key::Key4 => Some(0x05),
        Key::Key5 => Some(0x06),
        Key::Key6 => Some(0x07),
        Key::Key7 => Some(0x08),
        Key::Key8 => Some(0x09),
        Key::Key9 => Some(0x0a),
        // Function keys
        Key::F1 => Some(0x3b),
        Key::F2 => Some(0x3c),
        Key::F3 => Some(0x3d),
        Key::F4 => Some(0x3e),
        Key::F5 => Some(0x3f),
        Key::F6 => Some(0x40),
        Key::F7 => Some(0x41),
        Key::F8 => Some(0x42),
        Key::F9 => Some(0x43),
        Key::F10 => Some(0x44),
        Key::F11 => Some(0x57),
        Key::F12 => Some(0x58),
        // Navigation (arrow keys alias to WASD for movement)
        Key::Up => Some(0x11),    // W
        Key::Down => Some(0x1f),  // S
        Key::Left => Some(0x1e),  // A
        Key::Right => Some(0x20), // D
        Key::Home => Some(0x47),
        Key::End => Some(0x4f),
        Key::PageUp => Some(0x49),
        Key::PageDown => Some(0x51),
        Key::Insert => Some(0x52),
        Key::Delete => Some(0x53),
        // Modifiers
        Key::LeftShift => Some(0x2a),
        Key::RightShift => Some(0x36),
        Key::LeftCtrl => Some(0x1d),
        Key::RightCtrl => Some(0x1d), // Ctrl scancode same, distinguished by extended bit
        Key::LeftAlt => Some(0x38),
        Key::RightAlt => Some(0x38), // Alt scancode same, distinguished by extended bit
        // Action keys
        Key::Space => Some(0x39),
        Key::Enter => Some(0x1c),
        Key::Backspace => Some(0x0e),
        Key::Tab => Some(0x0f),
        Key::Escape => Some(0x01),
        // Punctuation / symbols
        Key::Backquote => Some(0x29),
        Key::Minus => Some(0x0c),
        Key::Equal => Some(0x0d),
        Key::LeftBracket => Some(0x1a),
        Key::RightBracket => Some(0x1b),
        Key::Backslash => Some(0x2b),
        Key::Semicolon => Some(0x27),
        Key::Apostrophe => Some(0x28),
        Key::Comma => Some(0x33),
        Key::Period => Some(0x34),
        Key::Slash => Some(0x35),
        // Keypad
        Key::NumPad0 => Some(0x52),
        Key::NumPad1 => Some(0x4f),
        Key::NumPad2 => Some(0x50),
        Key::NumPad3 => Some(0x51),
        Key::NumPad4 => Some(0x4b),
        Key::NumPad5 => Some(0x4c),
        Key::NumPad6 => Some(0x4d),
        Key::NumPad7 => Some(0x47),
        Key::NumPad8 => Some(0x48),
        Key::NumPad9 => Some(0x49),
        Key::NumPadPlus => Some(0x4e),
        Key::NumPadMinus => Some(0x4a),
        Key::NumPadAsterisk => Some(0x37),
        Key::NumPadSlash => Some(0x35), // extended
        Key::NumPadDot => Some(0x53),
        Key::NumPadEnter => Some(0x1c), // extended
        // Lock keys
        Key::CapsLock => Some(0x3a),
        Key::NumLock => Some(0x45),
        Key::ScrollLock => Some(0x46),
        // Misc
        Key::Pause => Some(0x45), // Ctrl+Pause = 0x46 for Break
        Key::Menu => Some(0x5d),  // Application key (extended)
        _ => None,
    }
}

fn decode_frame_buffer_into(frame: &LiveFrame, buffer: &mut Vec<u32>) -> AppResult<()> {
    let expected_bytes = (frame.width as usize)
        .checked_mul(frame.height as usize)
        .and_then(|pixel_count| pixel_count.checked_mul(4))
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "live frame dimensions overflow",
            )
        })?;
    if frame.bytes.len() < expected_bytes {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!(
                "live frame buffer is too small for {}x{} {:?}",
                frame.width, frame.height, frame.format
            ),
        ));
    }

    buffer.clear();
    buffer.reserve(frame.width as usize * frame.height as usize);
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
            ));
        }
    }
    Ok(())
}

fn export_live_frame(frame: &LiveFrame, path: &Path) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            AppError::new(
                ReasonCode::RcIo,
                format!("failed to create {}: {error}", parent.display()),
            )
        })?;
    }

    let expected_bytes = (frame.width as usize)
        .checked_mul(frame.height as usize)
        .and_then(|pixel_count| pixel_count.checked_mul(4))
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "live frame dimensions overflow",
            )
        })?;
    if frame.bytes.len() < expected_bytes {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!(
                "live frame buffer is too small for {}x{} {:?}",
                frame.width, frame.height, frame.format
            ),
        ));
    }

    let mut ppm = format!("P6\n{} {}\n255\n", frame.width, frame.height).into_bytes();
    ppm.reserve(frame.width as usize * frame.height as usize * 3);
    match frame.format {
        DxgiFormat::B8G8R8A8Unorm => {
            for chunk in frame.bytes[..expected_bytes].chunks_exact(4) {
                ppm.extend_from_slice(&[chunk[2], chunk[1], chunk[0]]);
            }
        }
        DxgiFormat::R8G8B8A8Unorm => {
            for chunk in frame.bytes[..expected_bytes].chunks_exact(4) {
                ppm.extend_from_slice(&chunk[..3]);
            }
        }
        other => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("live frame export does not support {other:?}"),
            ));
        }
    }

    fs::write(path, ppm).map_err(|error| {
        AppError::new(
            ReasonCode::RcIo,
            format!("failed to write {}: {error}", path.display()),
        )
    })
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
            AppError::new(
                ReasonCode::RcAudioUnsupported,
                "no host audio output device is available",
            )
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
            eprintln!(
                "{{\"reason_code\":1017,\"reason_name\":\"RC_AUDIO_UNSUPPORTED\",\"message\":\"live audio stream error: {error}\",\"reproduction_hints\":[]}}"
            );
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
                ));
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

/// Upper bound on the number of resampled frames produced per chunk.
/// Guest-controlled sample rates must not be able to force multi-GB
/// allocations (the audio queue trims to a few seconds anyway).
const MAX_ADAPTED_FRAMES: usize = 4 * 1024 * 1024;

fn adapt_audio_chunk(
    samples: &[f32],
    input_channels: u16,
    input_sample_rate: u32,
    output_channels: u16,
    output_sample_rate: u32,
) -> Vec<f32> {
    let input_channels = input_channels.max(1) as usize;
    let output_channels = output_channels.max(1) as usize;
    // The sample rates come from the guest's WaveFormat and are untrusted:
    // a zero rate would divide by zero, and a tiny rate would explode the
    // resampled chunk size.
    let input_sample_rate = input_sample_rate.max(1) as u64;
    let output_sample_rate = output_sample_rate.max(1) as u64;
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
        let frames = (input_frames as u64)
            .saturating_mul(output_sample_rate)
            .checked_div(input_sample_rate)
            .unwrap_or(0)
            .max(1);
        frames.min(MAX_ADAPTED_FRAMES as u64) as usize
    };
    let mut output = vec![0.0; output_frames * output_channels];
    for output_frame in 0..output_frames {
        let input_frame = if input_sample_rate == output_sample_rate {
            output_frame.min(input_frames - 1)
        } else {
            (output_frame as u64)
                .saturating_mul(input_sample_rate)
                .checked_div(output_sample_rate)
                .unwrap_or(0) as usize
        }
        .min(input_frames - 1);
        let source = &samples[input_frame * input_channels..(input_frame + 1) * input_channels];
        for channel in 0..output_channels {
            output[output_frame * output_channels + channel] =
                remap_channel(source, channel, output_channels);
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
        let held = [Key::Left, Key::Down, Key::Space, Key::P];

        let scancodes = collect_scancodes_for_frame(|key| held.contains(&key));

        assert_eq!(
            scancodes.into_iter().collect::<Vec<_>>(),
            vec![0x19, 0x1e, 0x1f, 0x39]
        );
    }

    #[test]
    fn scancode_transitions_emit_press_once_until_release() {
        let current = collect_scancodes_for_frame(|key| [Key::Up, Key::Left].contains(&key));
        let (pressed, released) = scancode_transitions(&BTreeSet::new(), &current);
        let (pressed_again, released_again) = scancode_transitions(&current, &current);
        let (pressed_final, released_final) = scancode_transitions(&current, &BTreeSet::new());

        assert_eq!(pressed, vec![0x11, 0x1e]);
        assert!(released.is_empty());
        assert!(pressed_again.is_empty());
        assert!(released_again.is_empty());
        assert!(pressed_final.is_empty());
        assert_eq!(released_final, vec![0x11, 0x1e]);
    }

    #[test]
    fn collect_scancodes_for_frame_supports_arrow_aliases_for_movement() {
        let held = [Key::Right];

        let scancodes = collect_scancodes_for_frame(|key| held.contains(&key));

        assert_eq!(scancodes.into_iter().collect::<Vec<_>>(), vec![0x20]);
    }

    #[test]
    fn scancode_events_for_frame_capture_taps_between_snapshots() {
        let current = BTreeSet::new();

        let (pressed, released) =
            scancode_events_for_frame(&BTreeSet::new(), &current, &[Key::Enter], &[Key::Enter]);

        assert_eq!(pressed, vec![0x1c]);
        assert_eq!(released, vec![0x1c]);
    }

    #[test]
    fn scancode_events_for_frame_deduplicate_alias_keys() {
        let current = collect_scancodes_for_frame(|key| [Key::Left].contains(&key));

        let (pressed, released) =
            scancode_events_for_frame(&BTreeSet::new(), &current, &[Key::A, Key::Left], &[]);

        assert_eq!(pressed, vec![0x1e]);
        assert!(released.is_empty());
    }

    #[test]
    fn validate_presentable_dims_rejects_oversize() {
        assert!(validate_presentable_dims(0, 10).is_err());
        assert!(validate_presentable_dims(10, 0).is_err());
        assert!(validate_presentable_dims(MAX_WINDOW_DIM + 1, 10).is_err());
        assert!(validate_presentable_dims(100_000, 100_000).is_err());
        assert!(validate_presentable_dims(1920, 1080).is_ok());
        assert!(validate_presentable_dims(MAX_WINDOW_DIM, MAX_WINDOW_DIM).is_err());
    }

    #[test]
    fn adapt_audio_chunk_zero_input_rate_does_not_panic() {
        let samples = vec![0.0f32; 64];
        let out = adapt_audio_chunk(&samples, 2, 0, 2, 44100);
        assert!(!out.is_empty());
        assert_eq!(out.len() % 2, 0);
    }

    #[test]
    fn adapt_audio_chunk_tiny_input_rate_is_capped() {
        // A guest claiming a 1 Hz input rate would otherwise amplify a
        // one-second chunk into ~1.9 billion frames.
        let samples = vec![0.0f32; 44100 * 2];
        let out = adapt_audio_chunk(&samples, 2, 1, 2, 44100);
        assert!(out.len() <= MAX_ADAPTED_FRAMES * 2);
    }

    #[test]
    fn final_frame_published_after_worker_finish_is_still_consumed() {
        // Reproduce the F5 race deterministically: the loop's top-of-loop
        // drain runs BEFORE the worker publishes its final frame; the worker
        // then terminates.  The finish-path final drain must still consume
        // the frame — otherwise the run exits windowless and loses it.
        let (host_session, pe_session) = new_live_session();
        let mut latest_frame: Option<LiveFrame> = None;

        let final_frame = LiveFrame {
            width: 2,
            height: 1,
            format: DxgiFormat::B8G8R8A8Unorm,
            bytes: vec![0x11, 0x22, 0x33, 0xff, 0x44, 0x55, 0x66, 0xff],
            displayed_frame_index: 7,
        };
        let expected_frame = final_frame.clone();

        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || -> Result<(), AppError> {
            go_rx.recv().expect("go signal");
            pe_session
                .frame_tx
                .send(final_frame)
                .expect("send final frame");
            Ok(())
        });

        // Top-of-loop drain: runs before the worker publishes anything.
        let drained = drain_frames(&host_session.frame_rx, &mut latest_frame);
        assert_eq!(
            drained, 0,
            "no frames may be pending before the worker publishes"
        );
        assert!(latest_frame.is_none());

        // The worker publishes its final frame and terminates.
        go_tx.send(()).expect("signal worker");
        while !worker.is_finished() {
            std::thread::yield_now();
        }
        assert!(worker.is_finished());
        worker
            .join()
            .expect("worker join")
            .expect("worker succeeded");

        // The finish-path final drain must consume the frame that arrived
        // between the top-of-loop drain and the finish check.
        let final_drained = drain_frames(&host_session.frame_rx, &mut latest_frame);
        assert_eq!(
            final_drained, 1,
            "the final frame must be consumed by the finish-path drain"
        );
        let consumed = latest_frame.expect("final frame must be retained");
        assert_eq!(consumed.width, 2);
        assert_eq!(consumed.height, 1);
        assert_eq!(consumed.bytes, expected_frame.bytes);
        assert_eq!(consumed.displayed_frame_index, 7);
    }
}
