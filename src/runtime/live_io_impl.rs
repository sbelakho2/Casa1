//! Live session input, frame, and audio publishing (runtime methods).

use super::*;

impl PeHostRuntime {
    pub(crate) fn poll_live_input(&mut self) -> AppResult<()> {
        // Phase 5.3.2: Poll for game controller hotplug events
        // (connections / disconnections detected via macOS IORegistry).
        self.user32.poll_controller_hotplug()?;

        // Phase 5.2.4: Collect raw gamepad states for Steam Input
        {
            let mut raw_states = Vec::new();
            for slot in 0..4u8 {
                if let Ok(xi_state) = self.xinput_manager.get_state(slot as u32) {
                    let handle = crate::steam_input::SteamInput::handle_for_slot(slot);
                    let raw = crate::steam_input::RawGamepadState {
                        buttons: xi_state.buttons,
                        left_trigger: xi_state.left_trigger,
                        right_trigger: xi_state.right_trigger,
                        thumb_lx: xi_state.left_thumb_x,
                        thumb_ly: xi_state.left_thumb_y,
                        thumb_rx: xi_state.right_thumb_x,
                        thumb_ry: xi_state.right_thumb_y,
                    };
                    raw_states.push((handle, raw));
                }
            }
            self.steam_input.run_frame(raw_states);
        }

        let Some(input_rx) = self
            .live_session
            .as_ref()
            .map(|session| session.input_rx.clone())
        else {
            return Ok(());
        };
        while let Ok(event) = input_rx.try_recv() {
            match event {
                LiveInputEvent::KeyDown {
                    scancode,
                    shift,
                    altgr,
                } => {
                    // Forward to Win32 guest (existing path)
                    let Some(hwnd) = self
                        .user32
                        .get_focus()
                        .or(self.user32.get_foreground_window())
                    else {
                        continue;
                    };
                    let Some(device_id) = self.live_keyboard_device.as_deref() else {
                        continue;
                    };
                    self.user32.inject_keyboard_input(
                        hwnd,
                        device_id,
                        scancode,
                        KeyModifiers { shift, altgr },
                    )?;

                    // Also forward to CEF/WKWebView browser (Gap 1.3)
                    crate::cef_bridge::with_global_cef_bridge(|bridge| {
                        bridge.forward_keyboard_event(true, scancode);
                    });

                    self.push_trace(
                        "input",
                        "LiveKeyboardInput",
                        BTreeMap::from([
                            ("scancode".to_string(), json!(scancode)),
                            ("shift".to_string(), json!(shift)),
                            ("altgr".to_string(), json!(altgr)),
                        ]),
                        json!(hwnd),
                    );
                }
                LiveInputEvent::KeyUp {
                    scancode,
                    shift,
                    altgr,
                } => {
                    // Forward to Win32 guest (existing path)
                    let Some(hwnd) = self
                        .user32
                        .get_focus()
                        .or(self.user32.get_foreground_window())
                    else {
                        continue;
                    };
                    let Some(device_id) = self.live_keyboard_device.as_deref() else {
                        continue;
                    };
                    self.user32.inject_keyboard_input_up(
                        hwnd,
                        device_id,
                        scancode,
                        KeyModifiers { shift, altgr },
                    )?;

                    // Also forward to CEF/WKWebView browser (Gap 1.3)
                    crate::cef_bridge::with_global_cef_bridge(|bridge| {
                        bridge.forward_keyboard_event(false, scancode);
                    });

                    self.push_trace(
                        "input",
                        "LiveKeyboardInput",
                        BTreeMap::from([
                            ("scancode".to_string(), json!(scancode)),
                            ("shift".to_string(), json!(shift)),
                            ("altgr".to_string(), json!(altgr)),
                            ("pressed".to_string(), json!(false)),
                        ]),
                        json!(hwnd),
                    );
                }
                LiveInputEvent::MouseInput {
                    x,
                    y,
                    left_pressed,
                    left_released,
                    right_pressed,
                    right_released,
                    middle_pressed,
                    middle_released,
                } => {
                    // Forward to Win32 guest with all button states
                    self.dispatch_live_mouse_input(
                        x,
                        y,
                        left_pressed,
                        left_released,
                        right_pressed,
                        right_released,
                        middle_pressed,
                        middle_released,
                    )?;

                    // Also forward to CEF/WKWebView browser
                    crate::cef_bridge::with_global_cef_bridge(|bridge| {
                        bridge.forward_mouse_event(x, y, left_pressed, left_released);
                    });
                }
                LiveInputEvent::MouseScroll {
                    x,
                    y,
                    delta_x,
                    delta_y,
                } => {
                    // Forward scroll to Win32 guest
                    let Some(device_id) = self.live_mouse_device.as_deref() else {
                        continue;
                    };
                    let target_hwnd = self
                        .user32
                        .get_focus()
                        .or_else(|| self.user32.get_foreground_window());
                    if let Some(hwnd) = target_hwnd {
                        self.user32.inject_mouse_input(
                            hwnd,
                            device_id,
                            0,
                            0,
                            &[],
                            delta_y,
                            delta_x,
                        )?;
                    }
                    self.push_trace(
                        "input",
                        "LiveMouseScroll",
                        BTreeMap::from([
                            ("x".to_string(), json!(x)),
                            ("y".to_string(), json!(y)),
                            ("delta_x".to_string(), json!(delta_x)),
                            ("delta_y".to_string(), json!(delta_y)),
                        ]),
                        json!(0),
                    );
                }
                LiveInputEvent::CloseRequested => {
                    self.user32.post_quit_message(0)?;
                    self.push_trace("input", "LiveCloseRequested", BTreeMap::new(), json!(0));
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_live_mouse_input(
        &mut self,
        x: i32,
        y: i32,
        left_pressed: bool,
        left_released: bool,
        right_pressed: bool,
        right_released: bool,
        middle_pressed: bool,
        middle_released: bool,
    ) -> AppResult<()> {
        let Some(device_id) = self.live_mouse_device.as_deref() else {
            return Ok(());
        };
        let previews = self.user32.window_previews();
        let Some(target_hwnd) = self
            .user32
            .get_capture()
            .or_else(|| live_preview_hit_test(&previews, x, y))
            .or_else(|| self.user32.get_focus())
            .or_else(|| self.user32.get_foreground_window())
        else {
            return Ok(());
        };

        let (cursor_x, cursor_y) = self.user32.get_cursor_pos();
        let mut buttons = Vec::new();
        if left_pressed {
            buttons.push(MouseButtonEvent {
                button: MouseButton::Left,
                pressed: true,
            });
        }
        if left_released {
            buttons.push(MouseButtonEvent {
                button: MouseButton::Left,
                pressed: false,
            });
        }
        if right_pressed {
            buttons.push(MouseButtonEvent {
                button: MouseButton::Right,
                pressed: true,
            });
        }
        if right_released {
            buttons.push(MouseButtonEvent {
                button: MouseButton::Right,
                pressed: false,
            });
        }
        if middle_pressed {
            buttons.push(MouseButtonEvent {
                button: MouseButton::Middle,
                pressed: true,
            });
        }
        if middle_released {
            buttons.push(MouseButtonEvent {
                button: MouseButton::Middle,
                pressed: false,
            });
        }
        self.user32.inject_mouse_input(
            target_hwnd,
            device_id,
            x - cursor_x,
            y - cursor_y,
            &buttons,
            0,
            0,
        )?;
        self.push_trace(
            "input",
            "LiveMouseInput",
            BTreeMap::from([
                ("x".to_string(), json!(x)),
                ("y".to_string(), json!(y)),
                ("left_pressed".to_string(), json!(left_pressed)),
                ("left_released".to_string(), json!(left_released)),
                ("right_pressed".to_string(), json!(right_pressed)),
                ("right_released".to_string(), json!(right_released)),
                ("middle_pressed".to_string(), json!(middle_pressed)),
                ("middle_released".to_string(), json!(middle_released)),
            ]),
            json!(target_hwnd),
        );
        Ok(())
    }

    pub(crate) fn publish_live_frame(&self, frame: LiveFrame) {
        if let Some(session) = &self.live_session {
            let result = session.frame_tx.try_send(frame);
            if result.is_err() {
                crate::live::live_trace("[pe] publish_live_frame — channel full, frame dropped");
                // Steam run instrumentation (no behavior change): record the
                // first dropped frame as the graphics first-failure.
                crate::steam_milestones::record_first_failure(
                    crate::steam_milestones::FailureCategory::Gfx,
                    0,
                    crate::steam_milestones::host_thread_id(),
                    Some("LiveFramePublish".to_string()),
                    None,
                    "live frame channel full — frame dropped".to_string(),
                    None,
                    None,
                );
            }
        }
    }

    /// Publish the current real GDI window content to the live frame channel,
    /// rate-limited to ~30 FPS.  Only frames composed of REAL guest GDI pixels
    /// (window surfaces populated by guest-driven blits) are published: if no
    /// real window surface exists, nothing is sent and the cached frame is
    /// cleared.  Synthetic chrome/theme composition never feeds the channel.
    pub(crate) fn publish_live_window_preview_if_needed(&mut self) {
        if self.live_session.is_none() {
            return;
        }

        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_gdi_preview_publish);
        if elapsed.as_millis() < 33 && self.last_real_gdi_frame.is_some() {
            return;
        }

        crate::live::live_trace(&format!(
            "[pe] publish_live_window_preview_if_needed called — window_previews_count={}",
            self.user32.window_previews().len(),
        ));

        let previews = self.user32.window_previews();
        // Compose only the REAL window surfaces (guest-driven blits).  When
        // no real surface exists, `render_live_window_preview` returns None
        // and nothing is published.
        if let Some(frame) = render_live_window_preview(&previews, &self.window_surfaces) {
            self.last_gdi_preview_publish = now;
            self.last_real_gdi_frame = Some(frame.clone());
            self.publish_live_frame(frame);
        } else {
            // No real GDI pixels: do not fabricate a frame.  Drop any cached
            // value so a stale surface never re-publishes as if it were fresh.
            self.last_real_gdi_frame = None;
            crate::live::live_trace(
                "[pe] publish_live_window_preview_if_needed — render_live_window_preview returned None (no real GDI surface)",
            );
        }
    }

    pub(crate) fn publish_live_audio(&self, chunk: LiveAudioChunk) {
        if let Some(session) = &self.live_session {
            let _ = session.audio_tx.try_send(chunk);
        }
    }

    pub(crate) fn inject_keyboard_replay_if_needed(&mut self, hwnd: u32) -> AppResult<()> {
        if self.keyboard_replay_injected || self.pending_keyboard_replay.is_empty() {
            return Ok(());
        }
        let Some(device_id) = self.keyboard_replay_device.clone() else {
            return Ok(());
        };
        for event in &self.pending_keyboard_replay {
            self.user32.inject_keyboard_input(
                hwnd,
                &device_id,
                event.scancode,
                KeyModifiers {
                    shift: event.shift,
                    altgr: event.altgr,
                },
            )?;
        }
        self.keyboard_replay_injected = true;
        self.push_trace(
            "input",
            "KeyboardReplay",
            BTreeMap::from([(
                "events".to_string(),
                json!(self.pending_keyboard_replay.len()),
            )]),
            json!(hwnd),
        );
        Ok(())
    }
}
