use casa1::reason::ReasonCode;
use casa1::user32::{
    AxisCalibration, BatteryInfo, ControllerKind, ControllerSpec, ControllerTransport,
    DeviceAxis, DirectInputDataFormat, DpiAwarenessContext, ForceFeedbackEffect,
    FullscreenMode, KeyboardDevice, KeyboardLayoutId, KeyModifiers, KeyRepeatConfig,
    KeyTranslation, Message, MessageKind, MouseButton, MouseButtonEvent, MouseDevice,
    Rect, RumbleState, User32Subsystem, VirtualKey,
};
use std::collections::{BTreeMap, BTreeSet};

fn pump_messages(user32: &mut User32Subsystem) -> Vec<Message> {
    let mut observed = Vec::new();
    while let Some(message) = user32.get_message_w() {
        if message.kind == MessageKind::KeyDown {
            user32.translate_message(&message).expect("translate keydown");
        }
        user32.dispatch_message_w(&message).expect("dispatch message");
        observed.push(message);
    }
    observed
}

fn message_kinds(messages: &[Message]) -> Vec<MessageKind> {
    messages.iter().map(|message| message.kind).collect()
}

fn text_messages(messages: &[Message]) -> Vec<(MessageKind, char)> {
    messages
        .iter()
        .filter_map(|message| match message.kind {
            MessageKind::Char | MessageKind::DeadChar => {
                Some((message.kind, char::from_u32(message.wparam as u32).expect("valid char")))
            }
            _ => None,
        })
        .collect()
}

fn hotas_spec(name: &str, serial: &str) -> ControllerSpec {
    ControllerSpec {
        name: name.to_string(),
        kind: ControllerKind::Hotas,
        transport: ControllerTransport::Hid,
        vendor_id: 0x044f,
        product_id: 0x0404,
        serial: serial.to_string(),
        xinput_capable: false,
        battery: BatteryInfo {
            level_percent: 100,
            wired: true,
        },
        axes: BTreeMap::from([
            (DeviceAxis::X, 512),
            (DeviceAxis::Y, -512),
            (DeviceAxis::Rz, 256),
            (DeviceAxis::Slider0, 1024),
            (DeviceAxis::Pov0, 9000),
        ]),
        calibrations: BTreeMap::from([
            (
                DeviceAxis::X,
                AxisCalibration {
                    min: -1024,
                    center: 0,
                    max: 1024,
                },
            ),
            (
                DeviceAxis::Y,
                AxisCalibration {
                    min: -1024,
                    center: 0,
                    max: 1024,
                },
            ),
            (
                DeviceAxis::Rz,
                AxisCalibration {
                    min: -1024,
                    center: 0,
                    max: 1024,
                },
            ),
            (
                DeviceAxis::Slider0,
                AxisCalibration {
                    min: 0,
                    center: 0,
                    max: 1024,
                },
            ),
        ]),
        buttons: BTreeSet::from(["trigger".to_string(), "thumb".to_string()]),
        supported_effects: BTreeSet::new(),
    }
}

#[test]
fn t6_1_message_ordering_oracle_matches_expected_focus_resize_and_input_sequence() {
    let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
    assert_eq!(
        user32.set_process_dpi_awareness_context(DpiAwarenessContext::PerMonitorAwareV2),
        DpiAwarenessContext::SystemAware
    );
    assert_eq!(user32.register_class_ex_w("GameWindow"), 1);
    let hwnd = user32
        .create_window_ex_w("GameWindow", "Casa1 Demo", 1280, 720, true, true, 1)
        .expect("create borderless fullscreen window");
    let keyboard_id = user32.register_keyboard_device(&KeyboardDevice {
        vendor_id: 0x046d,
        product_id: 0xc31c,
        serial: "kbd-a".to_string(),
    });
    user32.resize_window(hwnd, 1600, 900).expect("queue resize");
    user32
        .inject_keyboard_input(hwnd, &keyboard_id, 0x10, KeyModifiers { shift: false, altgr: false })
        .expect("queue keyboard input");

    assert_eq!(
        user32.peek_message_w(false).expect("peek first message").kind,
        MessageKind::NcCreate
    );
    let observed = pump_messages(&mut user32);
    assert_eq!(
        message_kinds(&observed),
        vec![
            MessageKind::NcCreate,
            MessageKind::Create,
            MessageKind::ShowWindow,
            MessageKind::WindowPosChanging,
            MessageKind::Size,
            MessageKind::Activate,
            MessageKind::SetFocus,
            MessageKind::WindowPosChanging,
            MessageKind::Size,
            MessageKind::KeyDown,
            MessageKind::Char,
        ]
    );
    assert_eq!(message_kinds(user32.message_log()), message_kinds(&observed));
    assert_eq!(user32.get_foreground_window(), Some(hwnd));
    assert_eq!(user32.get_focus(), Some(hwnd));
    let window = user32.window_state(hwnd).expect("window state");
    assert_eq!(window.class_name, "GameWindow");
    assert_eq!(window.fullscreen.mode, FullscreenMode::Borderless);
    assert!(window.fullscreen.requested_exclusive);
    assert!(window.fullscreen.shim_applied);
    assert_eq!(window.monitor_id, 1);
    assert_eq!(window.dpi, 144);
    assert_eq!(user32.get_dpi_for_monitor(1).expect("monitor dpi"), (144, 144));

    user32
        .send_message_w(hwnd, MessageKind::Input, 7, 0)
        .expect("send message");
    assert_eq!(user32.message_log().last().expect("message log tail").kind, MessageKind::Input);
}

#[test]
fn t6_2_layout_oracle_scancode_dead_keys_raw_ids_and_repeat_timing_match_reference() {
    let cases = vec![
        (
            KeyboardLayoutId::Us,
            0x10,
            KeyModifiers { shift: false, altgr: false },
            KeyTranslation {
                vk: VirtualKey::Q,
                output_char: Some('q'),
                dead_char: None,
            },
        ),
        (
            KeyboardLayoutId::Uk,
            0x28,
            KeyModifiers { shift: false, altgr: false },
            KeyTranslation {
                vk: VirtualKey::Oem7,
                output_char: Some('\''),
                dead_char: None,
            },
        ),
        (
            KeyboardLayoutId::Fr,
            0x12,
            KeyModifiers { shift: false, altgr: true },
            KeyTranslation {
                vk: VirtualKey::E,
                output_char: Some('€'),
                dead_char: None,
            },
        ),
        (
            KeyboardLayoutId::De,
            0x15,
            KeyModifiers { shift: false, altgr: false },
            KeyTranslation {
                vk: VirtualKey::Z,
                output_char: Some('z'),
                dead_char: None,
            },
        ),
        (
            KeyboardLayoutId::Arabic,
            0x10,
            KeyModifiers { shift: false, altgr: false },
            KeyTranslation {
                vk: VirtualKey::Q,
                output_char: Some('ض'),
                dead_char: None,
            },
        ),
        (
            KeyboardLayoutId::Turkish,
            0x12,
            KeyModifiers { shift: false, altgr: true },
            KeyTranslation {
                vk: VirtualKey::E,
                output_char: Some('€'),
                dead_char: None,
            },
        ),
    ];

    for (layout, scancode, modifiers, expected) in cases {
        let user32 = User32Subsystem::new(layout);
        assert_eq!(user32.translate_scancode(scancode, modifiers).expect("translate scancode"), expected);
    }

    let dead_key_cases = vec![
        (KeyboardLayoutId::Fr, '^', vec![0x1a, 0x12], vec![(MessageKind::DeadChar, '^'), (MessageKind::Char, 'ê')]),
        (KeyboardLayoutId::Es, '´', vec![0x1a, 0x12], vec![(MessageKind::DeadChar, '´'), (MessageKind::Char, 'é')]),
        (KeyboardLayoutId::It, '`', vec![0x1a, 0x12], vec![(MessageKind::DeadChar, '`'), (MessageKind::Char, 'è')]),
        (KeyboardLayoutId::Turkish, '^', vec![0x1a, 0x12], vec![(MessageKind::DeadChar, '^'), (MessageKind::Char, 'ê')]),
    ];
    for (layout, dead_char, scancodes, expected) in dead_key_cases {
        let mut user32 = User32Subsystem::new(layout);
        user32.register_class_ex_w("kbd");
        let hwnd = user32
            .create_window_ex_w("kbd", "layout", 640, 480, true, false, 1)
            .expect("create layout window");
        let _ = pump_messages(&mut user32);
        let keyboard_id = user32.register_keyboard_device(&KeyboardDevice {
            vendor_id: 1,
            product_id: 2,
            serial: format!("layout-{dead_char}"),
        });
        for scancode in scancodes {
            user32
                .inject_keyboard_input(hwnd, &keyboard_id, scancode, KeyModifiers { shift: false, altgr: false })
                .expect("inject keyboard sequence");
        }
        let observed = pump_messages(&mut user32);
        assert_eq!(text_messages(&observed), expected);
    }

    let device = KeyboardDevice {
        vendor_id: 0x046d,
        product_id: 0xc31c,
        serial: "stable-kbd".to_string(),
    };
    let mut first = User32Subsystem::new(KeyboardLayoutId::Us);
    let mut second = User32Subsystem::new(KeyboardLayoutId::Us);
    let first_id = first.register_keyboard_device(&device);
    let second_id = second.register_keyboard_device(&device);
    assert_eq!(first_id, second_id);
    assert_ne!(
        first_id,
        second.register_keyboard_device(&KeyboardDevice {
            serial: "different-kbd".to_string(),
            ..device.clone()
        })
    );

    let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
    user32.register_class_ex_w("repeat");
    let hwnd = user32
        .create_window_ex_w("repeat", "repeat", 320, 200, true, false, 1)
        .expect("create repeat window");
    let repeat_id = user32.register_keyboard_device(&device);
    user32.set_key_repeat_config(KeyRepeatConfig {
        delay_ms: 300,
        rate_hz: 20,
    });
    let repeats = user32
        .synthesize_key_repeats(
            hwnd,
            &repeat_id,
            0x10,
            KeyModifiers { shift: false, altgr: false },
            850,
        )
        .expect("synthesize repeats");
    assert_eq!(repeats.len(), 11);
}

#[test]
fn t6_3_raw_mouse_delta_clipcursor_and_1000hz_queue_stress_match_reference() {
    let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
    user32.register_class_ex_w("mouse");
    let hwnd = user32
        .create_window_ex_w("mouse", "mouse", 800, 600, true, false, 1)
        .expect("create mouse window");
    let _ = pump_messages(&mut user32);
    let mouse_id = user32.register_mouse_device(&MouseDevice {
        vendor_id: 0x046d,
        product_id: 0xc08b,
        serial: "mouse-a".to_string(),
    });
    user32.set_cursor_pos(95, 95);
    user32.clip_cursor(Some(Rect {
        left: 0,
        top: 0,
        right: 100,
        bottom: 100,
    }));
    assert_eq!(user32.set_capture(hwnd).expect("set capture"), None);

    let mut packets = Vec::new();
    for _ in 0..999 {
        packets.push(
            user32
                .inject_mouse_input(hwnd, &mouse_id, 1, 1, &[], 0, 0)
                .expect("inject raw mouse packet"),
        );
    }
    packets.push(
        user32
            .inject_mouse_input(
                hwnd,
                &mouse_id,
                5,
                -3,
                &[
                    MouseButtonEvent {
                        button: MouseButton::X1,
                        pressed: true,
                    },
                    MouseButtonEvent {
                        button: MouseButton::X2,
                        pressed: true,
                    },
                ],
                120,
                -120,
            )
            .expect("inject raw mouse packet with buttons and wheels"),
    );

    assert_eq!(packets.len(), 1000);
    assert_eq!(packets.iter().map(|packet| packet.raw_dx).sum::<i32>(), 1004);
    assert_eq!(packets.iter().map(|packet| packet.raw_dy).sum::<i32>(), 996);
    assert_eq!(user32.get_cursor_pos(), (100, 97));

    let observed = pump_messages(&mut user32);
    assert_eq!(
        observed.iter().filter(|message| message.kind == MessageKind::RawInput).count(),
        1000
    );
    assert_eq!(
        observed.iter().filter(|message| message.kind == MessageKind::MouseMove).count(),
        1000
    );
    assert_eq!(
        observed.iter().filter(|message| message.kind == MessageKind::MouseWheel).count(),
        1
    );
    assert_eq!(
        observed.iter().filter(|message| message.kind == MessageKind::MouseHWheel).count(),
        1
    );
    assert_eq!(
        observed.iter().filter(|message| message.kind == MessageKind::XButtonDown).count(),
        2
    );
    assert_eq!(user32.get_capture(), Some(hwnd));
    assert_eq!(user32.release_capture(), Some(hwnd));
    assert_eq!(user32.get_capture(), None);
}

#[test]
fn t6_4_xinput_matrix_hotplug_notifications_and_ownership_model_match_reference() {
    let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
    user32.register_class_ex_w("pad");
    let hwnd = user32
        .create_window_ex_w("pad", "controllers", 800, 600, true, false, 1)
        .expect("create controller window");
    let _ = pump_messages(&mut user32);

    let specs = vec![
        ControllerSpec {
            name: "Xbox USB".to_string(),
            kind: ControllerKind::Xbox,
            transport: ControllerTransport::Usb,
            vendor_id: 0x045e,
            product_id: 0x0b12,
            serial: "xusb".to_string(),
            xinput_capable: true,
            battery: BatteryInfo {
                level_percent: 100,
                wired: true,
            },
            axes: BTreeMap::from([(DeviceAxis::X, 120), (DeviceAxis::Y, -75)]),
            calibrations: BTreeMap::new(),
            buttons: BTreeSet::from(["A".to_string(), "Start".to_string()]),
            supported_effects: BTreeSet::from([ForceFeedbackEffect::Constant]),
        },
        ControllerSpec {
            name: "Xbox BT".to_string(),
            kind: ControllerKind::Xbox,
            transport: ControllerTransport::Bluetooth,
            vendor_id: 0x045e,
            product_id: 0x0b13,
            serial: "xbt".to_string(),
            xinput_capable: true,
            battery: BatteryInfo {
                level_percent: 87,
                wired: false,
            },
            axes: BTreeMap::from([(DeviceAxis::X, 12), (DeviceAxis::Y, -9)]),
            calibrations: BTreeMap::new(),
            buttons: BTreeSet::from(["B".to_string()]),
            supported_effects: BTreeSet::from([ForceFeedbackEffect::Constant]),
        },
        ControllerSpec {
            name: "Third Party XInput".to_string(),
            kind: ControllerKind::ThirdPartyXInput,
            transport: ControllerTransport::Usb,
            vendor_id: 0x0f0d,
            product_id: 0x00c1,
            serial: "third".to_string(),
            xinput_capable: true,
            battery: BatteryInfo {
                level_percent: 100,
                wired: true,
            },
            axes: BTreeMap::from([(DeviceAxis::X, 1), (DeviceAxis::Y, 2)]),
            calibrations: BTreeMap::new(),
            buttons: BTreeSet::from(["X".to_string()]),
            supported_effects: BTreeSet::from([ForceFeedbackEffect::Constant]),
        },
        ControllerSpec {
            name: "HID Only Pad".to_string(),
            kind: ControllerKind::HidGamepad,
            transport: ControllerTransport::Hid,
            vendor_id: 0x28de,
            product_id: 0x11ff,
            serial: "steam-pad".to_string(),
            xinput_capable: false,
            battery: BatteryInfo {
                level_percent: 55,
                wired: false,
            },
            axes: BTreeMap::from([(DeviceAxis::X, 33), (DeviceAxis::Y, 44)]),
            calibrations: BTreeMap::new(),
            buttons: BTreeSet::from(["Steam".to_string()]),
            supported_effects: BTreeSet::new(),
        },
    ];

    let mut guids = specs
        .into_iter()
        .map(|spec| user32.attach_controller(Some(hwnd), spec).expect("attach controller"))
        .collect::<Vec<_>>();
    let hotplug_messages = pump_messages(&mut user32);
    assert_eq!(
        hotplug_messages
            .iter()
            .filter(|message| message.kind == MessageKind::InputDeviceChange && message.wparam == 1)
            .count(),
        4
    );

    let devices = user32.enum_directinput_devices();
    let mut xinput_devices = devices
        .iter()
        .filter(|device| device.xinput_slot.is_some())
        .map(|device| (device.guid.clone(), device.xinput_slot.expect("slot assigned")))
        .collect::<Vec<_>>();
    xinput_devices.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(xinput_devices.iter().map(|(_, slot)| *slot).collect::<Vec<_>>(), vec![0, 1, 2]);
    assert!(devices.iter().any(|device| device.xinput_slot.is_none() && device.name == "HID Only Pad"));

    for (_, slot) in &xinput_devices {
        let capabilities = user32.xinput_get_capabilities(*slot).expect("xinput capabilities");
        assert!(capabilities.supports_rumble);
        let state = user32.xinput_get_state(*slot).expect("xinput state");
        assert!(state.packet_number >= 1);
        assert!(!state.buttons.is_empty());
        assert!(user32.xinput_get_keystroke(*slot).expect("xinput keystroke").is_some());
        let _ = user32.xinput_get_battery_information(*slot).expect("battery information");
    }

    let preferred_slot = xinput_devices[1].1;
    user32
        .xinput_set_state(preferred_slot, 40_000, 20_000)
        .expect("set xinput rumble state");
    assert_eq!(
        user32.xinput_rumble_state(preferred_slot).expect("rumble state"),
        RumbleState {
            left_motor: 40_000,
            right_motor: 20_000,
        }
    );

    assert!(user32.claim_input_owner("steam"));
    assert!(!user32.claim_input_owner("game"));
    assert_eq!(user32.input_owner(), Some("steam"));
    assert!(user32.release_input_owner("steam"));
    assert!(user32.claim_input_owner("game"));

    guids.sort();
    user32
        .remove_controller(Some(hwnd), &guids[0])
        .expect("remove hotplugged controller");
    let removal_messages = pump_messages(&mut user32);
    assert_eq!(
        removal_messages
            .iter()
            .filter(|message| message.kind == MessageKind::InputDeviceChange && message.wparam == 0)
            .count(),
        1
    );
}

#[test]
fn t6_5_directinput_joystick_axis_ranges_guid_stability_and_enumeration_match_reference() {
    let spec = hotas_spec("HOTAS Warthog", "hotas-stable");
    let mut first = User32Subsystem::new(KeyboardLayoutId::Us);
    let mut second = User32Subsystem::new(KeyboardLayoutId::Us);
    let guid_a = first.attach_controller(None, spec.clone()).expect("attach first HOTAS");
    let guid_b = second.attach_controller(None, spec.clone()).expect("attach second HOTAS");
    assert_eq!(guid_a, guid_b);

    let other_guid = first
        .attach_controller(None, hotas_spec("Wheel", "wheel-stable"))
        .expect("attach second directinput device");
    let mut expected_order = vec![guid_a.clone(), other_guid.clone()];
    expected_order.sort();
    assert_eq!(
        first
            .enum_directinput_devices()
            .into_iter()
            .map(|device| device.guid)
            .collect::<Vec<_>>(),
        expected_order
    );

    let handle = first
        .create_directinput_device(&guid_a)
        .expect("create directinput device");
    first
        .set_data_format(&handle, DirectInputDataFormat::Hotas)
        .expect("set HOTAS format");
    first.acquire_device(&handle).expect("acquire HOTAS");
    let state = first.get_device_state(&handle).expect("directinput state");
    assert_eq!(state.axes[&DeviceAxis::X], 500);
    assert_eq!(state.axes[&DeviceAxis::Y], -500);
    assert_eq!(state.axes[&DeviceAxis::Rz], 250);
    assert_eq!(state.axes[&DeviceAxis::Slider0], 1000);
    assert_eq!(state.axes[&DeviceAxis::Pov0], 9000);
    assert!(state.buttons.contains("trigger"));
    assert!(state.buttons.contains("thumb"));

    let events = first.get_device_data(&handle).expect("directinput event data");
    assert!(events.iter().any(|event| event.object == "axis::X" && event.value == 500));
    assert!(events.iter().any(|event| event.object == "axis::Y" && event.value == -500));
    assert!(events.iter().any(|event| event.object == "button::trigger" && event.value == 1));
    assert!(events.iter().any(|event| event.object == "button::thumb" && event.value == 1));
}

#[test]
fn t6_6_force_feedback_negative_tests_return_exact_unsupported_errors() {
    let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
    let guid = user32
        .attach_controller(
            None,
            ControllerSpec {
                name: "Wheel FF".to_string(),
                kind: ControllerKind::WheelPedals,
                transport: ControllerTransport::Usb,
                vendor_id: 0x046d,
                product_id: 0xc29b,
                serial: "ff-wheel".to_string(),
                xinput_capable: false,
                battery: BatteryInfo {
                    level_percent: 100,
                    wired: true,
                },
                axes: BTreeMap::from([(DeviceAxis::X, 0)]),
                calibrations: BTreeMap::new(),
                buttons: BTreeSet::new(),
                supported_effects: BTreeSet::from([
                    ForceFeedbackEffect::Constant,
                    ForceFeedbackEffect::Ramp,
                    ForceFeedbackEffect::Periodic,
                ]),
            },
        )
        .expect("attach force-feedback wheel");

    assert_eq!(
        user32
            .apply_force_feedback(&guid, ForceFeedbackEffect::Constant, 5000, 100)
            .expect("constant effect"),
        casa1::user32::ForceFeedbackPlan {
            effect: ForceFeedbackEffect::Constant,
            magnitude: 5000,
            duration_ms: 100,
        }
    );
    assert_eq!(
        user32
            .apply_force_feedback(&guid, ForceFeedbackEffect::Ramp, 7500, 250)
            .expect("ramp effect"),
        casa1::user32::ForceFeedbackPlan {
            effect: ForceFeedbackEffect::Ramp,
            magnitude: 7500,
            duration_ms: 250,
        }
    );
    assert_eq!(
        user32
            .apply_force_feedback(&guid, ForceFeedbackEffect::Periodic, 6000, 180)
            .expect("periodic effect"),
        casa1::user32::ForceFeedbackPlan {
            effect: ForceFeedbackEffect::Periodic,
            magnitude: 6000,
            duration_ms: 180,
        }
    );

    let unsupported = user32
        .apply_force_feedback(&guid, ForceFeedbackEffect::Spring, 4000, 100)
        .expect_err("spring must return exact unsupported error");
    assert_eq!(unsupported.code, ReasonCode::RcInputUnsupported);
}

#[test]
fn t6_7_recorded_hid_stream_replays_exactly() {
    let mut first = User32Subsystem::new(KeyboardLayoutId::Us);
    first.register_class_ex_w("ReplayWindow");
    let first_hwnd = first
        .create_window_ex_w("ReplayWindow", "Replay", 1280, 720, true, false, 1)
        .expect("create replay window");
    let first_keyboard = first.register_keyboard_device(&KeyboardDevice {
        vendor_id: 0x046d,
        product_id: 0xc31c,
        serial: "replay-kbd".to_string(),
    });
    let first_mouse = first.register_mouse_device(&MouseDevice {
        vendor_id: 0x046d,
        product_id: 0xc077,
        serial: "replay-mouse".to_string(),
    });
    let _ = pump_messages(&mut first);

    first
        .inject_keyboard_input(first_hwnd, &first_keyboard, 0x10, KeyModifiers { shift: false, altgr: false })
        .expect("record keyboard input");
    first
        .inject_mouse_input(
            first_hwnd,
            &first_mouse,
            24,
            -8,
            &[
                MouseButtonEvent {
                    button: MouseButton::X1,
                    pressed: true,
                },
                MouseButtonEvent {
                    button: MouseButton::X1,
                    pressed: false,
                },
            ],
            120,
            0,
        )
        .expect("record mouse input");
    let expected = pump_messages(&mut first);
    let recorded = first.recorded_input_stream().to_vec();
    assert_eq!(recorded.len(), 2);

    let mut replay = User32Subsystem::new(KeyboardLayoutId::Us);
    replay.register_class_ex_w("ReplayWindow");
    let replay_hwnd = replay
        .create_window_ex_w("ReplayWindow", "Replay", 1280, 720, true, false, 1)
        .expect("create replay target window");
    let replay_keyboard = replay.register_keyboard_device(&KeyboardDevice {
        vendor_id: 0x046d,
        product_id: 0xc31c,
        serial: "replay-kbd".to_string(),
    });
    let replay_mouse = replay.register_mouse_device(&MouseDevice {
        vendor_id: 0x046d,
        product_id: 0xc077,
        serial: "replay-mouse".to_string(),
    });
    let _ = pump_messages(&mut replay);
    assert_eq!(first_hwnd, replay_hwnd);
    assert_eq!(first_keyboard, replay_keyboard);
    assert_eq!(first_mouse, replay_mouse);

    replay.replay_input_stream(&recorded).expect("replay recorded HID stream");
    let replayed = pump_messages(&mut replay);
    assert_eq!(replayed, expected);
}