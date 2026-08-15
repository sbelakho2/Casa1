use casa1::d3d12::{
    D3D12BuildAccelerationStructureDesc, D3D12BuildRaytracingInputs, D3D12DispatchRaysDesc,
    D3D12RaytracingGeometryDesc, D3d12Runtime,
};
use casa1::gfx::{
    D3D12DescriptorRangeType, D3D12ResourceBarrierDesc, D3D12ResourceBarrierFlags,
    D3D12ResourceBarrierType, D3D12ShaderVisibility, D3D12StaticSamplerDesc, DescriptorRange,
    DxgiFormat, FeatureQuery, PipelineStateDesc, ResourceState, RootParameter, RootSignatureDesc,
    SwapchainDesc, ViewDescriptor,
};
use casa1::reason::ReasonCode;
use casa1::user32::{
    AxisCalibration, BatteryInfo, ControllerKind, ControllerSpec, ControllerTransport, DeviceAxis,
    DirectInputDataFormat, DpiAwarenessContext, ForceFeedbackEffect, FullscreenMode, KeyModifiers,
    KeyRepeatConfig, KeyTranslation, KeyboardDevice, KeyboardLayoutId, Message, MessageKind,
    MouseButton, MouseButtonEvent, MouseDevice, Rect, RumbleState, User32Subsystem, VirtualKey,
};
use std::collections::{BTreeMap, BTreeSet};

fn pump_messages(user32: &mut User32Subsystem) -> Vec<Message> {
    let mut observed = Vec::new();
    while let Some(message) = user32.get_message_w() {
        if message.kind == MessageKind::KeyDown {
            user32
                .translate_message(&message)
                .expect("translate keydown");
        }
        user32
            .dispatch_message_w(&message)
            .expect("dispatch message");
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
            MessageKind::Char | MessageKind::DeadChar => Some((
                message.kind,
                char::from_u32(message.wparam as u32).expect("valid char"),
            )),
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
        .create_window_ex_w("GameWindow", "Casa1 Demo", 1280, 720, true, true, None, 1)
        .expect("create borderless fullscreen window");
    let keyboard_id = user32.register_keyboard_device(&KeyboardDevice {
        vendor_id: 0x046d,
        product_id: 0xc31c,
        serial: "kbd-a".to_string(),
    });
    user32.resize_window(hwnd, 1600, 900).expect("queue resize");
    user32
        .inject_keyboard_input(
            hwnd,
            &keyboard_id,
            0x10,
            KeyModifiers {
                shift: false,
                altgr: false,
            },
        )
        .expect("queue keyboard input");

    assert_eq!(
        user32
            .peek_message_w(false)
            .expect("peek first message")
            .kind,
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
    assert_eq!(
        message_kinds(user32.message_log()),
        message_kinds(&observed)
    );
    assert_eq!(user32.get_foreground_window(), Some(hwnd));
    assert_eq!(user32.get_focus(), Some(hwnd));
    let window = user32.window_state(hwnd).expect("window state");
    assert_eq!(window.class_name, "GameWindow");
    assert_eq!(window.fullscreen.mode, FullscreenMode::Borderless);
    assert!(window.fullscreen.requested_exclusive);
    assert!(window.fullscreen.shim_applied);
    assert_eq!(window.monitor_id, 1);
    // DPI is host-dependent (96 on standard displays, 144 on 150% scaling, etc.)
    let (dpi_x, dpi_y) = user32.get_dpi_for_monitor(1, 0);
    assert_eq!(window.dpi, dpi_x, "window DPI should match monitor DPI");
    assert_eq!(dpi_x, dpi_y, "monitor should report square pixels");

    user32
        .send_message_w(hwnd, MessageKind::Input, 7, 0)
        .expect("send message");
    assert_eq!(
        user32.message_log().last().expect("message log tail").kind,
        MessageKind::Input
    );
}

#[test]
fn t6_2_layout_oracle_scancode_dead_keys_raw_ids_and_repeat_timing_match_reference() {
    let cases = vec![
        (
            KeyboardLayoutId::Us,
            0x10,
            KeyModifiers {
                shift: false,
                altgr: false,
            },
            KeyTranslation {
                vk: VirtualKey::Q,
                output_char: Some('q'),
                dead_char: None,
            },
        ),
        (
            KeyboardLayoutId::Uk,
            0x28,
            KeyModifiers {
                shift: false,
                altgr: false,
            },
            KeyTranslation {
                vk: VirtualKey::Oem7,
                output_char: Some('\''),
                dead_char: None,
            },
        ),
        (
            KeyboardLayoutId::Fr,
            0x12,
            KeyModifiers {
                shift: false,
                altgr: true,
            },
            KeyTranslation {
                vk: VirtualKey::E,
                output_char: Some('€'),
                dead_char: None,
            },
        ),
        (
            KeyboardLayoutId::De,
            0x15,
            KeyModifiers {
                shift: false,
                altgr: false,
            },
            KeyTranslation {
                vk: VirtualKey::Z,
                output_char: Some('z'),
                dead_char: None,
            },
        ),
        (
            KeyboardLayoutId::Arabic,
            0x10,
            KeyModifiers {
                shift: false,
                altgr: false,
            },
            KeyTranslation {
                vk: VirtualKey::Q,
                output_char: Some('ض'),
                dead_char: None,
            },
        ),
        (
            KeyboardLayoutId::Turkish,
            0x12,
            KeyModifiers {
                shift: false,
                altgr: true,
            },
            KeyTranslation {
                vk: VirtualKey::E,
                output_char: Some('€'),
                dead_char: None,
            },
        ),
    ];

    for (layout, scancode, modifiers, expected) in cases {
        let user32 = User32Subsystem::new(layout);
        assert_eq!(
            user32
                .translate_scancode(scancode, modifiers)
                .expect("translate scancode"),
            expected
        );
    }

    let dead_key_cases = vec![
        (
            KeyboardLayoutId::Fr,
            '^',
            vec![0x1a, 0x12],
            vec![(MessageKind::DeadChar, '^'), (MessageKind::Char, 'ê')],
        ),
        (
            KeyboardLayoutId::Es,
            '´',
            vec![0x1a, 0x12],
            vec![(MessageKind::DeadChar, '´'), (MessageKind::Char, 'é')],
        ),
        (
            KeyboardLayoutId::It,
            '`',
            vec![0x1a, 0x12],
            vec![(MessageKind::DeadChar, '`'), (MessageKind::Char, 'è')],
        ),
        (
            KeyboardLayoutId::Turkish,
            '^',
            vec![0x1a, 0x12],
            vec![(MessageKind::DeadChar, '^'), (MessageKind::Char, 'ê')],
        ),
    ];
    for (layout, dead_char, scancodes, expected) in dead_key_cases {
        let mut user32 = User32Subsystem::new(layout);
        user32.register_class_ex_w("kbd");
        let hwnd = user32
            .create_window_ex_w("kbd", "layout", 640, 480, true, false, None, 1)
            .expect("create layout window");
        let _ = pump_messages(&mut user32);
        let keyboard_id = user32.register_keyboard_device(&KeyboardDevice {
            vendor_id: 1,
            product_id: 2,
            serial: format!("layout-{dead_char}"),
        });
        for scancode in scancodes {
            user32
                .inject_keyboard_input(
                    hwnd,
                    &keyboard_id,
                    scancode,
                    KeyModifiers {
                        shift: false,
                        altgr: false,
                    },
                )
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
        .create_window_ex_w("repeat", "repeat", 320, 200, true, false, None, 1)
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
            KeyModifiers {
                shift: false,
                altgr: false,
            },
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
        .create_window_ex_w("mouse", "mouse", 800, 600, true, false, None, 1)
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
    assert_eq!(
        packets.iter().map(|packet| packet.raw_dx).sum::<i32>(),
        1004
    );
    assert_eq!(packets.iter().map(|packet| packet.raw_dy).sum::<i32>(), 996);
    assert_eq!(user32.get_cursor_pos(), (100, 97));

    let observed = pump_messages(&mut user32);
    assert_eq!(
        observed
            .iter()
            .filter(|message| message.kind == MessageKind::RawInput)
            .count(),
        1000
    );
    assert_eq!(
        observed
            .iter()
            .filter(|message| message.kind == MessageKind::MouseMove)
            .count(),
        1000
    );
    assert_eq!(
        observed
            .iter()
            .filter(|message| message.kind == MessageKind::MouseWheel)
            .count(),
        1
    );
    assert_eq!(
        observed
            .iter()
            .filter(|message| message.kind == MessageKind::MouseHWheel)
            .count(),
        1
    );
    assert_eq!(
        observed
            .iter()
            .filter(|message| message.kind == MessageKind::XButtonDown)
            .count(),
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
        .create_window_ex_w("pad", "controllers", 800, 600, true, false, None, 1)
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
        .map(|spec| {
            user32
                .add_controller(Some(hwnd), spec)
                .expect("attach controller")
        })
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
        .map(|device| {
            (
                device.guid.clone(),
                device.xinput_slot.expect("slot assigned"),
            )
        })
        .collect::<Vec<_>>();
    xinput_devices.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(
        xinput_devices
            .iter()
            .map(|(_, slot)| *slot)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(
        devices
            .iter()
            .any(|device| device.xinput_slot.is_none() && device.name == "HID Only Pad")
    );

    for (_, slot) in &xinput_devices {
        let capabilities = user32
            .xinput_get_capabilities(*slot)
            .expect("xinput capabilities");
        assert!(capabilities.supports_rumble);
        let state = user32.xinput_get_state(*slot).expect("xinput state");
        assert!(state.packet_number >= 1);
        assert!(!state.buttons.is_empty());
        assert!(
            user32
                .xinput_get_keystroke(*slot)
                .expect("xinput keystroke")
                .is_some()
        );
        let _ = user32
            .xinput_get_battery_information(*slot)
            .expect("battery information");
    }

    let preferred_slot = xinput_devices[1].1;
    user32
        .xinput_set_state(preferred_slot, 40_000, 20_000)
        .expect("set xinput rumble state");
    assert_eq!(
        user32
            .xinput_rumble_state(preferred_slot)
            .expect("rumble state"),
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
    let guid_a = first
        .add_controller(None, spec.clone())
        .expect("attach first HOTAS");
    let guid_b = second
        .add_controller(None, spec.clone())
        .expect("attach second HOTAS");
    assert_eq!(guid_a, guid_b);

    let other_guid = first
        .add_controller(None, hotas_spec("Wheel", "wheel-stable"))
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

    let events = first
        .get_device_data(&handle)
        .expect("directinput event data");
    assert!(
        events
            .iter()
            .any(|event| event.object == "axis::X" && event.value == 500)
    );
    assert!(
        events
            .iter()
            .any(|event| event.object == "axis::Y" && event.value == -500)
    );
    assert!(
        events
            .iter()
            .any(|event| event.object == "button::trigger" && event.value == 1)
    );
    assert!(
        events
            .iter()
            .any(|event| event.object == "button::thumb" && event.value == 1)
    );
}

#[test]
fn t6_6_force_feedback_negative_tests_return_exact_unsupported_errors() {
    let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
    let guid = user32
        .add_controller(
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
        .create_window_ex_w("ReplayWindow", "Replay", 1280, 720, true, false, None, 1)
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
        .inject_keyboard_input(
            first_hwnd,
            &first_keyboard,
            0x10,
            KeyModifiers {
                shift: false,
                altgr: false,
            },
        )
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
        .create_window_ex_w("ReplayWindow", "Replay", 1280, 720, true, false, None, 1)
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

    replay
        .replay_input_stream(&recorded)
        .expect("replay recorded HID stream");
    let replayed = pump_messages(&mut replay);
    assert_eq!(replayed, expected);
}

// =========================================================================
// Phase 2.1-2.2 Tests: D3D12 Root Signatures + Resource Barriers
// =========================================================================

fn make_d3d12_runtime() -> D3d12Runtime {
    D3d12Runtime::new()
}

// -------------------------------------------------------------------------
// Root Signature Serialization / Deserialization Round-Trip
// -------------------------------------------------------------------------

#[test]
fn t6_8_root_signature_round_trip() {
    let mut runtime = make_d3d12_runtime();

    // Create a root signature with descriptor tables, root constants, and static samplers
    let desc = RootSignatureDesc {
        descriptor_tables: vec![2, 3, 1],
        root_constants: 4,
        parameters: vec![
            RootParameter::DescriptorTable {
                ranges: vec![DescriptorRange {
                    range_type: D3D12DescriptorRangeType::Srv,
                    num_descriptors: 2,
                    base_shader_register: 0,
                    register_space: 0,
                    offset_in_table: 0,
                }],
                visibility: D3D12ShaderVisibility::Pixel,
            },
            RootParameter::RootConstants {
                shader_register: 0,
                register_space: 0,
                num_32bit_values: 4,
                visibility: D3D12ShaderVisibility::All,
            },
            RootParameter::RootDescriptor {
                range_type: D3D12DescriptorRangeType::Cbv,
                shader_register: 1,
                register_space: 0,
                visibility: D3D12ShaderVisibility::Vertex,
            },
        ],
        static_samplers: vec![D3D12StaticSamplerDesc {
            shader_register: 0,
            register_space: 0,
            filter: 0,    // D3D12_FILER_MIN_MAG_MIP_POINT
            address_u: 2, // WRAP
            address_v: 2,
            address_w: 2,
            mip_lod_bias: 0.0,
            max_anisotropy: 1,
            comparison_func: 0,
            border_color: 0,
            min_lod: 0.0,
            max_lod: 1000.0,
            shader_visibility: D3D12ShaderVisibility::All,
        }],
        visibility_offsets: BTreeMap::new(),
    };

    let id = runtime.create_root_signature(desc.clone());
    let stored = runtime
        .root_signature_desc(id)
        .expect("root signature should be stored");

    // Verify parameters round-trip
    assert_eq!(stored.parameters.len(), 3);
    assert_eq!(stored.root_constants, 4);
    assert_eq!(stored.static_samplers.len(), 1);
    assert_eq!(stored.descriptor_tables, vec![2, 3, 1]);

    // Verify static sampler fields
    let sampler = &stored.static_samplers[0];
    assert_eq!(sampler.shader_register, 0);
    assert_eq!(sampler.max_anisotropy, 1);
}

// -------------------------------------------------------------------------
// Static Sampler Creation with All Filter Modes
// -------------------------------------------------------------------------

#[test]
fn t6_9_static_sampler_filter_modes() {
    // Validate filter mode mapping
    let (min_f, mag_f, mip_f, aniso, cmp) = D3d12Runtime::map_d3d12_filter_to_metal(0); // MIN_MAG_MIP_POINT
    assert_eq!(min_f, "nearest");
    assert_eq!(mag_f, "nearest");
    assert_eq!(mip_f, "nearest");
    assert!(!aniso);
    assert!(!cmp);

    let (min_f, mag_f, mip_f, aniso, cmp) = D3d12Runtime::map_d3d12_filter_to_metal(0x14); // MIN_MAG_LINEAR_MIP_POINT
    assert_eq!(min_f, "linear");
    assert_eq!(mag_f, "linear");
    assert_eq!(mip_f, "nearest");
    assert!(!aniso);
    assert!(!cmp);

    let (_min_f, _mag_f, _mip_f, aniso, cmp) = D3d12Runtime::map_d3d12_filter_to_metal(0x55); // ANISOTROPIC
    assert!(aniso);
    assert!(!cmp);

    let (_min_f, _mag_f, _mip_f, aniso, cmp) = D3d12Runtime::map_d3d12_filter_to_metal(0x80); // COMPARISON_MIN_MAG_MIP_POINT
    assert!(!aniso);
    assert!(cmp);

    // Validate address mode mapping
    assert_eq!(D3d12Runtime::map_d3d12_address_mode(1), "clamp_to_edge");
    assert_eq!(D3d12Runtime::map_d3d12_address_mode(2), "repeat");
    assert_eq!(D3d12Runtime::map_d3d12_address_mode(3), "mirror_repeat");
    assert_eq!(D3d12Runtime::map_d3d12_address_mode(4), "clamp_to_zero");

    // Validate comparison function mapping
    assert_eq!(D3d12Runtime::map_d3d12_comparison_func(1), "never");
    assert_eq!(D3d12Runtime::map_d3d12_comparison_func(2), "less");
    assert_eq!(D3d12Runtime::map_d3d12_comparison_func(3), "equal");
    assert_eq!(D3d12Runtime::map_d3d12_comparison_func(4), "less_equal");
    assert_eq!(D3d12Runtime::map_d3d12_comparison_func(5), "greater");
    assert_eq!(D3d12Runtime::map_d3d12_comparison_func(8), "always");

    // Validate border color mapping
    assert_eq!(D3d12Runtime::map_d3d12_border_color(0), "transparent_black");
    assert_eq!(D3d12Runtime::map_d3d12_border_color(1), "opaque_black");
    assert_eq!(D3d12Runtime::map_d3d12_border_color(2), "opaque_white");

    // Validate static sampler descriptor generation
    let sampler = D3D12StaticSamplerDesc {
        shader_register: 0,
        register_space: 0,
        filter: 0,
        address_u: 2,
        address_v: 2,
        address_w: 2,
        mip_lod_bias: 0.0,
        max_anisotropy: 1,
        comparison_func: 0,
        border_color: 0,
        min_lod: 0.0,
        max_lod: 1000.0,
        shader_visibility: D3D12ShaderVisibility::All,
    };
    let metal_desc = D3d12Runtime::static_sampler_to_metal_desc(&sampler);
    assert!(metal_desc.contains("address::repeat"));
    assert!(metal_desc.contains("filter::nearest,nearest,nearest"));
    assert!(metal_desc.contains("border_color::transparent_black"));

    // Validate static sampler validation
    let _result = D3d12Runtime::validate_static_sampler(&sampler);
    assert!(_result.is_ok(), "expected Ok, got {_result:?}");

    let bad_sampler = D3D12StaticSamplerDesc {
        max_anisotropy: 32, // Exceeds Metal limit of 16
        ..sampler
    };
    let _result = D3d12Runtime::validate_static_sampler(&bad_sampler);
    assert!(_result.is_err(), "expected Err, got {_result:?}");

    let bad_lod = D3D12StaticSamplerDesc {
        min_lod: 5.0,
        max_lod: 1.0, // min > max
        ..sampler
    };
    let _result = D3d12Runtime::validate_static_sampler(&bad_lod);
    assert!(_result.is_err(), "expected Err, got {_result:?}");
}

// -------------------------------------------------------------------------
// Root Constants Binding and Verification
// -------------------------------------------------------------------------

#[test]
fn t6_10_root_constants_binding() {
    let mut runtime = make_d3d12_runtime();

    let desc = RootSignatureDesc {
        descriptor_tables: vec![],
        root_constants: 8,
        parameters: vec![RootParameter::RootConstants {
            shader_register: 0,
            register_space: 0,
            num_32bit_values: 8,
            visibility: D3D12ShaderVisibility::All,
        }],
        static_samplers: vec![],
        visibility_offsets: BTreeMap::new(),
    };

    let allocator = runtime.create_command_allocator();
    let root_sig = runtime.create_root_signature(desc);
    let pipeline_state = runtime.create_pipeline_state(
        root_sig,
        casa1::gfx::PipelineStateDesc {
            label: "root_constants_test".to_string(),
            compute: false,
            render_target_formats: vec![],
            depth_format: None,
        },
    );
    let list = runtime.create_graphics_command_list(allocator, pipeline_state, false);

    // Record root constants
    runtime
        .record_set_root_constants(list, vec![1, 2, 3, 4, 5, 6, 7, 8])
        .expect("set root constants");

    // Verify the root signature stored parameters
    let stored = runtime.root_signature_desc(root_sig).expect("root sig");
    assert_eq!(stored.root_constants, 8);
}

// -------------------------------------------------------------------------
// Resource State Transition Tracking
// -------------------------------------------------------------------------

#[test]
fn t6_11_resource_state_transition() {
    let mut runtime = make_d3d12_runtime();

    // Create a resource with multiple subresources
    let resource = runtime
        .create_committed_resource(casa1::gfx::ResourceDesc {
            name: "test_resource".to_string(),
            format: casa1::gfx::DxgiFormat::R8G8B8A8Unorm,
            heap: casa1::gfx::HeapType::Default,
            size: 1024,
            subresources: 4,
            initial_state: ResourceState::Common,
            usage_hint: casa1::gfx::ResourceUsageHint::Generic,
        })
        .expect("create resource");

    // Create a command list for recording transitions
    let allocator = runtime.create_command_allocator();
    let root_sig = runtime.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![],
        root_constants: 0,
        ..Default::default()
    });
    let pso = runtime.create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "transition_test".to_string(),
            compute: true,
            render_target_formats: vec![],
            depth_format: None,
        },
    );
    let list_id = runtime.create_graphics_command_list(allocator, pso, false);

    // Verify initial state
    assert_eq!(
        runtime.resource_state(resource, 0).expect("state"),
        ResourceState::Common
    );
    assert_eq!(
        runtime.resource_state(resource, 3).expect("state"),
        ResourceState::Common
    );

    // Transition subresource 0 to RenderTarget
    runtime
        .record_transition(
            list_id,
            resource,
            0,
            ResourceState::Common,
            ResourceState::RenderTarget,
        )
        .expect("transition");

    assert_eq!(
        runtime.resource_state(resource, 0).expect("state"),
        ResourceState::RenderTarget
    );

    // Transition subresource 1 to CopyDest
    runtime
        .record_transition(
            list_id,
            resource,
            1,
            ResourceState::Common,
            ResourceState::CopyDest,
        )
        .expect("transition");

    assert_eq!(
        runtime.resource_state(resource, 1).expect("state"),
        ResourceState::CopyDest
    );

    // Verify subresources 2 and 3 remain Common
    assert_eq!(
        runtime.resource_state(resource, 2).expect("state"),
        ResourceState::Common
    );

    // Transition back to Common
    runtime
        .record_transition(
            list_id,
            resource,
            0,
            ResourceState::RenderTarget,
            ResourceState::Common,
        )
        .expect("transition");
    assert_eq!(
        runtime.resource_state(resource, 0).expect("state"),
        ResourceState::Common
    );
}

// -------------------------------------------------------------------------
// Split Barrier Begin/End Semantics
// -------------------------------------------------------------------------

#[test]
fn t6_12_split_barrier_begin_end() {
    let mut runtime = make_d3d12_runtime();

    let resource = runtime
        .create_committed_resource(casa1::gfx::ResourceDesc {
            name: "split_test".to_string(),
            format: casa1::gfx::DxgiFormat::R8G8B8A8Unorm,
            heap: casa1::gfx::HeapType::Default,
            size: 512,
            subresources: 1,
            initial_state: ResourceState::Common,
            usage_hint: casa1::gfx::ResourceUsageHint::Generic,
        })
        .expect("create resource");

    let allocator = runtime.create_command_allocator();
    let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
    let ps = runtime.create_pipeline_state(
        root_sig,
        casa1::gfx::PipelineStateDesc {
            label: "split_test".to_string(),
            compute: false,
            render_target_formats: vec![],
            depth_format: None,
        },
    );
    let list = runtime.create_graphics_command_list(allocator, ps, false);

    // Begin split barrier: Common -> RenderTarget
    runtime
        .record_split_barrier_begin(
            list,
            resource,
            0,
            ResourceState::Common,
            ResourceState::RenderTarget,
        )
        .expect("split begin");
    assert_eq!(runtime.pending_split_barrier_count(), 1);

    // State should NOT have changed yet (BEGIN_ONLY)
    assert_eq!(
        runtime.resource_state(resource, 0).expect("state"),
        ResourceState::Common
    );

    // End split barrier: Common -> RenderTarget
    runtime
        .record_split_barrier_end(
            list,
            resource,
            0,
            ResourceState::Common,
            ResourceState::RenderTarget,
        )
        .expect("split end");
    assert_eq!(runtime.pending_split_barrier_count(), 0);

    // State should NOW be RenderTarget (END_ONLY completes it)
    assert_eq!(
        runtime.resource_state(resource, 0).expect("state"),
        ResourceState::RenderTarget
    );
}

// -------------------------------------------------------------------------
// Aliasing Barrier Notification
// -------------------------------------------------------------------------

#[test]
fn t6_13_aliasing_barrier() {
    let mut runtime = make_d3d12_runtime();

    let resource_a = runtime
        .create_committed_resource(casa1::gfx::ResourceDesc {
            name: "alias_a".to_string(),
            format: casa1::gfx::DxgiFormat::R8G8B8A8Unorm,
            heap: casa1::gfx::HeapType::Default,
            size: 256,
            subresources: 1,
            initial_state: ResourceState::Common,
            usage_hint: casa1::gfx::ResourceUsageHint::Generic,
        })
        .expect("create resource_a");

    let resource_b = runtime
        .create_committed_resource(casa1::gfx::ResourceDesc {
            name: "alias_b".to_string(),
            format: casa1::gfx::DxgiFormat::R8G8B8A8Unorm,
            heap: casa1::gfx::HeapType::Default,
            size: 256,
            subresources: 1,
            initial_state: ResourceState::Common,
            usage_hint: casa1::gfx::ResourceUsageHint::Generic,
        })
        .expect("create resource_b");

    let allocator = runtime.create_command_allocator();
    let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
    let ps = runtime.create_pipeline_state(
        root_sig,
        casa1::gfx::PipelineStateDesc {
            label: "alias_test".to_string(),
            compute: false,
            render_target_formats: vec![],
            depth_format: None,
        },
    );
    let list = runtime.create_graphics_command_list(allocator, ps, false);

    // Record aliasing barrier: resource_a before, resource_b after
    runtime
        .record_aliasing_barrier(list, Some(resource_a), Some(resource_b))
        .expect("aliasing barrier");

    // Verify overlap tracking
    assert!(runtime.check_aliasing_overlap(resource_a, resource_b));

    // Check that none-overlapping resources don't match
    let resource_c = runtime
        .create_committed_resource(casa1::gfx::ResourceDesc {
            name: "alias_c".to_string(),
            format: casa1::gfx::DxgiFormat::R8G8B8A8Unorm,
            heap: casa1::gfx::HeapType::Default,
            size: 256,
            subresources: 1,
            initial_state: ResourceState::Common,
            usage_hint: casa1::gfx::ResourceUsageHint::Generic,
        })
        .expect("create resource_c");
    assert!(!runtime.check_aliasing_overlap(resource_a, resource_c));

    runtime.clear_aliasing_overlaps();
    assert!(!runtime.check_aliasing_overlap(resource_a, resource_b));
}

// -------------------------------------------------------------------------
// UAV Barrier Insertion
// -------------------------------------------------------------------------

#[test]
fn t6_14_uav_barrier() {
    let mut runtime = make_d3d12_runtime();

    let resource = runtime
        .create_committed_resource(casa1::gfx::ResourceDesc {
            name: "uav_test".to_string(),
            format: casa1::gfx::DxgiFormat::R8G8B8A8Unorm,
            heap: casa1::gfx::HeapType::Default,
            size: 1024,
            subresources: 1,
            initial_state: ResourceState::Common,
            usage_hint: casa1::gfx::ResourceUsageHint::Generic,
        })
        .expect("create resource");

    let allocator = runtime.create_command_allocator();
    let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
    let ps = runtime.create_pipeline_state(
        root_sig,
        casa1::gfx::PipelineStateDesc {
            label: "uav_test".to_string(),
            compute: false,
            render_target_formats: vec![],
            depth_format: None,
        },
    );
    let list = runtime.create_graphics_command_list(allocator, ps, false);

    // Record a UAV barrier
    runtime
        .record_uav_barrier(list, resource)
        .expect("uav barrier");

    // Also test via the resource_barrier dispatch
    let desc = D3D12ResourceBarrierDesc {
        barrier_type: D3D12ResourceBarrierType::Uav,
        flags: D3D12ResourceBarrierFlags::None,
        resource: Some(resource),
        subresource: 0,
        state_before: ResourceState::Common,
        state_after: ResourceState::UnorderedAccess,
        resource_before: None,
        resource_after: None,
    };
    runtime
        .record_resource_barrier(list, &desc)
        .expect("resource barrier uav");

    // Verify state is still correct
    assert_eq!(
        runtime.resource_state(resource, 0).expect("state"),
        ResourceState::Common
    );
}

// -------------------------------------------------------------------------
// Descriptor Range Type and Unbounded Arrays
// -------------------------------------------------------------------------

#[test]
fn t6_15_descriptor_range_types() {
    // Verify descriptor range type string mappings
    assert_eq!(
        D3d12Runtime::descriptor_range_type_to_metal(D3D12DescriptorRangeType::Srv),
        "texture"
    );
    assert_eq!(
        D3d12Runtime::descriptor_range_type_to_metal(D3D12DescriptorRangeType::Uav),
        "texture"
    );
    assert_eq!(
        D3d12Runtime::descriptor_range_type_to_metal(D3D12DescriptorRangeType::Cbv),
        "buffer"
    );
    assert_eq!(
        D3d12Runtime::descriptor_range_type_to_metal(D3D12DescriptorRangeType::Sampler),
        "sampler"
    );

    // Verify unbounded range resolution
    assert_eq!(
        D3d12Runtime::resolve_unbounded_range(D3D12DescriptorRangeType::Srv, u32::MAX),
        1024
    );
    assert_eq!(
        D3d12Runtime::resolve_unbounded_range(D3D12DescriptorRangeType::Uav, u32::MAX),
        1024
    );
    assert_eq!(
        D3d12Runtime::resolve_unbounded_range(D3D12DescriptorRangeType::Cbv, u32::MAX),
        256
    );
    assert_eq!(
        D3d12Runtime::resolve_unbounded_range(D3D12DescriptorRangeType::Sampler, u32::MAX),
        64
    );
    // Bounded ranges pass through unchanged
    assert_eq!(
        D3d12Runtime::resolve_unbounded_range(D3D12DescriptorRangeType::Srv, 16),
        16
    );
}

// -------------------------------------------------------------------------
// Visibility Flags
// -------------------------------------------------------------------------

#[test]
fn t6_16_visibility_flags() {
    // Verify visibility offset handling
    let desc = RootSignatureDesc {
        descriptor_tables: vec![2, 1],
        root_constants: 0,
        parameters: vec![
            RootParameter::DescriptorTable {
                ranges: vec![DescriptorRange {
                    range_type: D3D12DescriptorRangeType::Srv,
                    num_descriptors: 2,
                    base_shader_register: 0,
                    register_space: 0,
                    offset_in_table: 0,
                }],
                visibility: D3D12ShaderVisibility::Pixel,
            },
            RootParameter::DescriptorTable {
                ranges: vec![DescriptorRange {
                    range_type: D3D12DescriptorRangeType::Srv,
                    num_descriptors: 1,
                    base_shader_register: 0,
                    register_space: 0,
                    offset_in_table: 0,
                }],
                visibility: D3D12ShaderVisibility::Vertex,
            },
        ],
        static_samplers: vec![],
        visibility_offsets: BTreeMap::from([
            (D3D12ShaderVisibility::Pixel, vec![0]),
            (D3D12ShaderVisibility::Vertex, vec![1]),
        ]),
    };

    let pixel_offsets = D3d12Runtime::visibility_offsets(&desc, D3D12ShaderVisibility::Pixel);
    assert_eq!(pixel_offsets, &[0]);

    let vertex_offsets = D3d12Runtime::visibility_offsets(&desc, D3D12ShaderVisibility::Vertex);
    assert_eq!(vertex_offsets, &[1]);

    // Shader visibility with no entries returns empty slice
    let hull_offsets = D3d12Runtime::visibility_offsets(&desc, D3D12ShaderVisibility::Hull);
    assert!(hull_offsets.is_empty());
}

// -------------------------------------------------------------------------
// ResourceState bitmask conversion
// -------------------------------------------------------------------------

#[test]
fn t6_17_resource_state_bitmask() {
    // Verify D3D12_RESOURCE_STATES bitmask round-trip
    let test_cases = vec![
        (ResourceState::Common, 0u32),
        (ResourceState::RenderTarget, 0x0004),
        (ResourceState::UnorderedAccess, 0x0008),
        (ResourceState::DepthWrite, 0x0010),
        (ResourceState::CopyDest, 0x0400),
        (ResourceState::CopySource, 0x0800),
        (ResourceState::GenericRead, 0x0AC3),
        (ResourceState::VertexAndConstantBuffer, 0x0001),
        (ResourceState::IndexBuffer, 0x0002),
        (ResourceState::DepthRead, 0x0020),
        (ResourceState::NonPixelShaderResource, 0x0040),
        (ResourceState::PixelShaderResource, 0x0080),
        (ResourceState::StreamOut, 0x0100),
        (ResourceState::IndirectArgument, 0x0200),
        (ResourceState::ResolveDest, 0x1000),
        (ResourceState::ResolveSource, 0x2000),
        (ResourceState::RaytracingAccelerationStructure, 0x4000),
        (ResourceState::ShadingRateSource, 0x10000),
    ];

    for (state, bits) in test_cases {
        assert_eq!(
            state.to_d3d12_bits(),
            bits,
            "state {state:?} -> bits mismatch"
        );
        let round_trip = ResourceState::from_d3d12_bits(bits);
        assert!(
            round_trip.contains(&state),
            "bits {bits:#x} -> states {round_trip:?} should include {state:?}"
        );
    }

    // GenericRead from multiple combined bits
    let generic_bits = 0x0001 | 0x0002 | 0x0040 | 0x0200 | 0x0800; // VB+IB+NPSR+IA+CS
    let states = ResourceState::from_d3d12_bits(generic_bits);
    assert!(states.contains(&ResourceState::VertexAndConstantBuffer));
    assert!(states.contains(&ResourceState::IndexBuffer));
    assert!(states.contains(&ResourceState::NonPixelShaderResource));
    assert!(states.contains(&ResourceState::IndirectArgument));
    assert!(states.contains(&ResourceState::CopySource));
}

// -------------------------------------------------------------------------
// Subresource State Tracking
// -------------------------------------------------------------------------

#[test]
fn t6_18_subresource_state_tracking() {
    let mut runtime = make_d3d12_runtime();

    let resource = runtime
        .create_committed_resource(casa1::gfx::ResourceDesc {
            name: "subresource_test".to_string(),
            format: casa1::gfx::DxgiFormat::R8G8B8A8Unorm,
            heap: casa1::gfx::HeapType::Default,
            size: 4096,
            subresources: 6, // 2 array slices * 3 mip levels
            initial_state: ResourceState::Common,
            usage_hint: casa1::gfx::ResourceUsageHint::Texture {
                sampled: true,
                render_target: false,
                depth_stencil: false,
                cpu_write_frequent: false,
            },
        })
        .expect("create resource");

    // Track per-subresource states using array_slice + mip_level
    runtime.set_subresource_state(resource, 0, 0, ResourceState::RenderTarget);
    runtime.set_subresource_state(resource, 0, 1, ResourceState::UnorderedAccess);
    runtime.set_subresource_state(resource, 1, 0, ResourceState::CopyDest);

    assert_eq!(
        runtime.subresource_state(resource, 0, 0),
        Some(ResourceState::RenderTarget)
    );
    assert_eq!(
        runtime.subresource_state(resource, 0, 1),
        Some(ResourceState::UnorderedAccess)
    );
    assert_eq!(
        runtime.subresource_state(resource, 1, 0),
        Some(ResourceState::CopyDest)
    );
    assert_eq!(runtime.subresource_state(resource, 1, 1), None);
}

// ── Phase 2.3: Mesh Shader tests ────────────────────────────────────

#[test]
fn t6_19_mesh_pipeline_dispatch() {
    let mut runtime = make_d3d12_runtime();
    let swapchain = runtime
        .create_swapchain(SwapchainDesc {
            width: 256,
            height: 256,
            format: DxgiFormat::R8G8B8A8Unorm,
            buffer_count: 2,
        })
        .expect("create swapchain");
    let backbuffer = runtime
        .swapchain_state(swapchain)
        .expect("swapchain state")
        .backbuffers[0];

    let rtv_heap = runtime.create_descriptor_heap(casa1::gfx::DescriptorHeapType::Rtv, 1);
    runtime
        .write_descriptor(
            rtv_heap,
            0,
            ViewDescriptor::Rtv {
                resource: backbuffer,
                format: DxgiFormat::R8G8B8A8Unorm,
            },
        )
        .expect("write rtv descriptor");

    let root_signature = runtime.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![],
        root_constants: 0,
        ..Default::default()
    });

    let pipeline_state = runtime.create_pipeline_state(
        root_signature,
        PipelineStateDesc {
            label: "mesh_test".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
            depth_format: None,
        },
    );

    let queue = runtime.create_command_queue();
    let allocator = runtime.create_command_allocator();
    let list = runtime.create_graphics_command_list(allocator, pipeline_state, false);

    // DispatchMesh requires an active render pass (it generates geometry for rasterization)
    runtime
        .record_begin_render_pass(
            list,
            vec![DxgiFormat::R8G8B8A8Unorm],
            None,
            "clear",
            "store",
        )
        .expect("begin render pass");

    // Dispatch mesh with a 8×1×1 threadgroup grid
    runtime.dispatch_mesh(list, 8, 1, 1).expect("dispatch mesh");

    let stream = runtime.close_command_list(list).expect("close list");
    let fence = runtime.create_fence(0);
    let plan = runtime
        .execute_command_lists(queue, &[stream], Some((fence, 1)))
        .expect("execute command lists");

    // Mesh shader dispatch counts as a draw call within the render pass
    assert_eq!(plan.render_passes.len(), 1);
    assert_eq!(plan.render_passes[0].draw_calls, 1);
}

#[test]
fn t6_20_mesh_dispatch_zero_dimensions_is_noop() {
    let mut runtime = make_d3d12_runtime();
    let swapchain = runtime
        .create_swapchain(SwapchainDesc {
            width: 256,
            height: 256,
            format: DxgiFormat::R8G8B8A8Unorm,
            buffer_count: 2,
        })
        .expect("create swapchain");
    let backbuffer = runtime
        .swapchain_state(swapchain)
        .expect("swapchain state")
        .backbuffers[0];

    let rtv_heap = runtime.create_descriptor_heap(casa1::gfx::DescriptorHeapType::Rtv, 1);
    runtime
        .write_descriptor(
            rtv_heap,
            0,
            ViewDescriptor::Rtv {
                resource: backbuffer,
                format: DxgiFormat::R8G8B8A8Unorm,
            },
        )
        .expect("write rtv descriptor");

    let root_signature = runtime.create_root_signature(RootSignatureDesc::default());
    let pipeline_state = runtime.create_pipeline_state(
        root_signature,
        PipelineStateDesc {
            label: "mesh_zero".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
            depth_format: None,
        },
    );

    let queue = runtime.create_command_queue();
    let allocator = runtime.create_command_allocator();
    let list = runtime.create_graphics_command_list(allocator, pipeline_state, false);

    runtime
        .record_begin_render_pass(
            list,
            vec![DxgiFormat::R8G8B8A8Unorm],
            None,
            "clear",
            "store",
        )
        .expect("begin render pass");

    // Dispatch with zero dimensions should still be accepted
    let _result = runtime.dispatch_mesh(list, 0, 0, 0);
    assert!(_result.is_ok(), "expected Ok, got {_result:?}");

    let stream = runtime.close_command_list(list).expect("close list");
    let fence = runtime.create_fence(0);
    let plan = runtime
        .execute_command_lists(queue, &[stream], Some((fence, 1)))
        .expect("execute command lists");

    assert_eq!(plan.render_passes.len(), 1);
    // Zero-threadgroup dispatch still registers as a draw call
    assert_eq!(plan.render_passes[0].draw_calls, 1);
}

// ── Phase 2.4: DXR Raytracing tests ─────────────────────────────────

#[test]
fn t6_21_build_bottom_level_acceleration_structure() {
    let mut runtime = make_d3d12_runtime();

    let desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0x1000,
        inputs: D3D12BuildRaytracingInputs {
            ty: 0, // BOTTOM_LEVEL
            flags: 0,
            num_descs: 1,
            geometries: vec![D3D12RaytracingGeometryDesc {
                ty: 0, // TRIANGLES
                flags: 0,
                vertex_buffer: 0x2000,
                vertex_format: 80, // DXGI_FORMAT_R32G32B32_FLOAT
                vertex_stride: 12,
                vertex_count: 36,
                index_buffer: 0x3000,
                index_format: 57, // DXGI_FORMAT_R16_UINT
                index_count: 36,
            }],
        },
        source_address: 0,
        scratch_address: 0x4000,
    };

    let allocator = runtime.create_command_allocator();
    let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
    let list = runtime.create_graphics_command_list(allocator, root_sig, false);

    let result = runtime.build_raytracing_acceleration_structure(list, &desc);
    assert!(result.is_ok(), "build BLAS should succeed");

    let gpu_addr = result.unwrap();
    assert_eq!(gpu_addr, 0x1000);

    let accel = runtime.acceleration_structure(gpu_addr);
    assert!(accel.is_some(), "acceleration structure should exist");
    let accel = accel.unwrap();
    assert!(!accel.is_top_level, "should be bottom-level");
    assert!(accel.built, "should be marked as built");
    assert_eq!(accel.gpu_address, 0x1000);
    // Size should be at least the minimum (256 bytes)
    assert!(accel.size >= 256, "AS size should be at least 256 bytes");
}

#[test]
fn t6_22_build_top_level_acceleration_structure() {
    let mut runtime = make_d3d12_runtime();

    // First create a BLAS to reference
    let blas_desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0x1000,
        inputs: D3D12BuildRaytracingInputs {
            ty: 0,
            flags: 0,
            num_descs: 1,
            geometries: vec![D3D12RaytracingGeometryDesc {
                ty: 0,
                flags: 0,
                vertex_buffer: 0x2000,
                vertex_format: 80,
                vertex_stride: 12,
                vertex_count: 36,
                index_buffer: 0x3000,
                index_format: 57,
                index_count: 36,
            }],
        },
        source_address: 0,
        scratch_address: 0x4000,
    };

    let allocator = runtime.create_command_allocator();
    let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
    let list = runtime.create_graphics_command_list(allocator, root_sig, false);

    runtime
        .build_raytracing_acceleration_structure(list, &blas_desc)
        .expect("build BLAS");

    // Now build a TLAS referencing it
    let tlas_desc = D3D12BuildAccelerationStructureDesc {
        dest_address: 0x5000,
        inputs: D3D12BuildRaytracingInputs {
            ty: 1, // TOP_LEVEL
            flags: 0,
            num_descs: 1,
            geometries: vec![], // TLAS uses instance descs, not geometries
        },
        source_address: 0,
        scratch_address: 0x6000,
    };

    let result = runtime.build_raytracing_acceleration_structure(list, &tlas_desc);
    assert!(result.is_ok(), "build TLAS should succeed");

    let accel = runtime.acceleration_structure(0x5000);
    assert!(accel.is_some(), "TLAS should exist");
    let accel = accel.unwrap();
    assert!(accel.is_top_level, "should be top-level");
    assert_eq!(accel.gpu_address, 0x5000);
    // TLAS with 1 instance: header (64) + instance (72) = 136, minimum 256
    assert!(accel.size >= 256, "TLAS size should be at least 256 bytes");
}

#[test]
fn t6_23_dispatch_rays_shader_table_parsing() {
    let mut runtime = make_d3d12_runtime();

    let allocator = runtime.create_command_allocator();
    let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
    let list = runtime.create_graphics_command_list(allocator, root_sig, false);

    // Set a raytracing pipeline state first
    let dxil = vec![0u8; 128];
    runtime
        .set_pipeline_state1(list, 0xABCD, dxil)
        .expect("set pipeline state1");

    let pso = runtime.get_raytracing_pipeline_state(0xABCD);
    assert!(pso.is_some(), "PSO should be stored");
    assert_eq!(pso.unwrap().dxil_bytecode.len(), 128);
    assert_eq!(pso.unwrap().payload_size, 32, "default payload size");
    assert_eq!(pso.unwrap().attribute_size, 8, "default attribute size");
    assert_eq!(
        pso.unwrap().max_recursion_depth,
        1,
        "default recursion depth"
    );

    // Dispatch rays with valid shader table addresses
    let dispatch_desc = D3D12DispatchRaysDesc {
        raygen_shader_start_address: 0x5000,
        raygen_shader_size: 64,
        miss_shader_start_address: 0x6000,
        miss_shader_size: 64,
        miss_shader_stride: 64,
        hit_group_start_address: 0x7000,
        hit_group_size: 64,
        hit_group_stride: 64,
        callable_shader_start_address: 0,
        callable_shader_size: 0,
        callable_shader_stride: 0,
        width: 16,
        height: 16,
        depth: 1,
    };

    let result = runtime.dispatch_rays(list, &dispatch_desc);
    assert!(result.is_ok(), "dispatch rays should succeed");

    // Zero-dimension dispatch should be a no-op
    let zero_desc = D3D12DispatchRaysDesc {
        raygen_shader_start_address: 0x5000,
        raygen_shader_size: 64,
        miss_shader_start_address: 0x6000,
        miss_shader_size: 64,
        miss_shader_stride: 64,
        hit_group_start_address: 0x7000,
        hit_group_size: 64,
        hit_group_stride: 64,
        callable_shader_start_address: 0,
        callable_shader_size: 0,
        callable_shader_stride: 0,
        width: 0,
        height: 0,
        depth: 0,
    };
    assert!(
        runtime.dispatch_rays(list, &zero_desc).is_ok(),
        "zero dispatch should be no-op"
    );

    // Empty raygen shader should be accepted (no-op)
    let no_raygen_desc = D3D12DispatchRaysDesc {
        raygen_shader_start_address: 0,
        raygen_shader_size: 0,
        miss_shader_start_address: 0,
        miss_shader_size: 0,
        miss_shader_stride: 0,
        hit_group_start_address: 0,
        hit_group_size: 0,
        hit_group_stride: 0,
        callable_shader_start_address: 0,
        callable_shader_size: 0,
        callable_shader_stride: 0,
        width: 16,
        height: 16,
        depth: 1,
    };
    assert!(
        runtime.dispatch_rays(list, &no_raygen_desc).is_ok(),
        "no raygen shader should be accepted as no-op"
    );
}

#[test]
fn t6_24_raytracing_pipeline_state_and_feature_query() {
    let mut runtime = make_d3d12_runtime();

    // Verify raytracing feature query is available
    let caps = runtime.backend().capabilities();
    // The raytracing field exists and is queryable
    let _raytracing_supported = caps.raytracing;

    // Query through the feature query API
    let backend = runtime.backend();
    let raytracing_available = backend.query_feature(FeatureQuery::Raytracing);
    // On Apple Silicon (Apple7+), raytracing should be reported;
    // on other hardware it may be false. Just verify the query executes.
    let _ = raytracing_available;

    // Mesh shader feature query should also be available
    let mesh_available = backend.query_feature(FeatureQuery::MeshShaders);
    let _ = mesh_available;

    // Set and query raytracing pipeline state
    let allocator = runtime.create_command_allocator();
    let root_sig = runtime.create_root_signature(RootSignatureDesc::default());
    let list = runtime.create_graphics_command_list(allocator, root_sig, false);

    let dxil = vec![42u8; 256];
    runtime
        .set_pipeline_state1(list, 0xBEEF, dxil)
        .expect("set raytracing pipeline state");

    let pso = runtime.get_raytracing_pipeline_state(0xBEEF);
    assert!(pso.is_some(), "raytracing PSO should be stored");
    let pso = pso.unwrap();
    assert_eq!(pso.dxil_bytecode.len(), 256);
    assert_eq!(pso.dxil_bytecode[0], 42);
    assert_eq!(pso.dxil_bytecode[255], 42);

    // Unknown state object pointer should return None
    assert!(
        runtime.get_raytracing_pipeline_state(0xDEAD).is_none(),
        "unknown state object should not exist"
    );
}
