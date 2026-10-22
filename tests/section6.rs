#![allow(dead_code, unused_imports)]
use casa1::d3d12::{
    D3D12BuildAccelerationStructureDesc, D3D12BuildRaytracingInputs, D3D12RaytracingGeometryDesc,
    D3d12Runtime,
};
use casa1::gfx::{D3D12ShaderVisibility, D3D12StaticSamplerDesc, ResourceState, RootSignatureDesc};
use casa1::reason::ReasonCode;
use casa1::user32::{
    AxisCalibration, BatteryInfo, ControllerKind, ControllerSpec, ControllerTransport, DeviceAxis,
    ForceFeedbackEffect, KeyboardLayoutId, Message, MessageKind, MouseButton, MouseButtonEvent,
    MouseDevice, Rect, RumbleState, User32Subsystem,
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

    // Assert concrete xinput values: the attach event seeds the packet
    // number at 1 and XInputGetState advances it on every poll (see
    // User32Subsystem::xinput_get_state), so the first observed poll after
    // attach reports 2; buttons/battery/keystroke match the injected specs.
    for device in devices.iter().filter(|device| device.xinput_slot.is_some()) {
        let slot = device.xinput_slot.expect("slot assigned");
        let capabilities = user32
            .xinput_get_capabilities(slot)
            .expect("xinput capabilities");
        assert!(capabilities.supports_rumble);
        let state = user32.xinput_get_state(slot).expect("xinput state");
        assert_eq!(
            state.packet_number, 2,
            "first poll advances the attach packet 1 -> 2"
        );
        let expected_buttons = match device.name.as_str() {
            "Xbox USB" => {
                assert_eq!(
                    user32
                        .xinput_get_battery_information(slot)
                        .expect("battery information"),
                    BatteryInfo {
                        level_percent: 100,
                        wired: true,
                    }
                );
                vec!["A".to_string(), "Start".to_string()]
            }
            "Xbox BT" => {
                assert_eq!(
                    user32
                        .xinput_get_battery_information(slot)
                        .expect("battery information"),
                    BatteryInfo {
                        level_percent: 87,
                        wired: false,
                    }
                );
                vec!["B".to_string()]
            }
            "Third Party XInput" => {
                assert_eq!(
                    user32
                        .xinput_get_battery_information(slot)
                        .expect("battery information"),
                    BatteryInfo {
                        level_percent: 100,
                        wired: true,
                    }
                );
                vec!["X".to_string()]
            }
            other => panic!("unexpected xinput device {other:?}"),
        };
        assert_eq!(
            state.buttons.iter().collect::<Vec<_>>(),
            expected_buttons.iter().collect::<Vec<_>>(),
            "buttons for {} must match the attached spec",
            device.name
        );
        assert_eq!(
            user32.xinput_get_keystroke(slot).expect("xinput keystroke"),
            expected_buttons.first().cloned(),
            "keystroke must report the first button of the attached spec"
        );
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
    // The rumble update advances the packet number (2 -> 3) and the poll
    // that observes it advances once more, so the reading is 4.
    assert_eq!(
        user32
            .xinput_get_state(preferred_slot)
            .expect("xinput state after rumble")
            .packet_number,
        4
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

// =========================================================================
// Phase 2.1-2.2 Tests: D3D12 Root Signatures + Resource Barriers
// =========================================================================

fn make_d3d12_runtime() -> D3d12Runtime {
    D3d12Runtime::new()
}

// -------------------------------------------------------------------------
// Root Signature Serialization / Deserialization Round-Trip
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Static Sampler Creation with All Filter Modes
// -------------------------------------------------------------------------

#[test]
fn t6_9_static_sampler_filter_modes() {
    use casa1::d3d12::D3D12FilterReduction::*;
    // Validate filter mode mapping
    let mapping = D3d12Runtime::map_d3d12_filter_to_metal(0); // MIN_MAG_MIP_POINT
    assert_eq!(mapping.min_filter, "nearest");
    assert_eq!(mapping.mag_filter, "nearest");
    assert_eq!(mapping.mip_filter, "nearest");
    assert!(!mapping.anisotropic);
    assert!(!mapping.is_comparison());
    assert_eq!(mapping.reduction, Standard);

    let mapping = D3d12Runtime::map_d3d12_filter_to_metal(0x14); // MIN_MAG_LINEAR_MIP_POINT
    assert_eq!(mapping.min_filter, "linear");
    assert_eq!(mapping.mag_filter, "linear");
    assert_eq!(mapping.mip_filter, "nearest");
    assert!(!mapping.anisotropic);
    assert_eq!(mapping.reduction, Standard);

    let mapping = D3d12Runtime::map_d3d12_filter_to_metal(0x55); // ANISOTROPIC
    assert!(mapping.anisotropic);
    assert_eq!(mapping.reduction, Standard);

    let mapping = D3d12Runtime::map_d3d12_filter_to_metal(0x80); // COMPARISON_MIN_MAG_MIP_POINT
    assert!(!mapping.anisotropic);
    assert!(mapping.is_comparison());
    assert_eq!(mapping.reduction, Comparison);

    // The full four-way reduction: MINIMUM and MAXIMUM are decoded as their
    // real enum variants (never collapsed into comparison).
    let mapping = D3d12Runtime::map_d3d12_filter_to_metal(0x100); // MINIMUM_MIN_MAG_MIP_POINT
    assert!(!mapping.is_comparison());
    assert_eq!(mapping.reduction, Minimum);
    let mapping = D3d12Runtime::map_d3d12_filter_to_metal(0x180); // MAXIMUM_MIN_MAG_MIP_POINT
    assert!(!mapping.is_comparison());
    assert_eq!(mapping.reduction, Maximum);

    // Validate address mode mapping against the real D3D12 enum:
    // 0=WRAP, 1=MIRROR, 2=CLAMP, 3=BORDER, 4=MIRROR_ONCE.
    assert_eq!(D3d12Runtime::map_d3d12_address_mode(0).unwrap(), "repeat");
    assert_eq!(
        D3d12Runtime::map_d3d12_address_mode(1).unwrap(),
        "mirror_repeat"
    );
    assert_eq!(
        D3d12Runtime::map_d3d12_address_mode(2).unwrap(),
        "clamp_to_edge"
    );
    assert_eq!(
        D3d12Runtime::map_d3d12_address_mode(3).unwrap(),
        "clamp_to_border"
    );
    assert_eq!(
        D3d12Runtime::map_d3d12_address_mode(4).unwrap(),
        "mirror_clamp_to_edge"
    );
    // Values outside 0..=4 are undefined per d3d12.h — a validation error
    // on Windows, never a silent default.
    for invalid in [5, 6, 7, 8, 99] {
        assert!(
            D3d12Runtime::map_d3d12_address_mode(invalid).is_err(),
            "address mode {invalid} must be rejected"
        );
    }

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
        address_u: 0, // D3D12_TEXTURE_ADDRESS_MODE_WRAP
        address_v: 0,
        address_w: 0,
        mip_lod_bias: 0.0,
        max_anisotropy: 1,
        comparison_func: 0,
        border_color: 0,
        min_lod: 0.0,
        max_lod: 1000.0,
        shader_visibility: D3D12ShaderVisibility::All,
    };
    let metal_desc = D3d12Runtime::static_sampler_to_metal_desc(&sampler)
        .expect("static sampler descriptor should validate");
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

// -------------------------------------------------------------------------
// Resource State Transition Tracking
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Split Barrier Begin/End Semantics
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// Descriptor Range Type and Unbounded Arrays
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Visibility Flags
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// ResourceState bitmask conversion
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Subresource State Tracking
// -------------------------------------------------------------------------

// ── Phase 2.3: Mesh Shader tests ────────────────────────────────────

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
