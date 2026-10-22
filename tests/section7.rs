#![allow(dead_code, unused_imports)]
use casa1::gfx::{
    DescriptorHeapType, DxgiFormat, FilterMode, GraphicsBackend, HeapType, PipelineStateDesc,
    ResourceDesc, ResourceState, ResourceUsageHint, RootSignatureDesc, ViewDescriptor,
};
use casa1::reason::ReasonCode;

#[test]
fn t7_4_metal_validation_gate_reports_errors_for_invalid_scenes() {
    // The Metal validation gate lives in execute_command_lists
    // (src/gfx.rs:2472-2537), not in render_scene (which always reports zero
    // validation errors, src/gfx.rs:2717-2721). Exercise the real gate: valid
    // command streams must validate clean, invalid ones must produce errors.

    let mut backend = GraphicsBackend::new();
    let color = backend
        .create_resource(ResourceDesc {
            name: "validation-color".to_string(),
            format: DxgiFormat::B8G8R8A8Unorm,
            heap: HeapType::Default,
            size: 64,
            subresources: 1,
            initial_state: ResourceState::Common,
            usage_hint: ResourceUsageHint::Generic,
        })
        .expect("create validation color resource");

    // Valid scene: begin render pass, clear RTV, draw.
    let rtv_heap = backend.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
    backend
        .write_descriptor(
            rtv_heap,
            0,
            ViewDescriptor::Rtv {
                resource: color,
                format: DxgiFormat::B8G8R8A8Unorm,
            },
        )
        .expect("write validation RTV");
    let root_signature = backend.create_root_signature(RootSignatureDesc::default());
    let pipeline_state = backend.create_pipeline_state(
        root_signature,
        PipelineStateDesc {
            label: "validation".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
            depth_format: None,
        },
    );
    let queue = backend.create_command_queue();
    let allocator = backend.create_command_allocator();
    let list = backend.create_graphics_command_list(allocator, pipeline_state, false);
    backend
        .record_begin_render_pass(
            list,
            vec![DxgiFormat::B8G8R8A8Unorm],
            None,
            "clear",
            "store",
        )
        .expect("begin render pass");
    backend
        .record_clear_rtv(list, rtv_heap, 0)
        .expect("clear RTV");
    backend.record_draw(list, 3).expect("record draw");
    let closed = backend
        .close_command_list(list)
        .expect("close valid command list");
    let fence = backend.create_fence(0);
    let valid_plan = backend
        .execute_command_lists(queue, &[closed], Some((fence, 1)))
        .expect("execute valid command list");
    assert!(
        valid_plan.validation_errors.is_empty(),
        "valid command stream must validate clean; got {:?}",
        valid_plan.validation_errors
    );

    // Invalid scene 1: draw without an active render pass.
    let allocator = backend.create_command_allocator();
    let list = backend.create_graphics_command_list(allocator, pipeline_state, false);
    backend.record_draw(list, 3).expect("record orphan draw");
    let closed = backend
        .close_command_list(list)
        .expect("close invalid command list");
    let fence = backend.create_fence(0);
    let invalid_plan = backend
        .execute_command_lists(queue, &[closed], Some((fence, 2)))
        .expect("execute invalid command list");
    assert!(
        invalid_plan
            .validation_errors
            .iter()
            .any(|error| error.contains("draw without active render pass")),
        "orphan draw must be reported by the validation gate; got {:?}",
        invalid_plan.validation_errors
    );

    // Invalid scene 2: clearing an RTV slot that holds a non-RTV descriptor
    // is rejected eagerly at record time by the descriptor validation gate
    // (record_clear_rtv -> validate_rtv_descriptor, src/gfx.rs:1987-1998).
    let sampler_heap = backend.create_descriptor_heap(DescriptorHeapType::Sampler, 1);
    backend
        .write_descriptor(
            sampler_heap,
            0,
            ViewDescriptor::Sampler {
                filter: FilterMode::Point,
            },
        )
        .expect("write sampler descriptor");
    let allocator = backend.create_command_allocator();
    let list = backend.create_graphics_command_list(allocator, pipeline_state, false);
    let misattached = backend.record_clear_rtv(list, sampler_heap, 0);
    assert!(
        misattached.is_err(),
        "clear on a non-RTV descriptor must be rejected; got {misattached:?}"
    );
    assert_eq!(
        misattached.expect_err("misattached clear").code,
        ReasonCode::RcD3dInvalidState
    );
}
