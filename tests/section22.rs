//! Phase 8 — AAA Conformance Tests
//!
//! Comprehensive conformance tests covering shader translation, Metal backend
//! resource tracking, Vulkan state lifecycle, DRM integrity, SCM VM lifecycle,
//! Steam protocol stack, performance optimizations, visual fidelity SSIM,
//! stress testing, behavioral verification, and end-to-end integration.

use casa1::cpu::MemoryImage;
use casa1::d3d12::D3d12Runtime;
use casa1::diagnostics::{
    BehavioralTestStep, BehavioralVerifier, FrameCapture, StressTestConfig, StressTestRunner,
    compare_frames, compute_pixel_diff, compute_psnr, compute_ssim,
};
use casa1::gfx::{
    DescriptorHeapType, DxgiFormat, HeapType, PipelineStateDesc, ResourceDesc, ResourceState,
    ResourceUsageHint, RootSignatureDesc, SwapchainDesc, ViewDescriptor,
};
use casa1::perf::{BlockChainingCache, FileCache, LazyJitProfiler};
use casa1::scm::{ScmConfig, ScmRunnerIntegration, VmState};
use casa1::security::{
    CodeSection, DenuvoConfig, DenuvoEmulator, DenuvoVersion, EncryptionType, SteamstubLoader,
};
use casa1::shader::ShaderStage;
use casa1::shader_compiler::MslShaderGenerator;
use casa1::steam_protocol::{ConnectionState, SteamProtocolStack};

// ---------------------------------------------------------------------------
// t22_1_shader_translation_conformance
// ---------------------------------------------------------------------------

#[test]
fn t22_1_shader_translation_conformance() {
    // Create an MSL shader generator for a vertex shader
    let mut generator = MslShaderGenerator::new(ShaderStage::Vs, "VSMain");
    generator.add_input("position", "POSITION", 0, "float3");
    generator.add_input("texcoord", "TEXCOORD", 0, "float2");
    generator.add_output("out_pos", "SV_POSITION", 0, "float4");
    generator.add_output("out_uv", "TEXCOORD", 0, "float2");

    // Generate MSL from the shader
    let msl_source = generator.generate();

    // Verify MSL output contains expected constructs
    assert!(
        msl_source.contains("vertex"),
        "MSL output should contain 'vertex' function qualifier"
    );
    assert!(
        msl_source.contains("VSMain"),
        "MSL output should contain the entry point name"
    );
    assert!(
        msl_source.contains("#include <metal_stdlib>"),
        "MSL output should include metal_stdlib"
    );
    assert!(!msl_source.is_empty(), "MSL source should not be empty");

    // Test HLSL intrinsic translation
    use casa1::shader_compiler::translate_hlsl_intrinsic;
    assert_eq!(
        translate_hlsl_intrinsic("sin"),
        "sin",
        "sin should map to sin"
    );
    assert_eq!(
        translate_hlsl_intrinsic("tex2D"),
        "sample",
        "tex2D should translate to Metal sample call"
    );
}

// ---------------------------------------------------------------------------
// t22_2_metal_backend_resource_tracking
// ---------------------------------------------------------------------------

#[test]
fn t22_2_metal_backend_resource_tracking() {
    let mut runtime = D3d12Runtime::new();

    // Create multiple resources
    let mut resources = Vec::new();

    // Create buffers
    for i in 0..3 {
        let resource = runtime
            .create_committed_resource(ResourceDesc {
                name: format!("buffer_{i}"),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Upload,
                size: 1024,
                subresources: 1,
                initial_state: ResourceState::GenericRead,
                usage_hint: ResourceUsageHint::Buffer {
                    role: casa1::gfx::BufferRole::Vertex,
                    cpu_write_frequent: false,
                },
            })
            .expect("create buffer");
        resources.push(resource);
    }

    // Create textures
    for i in 0..3 {
        let resource = runtime
            .create_committed_resource(ResourceDesc {
                name: format!("texture_{i}"),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Default,
                size: 256 * 256 * 4,
                subresources: 1,
                initial_state: ResourceState::PixelShaderResource,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: true,
                    render_target: false,
                    depth_stencil: false,
                    cpu_write_frequent: false,
                },
            })
            .expect("create texture");
        resources.push(resource);
    }

    // Create descriptor heap and samplers
    let srv_heap = runtime.create_descriptor_heap(DescriptorHeapType::CbvSrvUav, 6);
    let sampler_heap = runtime.create_descriptor_heap(DescriptorHeapType::Sampler, 3);

    // Write descriptors for all resources
    for (i, &resource) in resources.iter().enumerate() {
        runtime
            .write_descriptor(
                srv_heap,
                i,
                ViewDescriptor::Srv {
                    resource,
                    format: DxgiFormat::R8G8B8A8Unorm,
                },
            )
            .expect("write SRV");
    }

    // Write sampler descriptors
    for i in 0..3 {
        runtime
            .write_descriptor(
                sampler_heap,
                i,
                ViewDescriptor::Sampler {
                    filter: casa1::gfx::FilterMode::Linear,
                },
            )
            .expect("write sampler");
    }

    // Verify all descriptors are tracked
    let srv_snapshot = runtime
        .descriptor_heap_snapshot(srv_heap)
        .expect("SRV snapshot");
    assert_eq!(srv_snapshot.len(), 6, "should have 6 SRV slots");
    for (i, desc) in srv_snapshot.iter().enumerate() {
        assert!(desc.is_some(), "SRV slot {i} should be occupied");
    }

    let sampler_snapshot = runtime
        .descriptor_heap_snapshot(sampler_heap)
        .expect("sampler snapshot");
    assert_eq!(sampler_snapshot.len(), 3, "should have 3 sampler slots");

    // Destroy all resources
    for resource in &resources {
        runtime
            .destroy_resource(*resource)
            .expect("destroy resource");
    }

    // After destroying all resources, verify the heap still exists
    let snapshot_after = runtime
        .descriptor_heap_snapshot(srv_heap)
        .expect("SRV snapshot after destroy");
    assert_eq!(
        snapshot_after.len(),
        6,
        "heap should still have 6 slots after resource destruction"
    );
}

// ---------------------------------------------------------------------------
// t22_3_vulkan_state_lifecycle
// ---------------------------------------------------------------------------

#[test]
fn t22_3_vulkan_state_lifecycle() {
    use casa1::vkgl::{GraphicsBackend, VulkanSample};

    // Test Vulkan loader creation
    let loader = casa1::vkgl::vulkan_loader();
    assert!(loader.supported, "Vulkan loader should report supported");
    assert_eq!(loader.backend, GraphicsBackend::VulkanOnMetal);

    // Test Vulkan sample creation and lifecycle
    let sample = VulkanSample {
        name: "triangle_test".to_string(),
        required_instance_extensions: vec!["VK_KHR_surface".to_string()],
        required_device_extensions: vec!["VK_KHR_swapchain".to_string()],
        clear_color: [0, 0, 128, 255],
        draw_calls: 1,
        compute_dispatches: 0,
    };

    // Exercise the actual render lifecycle instead of re-asserting the literals
    // written into the struct: the sample must render through the loader with no
    // validation errors, and the artifact must be deterministic across runs.
    let frame = loader.render_sample(&sample).expect("render sample");
    assert!(
        frame.validation_errors.is_empty(),
        "expected no validation errors, got {:?}",
        frame.validation_errors
    );
    let repeat = loader
        .render_sample(&sample)
        .expect("render sample again");
    assert_eq!(
        frame.hash, repeat.hash,
        "rendering the same sample must be deterministic"
    );

    // Test OpenGL driver
    let gl_driver = casa1::vkgl::opengl_driver();
    assert!(gl_driver.supported, "OpenGL driver should report supported");
    assert_eq!(gl_driver.backend, GraphicsBackend::MetalGl);
}

// ---------------------------------------------------------------------------
// t22_4_drm_denuvo_integrity
// ---------------------------------------------------------------------------

#[test]
fn t22_4_drm_denuvo_integrity() {
    // Create a memory image with code section data
    let mut memory = MemoryImage::default();
    let base_addr = 0x0040_0000u64;
    let code_data = vec![0x90u8; 256]; // NOP sled
    memory.map_bytes(base_addr, &code_data);

    // Create Denuvo config with one code section
    // RVA must be the absolute guest address where the code section lives.
    // initialize() computes `base + rva`, verify_integrity() uses `rva` directly,
    // so we pass base=0 and rva=base_addr to keep both paths consistent.
    let config = DenuvoConfig {
        version: DenuvoVersion::V6,
        enabled: true,
        integrity_check_interval_ms: 1000,
        code_sections: vec![CodeSection {
            rva: base_addr,
            size: 256,
            original_hash: [0u8; 32], // will be computed by initialize()
            decrypted: Vec::new(),
            encrypted: false,
        }],
        trigger_points: vec![0x0040_1000],
    };

    let mut emulator = DenuvoEmulator::new(config);

    // Initialize with base=0 so that base+rva = 0+base_addr = base_addr
    emulator
        .initialize(&mut memory, 0)
        .expect("initialize Denuvo emulator");

    assert!(emulator.state.initialized, "emulator should be initialized");
    assert!(
        !emulator.state.hardware_id.iter().all(|&b| b == 0),
        "hardware ID should be non-zero after initialization"
    );

    // Verify integrity of the code section
    let integrity_ok = emulator
        .verify_integrity(&memory, 0)
        .expect("verify integrity");
    assert!(
        integrity_ok,
        "integrity check should pass on unmodified code"
    );

    assert_eq!(
        emulator.integrity_checks_passed, 1,
        "should have 1 passed integrity check"
    );

    // Generate license token
    let token = emulator.generate_license_token();
    assert!(!token.is_empty(), "license token should not be empty");

    // Verify the license token
    let valid = emulator.verify_license_token(&token);
    assert!(valid, "license token should be valid");
    assert!(
        emulator.license_verified,
        "license should be verified after verification"
    );
}

// ---------------------------------------------------------------------------
// t22_5_drm_steamstub_decrypt
// ---------------------------------------------------------------------------

#[test]
fn t22_5_drm_steamstub_decrypt() {
    // Create a memory image with a mock PE + Steamstub header
    let mut memory = MemoryImage::default();
    let base_addr = 0x0040_0000u64;

    // Write DOS header
    memory.map_bytes(base_addr, b"MZ"); // e_magic
    memory.map_bytes(base_addr + 0x3C, &0x80u32.to_le_bytes()); // e_lfanew

    // Write PE signature at e_lfanew offset
    let pe_offset = 0x80u64;
    memory.map_bytes(base_addr + pe_offset, &0x0000_4550u32.to_le_bytes()); // PE\0\0

    // Write COFF header fields at correct offsets relative to PE signature
    memory.map_bytes(base_addr + pe_offset + 6, &1u16.to_le_bytes()); // NumberOfSections = 1
    memory.map_bytes(base_addr + pe_offset + 20, &0xF0u16.to_le_bytes()); // SizeOfOptionalHeader = 0xF0

    // Write section header for .bind (at PE sig + 24 + SizeOfOptionalHeader)
    let section_offset = base_addr + pe_offset + 24 + 0xF0;
    memory.map_bytes(section_offset, b".bind\x00\x00\x00"); // Name
    memory.map_bytes(section_offset + 8, &48u32.to_le_bytes()); // VirtualSize
    memory.map_bytes(section_offset + 12, &0x1000u32.to_le_bytes()); // VirtualAddress

    // Write Steamstub header at .bind section's VirtualAddress
    let stub_addr = base_addr + 0x1000;
    let mut stub_data = vec![0u8; 48]; // header is 48 bytes, must all be mapped
    stub_data[0..4].copy_from_slice(&0x53545542u32.to_le_bytes()); // magic "STUB"
    stub_data[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
    stub_data[8..12].copy_from_slice(&0u32.to_le_bytes()); // flags (XOR encryption)
    stub_data[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // original_entry_point
    stub_data[16..20].copy_from_slice(&0x3000u32.to_le_bytes()); // code_section_rva
    stub_data[20..24].copy_from_slice(&128u32.to_le_bytes()); // code_section_size
    stub_data[24..40].copy_from_slice(&[0xAB; 16]); // key_data
    stub_data[40..44].copy_from_slice(&12345u32.to_le_bytes()); // app_id
    memory.map_bytes(stub_addr, &stub_data);

    // Write encrypted code section
    let code_addr = base_addr + 0x3000;
    let encrypted_code: Vec<u8> = (0..128).map(|i| i as u8 ^ 0xAB).collect();
    memory.map_bytes(code_addr, &encrypted_code);

    // Detect Steamstub header
    let header = SteamstubLoader::detect_steamstub(&memory, base_addr).expect("detect steamstub");

    assert!(header.is_some(), "Steamstub header should be detected");

    let header = header.unwrap();
    assert_eq!(header.magic, 0x53545542, "magic should be STUB");
    assert_eq!(header.app_id, 12345, "app_id should match");
    assert_eq!(
        header.encryption_type,
        EncryptionType::Xor,
        "should use XOR encryption"
    );
    assert_eq!(
        header.code_section_size, 128,
        "code section size should match"
    );

    // Now exercise the actual decrypt path (the point of this test): load the stub
    // with the XOR key from the header and verify the decrypted section equals the
    // original `i ^ 0xAB` payload, that the bytes land back in guest memory, and
    // that the entry point is restored.
    let mut loader = SteamstubLoader::new();
    loader.header = Some(header.clone());
    let app_key = header.key_data; // [0xAB; 16]
    loader
        .load_steamstub(&mut memory, base_addr, &app_key)
        .expect("load/decrypt steamstub");

    assert!(loader.loaded, "loader must report loaded after decryption");
    let decrypted = loader
        .decrypted_text
        .expect("decrypted text must be populated");
    let expected: Vec<u8> = (0..128).map(|i| i as u8).collect();
    assert_eq!(
        decrypted, expected,
        "decrypted section must equal the original payload"
    );
    assert_eq!(
        memory.read_bytes(code_addr, 128).expect("read back memory"),
        expected,
        "decrypted bytes must be written back into guest memory"
    );
    let entry = memory.read_u32(base_addr + pe_offset + 40).expect("read entry");
    assert_eq!(
        entry, 0x1000,
        "AddressOfEntryPoint must be restored to original_entry_point"
    );

    // Wrong key: decryption must NOT produce the original payload.
    let mut wrong_loader = SteamstubLoader::new();
    wrong_loader.header = Some(header);
    wrong_loader
        .load_steamstub(&mut memory, base_addr, &[0xCD; 16])
        .expect("load with wrong key");
    let wrong = wrong_loader
        .decrypted_text
        .expect("decrypted text with wrong key");
    assert_ne!(
        wrong, expected,
        "decrypting with the wrong key must not yield the original payload"
    );
}

// ---------------------------------------------------------------------------
// t22_6_scm_vm_lifecycle
// ---------------------------------------------------------------------------

#[test]
fn t22_6_scm_vm_lifecycle() {
    // Create SCM runner with a test configuration (VM disabled for testing)
    let config = ScmConfig {
        enabled: false,
        cpu_count: 2,
        memory_mb: 1024,
        kernel_path: None,
        shared_directory: None,
        virtio_gpu: false,
        virtio_net: false,
        secure_boot: false,
        measured_launch: false,
    };

    let mut runner = ScmRunnerIntegration::new(config);

    // Verify initial state
    assert_eq!(
        runner.get_vm_state(),
        VmState::Stopped,
        "VM should start in Stopped state"
    );

    // Tick should succeed even when stopped
    runner.tick().expect("tick should succeed when stopped");

    // Verify state is still stopped (no VM launched)
    assert_eq!(
        runner.get_vm_state(),
        VmState::Stopped,
        "VM should remain Stopped after tick without launch"
    );

    // Shutdown should succeed
    runner.shutdown_vm().expect("shutdown should succeed");

    assert_eq!(
        runner.get_vm_state(),
        VmState::Stopped,
        "VM should be Stopped after shutdown"
    );
}

// ---------------------------------------------------------------------------
// t22_7_steam_protocol_stack
// ---------------------------------------------------------------------------

#[test]
fn t22_7_steam_protocol_stack() {
    let mut stack = SteamProtocolStack::new();

    // Verify initial state
    assert_eq!(
        stack.state,
        ConnectionState::Disconnected,
        "initial state should be Disconnected"
    );

    // Verify encryption setup (session cipher should not exist yet)
    let plaintext = b"Hello Steam!";
    let encrypted = stack.encrypt_payload(plaintext);
    // Without a session, encryption should be a no-op (returns plaintext)
    assert_eq!(
        encrypted, plaintext,
        "encryption without session should be passthrough"
    );

    let decrypted = stack.decrypt_payload(&encrypted);
    assert_eq!(
        decrypted, plaintext,
        "decryption without session should be passthrough"
    );

    // Test message serialization roundtrip
    use casa1::steam_protocol::{SteamMessage, SteamMessageType, serialize_message};

    let msg = SteamMessage {
        msg_type: SteamMessageType::ClientHeartBeat,
        payload: vec![1, 2, 3, 4],
        source_job_id: 0,
        target_job_id: 0,
        steam_id: 76561198000000000,
        session_id: 12345,
        message_type: SteamMessageType::ClientHeartBeat as u32,
    };

    let serialized = serialize_message(&msg);
    assert!(
        !serialized.is_empty(),
        "serialized message should not be empty"
    );

    // Verify the serialized data starts with the Steam magic
    let magic = u32::from_le_bytes([serialized[0], serialized[1], serialized[2], serialized[3]]);
    assert_eq!(magic, 0x31305356, "should start with Steam magic 'VS01'");

    // Disconnect should succeed
    stack.disconnect().expect("disconnect should succeed");
    assert_eq!(
        stack.state,
        ConnectionState::Disconnected,
        "state should be Disconnected after disconnect"
    );
}

// ---------------------------------------------------------------------------
// t22_8_performance_optimizations
// ---------------------------------------------------------------------------

#[test]
fn t22_8_performance_optimizations() {
    // --- Tiered compiler: verify block promotion ---
    let mut profiler = LazyJitProfiler::new(10, 100);

    // Record executions for a block — should promote from Uncompiled → Baseline → Optimized
    let addr = 0x1000u64;
    for _ in 0..9 {
        let tier = profiler.record_execution(addr, 10);
        assert_eq!(
            tier,
            casa1::perf::CompilationTier::Uncompiled,
            "should be uncompiled below hot threshold"
        );
    }

    // 10th execution should trigger baseline
    let tier = profiler.record_execution(addr, 10);
    assert_eq!(
        tier,
        casa1::perf::CompilationTier::Baseline,
        "should promote to Baseline at hot threshold"
    );

    // Continue to 100 for optimized
    for _ in 10..99 {
        profiler.record_execution(addr, 10);
    }

    let tier = profiler.record_execution(addr, 10);
    assert_eq!(
        tier,
        casa1::perf::CompilationTier::Optimized,
        "should promote to Optimized at optimize threshold"
    );

    // --- File cache: verify hit/miss ---
    let mut cache = FileCache::new(1024 * 1024);

    // Miss on first access
    assert!(cache.get("nonexistent.dat").is_none(), "cache miss");
    let (_hits, misses, _) = cache.stats();
    assert_eq!(misses, 1, "should have 1 miss");

    // Insert and then hit
    cache.insert("test.dat", vec![1, 2, 3, 4]).expect("insert");
    assert!(cache.get("test.dat").is_some(), "cache hit");
    let (hits, misses, _) = cache.stats();
    assert_eq!(hits, 1, "should have 1 hit");
    assert_eq!(misses, 1, "should still have 1 miss");

    // --- Block chaining cache ---
    let mut chaining = BlockChainingCache::new();
    chaining.register_block(0x1000, 0x2000, 128, 10);
    chaining.register_block(0x2000, 0x3000, 64, 5);

    assert_eq!(chaining.block_count(), 2, "should have 2 blocks");

    // Record execution to set fallthrough target
    chaining
        .record_execution(0x1000, 0x2000)
        .expect("record execution");

    // Execute 10+ times to make it hot
    for _ in 0..10 {
        chaining
            .record_execution(0x1000, 0x2000)
            .expect("record execution");
    }

    // Try to chain
    let chained = chaining.try_chain(0x1000);
    assert!(chained, "block should be chained after 10+ executions");
    assert_eq!(
        chaining.active_chain_count(),
        1,
        "should have 1 active chain"
    );
}

// ---------------------------------------------------------------------------
// t22_9_visual_fidelity_ssim
// ---------------------------------------------------------------------------

#[test]
fn t22_9_visual_fidelity_ssim() {
    let width = 64u32;
    let height = 64u32;

    // Create two identical frames
    let frame_a = FrameCapture::new_solid(width, height, 128, 64, 32, 255);
    let frame_b = FrameCapture::new_solid(width, height, 128, 64, 32, 255);

    // SSIM of identical frames should be 1.0
    let ssim = compute_ssim(&frame_a.pixels, &frame_b.pixels, width, height);
    assert!(
        ssim >= 0.99,
        "SSIM of identical frames should be >= 0.99, got {ssim}"
    );

    // PSNR of identical frames should be infinity
    let psnr = compute_psnr(&frame_a.pixels, &frame_b.pixels, width, height);
    assert!(
        psnr == f64::INFINITY || psnr > 100.0,
        "PSNR of identical frames should be very high, got {psnr}"
    );

    // Pixel diff of identical frames should be 100% match
    let (matching, total) = compute_pixel_diff(&frame_a.pixels, &frame_b.pixels, 0.0);
    assert_eq!(
        matching, total,
        "all pixels should match for identical frames"
    );

    // Create a slightly different frame
    let frame_c = FrameCapture::new_solid(width, height, 130, 66, 34, 255);

    // SSIM should still be high (close to 1.0)
    let ssim_diff = compute_ssim(&frame_a.pixels, &frame_c.pixels, width, height);
    assert!(
        ssim_diff > 0.9,
        "SSIM of similar frames should be > 0.9, got {ssim_diff}"
    );

    // PSNR should be high
    let psnr_diff = compute_psnr(&frame_a.pixels, &frame_c.pixels, width, height);
    assert!(
        psnr_diff > 30.0,
        "PSNR of similar frames should be > 30 dB, got {psnr_diff}"
    );

    // Compare using compare_frames
    let result = compare_frames(&frame_a, &frame_a, 0.0);
    assert!(result.passes, "identical frames should pass comparison");
    assert!(
        result.ssim >= 0.99,
        "SSIM should be near 1.0 for identical frames"
    );

    // Compare with tolerance
    let result_with_tolerance = compare_frames(&frame_a, &frame_c, 0.05);
    assert!(
        result_with_tolerance.pixel_match_percentage >= 95.0,
        "similar frames should have high pixel match with tolerance, got {}%",
        result_with_tolerance.pixel_match_percentage
    );
}

// ---------------------------------------------------------------------------
// t22_10_stress_memory_leak_detection
// ---------------------------------------------------------------------------

#[test]
fn t22_10_stress_memory_leak_detection() {
    let config = StressTestConfig {
        duration_seconds: 1,
        memory_leak_detection: true,
        gpu_leak_detection: false,
        network_resilience: false,
        multi_game_cycling: false,
        games_to_cycle: Vec::new(),
        cycle_interval_seconds: 1,
    };

    let mut runner = StressTestRunner::new(config);

    // Simulate a stable allocator (returns constant value)
    let mut allocator_call_count = 0usize;
    let result = runner.run_memory_leak_test(&mut || {
        allocator_call_count += 1;
        1024 * 1024 // Always report 1MB allocated
    });

    assert!(
        result.passed,
        "stress test should pass with stable allocator"
    );
    assert!(
        !result.memory_leak_detected,
        "no memory leak should be detected with stable allocator"
    );
    assert_eq!(result.iterations, 100, "should run 100 iterations");

    // Test network resilience
    let net_result = runner.run_network_resilience_test();
    assert!(
        net_result.passed,
        "network resilience test should pass on localhost"
    );
    assert_eq!(net_result.iterations, 10, "should run 10 iterations");

    // Test multi-game cycling
    let game_result = runner.run_multi_game_cycling_test(&[730, 570, 480]);
    assert!(
        game_result.passed,
        "multi-game cycling should pass with valid app IDs"
    );
    assert_eq!(game_result.iterations, 3, "should cycle through 3 games");
}

// ---------------------------------------------------------------------------
// t22_11_behavioral_verification
// ---------------------------------------------------------------------------

#[test]
fn t22_11_behavioral_verification() {
    let mut verifier = BehavioralVerifier::new();

    // Run through a series of behavioral test steps
    let steps = vec![
        BehavioralTestStep::ConnectToCM,
        BehavioralTestStep::EncryptionHandshake,
        BehavioralTestStep::SendLogon {
            username: "test_user".to_string(),
        },
        BehavioralTestStep::ReceiveLogOnResponse,
        BehavioralTestStep::BrowseStore {
            url: "https://store.steampowered.com".to_string(),
        },
        BehavioralTestStep::DownloadApp { app_id: 730 },
        BehavioralTestStep::LaunchApp { app_id: 730 },
        BehavioralTestStep::UnlockAchievement {
            name: "first_win".to_string(),
        },
        BehavioralTestStep::VerifyAchievement {
            name: "first_win".to_string(),
        },
    ];

    for step in steps {
        verifier.begin_step(step.clone());
        // Simulate step execution
        verifier.end_step(step, true, None);
    }

    // Verify all steps passed
    assert!(
        verifier.all_passed(),
        "all behavioral test steps should pass"
    );
    assert_eq!(verifier.results.len(), 9, "should have 9 results");

    // Generate summary
    let summary = verifier.summary();
    assert!(
        summary.contains("9/9 steps passed"),
        "summary should report 9/9 steps passed, got: {summary}"
    );

    // Negative path: a failed step must flip `all_passed()`, be recorded with its
    // error, and appear in the summary as a failure (a verifier that always
    // reports success would pass these).
    let mut failing = BehavioralVerifier::new();
    failing.begin_step(BehavioralTestStep::ConnectToCM);
    failing.end_step(
        BehavioralTestStep::ConnectToCM,
        false,
        Some("connection refused".to_string()),
    );
    assert!(
        !failing.all_passed(),
        "a failed step must make all_passed() false"
    );
    assert_eq!(failing.results.len(), 1);
    assert!(
        !failing.results[0].passed,
        "the failed step must be recorded as failed"
    );
    let failure_summary = failing.summary();
    assert!(
        !failure_summary.contains("9/9 steps passed"),
        "failure summary must not claim full success, got: {failure_summary}"
    );
    assert!(
        failure_summary.to_lowercase().contains("fail"),
        "failure summary must mention the failure, got: {failure_summary}"
    );
}

// ---------------------------------------------------------------------------
// t22_12_end_to_end_integration
// ---------------------------------------------------------------------------

#[test]
fn t22_12_end_to_end_integration() {
    // Create a D3D12 runtime (simulated backend)
    let mut runtime = D3d12Runtime::new();

    // Create a swapchain
    let swapchain = runtime
        .create_swapchain(SwapchainDesc {
            width: 1280,
            height: 720,
            format: DxgiFormat::R8G8B8A8Unorm,
            buffer_count: 2,
        })
        .expect("create swapchain");

    // Get backbuffer
    let backbuffer = runtime
        .swapchain_state(swapchain)
        .expect("swapchain state")
        .backbuffers[0];

    // Create RTV
    let rtv_heap = runtime.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
    runtime
        .write_descriptor(
            rtv_heap,
            0,
            ViewDescriptor::Rtv {
                resource: backbuffer,
                format: DxgiFormat::R8G8B8A8Unorm,
            },
        )
        .expect("write RTV");

    // Create root signature and pipeline
    let root_sig = runtime.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![1],
        root_constants: 4,
        ..Default::default()
    });
    let pso = runtime.create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "e2e_pipeline".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
            depth_format: None,
        },
    );

    // Create command queue, allocator, and list
    let queue = runtime.create_command_queue();
    let allocator = runtime.create_command_allocator();
    let list = runtime.create_graphics_command_list(allocator, pso, false);

    // Record rendering commands
    runtime
        .record_begin_render_pass(
            list,
            vec![DxgiFormat::R8G8B8A8Unorm],
            None,
            "clear",
            "store",
        )
        .expect("begin render pass");
    runtime
        .record_clear_rtv(list, rtv_heap, 0)
        .expect("clear RTV");
    runtime.record_draw(list, 3).expect("draw triangle");
    runtime.end_render_pass(list).expect("end render pass");

    // Close and execute
    let stream = runtime.close_command_list(list).expect("close list");
    let fence = runtime.create_fence(0);
    let plan = runtime
        .execute_command_lists(queue, &[stream], Some((fence, 1)))
        .expect("execute");

    // Verify execution
    assert_eq!(plan.render_passes.len(), 1, "should have 1 render pass");
    assert_eq!(
        plan.render_passes[0].draw_calls, 1,
        "should have 1 draw call"
    );
    assert_eq!(
        runtime.fence_value(fence).expect("fence value"),
        1,
        "fence should be signaled to 1"
    );

    // Present
    let present = runtime.present(swapchain, 1, false).expect("present");
    assert_eq!(
        present.effective_sync_interval, 1,
        "sync interval should be 1"
    );

    // Distinct E2E assertions (vs t21_4/t21_10): presenting must advance the frame
    // index and expose the presented frame with the swapchain's dimensions/format.
    let present2 = runtime.present(swapchain, 1, false).expect("present again");
    assert_eq!(
        present2.displayed_frame_index,
        present.displayed_frame_index + 1,
        "each present must advance the displayed frame index"
    );
    assert_eq!(present.displayed_frame_index, 1, "first present is frame 1");

    let presented = runtime
        .presented_frame(swapchain)
        .expect("presented frame");
    assert_eq!(presented.width, 1280);
    assert_eq!(presented.height, 720);
    assert_eq!(presented.format, DxgiFormat::R8G8B8A8Unorm);
    assert_eq!(
        presented.bytes.len(),
        1280 * 720 * 4,
        "presented frame must carry a full RGBA8 buffer"
    );

    // Verify visual fidelity infrastructure works alongside rendering
    let frame = FrameCapture::new_solid(1280, 720, 0, 0, 128, 255);
    assert_eq!(frame.width, 1280);
    assert_eq!(frame.height, 720);
    assert_eq!(frame.pixels.len(), 1280 * 720 * 4);

    // Verify behavioral verifier works
    let mut verifier = BehavioralVerifier::new();
    verifier.begin_step(BehavioralTestStep::LaunchApp { app_id: 730 });
    verifier.end_step(BehavioralTestStep::LaunchApp { app_id: 730 }, true, None);
    assert!(verifier.all_passed(), "behavioral step should pass");

    // Verify stress test runner works
    let mut stress_runner = StressTestRunner::new(StressTestConfig::default());
    let stress_result = stress_runner.run_memory_leak_test(&mut || 4096);
    assert!(stress_result.passed, "stress test should pass");
}
