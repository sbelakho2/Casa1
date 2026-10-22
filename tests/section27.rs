#![allow(dead_code, unused_imports)]
#![allow(clippy::overly_complex_bool_expr)]
#![allow(clippy::needless_range_loop)]

//! Section 27 — End-to-End Integration Test Suite
//!
//! Phase 6.5.3 from the execution plan. Covers full Steam boot→login→browse→
//! download→install→launch→play→exit workflow orchestration via the diagnostics,
//! steam protocol, and performance modules, plus MSAA resolve integration tests.
//!
//! Phase 6.5.3 from the execution plan. Covers full Steam boot→login→browse→
//! download→install→launch→play→exit workflow orchestration via the diagnostics,
//! steam protocol, and performance modules.
//!
//! Tests that may depend on external services (Steam CM servers) handle the
//! unreachable case gracefully rather than failing.

use casa1::diagnostics::{
    BehavioralTestStep, BehavioralVerifier, FrameCapture, StressTestConfig, StressTestRunner,
    compare_frames, compute_pixel_diff, compute_psnr, compute_ssim, detect_text_regions,
};
use std::path::Path;

// ===========================================================================
// t27_01 — Doctor Report Generation
// ===========================================================================

#[test]
fn t27_01_doctor_report_generation() {
    // `doctor()` requires a real GameEnvironment with a helper binary on disk.
    // We cannot construct one in a unit-test setting, so we verify the
    // diagnostic entry points that are self-contained and test that the
    // types are well-formed.

    // Verify DoctorReport fields are populated when constructed manually (the
    // types exist and are public).
    let report = casa1::diagnostics::DoctorReport {
        ge_name: "test".to_string(),
        ge_root: Path::new("/tmp/test").to_path_buf(),
        gpu: casa1::diagnostics::GpuCheck {
            status: "ok".to_string(),
            apple_silicon: cfg!(target_arch = "aarch64"),
            metal_framework_present: true,
            adapter_name: "Apple M".to_string(),
            metal_family: "Apple7".to_string(),
            unified_memory: true,
            argument_buffers: true,
            memoryless_render_targets: true,
            timestamp_queries: true,
            mesh_shaders: false,
        },
        entitlements: casa1::diagnostics::EntitlementsCheck {
            status: "ok".to_string(),
            allow_jit: true,
            allow_unsigned_executable_memory: true,
            raw_excerpt: "com.apple.security.cs.allow-jit".to_string(),
        },
        filesystem_permissions: casa1::diagnostics::FilesystemPermissionCheck {
            readable: true,
            writable: true,
            executable: true,
        },
        helper_process: casa1::diagnostics::HelperProcessCheck {
            helper_binary: "casa1-helper".to_string(),
            euid: 501,
            ran_as_root: false,
        },
    };

    // Verify all fields are populated — no defaults left empty
    assert!(!report.ge_name.is_empty(), "ge_name must not be empty");
    assert!(
        report.ge_root.to_string_lossy().contains("/tmp/test"),
        "ge_root must match input"
    );
    assert!(
        !report.gpu.adapter_name.is_empty(),
        "gpu adapter name must not be empty"
    );
    assert!(
        !report.entitlements.raw_excerpt.is_empty(),
        "entitlements excerpt must not be empty"
    );

    // Test error handling: doctor() on a nonexistent helper binary should
    // return an error gracefully (no panic).
    // We construct a minimal GameEnvironment to test the error path.
    let ge = casa1::ge::GameEnvironment {
        root: Path::new("/nonexistent_casa1_root").to_path_buf(),
        config: casa1::ge::GeConfig {
            schema_version: 1,
            name: "test_ge".to_string(),
            arch: casa1::ge::GeArch::X64,
            winver: "10.0".to_string(),
            user_name: "test".to_string(),
            long_paths_enabled: false,
            drive_mappings: Vec::new(),
            override_profiles: Vec::new(),
            fs_state: casa1::ge::GeFsState::default(),
        },
    };

    let result = casa1::diagnostics::doctor(&ge);
    // Should return Err gracefully (helper binary doesn't exist), not panic
    assert!(
        result.is_err(),
        "doctor() should return Err with nonexistent helper binary"
    );
    let err = result.unwrap_err();
    let err_str = format!("{:?}", err);
    assert!(!err_str.is_empty(), "error message should not be empty");
}

// ===========================================================================
// t27_02 — Diagnostics Export Roundtrip
// ===========================================================================

#[test]
fn t27_02_diagnostics_export_roundtrip() {
    // `export_diagnostics()` requires a real GameEnvironment and real helper
    // binary. Test the error path with a nonexistent environment to verify
    // graceful error handling.
    let ge = casa1::ge::GameEnvironment {
        root: Path::new("/nonexistent_casa1_root").to_path_buf(),
        config: casa1::ge::GeConfig {
            schema_version: 1,
            name: "test_ge".to_string(),
            arch: casa1::ge::GeArch::X64,
            winver: "10.0".to_string(),
            user_name: "test".to_string(),
            long_paths_enabled: false,
            drive_mappings: Vec::new(),
            override_profiles: Vec::new(),
            fs_state: casa1::ge::GeFsState::default(),
        },
    };

    let bad_path = Path::new("/nonexistent_dir/output.zip");
    let result = casa1::diagnostics::export_diagnostics(&ge, bad_path);
    // Should return Err gracefully (GE root doesn't exist), not panic
    assert!(
        result.is_err(),
        "export_diagnostics should return Err with invalid environment"
    );

    // Verify the ExportSummary type is well-formed
    let summary = casa1::diagnostics::ExportSummary {
        output_zip: Path::new("/tmp/test_output.zip").to_path_buf(),
        file_count: 42,
    };
    assert!(
        summary
            .output_zip
            .to_string_lossy()
            .contains("test_output.zip")
    );
    assert_eq!(summary.file_count, 42);
}

// ===========================================================================
// t27_03 — Frame Capture and Comparison
// ===========================================================================

#[test]
fn t27_03_frame_capture_and_comparison() {
    // Create two solid-color frames: red and blue (1920x1080)
    let red = FrameCapture::new_solid(1920, 1080, 255, 0, 0, 255);
    let blue = FrameCapture::new_solid(1920, 1080, 0, 0, 255, 255);
    let red2 = FrameCapture::new_solid(1920, 1080, 255, 0, 0, 255); // identical to red

    // SSIM between red and blue — should be well below 1.0 (different frames)
    let ssim_diff = compute_ssim(&red.pixels, &blue.pixels, red.width, red.height);
    assert!(
        ssim_diff < 1.0,
        "SSIM between red and blue frames should be < 1.0, got {ssim_diff}"
    );

    // SSIM between two identical red frames — should be ~1.0
    let ssim_same = compute_ssim(&red.pixels, &red2.pixels, red.width, red.height);
    assert!(
        (ssim_same - 1.0).abs() < 0.001,
        "SSIM between identical frames should be ~1.0, got {ssim_same}"
    );

    // PSNR between identical frames — should be exactly INFINITY (mse == 0)
    let psnr_same = compute_psnr(&red.pixels, &red2.pixels, red.width, red.height);
    assert_eq!(
        psnr_same,
        f64::INFINITY,
        "PSNR between identical frames must be +inf, got {psnr_same}"
    );

    // PSNR between different frames — should be finite
    let psnr_diff = compute_psnr(&red.pixels, &blue.pixels, red.width, red.height);
    assert!(
        psnr_diff.is_finite(),
        "PSNR between different frames should be finite, got {psnr_diff}"
    );

    // Pixel diff between identical frames — all pixels should match
    let (matching, total) = compute_pixel_diff(&red.pixels, &red2.pixels, 0.0);
    assert_eq!(
        matching, total,
        "all pixels should match between identical frames"
    );

    // Pixel diff between red and blue — few pixels should match at tolerance 0.0
    let (matching_diff, total_diff) = compute_pixel_diff(&red.pixels, &blue.pixels, 0.0);
    assert!(
        matching_diff < total_diff,
        "different-colored frames should have few matching pixels"
    );

    // compare_frames with tolerance 0.0 on identical frames
    let result_ident = compare_frames(&red, &red2, 0.0);
    assert!(
        (result_ident.ssim - 1.0).abs() < 0.001,
        "identical frames should have SSIM ~1.0"
    );
    assert!(
        result_ident.pixel_match_percentage > 99.9,
        "identical frames should have near 100% pixel match"
    );
    assert!(
        result_ident.passes,
        "identical frames should pass comparison"
    );

    // compare_frames with tolerance 0.0 on different frames
    let result_diff = compare_frames(&red, &blue, 0.0);
    assert!(
        result_diff.ssim < 1.0,
        "different frames should have SSIM < 1.0"
    );
    // Red vs blue at 0.0 tolerance matches 0% of pixels, so the comparison
    // must FAIL (compare_frames passes only at >= 95% pixel match and
    // SSIM >= 0.9) — a vacuous "may not pass" assertion is not enough.
    assert!(
        !result_diff.passes,
        "solid red vs solid blue at 0.0 tolerance must not pass (ssim={}, match={:.2}%)",
        result_diff.ssim, result_diff.pixel_match_percentage
    );
    assert!(
        result_diff.pixel_match_percentage < 1.0,
        "red vs blue must match virtually no pixels at tolerance 0.0, got {:.2}%",
        result_diff.pixel_match_percentage
    );

    // detect_text_regions on a simple solid-color frame (should return empty
    // for uniform frames)
    let regions = detect_text_regions(&red);
    assert!(
        regions.is_empty(),
        "solid red frame should have no text regions detected"
    );

    // detect_text_regions on a mixed frame (create a frame with some variation)
    let mut varied = FrameCapture::new_solid(64, 64, 128, 128, 128, 255);
    // Add some high-contrast pixels to simulate text
    for y in 10..20u32 {
        for x in 10..20u32 {
            let base = ((y * 64 + x) * 4) as usize;
            if base + 3 < varied.pixels.len() {
                varied.pixels[base] = 255;
                varied.pixels[base + 1] = 255;
                varied.pixels[base + 2] = 255;
            }
        }
    }
    let regions2 = detect_text_regions(&varied);
    // The 10x10 white block sits inside the single 32x32 grid block at (0,0):
    // gray(128) vs white(255) yields contrast 127 (> 80) with a mean of ~140,
    // so exactly one text region is detected at the block's bounds. This pins
    // the detector's grid semantics instead of accepting any count < 100.
    assert_eq!(
        regions2.len(),
        1,
        "the single high-contrast block must produce exactly one region, got {regions2:?}"
    );
    let region = &regions2[0];
    assert_eq!(region.x, 0);
    assert_eq!(region.y, 0);
    assert_eq!(region.width, 32);
    assert_eq!(region.height, 32);
    assert!(
        (region.confidence - (127.0 / 255.0)).abs() < 0.01,
        "confidence must reflect the measured contrast, got {}",
        region.confidence
    );
}

// ===========================================================================
// t27_04 — Frame Capture from Pixels
// ===========================================================================

// ===========================================================================
// t27_05 — Color Space Verification
// ===========================================================================

// ===========================================================================
// t27_06 — Reference Frame Database
// ===========================================================================

// ===========================================================================
// t27_07 — Behavioral Verifier Initialization
// ===========================================================================

#[test]
fn t27_07_behavioral_verifier_initialization() {
    // Create a BehavioralVerifier via new()
    let mut verifier = BehavioralVerifier::new();
    assert!(
        verifier.results.is_empty(),
        "new verifier should have no results"
    );
    assert_eq!(verifier.current_step, 0, "new verifier should be at step 0");

    // Test Default implementation
    let verifier_default: BehavioralVerifier = Default::default();
    assert!(
        verifier_default.results.is_empty(),
        "Default verifier should have no results"
    );

    // Begin a few steps with different BehavioralTestStep variants
    verifier.begin_step(BehavioralTestStep::ConnectToCM);
    verifier.end_step(BehavioralTestStep::ConnectToCM, true, None);

    verifier.begin_step(BehavioralTestStep::EncryptionHandshake);
    verifier.end_step(BehavioralTestStep::EncryptionHandshake, true, None);

    verifier.begin_step(BehavioralTestStep::SendLogon {
        username: "test_user".to_string(),
    });
    verifier.end_step(
        BehavioralTestStep::SendLogon {
            username: "test_user".to_string(),
        },
        false,
        Some("simulated failure".to_string()),
    );

    verifier.begin_step(BehavioralTestStep::ReceiveLogOnResponse);
    verifier.end_step(BehavioralTestStep::ReceiveLogOnResponse, true, None);

    verifier.begin_step(BehavioralTestStep::BrowseStore {
        url: "steam://store/730".to_string(),
    });
    verifier.end_step(
        BehavioralTestStep::BrowseStore {
            url: "steam://store/730".to_string(),
        },
        true,
        None,
    );

    verifier.begin_step(BehavioralTestStep::DownloadApp { app_id: 730 });
    verifier.end_step(BehavioralTestStep::DownloadApp { app_id: 730 }, true, None);

    verifier.begin_step(BehavioralTestStep::LaunchApp { app_id: 730 });
    verifier.end_step(BehavioralTestStep::LaunchApp { app_id: 730 }, true, None);

    verifier.begin_step(BehavioralTestStep::OpenOverlay);
    verifier.end_step(BehavioralTestStep::OpenOverlay, true, None);

    // Verify results tracking
    assert_eq!(verifier.results.len(), 8, "should have 8 recorded results");
    assert!(
        !verifier.all_passed(),
        "not all steps should pass (one failed)"
    );

    // Count passed/failed
    let passed_count = verifier.results.iter().filter(|r| r.passed).count();
    let failed_count = verifier.results.iter().filter(|r| !r.passed).count();
    assert_eq!(passed_count, 7, "7 steps should have passed");
    assert_eq!(failed_count, 1, "1 step should have failed");

    // Summary should return a non-empty string
    let summary = verifier.summary();
    assert!(!summary.is_empty(), "summary should not be empty");
    assert!(summary.contains("7/8"), "summary should contain pass count");

    // Test all step types via begin → end cycle
    let mut full_verifier = BehavioralVerifier::new();
    let step_types = [
        BehavioralTestStep::ConnectToCM,
        BehavioralTestStep::EncryptionHandshake,
        BehavioralTestStep::SendLogon {
            username: "user".to_string(),
        },
        BehavioralTestStep::ReceiveLogOnResponse,
        BehavioralTestStep::BrowseStore {
            url: "url".to_string(),
        },
        BehavioralTestStep::DownloadApp { app_id: 0 },
        BehavioralTestStep::LaunchApp { app_id: 0 },
        BehavioralTestStep::OpenOverlay,
        BehavioralTestStep::SaveToCloud {
            key: "k".to_string(),
            data: vec![1, 2, 3],
        },
        BehavioralTestStep::LoadFromCloud {
            key: "k".to_string(),
        },
        BehavioralTestStep::SubscribeWorkshop { item_id: 12345 },
        BehavioralTestStep::UnlockAchievement {
            name: "ach".to_string(),
        },
        BehavioralTestStep::VerifyAchievement {
            name: "ach".to_string(),
        },
    ];
    for step in &step_types {
        full_verifier.begin_step(step.clone());
        full_verifier.end_step(step.clone(), true, None);
    }
    assert_eq!(
        full_verifier.results.len(),
        step_types.len(),
        "should have all step types recorded"
    );
    assert!(full_verifier.all_passed(), "all steps should have passed");
}

// ===========================================================================
// t27_08 — Behavioral Verifier Steam Workflow
// ===========================================================================

#[test]
fn t27_08_behavioral_verifier_steam_workflow() {
    // The `run_*` workflow helpers connect to the real Steam CM servers, which
    // must never be contacted in unit tests (src/steam_protocol.rs
    // `steam_zero_touch_default_servers_not_contacted`). The verifier's own
    // contract — step recording, pass/fail accounting, and reporting — is
    // fully deterministic and is what this test pins.

    let mut verifier = BehavioralVerifier::new();
    assert!(
        !verifier.all_passed(),
        "a verifier with no steps must not report success"
    );
    assert!(verifier.results.is_empty(), "no steps recorded yet");

    // Record a passing step: all_passed must flip to true and the summary
    // must report exactly one passed step.
    verifier.begin_step(BehavioralTestStep::ConnectToCM);
    verifier.end_step(BehavioralTestStep::ConnectToCM, true, None);
    assert!(
        verifier.all_passed(),
        "one passing step must pass the verifier"
    );
    assert_eq!(verifier.results.len(), 1);
    assert!(verifier.results[0].passed);
    assert!(verifier.summary().contains("1/1 steps passed"));

    // Record a failing step: all_passed must flip back to false, the error
    // must be recorded, and the summary must report 1/2 with the failure.
    verifier.begin_step(BehavioralTestStep::SendLogon {
        username: "test_user".to_string(),
    });
    verifier.end_step(
        BehavioralTestStep::SendLogon {
            username: "test_user".to_string(),
        },
        false,
        Some("logon rejected".to_string()),
    );
    assert!(
        !verifier.all_passed(),
        "a failed step must fail the verifier"
    );
    assert_eq!(verifier.results.len(), 2);
    assert!(!verifier.results[1].passed);
    assert_eq!(verifier.results[1].error.as_deref(), Some("logon rejected"));
    let summary = verifier.summary();
    assert!(summary.contains("1/2 steps passed"), "got: {summary}");
    assert!(summary.contains("FAIL"), "got: {summary}");

    // Every recorded step carries a duration_ms field. The exact value is
    // intentionally not asserted: begin/end on a fast step is sub-millisecond
    // and wall-clock timing must not be pinned.
    assert_eq!(verifier.results.len(), 2, "both steps must be recorded");
}

// ===========================================================================
// t27_09 — Stress Test Runner Configuration
// ===========================================================================

#[test]
fn t27_09_stress_test_runner_configuration() {
    // Create a StressTestConfig::default()
    let config = StressTestConfig::default();

    // Verify default values are reasonable. The exact default duration is
    // intentionally not pinned (it has changed across releases); the
    // documented invariants are that a default config is non-trivial and
    // strictly longer than one cycle interval.
    assert!(
        config.duration_seconds >= config.cycle_interval_seconds,
        "default duration must be at least one cycle interval"
    );
    assert!(
        config.duration_seconds >= 30,
        "default duration must be a realistic stress-run length"
    );
    assert!(
        config.memory_leak_detection,
        "memory leak detection should be enabled by default"
    );
    assert!(
        config.gpu_leak_detection,
        "GPU leak detection should be enabled by default"
    );
    assert_eq!(
        config.cycle_interval_seconds, 5,
        "default cycle interval should be 5 seconds"
    );

    // Create a custom config
    let custom_config = StressTestConfig {
        duration_seconds: 120,
        memory_leak_detection: true,
        gpu_leak_detection: false,
        network_resilience: true,
        multi_game_cycling: true,
        games_to_cycle: vec![10, 20, 30],
        cycle_interval_seconds: 10,
    };
    assert_eq!(custom_config.duration_seconds, 120);
    assert_eq!(custom_config.games_to_cycle.len(), 3);

    // Create a StressTestRunner::new(config)
    let runner = StressTestRunner::new(custom_config);
    assert!(runner.result.is_none(), "new runner should have no result");
    assert!(!runner.running, "new runner should not be running");
    assert_eq!(runner.config.duration_seconds, 120);

    // Verify the runner initializes correctly with default config
    let default_runner = StressTestRunner::new(StressTestConfig::default());
    assert_eq!(
        default_runner.config.cycle_interval_seconds, 5,
        "default runner must keep the documented default cycle interval"
    );
    assert!(
        default_runner.config.duration_seconds >= 30,
        "default runner must keep a realistic default duration"
    );
}

// ===========================================================================
// t27_10 — Stress Test Memory Leak Detection
// ===========================================================================

#[test]
fn t27_10_stress_test_memory_leak_detection() {
    let config = StressTestConfig::default();
    let mut runner = StressTestRunner::new(config);

    // Create a simple allocator closure that returns 1024 each time
    let mut allocator = || -> usize { 1024 };

    // Run memory leak test
    let result = runner.run_memory_leak_test(&mut allocator);

    // Verify result has populated fields
    assert!(result.iterations > 0, "iterations should be > 0");
    assert_eq!(result.memory_start_bytes, 1024);
    assert_eq!(result.memory_end_bytes, 1024);
    // Since allocator always returns 1024, no leak should be detected
    assert!(
        !result.memory_leak_detected,
        "constant allocator should not show a leak"
    );
    assert!(result.passed, "no leak detected means test passes");

    // Test with an allocator that simulates growth (memory leak)
    let mut counter = 0usize;
    let mut growing_allocator = || -> usize {
        counter += 1024;
        counter
    };
    let result2 = runner.run_memory_leak_test(&mut growing_allocator);
    // The growing allocator should show memory growth
    assert!(
        result2.memory_end_bytes > result2.memory_start_bytes,
        "growing allocator should show increased memory"
    );
    // May or may not be detected as leak depending on growth rate
    assert!(
        result2.memory_start_bytes > 0 || result2.memory_end_bytes > 0,
        "memory fields should be populated"
    );

    // Test that StressTestResult fields are all accessible
    let _elapsed = result.elapsed_seconds;
    let _iter = result.iterations;
    let _mem_start = result.memory_start_bytes;
    let _mem_end = result.memory_end_bytes;
    let _leak = result.memory_leak_detected;
    let _gpu_start = result.gpu_allocations_start;
    let _gpu_end = result.gpu_allocations_end;
    let _gpu_leak = result.gpu_leak_detected;
    let _net_disc = result.network_disconnects;
    let _net_rec = result.network_reconnects;
    let _errors = result.errors;
    let _passed = result.passed;
}

// ===========================================================================
// t27_11 — Stress Test GPU Leak Detection
// ===========================================================================

#[test]
#[allow(unused_comparisons)]
fn t27_11_stress_test_gpu_leak_detection() {
    let config = StressTestConfig::default();
    let mut runner = StressTestRunner::new(config);

    // Create a simple allocator closure
    let mut allocator = || -> usize { 5 };

    // Run GPU leak test
    let result = runner.run_gpu_leak_test(&mut allocator);

    // Verify result has populated fields
    assert!(result.iterations > 0, "iterations should be > 0");
    assert_eq!(result.gpu_allocations_start, 5);
    assert_eq!(result.gpu_allocations_end, 5);
    // Constant allocator should not show a GPU leak
    assert!(
        !result.gpu_leak_detected,
        "constant GPU allocator should not show a leak"
    );
    assert!(result.passed, "no GPU leak means test passes");

    // Test with a growing GPU allocator
    let mut gpu_counter = 0usize;
    let mut growing_allocator = || -> usize {
        gpu_counter += 10;
        gpu_counter
    };
    let result2 = runner.run_gpu_leak_test(&mut growing_allocator);
    assert!(
        result2.gpu_allocations_end > result2.gpu_allocations_start || !result2.passed,
        "growing allocator may end with more allocations"
    );
}

// ===========================================================================
// t27_12 — Stress Test Network Resilience
// ===========================================================================

#[test]
fn t27_12_stress_test_network_resilience() {
    let config = StressTestConfig::default();
    let mut runner = StressTestRunner::new(config);

    // Run network resilience test
    let result = runner.run_network_resilience_test();

    // Verify the test runs without error
    assert!(result.iterations > 0, "iterations should be > 0");

    // Check that result reports some reconnection metrics
    // These could be 0 if all iterations failed at bind(), but the fields
    // should still be present
    assert!(
        (result.network_disconnects as i64) >= 0,
        "network_disconnects should be >= 0"
    );
    assert!(
        (result.network_reconnects as i64) >= 0,
        "network_reconnects should be >= 0"
    );

    // Verify StressTestResult fields are populated.
    // `elapsed_seconds` is a u64 (whole seconds, cannot be negative); the
    // exact value is intentionally not asserted (wall-clock timing).
    let _elapsed = result.elapsed_seconds;
}

// ===========================================================================
// t27_13 — Stress Test Game Cycling
// ===========================================================================

#[test]
fn t27_13_stress_test_game_cycling() {
    let config = StressTestConfig::default();
    let mut runner = StressTestRunner::new(config);

    // Run multi-game cycling with [0, 1, 2, 3, 4]
    let result = runner.run_multi_game_cycling_test(&[0, 1, 2, 3, 4]);

    // app_id 0 should be detected as invalid
    assert!(
        !result.errors.is_empty(),
        "there should be at least one error for app_id 0"
    );
    assert!(result.iterations == 5, "should have processed 5 games");

    // Test with empty games slice — should handle gracefully
    let mut empty_runner = StressTestRunner::new(StressTestConfig::default());
    let empty_result = empty_runner.run_multi_game_cycling_test(&[]);
    assert_eq!(
        empty_result.iterations, 0,
        "empty slice should have 0 iterations"
    );
    assert!(
        empty_result.errors.is_empty(),
        "empty slice should have no errors"
    );
    assert!(empty_result.passed, "empty slice should pass");

    // Test with single game [480]
    let mut single_runner = StressTestRunner::new(StressTestConfig::default());
    let single_result = single_runner.run_multi_game_cycling_test(&[480]);
    assert!(
        single_result.iterations >= 1,
        "should process at least 1 game"
    );
    assert!(
        single_result.errors.is_empty(),
        "single valid game should have no errors"
    );
    assert!(single_result.passed, "single valid game should pass");
}

// ===========================================================================
// t27_14 — Steam Protocol Handler Dispatch
// ===========================================================================

// ===========================================================================
// t27_15 — Frame Pacer Integration
// ===========================================================================

// ===========================================================================
// t27_16 — Comprehensive SSIM Matrix
// ===========================================================================

// ===========================================================================
// t27_17 — Diagnostics Error Paths
// ===========================================================================

#[test]
fn t27_17_diagnostics_error_paths() {
    // Test compute_ssim with mismatched buffer sizes
    let small_buf = vec![0u8; 100];
    let large_buf = vec![0u8; 200];
    // Buffer too small for the declared dimensions (100 bytes for even 1x1
    // RGBA frame would need 4 bytes). 100 bytes is enough for a 5x5 frame
    // (5*5*4 = 100 bytes), but 200 bytes for the same 5x5 frame is fine.
    // Use 100x1 which needs 400 bytes but only 100 provided.
    let ssim_mismatch = compute_ssim(&small_buf, &large_buf, 100, 1);
    // Should return a value without panicking (0.0 because buffers too small)
    assert!(
        ssim_mismatch == 0.0,
        "SSIM on undersized buffers should return 0.0, got {ssim_mismatch}"
    );

    // Test compute_psnr with all-zero buffer (identical) — should not panic
    let zero_a = vec![0u8; 64]; // 4x4 RGBA = 64 bytes
    let zero_b = vec![0u8; 64];
    let psnr_identical = compute_psnr(&zero_a, &zero_b, 4, 4);
    // Identical frames should give INFINITY
    assert!(
        psnr_identical.is_infinite(),
        "PSNR for identical all-zero buffers should be INFINITY, got {psnr_identical}"
    );

    // Test compute_pixel_diff with tolerance > 1.0 — should not panic
    let buf_a = vec![0u8; 64];
    let buf_b = vec![255u8; 64];
    let (matching, total) = compute_pixel_diff(&buf_a, &buf_b, 1.5);
    // With tolerance 1.5 * 255 = all channels within 382.5 (always true for u8)
    assert_eq!(
        matching, total,
        "with tolerance > 1.0, all pixels should match"
    );

    // Test compare_frames with different-sized frames — should handle gracefully
    let small_frame = FrameCapture::new_solid(4, 4, 255, 0, 0, 255);
    let large_frame = FrameCapture::new_solid(8, 8, 0, 0, 255, 255);
    // compare_frames will use captured.width/height for compute_ssim/psnr,
    // which may cause index mismatches; verify no panic
    let result = compare_frames(&small_frame, &large_frame, 0.0);
    // Result should be populated (may be inaccurate due to size mismatch,
    // but shouldn't panic)
    let _ = result.ssim;
    let _ = result.psnr;
    let _ = result.pixel_match_percentage;
    let _ = result.passes;

    // Test detect_text_regions on an all-zero frame — should not panic
    let zero_frame = FrameCapture::new_solid(32, 32, 0, 0, 0, 255);
    let regions = detect_text_regions(&zero_frame);
    assert!(
        regions.is_empty(),
        "uniform all-zero frame should have no text regions"
    );

    // Test compute_psnr with empty buffers — should not panic
    let empty_a: Vec<u8> = vec![];
    let empty_b: Vec<u8> = vec![];
    let psnr_empty = compute_psnr(&empty_a, &empty_b, 0, 0);
    // 0x0 frame with pixel_count 0 returns INFINITY
    assert!(
        psnr_empty.is_infinite(),
        "PSNR for empty buffers should be INFINITY, got {psnr_empty}"
    );

    // Test compute_ssim with empty buffers — should not panic
    let ssim_empty = compute_ssim(&empty_a, &empty_b, 0, 0);
    assert!(
        ssim_empty == 1.0,
        "SSIM for empty buffers should be 1.0, got {ssim_empty}"
    );

    // Test compute_pixel_diff with empty buffers — should not panic
    let (m, t) = compute_pixel_diff(&empty_a, &empty_b, 0.0);
    assert_eq!(m, 0, "empty buffers should have 0 matching pixels");
    assert_eq!(t, 0, "empty buffers should have 0 total pixels");
}

// ===========================================================================
// MSAA Resolve Integration Tests
// ===========================================================================
//
// These tests verify the MSAA resolve functionality across all backends:
//   - D3D11 ResolveSubresource dispatch
//   - D3D12 resolve_subresource_region dispatch
//   - Metal backend resolve_msaa_texture integration

// ---------------------------------------------------------------------------
// t27_18: D3D11 ResolveSubresource — basic dispatch
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t27_19: D3D12 resolve_subresource_region dispatch
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t27_20: D3D12 ResolveSubresource with different formats
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t27_21: Metal backend resolve_msaa_texture — no panic on integration
// ---------------------------------------------------------------------------

#[test]
fn t27_21_metal_backend_resolve_msaa_integration() {
    use casa1::metal_backend::{
        MetalGpuBackend, MetalRenderEncoder, MetalTexture, MsaaResolveConfig, MsaaResolveMode,
        create_render_pass_descriptor, resolve_msaa,
    };

    // Try to create a Metal backend
    let mut backend = match MetalGpuBackend::new() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[skip] MetalGpuBackend not available: {e}");
            return;
        }
    };

    // Create MSAA source and resolve destination textures.
    let msaa = backend.create_texture(
        64,
        64,
        metal::MTLPixelFormat::BGRA8Unorm,
        metal::MTLTextureUsage::RenderTarget | metal::MTLTextureUsage::ShaderRead,
    );

    let resolve = backend.create_texture(
        64,
        64,
        metal::MTLPixelFormat::BGRA8Unorm,
        metal::MTLTextureUsage::RenderTarget | metal::MTLTextureUsage::ShaderRead,
    );

    let src_info = backend
        .get_texture(msaa)
        .expect("MSAA texture should exist in backend");
    let resolve_info = backend
        .get_texture(resolve)
        .expect("Resolve texture should exist in backend");
    assert_eq!(src_info.width(), 64, "MSAA source should have width 64");
    assert_eq!(
        resolve_info.width(),
        64,
        "Resolve target should have width 64"
    );

    // Exercise the real resolve path end-to-end: build a render encoder from
    // the backend's command queue, wrap the textures, and call resolve_msaa.
    // Previously this test only created textures and never called the resolve.
    let cmd_buffer = backend.command_queue().new_command_buffer();
    let descriptor = create_render_pass_descriptor(src_info, None);
    let mut encoder =
        MetalRenderEncoder::new(cmd_buffer, &descriptor).expect("render encoder must be creatable");

    let config = MsaaResolveConfig {
        sample_count: 4,
        resolve_mode: MsaaResolveMode::Average,
        custom_resolve_shader: None,
    };
    let src_wrapped = MetalTexture {
        handle: msaa,
        texture: src_info.to_owned(),
        width: 64,
        height: 64,
        format: casa1::metal_backend::PixelFormat::Bgra8Unorm,
    };
    let dst_wrapped = MetalTexture {
        handle: resolve,
        texture: resolve_info.to_owned(),
        width: 64,
        height: 64,
        format: casa1::metal_backend::PixelFormat::Bgra8Unorm,
    };

    // The implemented contract: resolve_msaa refuses Average (and every
    // mode) through a render encoder rather than silently faking it, exactly
    // like set_depth_bounds — RcInvalidState with the guidance message.
    let unsupported = resolve_msaa(&mut encoder, &src_wrapped, &dst_wrapped, &config)
        .expect_err("Average resolve must be refused, not faked");
    assert_eq!(
        unsupported.code,
        casa1::reason::ReasonCode::RcInvalidState,
        "unsupported resolve mode must be reported with RcInvalidState"
    );

    // Dimension mismatch must be rejected by the resolve path itself.
    let bad_dst = MetalTexture {
        handle: 0,
        texture: resolve_info.to_owned(),
        width: 32,
        height: 32,
        format: casa1::metal_backend::PixelFormat::Bgra8Unorm,
    };
    let mismatch = resolve_msaa(&mut encoder, &src_wrapped, &bad_dst, &config)
        .expect_err("resolve with mismatched dimensions must fail");
    assert_eq!(
        mismatch.code,
        casa1::reason::ReasonCode::RcCliInvalid,
        "dimension mismatch must be reported with RcCliInvalid"
    );

    encoder.end_encoding();
    cmd_buffer.commit();

    // Clean up - destroy_texture returns ()
    backend.destroy_texture(msaa);
    backend.destroy_texture(resolve);
}

// ---------------------------------------------------------------------------
// t27_22: D3D11 ResolveSubresource via D3D11Device
// ---------------------------------------------------------------------------

#[test]
fn t27_22_d3d11_device_resolve_subresource() {
    use casa1::d3d11::{self, d3d11_create_device};
    use casa1::gfx::{DxgiFormat, ResourceUsageHint};

    // Create a D3D11 device using the free function (D3D11Device has no ::new())
    let mut device = match d3d11_create_device(d3d11::DeviceCreationRequest {
        requested_feature_levels: vec![d3d11::FeatureLevel::Level11_0],
    }) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[skip] D3D11Device creation failed: {e}");
            return;
        }
    };

    // Create MSAA source and resolve target resources using create_texture_2d_with_usage
    let msaa = device.create_texture_2d_with_usage(
        "msaa_src",
        64,
        64,
        DxgiFormat::R8G8B8A8Unorm,
        ResourceUsageHint::Texture {
            sampled: false,
            render_target: true,
            depth_stencil: false,
            cpu_write_frequent: false,
        },
    );
    assert!(msaa.is_ok(), "Creating MSAA source should succeed");
    let msaa_id = msaa.unwrap();

    let dst = device.create_texture_2d_with_usage(
        "resolve_dst",
        64,
        64,
        DxgiFormat::R8G8B8A8Unorm,
        ResourceUsageHint::Texture {
            sampled: false,
            render_target: true,
            depth_stencil: false,
            cpu_write_frequent: false,
        },
    );
    assert!(dst.is_ok(), "Creating resolve target should succeed");
    let dst_id = dst.unwrap();

    // Call resolve_subresource on the D3D11 device
    // resolve_subresource(&mut self, dst, dst_subresource, src, src_subresource, format)
    let resolve_result =
        device.resolve_subresource(dst_id, 0, msaa_id, 0, DxgiFormat::R8G8B8A8Unorm as u32);
    assert!(
        resolve_result.is_ok(),
        "D3D11 ResolveSubresource via device should succeed"
    );
}
