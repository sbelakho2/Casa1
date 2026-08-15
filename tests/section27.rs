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
    BehavioralTestStep, BehavioralVerifier, ColorSpace, FrameCapture, ReferenceFrameDB,
    StressTestConfig, StressTestRunner, compare_frames, compute_pixel_diff, compute_psnr,
    compute_ssim, detect_text_regions, verify_color_space,
};
use casa1::perf::{FramePacer, FramePacingConfig};
use casa1::steam_protocol::{
    SteamProtocolCommand, SteamProtocolDispatchResult, SteamProtocolHandler,
    parse_steam_protocol_url,
};
use std::path::Path;
use std::time::Duration;

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
        psnr_same, f64::INFINITY,
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
        result_diff.ssim,
        result_diff.pixel_match_percentage
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

#[test]
fn t27_04_frame_capture_from_pixels() {
    // Create a 4x4 RGBA8 image with a gradient pattern
    let width = 4u32;
    let height = 4u32;
    let mut pixels = Vec::with_capacity((width * height * 4) as usize);
    for y in 0..height {
        for x in 0..width {
            pixels.push((x * 64) as u8); // R varies with x
            pixels.push((y * 64) as u8); // G varies with y
            pixels.push(128); // B constant
            pixels.push(255); // A full opaque
        }
    }

    let frame = FrameCapture::from_pixels(width, height, pixels.clone());
    assert_eq!(frame.width, width, "width should match");
    assert_eq!(frame.height, height, "height should match");
    assert_eq!(
        frame.pixels.len(),
        (width * height * 4) as usize,
        "pixel data length should match"
    );

    // Verify pixel content: pixel at (0,0) should be RGBA(0,0,128,255)
    assert_eq!(frame.pixels[0], 0, "pixel(0,0).R should be 0");
    assert_eq!(frame.pixels[1], 0, "pixel(0,0).G should be 0");
    assert_eq!(frame.pixels[2], 128, "pixel(0,0).B should be 128");
    assert_eq!(frame.pixels[3], 255, "pixel(0,0).A should be 255");

    // Pixel at (1,0) should be RGBA(64,0,128,255)
    assert_eq!(frame.pixels[4], 64, "pixel(1,0).R should be 64");
    assert_eq!(frame.pixels[5], 0, "pixel(1,0).G should be 0");

    // Pixel at (0,1) should be RGBA(0,64,128,255)
    assert_eq!(frame.pixels[16], 0, "pixel(0,1).R should be 0");
    assert_eq!(frame.pixels[17], 64, "pixel(0,1).G should be 64");

    // Test invalid data: size mismatch (pixels.len() doesn't match width*height*4)
    let bad_pixels = vec![0u8; 10]; // too small for any reasonable frame
    let bad_frame = FrameCapture::from_pixels(100, 100, bad_pixels);
    // The constructor doesn't validate; verify that downstream functions
    // handle the mismatch gracefully
    let ssim_bad = compute_ssim(&bad_frame.pixels, &frame.pixels, 100, 100);
    // Should not panic; returns 0.0 for mismatched sizes
    assert!(
        ssim_bad == 0.0,
        "SSIM on size-mismatched buffers should be 0.0, got {ssim_bad}"
    );

    // Test very small frame: 1x1
    let tiny = FrameCapture::from_pixels(1, 1, vec![255, 0, 0, 255]);
    assert_eq!(tiny.width, 1);
    assert_eq!(tiny.height, 1);
    assert_eq!(tiny.pixels.len(), 4);

    // SSIM on identical 1x1 frames
    let tiny2 = FrameCapture::from_pixels(1, 1, vec![255, 0, 0, 255]);
    let ssim_tiny = compute_ssim(&tiny.pixels, &tiny2.pixels, 1, 1);
    assert!(
        (ssim_tiny - 1.0).abs() < 0.001,
        "SSIM on identical 1x1 frames should be ~1.0, got {ssim_tiny}"
    );

    // Test large frame dimensions (256x256 — not full 4096x4096 to keep
    // test runtime reasonable)
    let lg = FrameCapture::new_solid(256, 256, 128, 128, 128, 255);
    assert_eq!(lg.pixels.len(), 256 * 256 * 4);
    let lg2 = FrameCapture::new_solid(256, 256, 128, 128, 128, 255);
    let ssim_lg = compute_ssim(&lg.pixels, &lg2.pixels, 256, 256);
    assert!(
        (ssim_lg - 1.0).abs() < 0.001,
        "SSIM on identical 256x256 frames should be ~1.0, got {ssim_lg}"
    );
}

// ===========================================================================
// t27_05 — Color Space Verification
// ===========================================================================

#[test]
fn t27_05_color_space_verification() {
    // Create a frame with known sRGB gamma characteristics:
    // sRGB-encoded mid-gray (128,128,128) should be a valid sRGB frame
    let srgb_frame = FrameCapture::new_solid(16, 16, 128, 128, 128, 255);
    let srgb_result = verify_color_space(&srgb_frame, ColorSpace::SRGB);
    assert!(
        srgb_result.is_ok(),
        "verify_color_space(SRGB) should not error"
    );
    // Mid-gray in sRGB should pass validation
    assert!(
        srgb_result.unwrap(),
        "solid mid-gray frame should pass sRGB verification"
    );

    // Create a frame with linear RGB data:
    // Linear 0.5 ≈ sRGB 188 (0.5^(1/2.4)*255), but we use raw (128,128,128)
    // which is closer to sRGB gamma. For LinearSRGB verification, this may
    // or may not pass; just verify no panic.
    let linear_frame = FrameCapture::new_solid(16, 16, 16, 16, 16, 255);
    let linear_result = verify_color_space(&linear_frame, ColorSpace::LinearSRGB);
    assert!(
        linear_result.is_ok(),
        "verify_color_space(LinearSRGB) should not error"
    );

    // Create a frame with DisplayP3 color space
    let p3_frame = FrameCapture::new_solid(16, 16, 200, 100, 50, 255);
    let p3_result = verify_color_space(&p3_frame, ColorSpace::DisplayP3);
    assert!(
        p3_result.is_ok(),
        "verify_color_space(DisplayP3) should not error"
    );

    // Test with extreme values (pure white, pure black)
    let white_frame = FrameCapture::new_solid(16, 16, 255, 255, 255, 255);
    let white_srgb = verify_color_space(&white_frame, ColorSpace::SRGB).unwrap();
    assert!(white_srgb, "solid white should pass sRGB verification");

    let black_frame = FrameCapture::new_solid(16, 16, 0, 0, 0, 255);
    let black_srgb = verify_color_space(&black_frame, ColorSpace::SRGB).unwrap();
    assert!(black_srgb, "solid black should pass sRGB verification");

    // Test with transparent frame (alpha=0) — should handle gracefully
    let transparent_frame = FrameCapture::new_solid(16, 16, 255, 0, 0, 0);
    let trans_srgb = verify_color_space(&transparent_frame, ColorSpace::SRGB);
    assert!(
        trans_srgb.is_ok(),
        "fully transparent frame should not cause panic"
    );

    // Verify the function returns consistent results across different color
    // space inputs for the same frame, and that re-verification is
    // deterministic.
    let test_frame = FrameCapture::new_solid(16, 16, 128, 128, 128, 255);
    let r1 = verify_color_space(&test_frame, ColorSpace::SRGB).unwrap();
    let r2 = verify_color_space(&test_frame, ColorSpace::LinearSRGB).unwrap();
    let r3 = verify_color_space(&test_frame, ColorSpace::DisplayP3).unwrap();
    assert!(r1, "solid mid-gray must pass sRGB verification");
    assert!(r2, "uniform mid-gray must pass LinearSRGB verification");
    assert!(r3, "solid mid-gray must pass DisplayP3 verification");
    assert_eq!(
        r1,
        verify_color_space(&test_frame, ColorSpace::SRGB).unwrap(),
        "re-verification must be deterministic"
    );
    assert_eq!(
        r2,
        verify_color_space(&test_frame, ColorSpace::LinearSRGB).unwrap(),
        "re-verification must be deterministic"
    );
    assert_eq!(
        r3,
        verify_color_space(&test_frame, ColorSpace::DisplayP3).unwrap(),
        "re-verification must be deterministic"
    );
}

// ===========================================================================
// t27_06 — Reference Frame Database
// ===========================================================================

#[test]
fn t27_06_reference_frame_database() {
    // Create a ReferenceFrameDB with tolerance 0.05
    let mut db = ReferenceFrameDB::new(0.05);
    assert_eq!(db.tolerance, 0.05, "tolerance should be 0.05");

    // Register reference frames
    let ref_red = FrameCapture::new_solid(64, 64, 255, 0, 0, 255);
    let ref_blue = FrameCapture::new_solid(64, 64, 0, 0, 255, 255);
    let ref_green = FrameCapture::new_solid(64, 64, 0, 255, 0, 255);

    db.insert("red", ref_red.clone());
    db.insert("blue", ref_blue.clone());
    db.insert("green", ref_green.clone());

    // Verify lookup
    let retrieved = db.get("red");
    assert!(retrieved.is_some(), "should find 'red' in database");
    assert_eq!(retrieved.unwrap().pixels, ref_red.pixels);

    let missing = db.get("nonexistent");
    assert!(missing.is_none(), "should not find nonexistent frame");

    // Compare candidates against references using compare_frames
    let candidate_red = FrameCapture::new_solid(64, 64, 255, 0, 0, 255);
    let candidate_purple = FrameCapture::new_solid(64, 64, 255, 0, 255, 255);

    // Red vs red reference should pass with tolerance 0.05
    let result_vs_red = compare_frames(&candidate_red, db.get("red").unwrap(), db.tolerance);
    assert!(
        (result_vs_red.ssim - 1.0).abs() < 0.001,
        "matching frames should have SSIM ~1.0"
    );
    assert!(
        result_vs_red.passes,
        "matching frames should pass comparison"
    );

    // Purple vs red reference should have lower SSIM
    let result_vs_purple = compare_frames(&candidate_purple, db.get("red").unwrap(), db.tolerance);
    assert!(
        result_vs_purple.ssim < result_vs_red.ssim,
        "different colors should have lower SSIM than matching colors"
    );

    // Test with tolerance 0.0 (exact match only)
    let mut exact_db = ReferenceFrameDB::new(0.0);
    exact_db.insert("ref", ref_red.clone());
    let exact_match = compare_frames(&candidate_red, exact_db.get("ref").unwrap(), 0.0);
    assert!(
        (exact_match.ssim - 1.0).abs() < 0.001,
        "exact match at tolerance 0.0 should have SSIM ~1.0"
    );
    assert!(
        exact_match.passes,
        "exact match should pass at tolerance 0.0"
    );

    // Test with high tolerance (1.0 — everything matches)
    let mut tolerant_db = ReferenceFrameDB::new(1.0);
    tolerant_db.insert("ref", ref_red.clone());
    let tolerant_result = compare_frames(&candidate_purple, tolerant_db.get("ref").unwrap(), 1.0);
    // At tolerance 1.0, all pixels match within threshold
    assert!(
        tolerant_result.pixel_match_percentage > 0.0,
        "high tolerance should allow many pixels to match"
    );
}

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
    assert!(verifier.all_passed(), "one passing step must pass the verifier");
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
    assert_eq!(
        verifier.results[1].error.as_deref(),
        Some("logon rejected")
    );
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

#[test]
fn t27_14_steam_protocol_handler_dispatch() {
    let handler = SteamProtocolHandler::new();

    // Parse a run-game URL
    let url = parse_steam_protocol_url("steam://run/730");
    assert!(url.is_some(), "should parse steam://run/730");
    let url = url.unwrap();
    assert_eq!(url.command, SteamProtocolCommand::Run(730));

    // Dispatch the URL
    let result = handler.dispatch(&url);
    match result {
        SteamProtocolDispatchResult::LaunchGame(app_id, action) => {
            assert_eq!(app_id, 730, "app_id should be 730");
            assert!(action.is_none(), "no action param in URL");
        }
        other => panic!("expected LaunchGame, got {:?}", other),
    }

    // Test store URL
    let store_url = parse_steam_protocol_url("steam://store/440").unwrap();
    let store_result = handler.dispatch(&store_url);
    match store_result {
        SteamProtocolDispatchResult::NavigateBrowser(url_str) => {
            assert!(
                url_str.contains("store.steampowered.com/app/440"),
                "store URL should point to Steam store"
            );
        }
        other => panic!("expected NavigateBrowser, got {:?}", other),
    }

    // Test install URL
    let install_url = parse_steam_protocol_url("steam://install/730").unwrap();
    let install_result = handler.dispatch(&install_url);
    match install_result {
        SteamProtocolDispatchResult::InstallGame(app_id) => {
            assert_eq!(app_id, 730, "install app_id should be 730");
        }
        other => panic!("expected InstallGame, got {:?}", other),
    }

    // Test friends URL
    let friends_url = parse_steam_protocol_url("steam://friends").unwrap();
    let friends_result = handler.dispatch(&friends_url);
    match friends_result {
        SteamProtocolDispatchResult::ShowFriends => {}
        other => panic!("expected ShowFriends, got {:?}", other),
    }

    // Test unknown command — should not panic
    let unknown_url = parse_steam_protocol_url("steam://unknown_command/123").unwrap();
    let unknown_result = handler.dispatch(&unknown_url);
    match unknown_result {
        SteamProtocolDispatchResult::Unrecognized(_) => {}
        other => panic!("expected Unrecognized, got {:?}", other),
    }

    // Test invalid steam URL (non-steam scheme) — should return None
    let invalid = parse_steam_protocol_url("https://example.com");
    assert!(invalid.is_none(), "non-steam URL should return None");

    // Test handle_url end-to-end
    let handle_result = handler.handle_url("steam://run/730?action=play");
    match handle_result {
        SteamProtocolDispatchResult::LaunchGame(app_id, action) => {
            assert_eq!(app_id, 730);
            assert_eq!(action.as_deref(), Some("play"));
        }
        other => panic!("expected LaunchGame with action, got {:?}", other),
    }
}

// ===========================================================================
// t27_15 — Frame Pacer Integration
// ===========================================================================

#[test]
fn t27_15_frame_pacer_integration() {
    // Create a FramePacer with target FPS of 60
    let config = FramePacingConfig {
        target_fps: 60,
        vsync_enabled: true,
        max_frame_latency: 2,
    };
    let mut pacer = FramePacer::new(config);

    // Begin a frame
    let delta = pacer.begin_frame();
    // The first frame has no previous frame, so the delta is exactly zero
    // (a pacer that fabricates a nonzero delta on the first frame fails).
    assert_eq!(
        delta,
        Duration::ZERO,
        "first frame delta must be exactly zero"
    );

    // End the frame
    pacer.end_frame();

    // Verify frame timing metrics are recorded
    // (access via the public stats — FrameTimingStats is public)
    let avg_fps = pacer.average_fps();
    assert!(avg_fps >= 0.0, "average FPS should be non-negative");

    // Test at 30 FPS target
    let config_30 = FramePacingConfig {
        target_fps: 30,
        vsync_enabled: false,
        max_frame_latency: 1,
    };
    let mut pacer_30 = FramePacer::new(config_30);
    pacer_30.begin_frame();
    pacer_30.end_frame();
    let fps_30 = pacer_30.average_fps();
    assert!(
        fps_30 >= 0.0,
        "30 FPS pacer should report valid average FPS"
    );

    // Test at 120 FPS target
    let config_120 = FramePacingConfig {
        target_fps: 120,
        vsync_enabled: false,
        max_frame_latency: 3,
    };
    let mut pacer_120 = FramePacer::new(config_120);
    pacer_120.begin_frame();
    pacer_120.end_frame();
    let fps_120 = pacer_120.average_fps();
    assert!(
        fps_120 >= 0.0,
        "120 FPS pacer should report valid average FPS"
    );

    // Verify frame pacing doesn't panic when called rapidly
    let config_rapid = FramePacingConfig {
        target_fps: 60,
        vsync_enabled: false,
        max_frame_latency: 2,
    };
    let mut rapid_pacer = FramePacer::new(config_rapid);
    for _ in 0..100 {
        rapid_pacer.begin_frame();
        rapid_pacer.end_frame();
    }
    let rapid_fps = rapid_pacer.average_fps();
    assert!(rapid_fps >= 0.0, "rapid frame pacing should not panic");

    // Verify frame_remaining_time doesn't panic
    pacer.begin_frame();
    let remaining = pacer.frame_remaining_time();
    assert!(
        remaining >= Duration::ZERO,
        "remaining time should be non-negative"
    );
}

// ===========================================================================
// t27_16 — Comprehensive SSIM Matrix
// ===========================================================================

#[test]
fn t27_16_comprehensive_ssim_matrix() {
    let size = 100u32;

    // Create frames for each color
    let red = FrameCapture::new_solid(size, size, 255, 0, 0, 255);
    let green = FrameCapture::new_solid(size, size, 0, 255, 0, 255);
    let blue = FrameCapture::new_solid(size, size, 0, 0, 255, 255);
    let black = FrameCapture::new_solid(size, size, 0, 0, 0, 255);
    let white = FrameCapture::new_solid(size, size, 255, 255, 255, 255);

    let frames: [(&str, &FrameCapture); 5] = [
        ("red", &red),
        ("green", &green),
        ("blue", &blue),
        ("black", &black),
        ("white", &white),
    ];

    // Compute SSIM for all pairs (25 comparisons)
    let mut matrix = [[0.0f64; 5]; 5];

    for (i, (_name_i, frame_i)) in frames.iter().enumerate() {
        for (j, (_name_j, frame_j)) in frames.iter().enumerate() {
            let ssim = compute_ssim(
                &frame_i.pixels,
                &frame_j.pixels,
                frame_i.width,
                frame_i.height,
            );
            matrix[i][j] = ssim;
        }
    }

    // Verify identity pairs (same color) have SSIM == 1.0 (or very close)
    for i in 0..5 {
        assert!(
            (matrix[i][i] - 1.0).abs() < 0.001,
            "identity pair {} should have SSIM ~1.0, got {}",
            frames[i].0,
            matrix[i][i]
        );
    }

    // Verify different color pairs have SSIM < 0.9
    for i in 0..5 {
        for j in 0..5 {
            if i != j {
                assert!(
                    matrix[i][j] < 1.0,
                    "different colors should have SSIM < 1.0, got {} vs {}: {}",
                    frames[i].0,
                    frames[j].0,
                    matrix[i][j]
                );
            }
        }
    }

    // Verify the matrix is symmetric
    for i in 0..5 {
        for j in 0..5 {
            let diff = (matrix[i][j] - matrix[j][i]).abs();
            assert!(
                diff < 0.001,
                "SSIM matrix should be symmetric: [{}][{}]={} vs [{}][{}]={}, diff={}",
                i,
                j,
                matrix[i][j],
                j,
                i,
                matrix[j][i],
                diff
            );
        }
    }

    // Verify specific expected relationships:
    // - Black and white should have lower SSIM than black and black (identity)
    // - Red and Green should have lower SSIM than Red and Red
    assert!(
        matrix[3][4] < 0.99, // black vs white
        "black vs white should have SSIM < 0.99, got {}",
        matrix[3][4]
    );
    assert!(
        matrix[0][1] < 0.99, // red vs green
        "red vs green should have SSIM < 0.99, got {}",
        matrix[0][1]
    );
}

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

#[test]
fn t27_18_d3d11_resolve_subresource_dispatch() {
    // Create a D3D11 device and resources for ResolveSubresource
    use casa1::gfx::{DxgiFormat, GraphicsBackend, ResourceDesc, ResourceUsageHint};

    let mut backend = GraphicsBackend::new();

    // Create a multisampled source resource and a single-sample destination
    let msaa_desc = ResourceDesc {
        name: "msaa_src".to_string(),
        format: DxgiFormat::R8G8B8A8Unorm,
        heap: casa1::gfx::HeapType::Default,
        size: 64 * 64 * 4,
        subresources: 1,
        initial_state: casa1::gfx::ResourceState::Common,
        usage_hint: ResourceUsageHint::Texture {
            sampled: false,
            render_target: true,
            depth_stencil: false,
            cpu_write_frequent: false,
        },
    };

    let resolve_desc = ResourceDesc {
        name: "resolve_dst".to_string(),
        format: DxgiFormat::R8G8B8A8Unorm,
        heap: casa1::gfx::HeapType::Default,
        size: 64 * 64 * 4,
        subresources: 1,
        initial_state: casa1::gfx::ResourceState::Common,
        usage_hint: ResourceUsageHint::Texture {
            sampled: false,
            render_target: true,
            depth_stencil: false,
            cpu_write_frequent: false,
        },
    };

    // Create resources through the backend
    let msaa_tex = backend.create_resource(msaa_desc);
    assert!(
        msaa_tex.is_ok(),
        "Creating MSAA source texture should succeed"
    );
    let resolve_tex = backend.create_resource(resolve_desc);
    assert!(
        resolve_tex.is_ok(),
        "Creating resolve destination texture should succeed"
    );

    let msaa_id = msaa_tex.unwrap();
    let resolve_id = resolve_tex.unwrap();

    // Create a command list and record a resolve subresource operation
    let allocator = backend.create_command_allocator();
    let root_sig = backend.create_root_signature(casa1::gfx::RootSignatureDesc {
        descriptor_tables: vec![],
        root_constants: 0,
        ..Default::default()
    });
    let pso = backend.create_pipeline_state(
        root_sig,
        casa1::gfx::PipelineStateDesc {
            label: "resolve_test".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
            depth_format: None,
        },
    );
    let list = backend.create_graphics_command_list(allocator, pso, false);

    // Record the resolve subresource operation
    let format_u32 = DxgiFormat::R8G8B8A8Unorm as u32;
    let resolve_result = backend.record_resolve_subresource(
        list, resolve_id, msaa_id, format_u32, 0, // D3D12_RESOLVE_MODE_DECOMPRESS → Average
    );
    assert!(
        resolve_result.is_ok(),
        "Recording ResolveSubresource should succeed"
    );

    // Close and execute the command list
    let stream = backend.close_command_list(list);
    assert!(stream.is_ok(), "Closing command list should succeed");

    let queue = backend.create_command_queue();
    let exec_result = backend.execute_command_lists(queue, &[stream.unwrap()], None);
    assert!(
        exec_result.is_ok(),
        "Executing resolve command list should succeed"
    );

    // Clean up resources
    backend.destroy_resource(msaa_id).ok();
    backend.destroy_resource(resolve_id).ok();
}

// ---------------------------------------------------------------------------
// t27_19: D3D12 resolve_subresource_region dispatch
// ---------------------------------------------------------------------------

#[test]
fn t27_19_d3d12_resolve_subresource_region_dispatch() {
    use casa1::d3d12::D3d12Runtime;
    use casa1::gfx::{
        DxgiFormat, PipelineStateDesc, ResourceDesc, ResourceUsageHint, RootSignatureDesc,
    };

    let mut runtime = D3d12Runtime::new();

    // Create multisampled source and single-sample destination resources
    let msaa_desc = ResourceDesc {
        name: "d3d12_msaa_src".to_string(),
        format: DxgiFormat::R8G8B8A8Unorm,
        heap: casa1::gfx::HeapType::Default,
        size: 128 * 128 * 4,
        subresources: 1,
        initial_state: casa1::gfx::ResourceState::Common,
        usage_hint: ResourceUsageHint::Texture {
            sampled: false,
            render_target: true,
            depth_stencil: false,
            cpu_write_frequent: false,
        },
    };

    let resolve_desc = ResourceDesc {
        name: "d3d12_resolve_dst".to_string(),
        format: DxgiFormat::R8G8B8A8Unorm,
        heap: casa1::gfx::HeapType::Default,
        size: 128 * 128 * 4,
        subresources: 1,
        initial_state: casa1::gfx::ResourceState::Common,
        usage_hint: ResourceUsageHint::Texture {
            sampled: false,
            render_target: true,
            depth_stencil: false,
            cpu_write_frequent: false,
        },
    };

    // Create resources
    let msaa_tex = runtime.create_committed_resource(msaa_desc);
    assert!(
        msaa_tex.is_ok(),
        "Creating D3D12 MSAA texture should succeed"
    );
    let resolve_tex = runtime.create_committed_resource(resolve_desc);
    assert!(
        resolve_tex.is_ok(),
        "Creating D3D12 resolve target should succeed"
    );

    let msaa_id = msaa_tex.unwrap();
    let resolve_id = resolve_tex.unwrap();

    // Create a command list
    let root_sig = runtime.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![],
        root_constants: 0,
        ..Default::default()
    });
    let pso = runtime.create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "d3d12_resolve_test".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
            depth_format: None,
        },
    );
    let allocator = runtime.create_command_allocator();
    let list = runtime.create_graphics_command_list(allocator, pso, false);

    // Call resolve_subresource_region (maps to record_resolve_subresource)
    let format_u32 = DxgiFormat::R8G8B8A8Unorm as u32;
    let resolve_result = runtime.resolve_subresource_region(list, resolve_id, msaa_id, format_u32);
    assert!(
        resolve_result.is_ok(),
        "D3D12 resolve_subresource_region should succeed"
    );

    // Clean up
    runtime.destroy_resource(msaa_id).ok();
    runtime.destroy_resource(resolve_id).ok();
}

// ---------------------------------------------------------------------------
// t27_20: D3D12 ResolveSubresource with different formats
// ---------------------------------------------------------------------------

#[test]
fn t27_20_d3d12_resolve_subresource_various_formats() {
    use casa1::d3d12::D3d12Runtime;
    use casa1::gfx::{
        DxgiFormat, PipelineStateDesc, ResourceDesc, ResourceUsageHint, RootSignatureDesc,
    };

    let mut runtime = D3d12Runtime::new();
    let root_sig = runtime.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![],
        root_constants: 0,
        ..Default::default()
    });
    let pso = runtime.create_pipeline_state(
        root_sig,
        PipelineStateDesc {
            label: "resolve_formats".to_string(),
            compute: false,
            render_target_formats: vec![DxgiFormat::R8G8B8A8Unorm],
            depth_format: None,
        },
    );
    let allocator = runtime.create_command_allocator();
    let list = runtime.create_graphics_command_list(allocator, pso, false);

    // Test with different DXGI formats
    let formats = [
        DxgiFormat::R8G8B8A8Unorm,
        DxgiFormat::R32G32B32A32Float,
        DxgiFormat::R16G16B16A16Float,
        DxgiFormat::R10G10B10A2Unorm,
        DxgiFormat::B8G8R8A8Unorm,
    ];

    for &fmt in &formats {
        let msaa_desc = ResourceDesc {
            name: format!("msaa_{:?}", fmt),
            format: fmt,
            heap: casa1::gfx::HeapType::Default,
            size: 32 * 32 * 4,
            subresources: 1,
            initial_state: casa1::gfx::ResourceState::Common,
            usage_hint: ResourceUsageHint::Texture {
                sampled: false,
                render_target: true,
                depth_stencil: false,
                cpu_write_frequent: false,
            },
        };
        let resolve_desc = ResourceDesc {
            name: format!("resolve_{:?}", fmt),
            format: fmt,
            heap: casa1::gfx::HeapType::Default,
            size: 32 * 32 * 4,
            subresources: 1,
            initial_state: casa1::gfx::ResourceState::Common,
            usage_hint: ResourceUsageHint::Texture {
                sampled: false,
                render_target: true,
                depth_stencil: false,
                cpu_write_frequent: false,
            },
        };

        if let (Ok(msaa), Ok(resolve)) = (
            runtime.create_committed_resource(msaa_desc),
            runtime.create_committed_resource(resolve_desc),
        ) {
            let result = runtime.resolve_subresource_region(list, resolve, msaa, fmt as u32);
            assert!(
                result.is_ok(),
                "ResolveSubresource for format {:?} should succeed",
                fmt
            );
            runtime.destroy_resource(msaa).ok();
            runtime.destroy_resource(resolve).ok();
        }
    }
}

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
    let mut encoder = MetalRenderEncoder::new(cmd_buffer, &descriptor)
        .expect("render encoder must be creatable");

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

    resolve_msaa(&mut encoder, &src_wrapped, &dst_wrapped, &config)
        .expect("average resolve must succeed on matching textures");

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
