//! Fuzz regression tests.
//!
//! Loads minimized crash/reproducer fixtures from `tests/fixtures/fuzz/` and
//! verifies that every Casa1 parser handles them gracefully (returns `Err` or
//! succeeds — never panics).
//!
//! Each fixture file is named `<parser>_<description>.bin` and contains raw
//! binary data that once caused a crash or undesirable behaviour.  Add new
//! fixtures here as fuzzing discovers them.

use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Recursively collect fixture files under `tests/fixtures/fuzz/`.
fn fuzz_fixtures() -> Vec<std::path::PathBuf> {
    let dir = Path::new("tests/fixtures/fuzz");
    if !dir.is_dir() {
        return Vec::new();
    }
    let mut files = Vec::new();
    collect_bin_files(dir, &mut files);
    files
}

fn collect_bin_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            collect_bin_files(&path, out);
        } else if path.extension().map_or(false, |e| e == "bin") {
            out.push(path);
        }
    }
}

fn load_fixture(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("failed to read fixture {:?}: {}", path, e))
}

/// Determine which parser to invoke based on the fixture filename prefix.
fn classify_fixture(name: &str) -> &'static str {
    if name.starts_with("pe_") {
        "pe"
    } else if name.starts_with("http_") {
        "http"
    } else if name.starts_with("steam_") {
        "steam"
    } else if name.starts_with("winhttp_") || name.starts_with("wininet_") {
        "winhttp"
    } else if name.starts_with("msi_") {
        "msi"
    } else if name.starts_with("media_") {
        "media"
    } else if name.starts_with("dxil_") {
        "dxil"
    } else if name.starts_with("spirv_") {
        "spirv"
    } else if name.starts_with("video_") {
        "video"
    } else {
        "unknown"
    }
}

// ---------------------------------------------------------------------------
// Fuzz regression tests – dynamically discovered
// ---------------------------------------------------------------------------

/// Smoke-test every fixture: make sure no parser panics.
#[test]
fn fuzz_fixtures_no_panic() {
    let fixtures = fuzz_fixtures();
    if fixtures.is_empty() {
        eprintln!("note: no fuzz fixture files found in tests/fixtures/fuzz/");
        return;
    }

    let mut failures = Vec::new();

    for path in &fixtures {
        let data = load_fixture(path);
        let name = path.file_stem().unwrap().to_string_lossy();
        let kind = classify_fixture(&name);

        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_parser(kind, &data)));

        match result {
            Ok(_) => { /* no panic – good */ }
            Err(_) => {
                failures.push(format!("{:?} ({} parser) panicked", path.display(), kind));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} fuzz fixture(s) caused panics:\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }
}

/// Run the appropriate parser for the given fixture kind.
/// Returns `Ok(())` if the parser handled the input gracefully (i.e. didn't
/// panic), regardless of whether parsing succeeded or returned an error.
fn run_parser(kind: &str, data: &[u8]) {
    match kind {
        "pe" => {
            let _ = casa1::pe::parse(data);
        }
        "http" => {
            let _ = casa1::security::parse_http_request(data);
        }
        "steam" => {
            let _ = casa1::steam_protocol::deserialize_message(data);
            let _ = casa1::steam_protocol::ExtendedHeader::deserialize(data);
            if let Ok(s) = std::str::from_utf8(data) {
                let _ = casa1::steam_protocol::parse_steam_protocol_url(s);
            }
        }
        "winhttp" => {
            let stack = casa1::winhttp::WinHttpStack::new();
            if let Ok(s) = std::str::from_utf8(data) {
                let _ = stack.internet_crack_url_w(s, s.len() as u32);
            }
            let _ = casa1::winhttp::ntlm_parse_challenge_msg(data);
        }
        "msi" => {
            let _ = casa1::installer::msi_fuzz_summary(data);
        }
        "media" => {
            let shim = casa1::media::MediaShim::new("C:/fuzz/ge");
            let _ = shim.classify_input(data);
        }
        "dxil" => {
            let _ = casa1::shader::fuzz_summary(data);
        }
        "spirv" => {
            let mut padded = data.to_vec();
            while padded.len() % 4 != 0 {
                padded.push(0);
            }
            let words: Vec<u32> = padded
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect();
            let mut translator = casa1::vkgl::SpirvTranslator::new();
            let _ = translator.parse(&words);
        }
        "video" => {
            let _ = casa1::video_decoder::parse_h264_annex_b(data);
        }
        _ => {
            // Unknown kind – just ensure we don't panic on generic handling
        }
    }
}

// ---------------------------------------------------------------------------
// Explicit regression tests for known crash reproducers
// ---------------------------------------------------------------------------

/// PE: minimal valid DOS header (MZ) – should return Err, not panic.
#[test]
fn regression_pe_minimal_mz() {
    let data = b"MZ";
    // Expect an Err because the PE is too short to be valid
    let result = casa1::pe::parse(data);
    assert!(
        result.is_err(),
        "expected Err for minimal MZ header, got Ok"
    );
}

/// PE: DOS header with valid e_lfanew but truncated NT headers.
#[test]
fn regression_pe_truncated_nt_headers() {
    // Allocate a buffer large enough to hold the DOS header + NT signature
    // (0x84 = 132 bytes) so we don't slice out of bounds.
    let mut data = vec![0u8; 0x84];
    data[0] = b'M';
    data[1] = b'Z';
    // e_lfanew at offset 0x3c pointing to 0x80
    let e_lfanew: u32 = 0x80;
    data[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    // NT signature present but truncated — optional header is missing
    data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    // The data ends after the NT signature; optional header is missing
    // so parse() should return an Err (not panic).
    let result = casa1::pe::parse(&data);
    assert!(result.is_err(), "expected Err for truncated NT headers");
}

/// HTTP: empty input should return Err.
#[test]
fn regression_http_empty() {
    let result = casa1::security::parse_http_request(b"");
    assert!(result.is_err(), "expected Err for empty HTTP input");
}

/// HTTP: malformed request line.
#[test]
fn regression_http_malformed() {
    let result = casa1::security::parse_http_request(b"GET\r\n\r\n");
    // Accept either Ok or Err — just ensure no panic
    let _ = result;
}

/// Steam: empty data to deserialize_message should return None.
#[test]
fn regression_steam_empty_frame() {
    let result = casa1::steam_protocol::deserialize_message(b"");
    assert!(result.is_none(), "expected None for empty steam frame");
}

/// Steam: bad magic bytes should return None.
#[test]
fn regression_steam_bad_magic() {
    let result = casa1::steam_protocol::deserialize_message(b"\x00\x00\x00\x00\x10\x00\x00\x00");
    assert!(result.is_none(), "expected None for bad steam magic");
}

/// Steam: truncated ExtendedHeader.
#[test]
fn regression_steam_truncated_header() {
    let result = casa1::steam_protocol::ExtendedHeader::deserialize(&[0u8; 10]);
    assert!(
        result.is_none(),
        "expected None for truncated ExtendedHeader"
    );
}

/// WinHTTP: empty URL should not panic.
#[test]
fn regression_winhttp_empty_url() {
    use casa1::winhttp::WinHttpStack;
    let stack = WinHttpStack::new();
    let result = stack.internet_crack_url_w("", 0);
    // Accept either Ok or Err
    let _ = result;
}

/// WinHTTP: NTLM empty data.
#[test]
fn regression_winhttp_ntlm_empty() {
    let result = casa1::winhttp::ntlm_parse_challenge_msg(b"");
    assert!(result.is_none(), "expected None for empty NTLM data");
}

/// WinINet: empty URL moniker.
#[test]
fn regression_wininet_empty_url() {
    let result = casa1::wininet::create_url_moniker("", None);
    // Accept either Ok or Err — just ensure no panic
    let _ = result;
}
