//! Phase 38 — Steam manifest release gate (deterministic, no emulation).
//!
//! Performs the exact `C:\package` operations Steam performs during boot
//! against the checked-in `steam-live-run-x86` GE:
//!
//! 1. `GetFileAttributesW` on `C:\package\steam_client_win32.installed` succeeds.
//! 2. `CreateFileW` OPEN_EXISTING + read access succeeds.
//! 3. `GetFileSizeEx` succeeds.
//! 4. `ReadFile` returns exactly the stored bytes.
//! 5. `CloseHandle` succeeds.
//! 6. The package-directory writability probe succeeds.
//! 7. Creating a temporary file succeeds.
//! 8. `WriteFile` succeeds.
//! 9. `FlushFileBuffers` succeeds.
//! 10. Close/reopen succeeds.
//! 11. `MoveFileEx`/`ReplaceFile` behavior succeeds.
//! 12. `DeleteFile` succeeds.
//! 13. The original manifest remains unchanged.
//!
//! This is the first release gate: it must pass before any Chromium/CEF
//! debugging is attempted. It runs against the exact GE in the repo
//! (`ges/steam-live-run-x86`) and drives the Win32Subsystem directly, so it
//! exposes filesystem-semantics mismatches without executing millions of
//! emulated instructions.

use casa1::ge::{FileAccess, GameEnvironment, ShareMode};
use casa1::win32::{CreationDisposition, Win32Subsystem};
use std::path::PathBuf;

const MANIFEST_GUEST_PATH: &str = r"C:\package\steam_client_win32.installed";

fn repo_ge_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("ges")
        .join("steam-live-run-x86")
}

fn setup() -> Win32Subsystem {
    let root = repo_ge_root();
    assert!(
        root.join("ge.json").is_file(),
        "steam-live-run-x86 GE missing at {}",
        root.display()
    );
    let ge = GameEnvironment::from_root(root).expect("open steam-live-run-x86 GE");
    Win32Subsystem::new(ge, false)
}

fn read_manifest_from_disk() -> Vec<u8> {
    std::fs::read(repo_ge_root().join("drive_c").join("package").join("steam_client_win32.installed"))
        .expect("read manifest from the GE on disk")
}

fn read_manifest_via_guest(win32: &mut Win32Subsystem) -> Vec<u8> {
    let handle = win32
        .create_file_w(
            MANIFEST_GUEST_PATH,
            FileAccess {
                read: true,
                write: false,
                delete: false,
            },
            ShareMode {
                read: true,
                write: false,
                delete: false,
            },
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        )
        .expect("CreateFileW OPEN_EXISTING manifest");
    let size = win32.get_file_size_ex(handle).expect("GetFileSizeEx");
    let data = win32
        .read_file(handle, size as usize)
        .expect("ReadFile manifest");
    win32.close_handle(handle).expect("CloseHandle manifest");
    data
}

/// Steps 1–5: the manifest must open, size correctly, and read back
/// byte-for-byte identically to the file on disk.
#[test]
fn manifest_open_read_verify_gate() {
    let mut win32 = setup();
    let manifest_bytes = read_manifest_from_disk();
    assert!(
        manifest_bytes.len() >= 64,
        "manifest looks truncated ({} bytes)",
        manifest_bytes.len()
    );

    // 1. GetFileAttributesW succeeds and reports a regular file.
    let attrs = win32
        .get_file_attributes_w(MANIFEST_GUEST_PATH)
        .expect("GetFileAttributesW on manifest");
    // An empty attribute list is the internal representation of a plain
    // file; the thunk converts [] to FILE_ATTRIBUTE_NORMAL (0x80), which is
    // exactly what Windows returns for an existing plain file (never 0).
    assert!(
        attrs.is_empty() || attrs.iter().all(|a| a != "directory"),
        "manifest must be a plain file, got: {attrs:?}"
    );

    // 2–5. Open / size / read / close.
    let guest_bytes = read_manifest_via_guest(&mut win32);
    assert_eq!(
        guest_bytes, manifest_bytes,
        "manifest bytes read through the guest must match the file on disk exactly"
    );
}

/// Steps 6–13: the package directory must be writable (temp file write/
/// flush/reopen/move/delete cycle), and the manifest must remain untouched.
#[test]
fn package_writability_probe_gate() {
    let mut win32 = setup();
    let manifest_bytes = read_manifest_from_disk();

    let temp_path = r"C:\package\casa1_probe.tmp";
    let moved_path = r"C:\package\casa1_probe_moved.tmp";
    let payload: &[u8] = b"casa1 package writability probe payload\n";

    // 6–7. Writability probe: CREATE_ALWAYS a temporary file in C:\package.
    let handle = win32
        .create_file_w(
            temp_path,
            FileAccess {
                read: true,
                write: true,
                delete: true,
            },
            ShareMode {
                read: false,
                write: false,
                delete: false,
            },
            CreationDisposition::CreateAlways,
            false,
            false,
            false,
        )
        .expect("CreateFileW CREATE_ALWAYS in C:\\package (writability probe)");

    // 8. WriteFile succeeds and reports the full byte count.
    let written = win32
        .write_file(handle, payload)
        .expect("WriteFile to probe file");
    assert_eq!(written as usize, payload.len(), "full payload must be written");

    // 9. FlushFileBuffers succeeds.
    win32
        .flush_file_buffers(handle)
        .expect("FlushFileBuffers on probe file");

    // 10. Close and reopen; the payload must survive.
    win32.close_handle(handle).expect("CloseHandle probe file");
    let handle = win32
        .create_file_w(
            temp_path,
            FileAccess {
                read: true,
                write: true,
                delete: true,
            },
            ShareMode {
                read: false,
                write: false,
                delete: false,
            },
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        )
        .expect("reopen probe file");
    let read_back = win32
        .read_file(handle, payload.len())
        .expect("read probe file back");
    assert_eq!(read_back, payload, "probe payload must survive close/reopen");

    // 11. MoveFileEx behavior: rename within the package directory.
    win32
        .move_file_ex_w(temp_path, moved_path, false)
        .expect("MoveFileEx probe file");
    win32
        .close_handle(handle)
        .expect("CloseHandle after move");

    // 12. DeleteFile succeeds.
    win32.delete_file_w(moved_path).expect("DeleteFile probe file");

    // 13. The original manifest is byte-for-byte unchanged.
    let final_bytes = read_manifest_via_guest(&mut win32);
    assert_eq!(
        final_bytes, manifest_bytes,
        "manifest must be unchanged by the package writability probe"
    );

    // The probe file must be gone.
    assert!(
        !repo_ge_root()
            .join("drive_c")
            .join("package")
            .join("casa1_probe_moved.tmp")
            .exists(),
        "probe file must be deleted"
    );
}

/// The manifest must be stable content we expect (regression pin on the
/// file itself, so a future Steam package swap is a deliberate change).
#[test]
fn manifest_content_is_stable() {
    let manifest_bytes = read_manifest_from_disk();
    assert_eq!(manifest_bytes.len(), 266, "manifest size must be stable");
    let text = String::from_utf8_lossy(&manifest_bytes);
    assert!(
        text.contains("steam_client_win32") || text.contains("Steam"),
        "manifest must contain Steam package metadata"
    );
}
