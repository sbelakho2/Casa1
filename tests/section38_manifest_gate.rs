//! Phase 38 — Steam manifest release gate (deterministic, no emulation).
//!
//! Performs the exact `C:\package` operations Steam performs during boot
//! against the checked-in `steam-live-run-x86` GE:
//!
//! 1. `GetFileAttributesW` on `C:\package\steam_client_win32.installed` succeeds
//!    and reports a plain file (`[]` == FILE_ATTRIBUTE_NORMAL).
//! 2. `CreateFileW` OPEN_EXISTING + read access succeeds (share=3 =
//!    READ|WRITE, matching Steam), including the verbatim `\\?\C:\` path form
//!    Steam actually uses.
//! 3. `GetFileSizeEx` succeeds.
//! 4. `ReadFile` returns exactly the stored bytes.
//! 5. `CloseHandle` succeeds.
//! 6. `GetFileInformationByHandleEx` (FileBasicInfo) succeeds and reports
//!    non-zero creation/access/write FILETIMEs and FILE_ATTRIBUTE_NORMAL.
//! 7. Steam's ACTUAL drive-root writability probe — create→close→delete of
//!    `C:\.crash` — succeeds.
//! 8. The package-directory probe (an EXTENSION: it mirrors the manifest
//!    open/read cycle exactly, then exercises temp-file write/flush/reopen/
//!    move/delete in `C:\package` so Steam's post-install writes, which land
//!    next to the manifest, are pinned too) succeeds.
//! 9. The original manifest remains unchanged, byte-for-byte, and its
//!    content is pinned by an exact FNV-1a 64-bit hash.
//!
//! Negative paths pin Steam's observed failure mode (the manifest open errored
//! at capture): OPEN_EXISTING on a missing file is ERROR_FILE_NOT_FOUND (2)
//! and on a path whose parent is missing is ERROR_PATH_NOT_FOUND (3), via the
//! same mapping the thunks use (`last_error_from_app_error`).
//!
//! Every test restores the checked-in GE on success AND on panic (Drop
//! guard): probe files are removed and ge.json is rewritten from its
//! start-of-test bytes if the fs_state syncs changed it, so the gate leaves
//! `git status` clean.
//!
//! This is the first release gate: it must pass before any Chromium/CEF
//! debugging is attempted. It runs against the exact GE in the repo
//! (`ges/steam-live-run-x86`) and drives the Win32Subsystem directly, so it
//! exposes filesystem-semantics mismatches without executing millions of
//! emulated instructions.

use casa1::error::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION};
use casa1::ge::{FileAccess, GameEnvironment, ShareMode};
use casa1::pe_runtime::last_error_from_app_error;
use casa1::reason::ReasonCode;
use casa1::win32::{CreationDisposition, Win32Subsystem};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

const MANIFEST_GUEST_PATH: &str = r"C:\package\steam_client_win32.installed";
const MANIFEST_VERBATIM_GUEST_PATH: &str = r"\\?\C:\package\steam_client_win32.installed";
const CRASH_PROBE_GUEST_PATH: &str = r"\\?\C:\.crash";

const PROBE_TEMP_GUEST_PATH: &str = r"C:\package\casa1_probe.tmp";
const PROBE_MOVED_GUEST_PATH: &str = r"C:\package\casa1_probe_moved.tmp";
const PROBE_DELETE_SHARE_GUEST_PATH: &str = r"\\?\C:\package\casa1_probe_delete_share.tmp";

/// The checked-in GE records `\\?\C:\.crash` fs_state keys, so Steam's real
/// drive-root probe uses the verbatim form; the plain form resolves to the
/// same file.
const PROBE_FILE_NAMES: [&str; 3] = [
    "casa1_probe.tmp",
    "casa1_probe_moved.tmp",
    "casa1_probe_delete_share.tmp",
];

/// FNV-1a 64-bit hash of the pinned manifest content (see
/// `manifest_content_is_stable`). Computed over the exact 266 bytes of
/// `ges/steam-live-run-x86/drive_c/package/steam_client_win32.installed`.
const MANIFEST_FNV1A64: u64 = 0x83bd_d251_bab3_6b69;

/// Serializes the gate tests: they share one checked-in GE (ge.json is
/// rewritten by fs_state syncs and share state lives in the GE's
/// fs_runtime.json), so a concurrent test could observe or corrupt another
/// test's mid-cycle state.
static GATE_SERIAL: Mutex<()> = Mutex::new(());

fn repo_ge_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("ges")
        .join("steam-live-run-x86")
}

/// Builds a `Win32Subsystem` over the checked-in GE and a `GateCleanup` guard
/// that restores the GE after the test, even on panic. The guard is returned
/// first so it drops LAST (after the subsystem), guaranteeing the restore is
/// the final touch on the GE.
fn setup() -> (GateCleanup, Win32Subsystem) {
    let serial = GATE_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = repo_ge_root();
    assert!(
        root.join("ge.json").is_file(),
        "steam-live-run-x86 GE missing at {}",
        root.display()
    );

    // Pre-assert the probe paths are absent: a previous failed run that left
    // files behind must fail loudly instead of silently reusing them.
    let package_dir = root.join("drive_c").join("package");
    for name in PROBE_FILE_NAMES {
        let probe = package_dir.join(name);
        assert!(
            !probe.exists(),
            "stale probe file {} must not exist before the gate runs",
            probe.display()
        );
    }
    let crash_file = root.join("drive_c").join(".crash");
    assert!(
        crash_file.is_file(),
        "tracked C:\\.crash probe target missing at {}",
        crash_file.display()
    );

    let ge_json_snapshot =
        std::fs::read(root.join("ge.json")).expect("snapshot ge.json before the gate runs");
    let crash_snapshot =
        std::fs::read(&crash_file).expect("snapshot C:\\.crash before the gate runs");
    let cleanup = GateCleanup {
        _serial: serial,
        ge_root: root.clone(),
        ge_json_snapshot,
        crash_snapshot,
    };

    let ge = GameEnvironment::from_root(root).expect("open steam-live-run-x86 GE");
    let win32 = Win32Subsystem::new(ge, false);
    (cleanup, win32)
}

/// Restores the checked-in GE when the test finishes (success or panic):
/// removes any `casa1_probe*` files, recreates the tracked `C:\.crash`
/// target if the probe deleted it, and rewrites ge.json from its start-of-test
/// bytes when the win32 fs_state syncs changed it.
struct GateCleanup {
    _serial: MutexGuard<'static, ()>,
    ge_root: PathBuf,
    ge_json_snapshot: Vec<u8>,
    crash_snapshot: Vec<u8>,
}

impl Drop for GateCleanup {
    fn drop(&mut self) {
        let package_dir = self.ge_root.join("drive_c").join("package");
        if let Ok(entries) = std::fs::read_dir(&package_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().starts_with("casa1_probe") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        let crash_file = self.ge_root.join("drive_c").join(".crash");
        if !crash_file.is_file() {
            let _ = std::fs::write(&crash_file, &self.crash_snapshot);
        }
        let ge_json_path = self.ge_root.join("ge.json");
        if std::fs::read(&ge_json_path).ok().as_deref() != Some(self.ge_json_snapshot.as_slice()) {
            let _ = std::fs::write(&ge_json_path, &self.ge_json_snapshot);
        }
    }
}

fn read_manifest_from_disk() -> Vec<u8> {
    std::fs::read(
        repo_ge_root()
            .join("drive_c")
            .join("package")
            .join("steam_client_win32.installed"),
    )
    .expect("read manifest from the GE on disk")
}

/// The manifest read cycle exactly as Steam performs it: OPEN_EXISTING with
/// read access and share=3 (FILE_SHARE_READ|FILE_SHARE_WRITE, no
/// FILE_SHARE_DELETE), GetFileSizeEx, ReadFile, CloseHandle.
fn read_manifest_via_guest(win32: &mut Win32Subsystem, path: &str) -> Vec<u8> {
    let handle = win32
        .create_file_w(
            path,
            FileAccess {
                read: true,
                write: false,
                delete: false,
            },
            ShareMode {
                read: true,
                write: true,
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

/// FNV-1a 64-bit hash (offset basis 0xcbf29ce484222325, prime
/// 0x100000001b3) — dependency-free content pin for the manifest.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

/// Steps 1–5: the manifest must open, size correctly, and read back
/// byte-for-byte identically to the file on disk.
#[test]
fn manifest_open_read_verify_gate() {
    let (_cleanup, mut win32) = setup();
    let manifest_bytes = read_manifest_from_disk();
    assert!(
        manifest_bytes.len() >= 64,
        "manifest looks truncated ({} bytes)",
        manifest_bytes.len()
    );

    // 1. GetFileAttributesW succeeds and reports a plain file. An empty
    // attribute list is the internal representation of FILE_ATTRIBUTE_NORMAL
    // (0x80); the thunk converts [] to FILE_ATTRIBUTE_NORMAL, which is
    // exactly what Windows returns for an existing plain file (never 0).
    let attrs = win32
        .get_file_attributes_w(MANIFEST_GUEST_PATH)
        .expect("GetFileAttributesW on manifest");
    assert!(
        attrs.is_empty(),
        "manifest must be a plain file: [] == FILE_ATTRIBUTE_NORMAL, got: {attrs:?}"
    );

    // 2–5. Open (share=3) / size / read / close.
    let guest_bytes = read_manifest_via_guest(&mut win32, MANIFEST_GUEST_PATH);
    assert_eq!(
        guest_bytes, manifest_bytes,
        "manifest bytes read through the guest must match the file on disk exactly"
    );
}

/// Steps 6: `GetFileInformationByHandleEx` (FileInformationClass 0 =
/// FileBasicInfo) on the open manifest must report real metadata — the
/// boot-sequence API Steam's bootstrap uses for `bootstrap_log` metadata.
#[test]
fn manifest_file_information_gate() {
    let (_cleanup, mut win32) = setup();
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
                write: true,
                delete: false,
            },
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        )
        .expect("CreateFileW OPEN_EXISTING manifest");

    let info = win32
        .get_file_information_by_handle_ex(handle)
        .expect("GetFileInformationByHandleEx FileBasicInfo");
    assert!(!info.is_directory, "manifest must not be a directory");
    assert_eq!(info.size, 266, "manifest size via FileBasicInfo");
    // [] is the internal representation of FILE_ATTRIBUTE_NORMAL (0x80).
    assert!(
        info.attributes.is_empty(),
        "manifest FileBasicInfo attributes must be FILE_ATTRIBUTE_NORMAL, got: {:?}",
        info.attributes
    );
    // Windows never reports zero FILETIMEs for a real file; a zero here
    // means the fs_state record leaked a zero tick into the guest.
    assert_ne!(
        info.creation_time_ticks, 0,
        "FileBasicInfo creation time must be non-zero"
    );
    assert_ne!(
        info.last_access_time_ticks, 0,
        "FileBasicInfo last-access time must be non-zero"
    );
    assert_ne!(
        info.last_write_time_ticks, 0,
        "FileBasicInfo last-write time must be non-zero"
    );

    win32.close_handle(handle).expect("CloseHandle manifest");
}

/// Steam's observed failure mode (the manifest open errored at capture)
/// pinned as negative paths: missing file and missing parent must map to the
/// exact Win32 error codes the thunks record via `last_error_from_app_error`.
#[test]
fn manifest_negative_paths_gate() {
    let (_cleanup, mut win32) = setup();
    let missing_file = r"C:\package\casa1_gate_missing_file.tmp";
    let missing_parent = r"C:\casa1_gate_nonexistent_dir\probe.tmp";

    let open_existing = |win32: &mut Win32Subsystem, path: &str| {
        win32.create_file_w(
            path,
            FileAccess {
                read: true,
                write: false,
                delete: false,
            },
            ShareMode {
                read: true,
                write: true,
                delete: false,
            },
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        )
    };

    // (a) OPEN_EXISTING on a nonexistent file inside a present parent →
    // ERROR_FILE_NOT_FOUND (2) via the thunk's mapping.
    let err = open_existing(&mut win32, missing_file)
        .expect_err("OPEN_EXISTING on a missing file must fail");
    assert_eq!(
        err.code,
        ReasonCode::RcFsNotFound,
        "missing file must surface RcFsNotFound, got: {}",
        err
    );
    assert_eq!(
        last_error_from_app_error(&err),
        ERROR_FILE_NOT_FOUND,
        "missing file must map to ERROR_FILE_NOT_FOUND"
    );

    // (b) OPEN_EXISTING on a path whose PARENT is missing →
    // ERROR_PATH_NOT_FOUND (3).
    let err = open_existing(&mut win32, missing_parent)
        .expect_err("OPEN_EXISTING with a missing parent must fail");
    assert_eq!(
        err.code,
        ReasonCode::RcFsPathInvalid,
        "missing parent must surface RcFsPathInvalid, got: {}",
        err
    );
    assert_eq!(
        last_error_from_app_error(&err),
        ERROR_PATH_NOT_FOUND,
        "missing parent must map to ERROR_PATH_NOT_FOUND"
    );

    // (c) GetFileAttributesW on a missing file → ERROR_FILE_NOT_FOUND (2).
    let err = win32
        .get_file_attributes_w(missing_file)
        .expect_err("GetFileAttributesW on a missing file must fail");
    assert_eq!(
        err.code,
        ReasonCode::RcFsNotFound,
        "GetFileAttributesW on a missing file must surface RcFsNotFound, got: {}",
        err
    );
    assert_eq!(
        last_error_from_app_error(&err),
        ERROR_FILE_NOT_FOUND,
        "GetFileAttributesW on a missing file must map to ERROR_FILE_NOT_FOUND"
    );
}

/// The verbatim `\\?\C:\` path form (the form Steam actually uses): the
/// verbatim open must resolve to the SAME file with identical bytes, share
/// state must participate (its key space is unified with the plain path), and
/// DELETE-sharing semantics must hold.
#[test]
fn verbatim_manifest_read_gate() {
    let (_cleanup, mut win32) = setup();
    let manifest_bytes = read_manifest_from_disk();

    // Verbatim read cycle: identical bytes to the plain-path cycle.
    let guest_bytes = read_manifest_via_guest(&mut win32, MANIFEST_VERBATIM_GUEST_PATH);
    assert_eq!(
        guest_bytes, manifest_bytes,
        "verbatim \\\\?\\ read must match the disk bytes exactly"
    );

    // While the verbatim handle is open with share=3, a second VERBATIM open
    // with a write access mask and share=0 must fail with
    // ERROR_SHARING_VIOLATION.
    let handle = win32
        .create_file_w(
            MANIFEST_VERBATIM_GUEST_PATH,
            FileAccess {
                read: true,
                write: false,
                delete: false,
            },
            ShareMode {
                read: true,
                write: true,
                delete: false,
            },
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        )
        .expect("verbatim CreateFileW OPEN_EXISTING manifest");
    let conflicting = win32.create_file_w(
        MANIFEST_VERBATIM_GUEST_PATH,
        FileAccess {
            read: false,
            write: true,
            delete: false,
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
    );
    let err = conflicting.expect_err("verbatim open with conflicting share must fail");
    assert_eq!(
        err.code,
        ReasonCode::RcFsSharingViolation,
        "verbatim share conflict must surface RcFsSharingViolation, got: {}",
        err
    );
    assert_eq!(
        last_error_from_app_error(&err),
        ERROR_SHARING_VIOLATION,
        "verbatim share conflict must map to ERROR_SHARING_VIOLATION"
    );

    // The verbatim key space is UNIFIED with the plain path key space: a
    // PLAIN-path open with the same conflicting share must also fail against
    // the verbatim handle (the same file on Windows).
    let cross_form = win32.create_file_w(
        MANIFEST_GUEST_PATH,
        FileAccess {
            read: false,
            write: true,
            delete: false,
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
    );
    let err = cross_form
        .expect_err("plain-path open must conflict with the verbatim handle's share state");
    assert_eq!(
        err.code,
        ReasonCode::RcFsSharingViolation,
        "cross-form share conflict must surface RcFsSharingViolation, got: {}",
        err
    );
    win32
        .close_handle(handle)
        .expect("CloseHandle verbatim manifest");

    // DELETE-sharing semantics in the verbatim key space (on a probe file,
    // never the checked-in manifest): DeleteFileW is refused while a handle
    // without FILE_SHARE_DELETE is open, and succeeds once a handle shares
    // delete access.
    let probe_handle = win32
        .create_file_w(
            PROBE_DELETE_SHARE_GUEST_PATH,
            FileAccess {
                read: false,
                write: true,
                delete: false,
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
        .expect("CreateFileW CREATE_ALWAYS verbatim delete-share probe");
    win32
        .close_handle(probe_handle)
        .expect("CloseHandle verbatim probe after create");

    let open_probe = |win32: &mut Win32Subsystem, share_delete: bool| {
        win32.create_file_w(
            PROBE_DELETE_SHARE_GUEST_PATH,
            FileAccess {
                read: true,
                write: false,
                delete: false,
            },
            ShareMode {
                read: true,
                write: true,
                delete: share_delete,
            },
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        )
    };

    let probe_handle = open_probe(&mut win32, false).expect("reopen verbatim delete-share probe");
    let err = win32
        .delete_file_w(PROBE_DELETE_SHARE_GUEST_PATH)
        .expect_err("DeleteFileW must fail while the probe is open without FILE_SHARE_DELETE");
    assert_eq!(
        err.code,
        ReasonCode::RcFsSharingViolation,
        "delete without FILE_SHARE_DELETE must surface RcFsSharingViolation, got: {}",
        err
    );
    assert_eq!(
        last_error_from_app_error(&err),
        ERROR_SHARING_VIOLATION,
        "delete without FILE_SHARE_DELETE must map to ERROR_SHARING_VIOLATION"
    );
    win32
        .close_handle(probe_handle)
        .expect("CloseHandle verbatim delete-share probe");

    let probe_handle = open_probe(&mut win32, true).expect("reopen with FILE_SHARE_DELETE");
    win32
        .delete_file_w(PROBE_DELETE_SHARE_GUEST_PATH)
        .expect("DeleteFileW must succeed once FILE_SHARE_DELETE is shared");
    win32
        .close_handle(probe_handle)
        .expect("CloseHandle verbatim delete-share probe");
    let err = win32
        .get_file_attributes_w(PROBE_DELETE_SHARE_GUEST_PATH)
        .expect_err("verbatim delete-share probe must be gone after DeleteFileW");
    assert_eq!(
        err.code,
        ReasonCode::RcFsNotFound,
        "deleted probe must surface RcFsNotFound, got: {}",
        err
    );
}

/// Share-mode fidelity: the manifest read-cycle open uses Steam's share=3
/// (READ|WRITE, no DELETE), and while it is open a second open with a write
/// access mask and share=0 fails with ERROR_SHARING_VIOLATION.
#[test]
fn manifest_share_mode_gate() {
    let (_cleanup, mut win32) = setup();
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
                write: true,
                delete: false,
            },
            CreationDisposition::OpenExisting,
            false,
            false,
            false,
        )
        .expect("manifest open with Steam share=3");

    let conflicting = win32.create_file_w(
        MANIFEST_GUEST_PATH,
        FileAccess {
            read: false,
            write: true,
            delete: false,
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
    );
    let err = conflicting
        .expect_err("write-access open with share=0 must conflict with the share=3 handle");
    assert_eq!(
        err.code,
        ReasonCode::RcFsSharingViolation,
        "share conflict must surface RcFsSharingViolation, got: {}",
        err
    );
    assert_eq!(
        last_error_from_app_error(&err),
        ERROR_SHARING_VIOLATION,
        "share conflict must map to ERROR_SHARING_VIOLATION"
    );

    win32.close_handle(handle).expect("CloseHandle manifest");
}

/// The package-directory probe — an EXTENSION of Steam's real writability
/// probe (see `crash_probe_gate`): it mirrors the manifest open/read cycle
/// exactly, then exercises the same writability sequence in `C:\package`
/// (temp file create/write/flush/reopen/move/delete), where Steam's
/// post-install writes land. The manifest must remain untouched.
#[test]
fn package_writability_probe_gate() {
    let (_cleanup, mut win32) = setup();
    let manifest_bytes = read_manifest_from_disk();

    let temp_path = PROBE_TEMP_GUEST_PATH;
    let moved_path = PROBE_MOVED_GUEST_PATH;
    let payload: &[u8] = b"casa1 package writability probe payload\n";

    // Writability probe: CREATE_ALWAYS a temporary file in C:\package.
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

    // WriteFile succeeds and reports the full byte count.
    let written = win32
        .write_file(handle, payload)
        .expect("WriteFile to probe file");
    assert_eq!(
        written as usize,
        payload.len(),
        "full payload must be written"
    );

    // FlushFileBuffers succeeds.
    win32
        .flush_file_buffers(handle)
        .expect("FlushFileBuffers on probe file");

    // Close and reopen; the payload must survive.
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
    assert_eq!(
        read_back, payload,
        "probe payload must survive close/reopen"
    );

    // MoveFileEx behavior: rename within the package directory.  The probe
    // handle is closed first: Windows cannot rename a file held open without
    // FILE_SHARE_DELETE (ERROR_SHARING_VIOLATION).
    win32.close_handle(handle).expect("CloseHandle before move");
    win32
        .move_file_ex_w(temp_path, moved_path, false, false)
        .expect("MoveFileEx probe file");

    // DeleteFile succeeds.
    win32
        .delete_file_w(moved_path)
        .expect("DeleteFile probe file");

    // The original manifest is byte-for-byte unchanged.
    let final_bytes = read_manifest_via_guest(&mut win32, MANIFEST_GUEST_PATH);
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

/// Steam's ACTUAL drive-root writability probe: create `C:\.crash`
/// (CREATE_ALWAYS, GENERIC_WRITE, share=0), close, then DeleteFileW — the
/// exact sequence Steam uses to test that the install drive is writable.
/// The checked-in GE records `\\?\C:\.crash` fs_state keys from the real
/// probe, so the verbatim path form is used.
#[test]
fn crash_probe_gate() {
    let (_cleanup, mut win32) = setup();

    // CREATE_ALWAYS GENERIC_WRITE share=0 on C:\.crash.
    let handle = win32
        .create_file_w(
            CRASH_PROBE_GUEST_PATH,
            FileAccess {
                read: false,
                write: true,
                delete: false,
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
        .expect("CreateFileW CREATE_ALWAYS C:\\.crash (Steam drive-root writability probe)");

    // CloseHandle, then DeleteFileW — both must succeed.
    win32
        .close_handle(handle)
        .expect("CloseHandle C:\\.crash probe");
    win32
        .delete_file_w(CRASH_PROBE_GUEST_PATH)
        .expect("DeleteFileW C:\\.crash probe");

    // The probe target must be gone.
    let err = win32
        .get_file_attributes_w(CRASH_PROBE_GUEST_PATH)
        .expect_err("C:\\.crash must be gone after DeleteFileW");
    assert_eq!(
        err.code,
        ReasonCode::RcFsNotFound,
        "deleted C:\\.crash must surface RcFsNotFound, got: {}",
        err
    );
}

/// The manifest must be the exact content we expect (regression pin on the
/// file itself, so a future Steam package swap is a deliberate change).
#[test]
fn manifest_content_is_stable() {
    let manifest_bytes = read_manifest_from_disk();
    let actual = fnv1a64(&manifest_bytes);
    assert_eq!(
        actual,
        MANIFEST_FNV1A64,
        "steam_client_win32.installed content changed ({} bytes, FNV-1a 64 = {:#018x}). \
         To update the pin: compute fnv1a64() over the new file (e.g. python3: \
         'h=14695981039346656037; [h:=((h^b)*1099511628211)&0xFFFFFFFFFFFFFFFF for b in \
         open(\"ges/steam-live-run-x86/drive_c/package/steam_client_win32.installed\",\"rb\") \
         .read()]; print(hex(h))') and replace MANIFEST_FNV1A64 in \
         tests/section38_manifest_gate.rs — only when the new content is expected.",
        manifest_bytes.len(),
        actual,
    );
}

/// Thunk-level variant of the manifest gate: the manifest open/read/close
/// cycle AND the `C:\.crash` writability probe are driven through the PE
/// host-thunk dispatch layer (`alloc_host_thunk` + the x86 thunk dispatch),
/// not just through `Win32Subsystem` methods.  The same outcomes must hold:
/// the manifest opens, reads back its exact bytes, and the writability probe
/// create/delete succeeds — and the instrumentation hooks record milestone
/// evidence (manifest opened, manifest fully read, writability probe) while
/// the cycle runs.
#[test]
fn manifest_gate_via_host_thunk_dispatch() {
    let (_cleanup, _win32) = setup();
    let ge = GameEnvironment::from_root(repo_ge_root()).expect("open steam-live-run-x86 GE");
    let result = casa1::pe_runtime::thunk_drive_manifest_gate(ge).expect("thunk-level gate");
    assert!(
        result.manifest_open_ok,
        "CreateFileW(OPEN_EXISTING) through the thunk layer must open the manifest",
    );
    assert!(
        result.manifest_read_ok,
        "ReadFile through the thunk layer must succeed",
    );
    assert_eq!(
        result.manifest_bytes,
        read_manifest_from_disk(),
        "manifest bytes read through the thunk layer must match the disk exactly",
    );
    assert!(
        result.probe_create_ok,
        "the C:\\.crash writability probe create must succeed through the thunk layer",
    );
    assert!(
        result.probe_delete_ok,
        "the C:\\.crash writability probe delete must succeed through the thunk layer",
    );
    // The instrumentation hooks saw the same cycle: manifest opened, a full
    // read completed, and the write-open of the probe path was recorded.
    assert!(
        result.milestones.steam.manifest_opened.is_some(),
        "manifest open must be recorded as milestone evidence",
    );
    assert!(
        result.milestones.steam.manifest_full_read.is_some(),
        "manifest full read must be recorded as milestone evidence",
    );
    assert!(
        result.milestones.steam.package_writability_probe.is_some(),
        "the probe write-open must be recorded as writability-probe evidence",
    );
}
