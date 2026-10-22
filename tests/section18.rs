#![allow(dead_code, unused_imports)]
use casa1::ge::{GameEnvironment, GeArch};
use casa1::win32::{MemoryProtection, Win32Subsystem};

fn setup_win32(label: &str) -> (tempfile::TempDir, Win32Subsystem) {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let ge = GameEnvironment::create_in(temp_dir.path(), label, GeArch::X86, "win11-23h2")
        .expect("create game environment");
    let win32 = Win32Subsystem::new(ge, false);
    (temp_dir, win32)
}

// ---------------------------------------------------------------------------
// t18_1_named_pipe_server_client_roundtrip
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t18_2_named_pipe_get_info
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t18_3_named_pipe_set_handle_state
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t18_4_named_pipe_peek
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t18_5_named_pipe_disconnect_reconnect
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t18_6_shared_memory_create_map_unmap
// ---------------------------------------------------------------------------

#[test]
fn t18_6_shared_memory_create_map_unmap() {
    let (_tmp, mut win32) = setup_win32("shm-create-map-unmap");

    let prot = MemoryProtection {
        read: true,
        write: true,
        execute: false,
    };

    // Create a named shared memory section
    let (handle, existed) = win32
        .create_file_mapping_w(Some("Local\\TestSection"), 4096, prot, false)
        .expect("create file mapping");
    assert!(!existed, "section should be newly created");

    // Map a view
    let base = win32
        .map_view_of_file(handle, 0, 4096)
        .expect("map view of file");
    assert!(base > 0, "base address should be non-zero");

    // Unmap
    win32.unmap_view_of_file(base).expect("unmap view of file");

    // Re-map same section
    let (handle2, existed2) = win32
        .create_file_mapping_w(Some("Local\\TestSection"), 4096, prot, false)
        .expect("re-open file mapping");
    assert!(
        existed2,
        "re-opening existing section should return existed=true"
    );

    let base2 = win32
        .map_view_of_file(handle2, 0, 4096)
        .expect("re-map view");
    assert!(base2 > 0, "re-map base should be non-zero");

    win32
        .unmap_view_of_file(base2)
        .expect("unmap re-mapped view");
}

// ---------------------------------------------------------------------------
// t18_7_shared_memory_multiple_views
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t18_8_call_named_pipe_roundtrip
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t18_9_pipe_security_descriptor_argument_accepted
// ---------------------------------------------------------------------------

// NOTE: this test verifies what the API surface currently exposes — a pipe created
// with a `security_descriptor` argument is accepted and fully usable. There is no
// query API to read the stored descriptor back, so round-trip verification of the
// descriptor value itself is not possible; if one is added, assert it here.

// ---------------------------------------------------------------------------
// t18_10_anonymous_pipe (CreatePipe equivalent)
// ---------------------------------------------------------------------------
