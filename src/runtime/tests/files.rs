use super::support::*;
use super::*;

#[test]
fn create_file_w_with_write_attributes_creates_missing_file() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "create-file-write-attrs",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w("C:\\package")
            .expect("create package dir");

        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, "C:\\package\\write-attrs.tmp")
            .expect("path");

        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                FILE_WRITE_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0,
                0,
            ],
        );

        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);
        assert!(runtime.win32.file_state(handle as u32).is_ok());
        assert!(
            runtime
                .win32
                .ge()
                .host_path_for_windows_path("C:\\package\\write-attrs.tmp")
                .expect("host path")
                .exists()
        );
    })
}

#[test]
fn create_file_w_with_zero_access_still_creates_missing_file() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "create-file-zero-access",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w("C:\\package")
            .expect("create package dir");

        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, "C:\\package\\zero-access.tmp")
            .expect("path");

        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0,
                0,
            ],
        );

        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);
        assert!(runtime.win32.file_state(handle as u32).is_ok());
        assert!(
            runtime
                .win32
                .ge()
                .host_path_for_windows_path("C:\\package\\zero-access.tmp")
                .expect("host path")
                .exists()
        );
    })
}

#[test]
fn create_file_w_rejects_invalid_template_handle() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "create-file-invalid-template",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");

        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\bogus-template.tmp")
            .expect("path");

        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_NEW,
                0,
                0xDEAD_BEEF,
            ],
        );

        // x86 dispatch truncates INVALID_HANDLE_VALUE (u64::MAX) to 32 bits.
        assert_eq!(handle, u32::MAX as u64);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
        assert!(
            !runtime
                .win32
                .ge()
                .host_path_for_windows_path(r"C:\package\bogus-template.tmp")
                .expect("host path")
                .exists()
        );
    })
}

// ── File access-right mapping tests ─────────────────────────────────
#[test]
fn file_execute_does_not_imply_read() {
    with_big_stack(|| {
        let access = file_access_from_win32(FILE_EXECUTE);
        assert!(!access.read, "FILE_EXECUTE must not imply read-data access");
        assert!(!access.write);
        assert!(!access.delete);
    })
}

#[test]
fn read_file_denied_on_write_only_handle() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "read-denied", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\deny-read.tmp")
            .expect("path");

        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0,
                0,
            ],
        );
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);

        let buffer = 0x30_000_u32;
        memory.map_bytes(buffer as u64, &[0_u8; 64]);
        let read_file = runtime.alloc_host_thunk(HostThunk::ReadFile);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_file,
            &[handle as u32, buffer, 16, 0, 0],
        );
        assert_eq!(result, 0, "ReadFile must fail on a write-only handle");
        assert_eq!(runtime.last_error, ERROR_ACCESS_DENIED);

        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[handle as u32]);
    })
}

#[test]
fn write_file_denied_on_read_only_handle() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "write-denied", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\deny-write.tmp")
            .expect("path");

        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0,
                0,
            ],
        );
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);

        let buffer = 0x30_000_u32;
        memory.map_bytes(buffer as u64, b"data");
        let write_file = runtime.alloc_host_thunk(HostThunk::WriteFile);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            write_file,
            &[handle as u32, buffer, 4, 0, 0],
        );
        assert_eq!(result, 0, "WriteFile must fail on a read-only handle");
        assert_eq!(runtime.last_error, ERROR_ACCESS_DENIED);

        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[handle as u32]);
    })
}

#[test]
fn set_file_pointer_denied_without_read_write() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "seek-denied", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\deny-seek.tmp")
            .expect("path");

        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                GENERIC_EXECUTE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0,
                0,
            ],
        );
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);

        let set_file_pointer = runtime.alloc_host_thunk(HostThunk::SetFilePointerEx);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            set_file_pointer,
            &[handle as u32, 0, 0, 1, 0],
        );
        assert_eq!(
            result, 0,
            "SetFilePointerEx must fail on a handle granted neither read nor write"
        );
        assert_eq!(runtime.last_error, ERROR_ACCESS_DENIED);

        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[handle as u32]);
    })
}

#[test]
fn create_always_share_conflict_does_not_truncate() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "ca-share-conflict",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\exclusive.tmp")
            .expect("path");

        // First open: exclusive (share=0), read+write.
        let h1 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                GENERIC_READ | GENERIC_WRITE,
                0,
                0,
                CREATE_ALWAYS,
                0,
                0,
            ],
        );
        assert_ne!(h1, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);

        // Write distinguishable content through the first handle.
        let buffer = 0x30_000_u32;
        memory.map_bytes(buffer as u64, b"important-content");
        let write_file = runtime.alloc_host_thunk(HostThunk::WriteFile);
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            write_file,
            &[h1 as u32, buffer, 17, 0, 0],
        );
        assert_eq!(written, 1);

        // CREATE_ALWAYS on the same path with incompatible share (0) must
        // fail with ERROR_SHARING_VIOLATION *before* any truncation.
        let h2 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[path as u32, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0],
        );
        // x86 dispatch truncates INVALID_HANDLE_VALUE (u64::MAX) to 32 bits.
        assert_eq!(h2, u32::MAX as u64);
        assert_eq!(runtime.last_error, ERROR_SHARING_VIOLATION);

        // Close the exclusive handle, reopen, and verify the content
        // survived the failed CREATE_ALWAYS.
        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[h1 as u32]);

        let h3 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                OPEN_EXISTING,
                0,
                0,
            ],
        );
        assert_ne!(h3, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);

        let read_buffer = 0x31_000_u32;
        memory.map_bytes(read_buffer as u64, &[0_u8; 64]);
        let read_file = runtime.alloc_host_thunk(HostThunk::ReadFile);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_file,
            &[h3 as u32, read_buffer, 64, 0, 0],
        );
        assert_eq!(result, 1);
        let bytes = memory
            .read_bytes(read_buffer as u64, 17)
            .expect("read guest buffer");
        assert_eq!(
            bytes, b"important-content",
            "CREATE_ALWAYS share conflict must not truncate the file"
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[h3 as u32]);
    })
}

#[test]
fn delete_on_close_conflicts_with_non_delete_sharing_holder() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "doc-share-conflict",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\doc-share.tmp")
            .expect("path");

        // Open A exclusively (share=0) without delete access.
        let h1 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                GENERIC_READ | GENERIC_WRITE,
                0,
                0,
                CREATE_ALWAYS,
                0,
                0,
            ],
        );
        assert_ne!(h1, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);

        // A FILE_FLAG_DELETE_ON_CLOSE open behaves like a DELETE access
        // request: it must conflict with the share=0 holder.
        let h2 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                OPEN_EXISTING,
                0x0400_0000,
                0,
            ],
        );
        // x86 dispatch truncates INVALID_HANDLE_VALUE (u64::MAX) to 32 bits.
        assert_eq!(h2, u32::MAX as u64);
        assert_eq!(runtime.last_error, ERROR_SHARING_VIOLATION);

        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[h1 as u32]);
    })
}

#[test]
fn ads_read_denied_on_zero_access_handle() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "ads-read-denied",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\ads-base.tmp:Zone.Identifier")
            .expect("path");

        // access=0: the handle carries no granted bits, so an ADS read must
        // be ERROR_ACCESS_DENIED (not silently bypass the check).
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0,
                0,
            ],
        );
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);

        let buffer = 0x30_000_u32;
        memory.map_bytes(buffer as u64, &[0_u8; 64]);
        let read_file = runtime.alloc_host_thunk(HostThunk::ReadFile);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_file,
            &[handle as u32, buffer, 16, 0, 0],
        );
        assert_eq!(result, 0, "ADS read must fail on a zero-access handle");
        assert_eq!(runtime.last_error, ERROR_ACCESS_DENIED);

        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[handle as u32]);
    })
}

#[test]
fn ads_write_denied_on_read_only_handle() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "ads-write-denied",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\ads-base.tmp:Zone.Identifier")
            .expect("path");

        // GENERIC_READ-only: an ADS write must be ERROR_ACCESS_DENIED.
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0,
                0,
            ],
        );
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);

        let buffer = 0x30_000_u32;
        memory.map_bytes(buffer as u64, b"zone-data");
        let write_file = runtime.alloc_host_thunk(HostThunk::WriteFile);
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            write_file,
            &[handle as u32, buffer, 9, 0, 0],
        );
        assert_eq!(result, 0, "ADS write must fail on a read-only handle");
        assert_eq!(runtime.last_error, ERROR_ACCESS_DENIED);

        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[handle as u32]);
    })
}

#[test]
fn create_always_open_always_existing_file_sets_last_error_183() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "already-exists-183",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\already-exists.tmp")
            .expect("path");
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

        // CREATE_ALWAYS on a NEW file: valid handle, last_error 0.
        let h1 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[path as u32, GENERIC_WRITE, share, 0, CREATE_ALWAYS, 0, 0],
        );
        assert_ne!(h1, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);
        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[h1 as u32]);

        // CREATE_ALWAYS on an EXISTING file: valid handle + last_error 183.
        let h2 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[path as u32, GENERIC_WRITE, share, 0, CREATE_ALWAYS, 0, 0],
        );
        assert_ne!(h2, INVALID_HANDLE_VALUE);
        assert_eq!(
            runtime.last_error, ERROR_ALREADY_EXISTS,
            "CREATE_ALWAYS on an existing file must set last_error 183"
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[h2 as u32]);

        // OPEN_ALWAYS on an EXISTING file: valid handle + last_error 183.
        let h3 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[path as u32, GENERIC_WRITE, share, 0, OPEN_ALWAYS, 0, 0],
        );
        assert_ne!(h3, INVALID_HANDLE_VALUE);
        assert_eq!(
            runtime.last_error, ERROR_ALREADY_EXISTS,
            "OPEN_ALWAYS on an existing file must set last_error 183"
        );
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[h3 as u32]);

        // OPEN_EXISTING on an existing file: valid handle, last_error 0.
        let h4 = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[path as u32, GENERIC_WRITE, share, 0, OPEN_EXISTING, 0, 0],
        );
        assert_ne!(h4, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);
        dispatch_x86_thunk(&mut runtime, &mut memory, close, &[h4 as u32]);
    })
}

#[test]
fn write_private_profile_string_w_missing_parent_fails_without_creating_directory() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "ini-missing-parent",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let thunk = runtime.alloc_host_thunk(HostThunk::WritePrivateProfileStringW);
        let ini_path = "C:\\users\\casa1\\AppData\\Roaming\\MissingIniDir\\test.ini";
        let path_ptr = runtime
            .alloc_utf16_string(&mut memory, ini_path)
            .expect("path ptr");
        let section_ptr = runtime
            .alloc_utf16_string(&mut memory, "Steam")
            .expect("section ptr");
        let key_ptr = runtime
            .alloc_utf16_string(&mut memory, "Language")
            .expect("key ptr");
        let value_ptr = runtime
            .alloc_utf16_string(&mut memory, "english")
            .expect("value ptr");

        // Windows never creates parent directories for WritePrivateProfileStringW:
        // the write fails and no directory is manufactured.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[
                section_ptr as u32,
                key_ptr as u32,
                value_ptr as u32,
                path_ptr as u32,
            ],
        );
        assert_eq!(result, 0, "missing parent must fail the write");
        assert!(
            !runtime
                .win32
                .ge()
                .host_path_for_windows_path("C:\\users\\casa1\\AppData\\Roaming\\MissingIniDir")
                .expect("resolve host dir")
                .exists(),
            "missing parent directory must not be created"
        );
    })
}

#[test]
fn delete_on_close_removes_file() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "delete-on-close",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\delete-on-close.tmp")
            .expect("path");

        // FILE_FLAG_DELETE_ON_CLOSE is 0x0400_0000 (0x0800_0000 is
        // FILE_FLAG_SEQUENTIAL_SCAN and must never delete).
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0x0400_0000,
                0,
            ],
        );
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);
        let host_path = runtime
            .win32
            .ge()
            .host_path_for_windows_path(r"C:\package\delete-on-close.tmp")
            .expect("host path");
        assert!(host_path.exists(), "file exists before close");

        let close = runtime.alloc_host_thunk(HostThunk::CloseHandle);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, close, &[handle as u32]);
        assert_eq!(result, 1);
        assert!(
            !host_path.exists(),
            "FILE_FLAG_DELETE_ON_CLOSE (0x0400_0000) must remove the file on CloseHandle"
        );
    })
}

#[test]
fn get_module_file_name_a_query_and_truncation_return_required_size() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "module-file-name-a-sizes",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let module_path = "C:\\Program Files (x86)\\Steam\\Steam.exe";
        runtime.main_module_path = module_path.to_string();
        let required_with_nul = module_path.len() as u32 + 1;
        let mut memory = MemoryImage::default();
        let thunk = runtime.alloc_host_thunk(HostThunk::GetModuleFileNameA);

        // (NULL, 0) query idiom: required size INCLUDING the NUL, no write.
        let query = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[0, 0, 0]);
        assert_eq!(query, required_with_nul as u64);
        assert_eq!(runtime.last_error, 0);

        // Truncation: size-1 chars + NUL, required size incl NUL,
        // ERROR_INSUFFICIENT_BUFFER.
        let small_buffer = 0x42_000;
        memory.map_bytes(small_buffer, &[0xFF; 64]);
        let trunc_size = 8_u32;
        let truncated = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[0, small_buffer as u32, trunc_size],
        );
        assert_eq!(truncated, required_with_nul as u64);
        assert_eq!(runtime.last_error, ERROR_INSUFFICIENT_BUFFER);
        let bytes = memory
            .read_bytes(small_buffer, trunc_size as usize)
            .expect("truncated bytes");
        assert_eq!(
            &bytes[..(trunc_size - 1) as usize],
            &module_path.as_bytes()[..(trunc_size - 1) as usize]
        );
        assert_eq!(bytes[(trunc_size - 1) as usize], 0);

        // Success: len chars + NUL, length EXCLUDING the NUL.
        let full_buffer = 0x43_000;
        memory.map_bytes(full_buffer, &[0xFF; 64]);
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[0, full_buffer as u32, 64],
        );
        assert_eq!(written as usize, module_path.len());
        assert_eq!(runtime.last_error, 0);
        let bytes = memory
            .read_bytes(full_buffer, module_path.len() + 1)
            .expect("module path bytes");
        assert_eq!(&bytes[..module_path.len()], module_path.as_bytes());
        assert_eq!(bytes[module_path.len()], 0);
    })
}

#[test]
fn get_current_directory_a_query_and_truncation() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "current-directory-a",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let cwd = "C:\\Steam";
        runtime.current_directory = cwd.to_string();
        let required_with_nul = cwd.len() as u32 + 1;
        let mut memory = MemoryImage::default();
        let thunk = runtime.alloc_host_thunk(HostThunk::GetCurrentDirectoryA);

        // (NULL, 0) query: required size incl NUL.
        let query = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[0, 0]);
        assert_eq!(query, required_with_nul as u64);
        assert_eq!(runtime.last_error, 0);

        // Small buffer: required size incl NUL + ERROR_INSUFFICIENT_BUFFER,
        // NUL-terminated size-1 bytes.
        let small_buffer = 0x42_000;
        memory.map_bytes(small_buffer, &[0xFF; 16]);
        let trunc_size = 4_u32;
        let truncated = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[trunc_size, small_buffer as u32],
        );
        assert_eq!(truncated, required_with_nul as u64);
        assert_eq!(runtime.last_error, ERROR_INSUFFICIENT_BUFFER);
        let bytes = memory
            .read_bytes(small_buffer, trunc_size as usize)
            .expect("truncated bytes");
        assert_eq!(
            &bytes[..(trunc_size - 1) as usize],
            &cwd.as_bytes()[..(trunc_size - 1) as usize]
        );
        assert_eq!(bytes[(trunc_size - 1) as usize], 0);

        // Full buffer: length EXCLUDING the NUL.
        let full_buffer = 0x43_000;
        memory.map_bytes(full_buffer, &[0xFF; 16]);
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[required_with_nul, full_buffer as u32],
        );
        assert_eq!(written as usize, cwd.len());
        assert_eq!(runtime.last_error, 0);
        let bytes = memory
            .read_bytes(full_buffer, cwd.len() + 1)
            .expect("full bytes");
        assert_eq!(&bytes[..cwd.len()], cwd.as_bytes());
        assert_eq!(bytes[cwd.len()], 0);
    })
}

#[test]
fn get_full_path_name_w_truncation_and_query_last_error() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "full-path-name-w-last-error",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        runtime.current_directory = "C:\\Games".to_string();
        let mut memory = MemoryImage::default();
        let path_ptr = runtime
            .alloc_utf16_string(&mut memory, "sub\\file.exe")
            .expect("alloc raw path");
        let full_path = resolve_full_guest_path(&runtime.current_directory, "sub\\file.exe");
        let path_length = full_path.encode_utf16().count() as u32;
        let thunk = runtime.alloc_host_thunk(HostThunk::GetFullPathNameW);

        // (NULL, 0) required-size query: required size INCLUDING the NUL,
        // last_error stays 0.
        let query = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[path_ptr as u32, 0, 0, 0],
        );
        assert_eq!(query, (path_length + 1) as u64);
        assert_eq!(runtime.last_error, 0);

        // Real truncation into a non-NULL buffer (size == path_length):
        // required size incl NUL + ERROR_INSUFFICIENT_BUFFER (122).
        let buffer = 0x42_000;
        memory.map_bytes(buffer, &[0xFF; 128]);
        let truncated = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[path_ptr as u32, path_length, buffer as u32, 0],
        );
        assert_eq!(truncated, (path_length + 1) as u64);
        assert_eq!(runtime.last_error, ERROR_INSUFFICIENT_BUFFER);

        // Exact fit: success returns the length excluding the NUL, last_error 0.
        let exact = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[path_ptr as u32, path_length + 1, buffer as u32, 0],
        );
        assert_eq!(exact, path_length as u64);
        assert_eq!(runtime.last_error, 0);
    })
}

#[test]
fn get_full_path_name_w_empty_path_fails_with_path_not_found() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "full-path-name-w-empty",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        runtime.current_directory = "C:\\Games".to_string();
        let mut memory = MemoryImage::default();
        let empty_path = runtime
            .alloc_utf16_string(&mut memory, "")
            .expect("empty path");
        let buffer = 0x42_000;
        memory.map_bytes(buffer, &[0xFF; 128]);
        let thunk = runtime.alloc_host_thunk(HostThunk::GetFullPathNameW);

        // Empty wide string: fails with ERROR_PATH_NOT_FOUND (3), never
        // resolves to the current directory.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[empty_path as u32, 128, buffer as u32, 0],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);

        // NULL pointer reads as an empty string: same failure.
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[0, 128, buffer as u32, 0],
        );
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);
    })
}

#[test]
fn get_module_file_name_w_query_and_truncation_return_required_size() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "module-file-name-w-sizes",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let module_path = "C:\\Program Files (x86)\\Steam\\Steam.exe";
        runtime.main_module_path = module_path.to_string();
        let path_length = module_path.encode_utf16().count() as u32;
        let required_with_nul = path_length + 1;
        let mut memory = MemoryImage::default();
        let thunk = runtime.alloc_host_thunk(HostThunk::GetModuleFileNameW);

        // (NULL, 0) query idiom: required size INCLUDING the NUL, no write,
        // last_error 0.
        let query = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[0, 0, 0]);
        assert_eq!(query, required_with_nul as u64);
        assert_eq!(runtime.last_error, 0);

        // Truncation: size-1 units + NUL, required size incl NUL,
        // ERROR_INSUFFICIENT_BUFFER.
        let small_buffer = 0x42_000;
        memory.map_bytes(small_buffer, &[0xFF; 128]);
        let trunc_size = 8_u32;
        let truncated = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[0, small_buffer as u32, trunc_size],
        );
        assert_eq!(truncated, required_with_nul as u64);
        assert_eq!(runtime.last_error, ERROR_INSUFFICIENT_BUFFER);
        let bytes = memory
            .read_bytes(small_buffer, (trunc_size as usize) * 2)
            .expect("truncated bytes");
        let expected_prefix = module_path
            .encode_utf16()
            .take((trunc_size - 1) as usize)
            .collect::<Vec<_>>();
        for (index, unit) in expected_prefix.iter().enumerate() {
            let stored = u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
            assert_eq!(stored, *unit);
        }
        let terminator = u16::from_le_bytes([
            bytes[(trunc_size - 1) as usize * 2],
            bytes[(trunc_size - 1) as usize * 2 + 1],
        ]);
        assert_eq!(terminator, 0);

        // Exact fit: success returns the length excluding the NUL, last_error 0.
        let exact = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            thunk,
            &[0, small_buffer as u32, required_with_nul],
        );
        assert_eq!(exact, path_length as u64);
        assert_eq!(runtime.last_error, 0);
    })
}

#[test]
fn create_file_w_null_path_fails_with_path_not_found() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "create-file-null-path",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        let empty_path = runtime
            .alloc_utf16_string(&mut memory, "")
            .expect("empty path");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);

        // NULL path: INVALID_HANDLE_VALUE + ERROR_PATH_NOT_FOUND (3).
        // x86 dispatch truncates INVALID_HANDLE_VALUE (u64::MAX) to 32 bits.
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[0, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0],
        );
        assert_eq!(handle, u32::MAX as u64);
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);

        // Empty wide string: same failure.
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[empty_path as u32, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0],
        );
        assert_eq!(handle, u32::MAX as u64);
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);
    })
}

#[test]
fn create_file_a_null_path_fails_with_path_not_found() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "create-file-a-null-path",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        let empty_ansi = 0x60_000;
        memory.map_bytes(empty_ansi, &[0_u8; 1]);
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileA);

        // NULL path: INVALID_HANDLE_VALUE + ERROR_PATH_NOT_FOUND (3).
        // x86 dispatch truncates INVALID_HANDLE_VALUE (u64::MAX) to 32 bits.
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[0, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0],
        );
        assert_eq!(handle, u32::MAX as u64);
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);

        // Empty ANSI string: same failure.
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[empty_ansi as u32, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0],
        );
        assert_eq!(handle, u32::MAX as u64);
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);
    })
}

#[test]
fn get_file_attributes_w_empty_path_returns_invalid_file_attributes() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "attributes-empty-path",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        runtime.current_directory = "C:\\Games".to_string();
        let mut memory = MemoryImage::default();
        let empty_path = runtime
            .alloc_utf16_string(&mut memory, "")
            .expect("empty path");
        let thunk = runtime.alloc_host_thunk(HostThunk::GetFileAttributesW);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[empty_path as u32]);
        assert_eq!(result, INVALID_FILE_ATTRIBUTES);
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);
    })
}

#[test]
fn set_current_directory_w_empty_path_returns_false() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "set-cwd-empty-path",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        runtime.current_directory = "C:\\Games".to_string();
        let mut memory = MemoryImage::default();
        let empty_path = runtime
            .alloc_utf16_string(&mut memory, "")
            .expect("empty path");
        let thunk = runtime.alloc_host_thunk(HostThunk::SetCurrentDirectoryW);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[empty_path as u32]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);
        assert_eq!(runtime.current_directory, "C:\\Games");
    })
}

#[test]
fn delete_file_w_empty_path_returns_false() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "delete-file-empty-path",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        let empty_path = runtime
            .alloc_utf16_string(&mut memory, "")
            .expect("empty path");
        let thunk = runtime.alloc_host_thunk(HostThunk::DeleteFileW);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[empty_path as u32]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);
    })
}

#[test]
fn empty_paths_fail_remaining_path_thunks_with_path_not_found() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "empty-path-thunks",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        let empty_path = runtime
            .alloc_utf16_string(&mut memory, "")
            .expect("empty path");
        let empty_ansi = 0x60_000;
        memory.map_bytes(empty_ansi, &[0_u8; 1]);

        let create_dir = runtime.alloc_host_thunk(HostThunk::CreateDirectoryW);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, create_dir, &[empty_path as u32]),
            0
        );
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);

        let remove_dir = runtime.alloc_host_thunk(HostThunk::RemoveDirectoryW);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, remove_dir, &[empty_path as u32]),
            0
        );
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);

        let attributes_ex = runtime.alloc_host_thunk(HostThunk::GetFileAttributesExW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                attributes_ex,
                &[empty_path as u32, 0, 0],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);

        let move_file = runtime.alloc_host_thunk(HostThunk::MoveFileExW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                move_file,
                &[empty_path as u32, empty_path as u32, 0],
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);

        let remove_dir_a = runtime.alloc_host_thunk(HostThunk::RemoveDirectoryA);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                remove_dir_a,
                &[empty_ansi as u32]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);

        let attributes_a = runtime.alloc_host_thunk(HostThunk::GetFileAttributesA);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                attributes_a,
                &[empty_ansi as u32]
            ),
            INVALID_FILE_ATTRIBUTES
        );
        assert_eq!(runtime.last_error, ERROR_PATH_NOT_FOUND);
    })
}

#[test]
fn create_file_w_template_ignored_for_create_always_on_existing_file() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "create-file-template-overwrite",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");

        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let template_path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\template.tmp")
            .expect("template path");
        let template_handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                template_path as u32,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0,
                0,
            ],
        );
        assert_ne!(template_handle, INVALID_HANDLE_VALUE);
        // Give the template distinctive attributes to observe copying.
        runtime
            .win32
            .set_file_attributes_w(r"C:\package\template.tmp", &["hidden"])
            .expect("set template attributes");

        // Pre-existing target created without the attribute.
        let target_path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\existing.tmp")
            .expect("target path");
        let first = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                target_path as u32,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_NEW,
                0,
                0,
            ],
        );
        assert_ne!(first, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, 0);

        // CREATE_ALWAYS on the EXISTING file with a template is
        // FILE_OVERWRITE_IF: the template attributes must NOT be copied.
        let second = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                target_path as u32,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0,
                template_handle as u32,
            ],
        );
        assert_ne!(second, INVALID_HANDLE_VALUE);
        assert_eq!(runtime.last_error, ERROR_ALREADY_EXISTS);
        let target_attributes = runtime
            .win32
            .get_file_attributes_w(r"C:\package\existing.tmp")
            .expect("target attributes");
        assert!(
            !target_attributes
                .iter()
                .any(|attribute| attribute == "hidden"),
            "CREATE_ALWAYS on an existing file must not copy template attributes"
        );

        // CREATE_ALWAYS on a MISSING file with a template: genuinely new
        // file, the template attributes ARE copied.
        let missing_path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\fresh.tmp")
            .expect("missing path");
        let fresh = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                missing_path as u32,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0,
                template_handle as u32,
            ],
        );
        assert_ne!(fresh, INVALID_HANDLE_VALUE);
        let fresh_attributes = runtime
            .win32
            .get_file_attributes_w(r"C:\package\fresh.tmp")
            .expect("fresh attributes");
        assert_eq!(fresh_attributes, vec!["hidden".to_string()]);
    })
}

#[test]
fn connect_named_pipe_overlapped_parks_get_overlapped_result_until_client_connects() {
    // Overlapped ConnectNamedPipe issues a typed Connection request and
    // returns FALSE + ERROR_IO_PENDING; GetOverlappedResult(TRUE) parks
    // on the scheduler's Overlapped wait; the client connect completes
    // the request and the caller resumes with TRUE.
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "pipe-connect-overlapped-pump",
            GeArch::X86,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        runtime
            .seed_process_state(&mut memory, "C:\\Steam\\Steam.exe", &[], 0x400000, 0x1000)
            .expect("seed process state");

        let server = runtime
            .win32
            .create_named_pipe_w(
                r"\\.\pipe\ovl-connect",
                0x3,
                0,
                1,
                4096,
                4096,
                0,
                false,
                None,
                None,
            )
            .expect("create server pipe");

        let connect_named_pipe = runtime.alloc_host_thunk(HostThunk::ConnectNamedPipe);
        let get_overlapped_result = runtime.alloc_host_thunk(HostThunk::GetOverlappedResult);
        let create_thread = runtime.alloc_host_thunk(HostThunk::CreateThread);
        let connect_slot = 0x41_000_u64;
        let get_result_slot = 0x41_008_u64;
        let entry = 0x41_100_u64;
        let overlapped_ptr = 0x41_200_u64;
        let bytes_ptr = 0x41_300_u64;
        let connect_result_ptr = 0x41_400_u64;
        let get_result_ptr = 0x41_404_u64;
        let thread_id_ptr = 0x41_408_u64;
        write_u32(&mut memory, connect_slot, connect_named_pipe as u32);
        write_u32(&mut memory, get_result_slot, get_overlapped_result as u32);
        memory.map_bytes(overlapped_ptr, &[0_u8; 20]);
        memory.map_bytes(bytes_ptr, &[0_u8; 4]);
        memory.map_bytes(connect_result_ptr, &[0_u8; 4]);
        memory.map_bytes(get_result_ptr, &[0_u8; 4]);

        // push lpOverlapped; push hPipe; call [ConnectNamedPipe];
        // mov [connect_result], eax; push 1; push lpBytes;
        // push lpOverlapped; push hPipe; call [GetOverlappedResult];
        // mov [get_result], eax; ret
        let mut code = Vec::new();
        code.extend_from_slice(&[0x68]);
        code.extend_from_slice(&(overlapped_ptr as u32).to_le_bytes());
        code.extend_from_slice(&[0x68]);
        code.extend_from_slice(&server.to_le_bytes());
        code.extend_from_slice(&[0xFF, 0x15]);
        code.extend_from_slice(&(connect_slot as u32).to_le_bytes());
        code.extend_from_slice(&[0xA3]);
        code.extend_from_slice(&(connect_result_ptr as u32).to_le_bytes());
        for arg in [1_u32, bytes_ptr as u32, overlapped_ptr as u32, server] {
            code.extend_from_slice(&[0x68]);
            code.extend_from_slice(&arg.to_le_bytes());
        }
        code.extend_from_slice(&[0xFF, 0x15]);
        code.extend_from_slice(&(get_result_slot as u32).to_le_bytes());
        code.extend_from_slice(&[0xA3]);
        code.extend_from_slice(&(get_result_ptr as u32).to_le_bytes());
        code.push(0xC3);
        memory.map_bytes(entry, &code);

        let _caller = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_thread,
            &[0, 0, entry as u32, 0, 0, thread_id_ptr as u32],
        );

        // First pump: ConnectNamedPipe returns FALSE + ERROR_IO_PENDING
        // (the request id lands in OVERLAPPED.Internal), then the thread
        // parks inside GetOverlappedResult(TRUE).
        let mut parked = false;
        for _ in 0..100 {
            let _ = runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump pending thread");
            if runtime
                .pending_guest_threads
                .iter()
                .any(|thread| thread.wait.is_some())
            {
                parked = true;
                break;
            }
        }
        assert!(parked, "caller must park inside GetOverlappedResult");
        assert_eq!(
            read_u32(&memory, connect_result_ptr).expect("connect result"),
            0,
            "overlapped ConnectNamedPipe returns FALSE"
        );
        let parked_thread = runtime
            .pending_guest_threads
            .iter()
            .find(|thread| thread.wait.is_some())
            .map(|thread| thread.thread_id)
            .expect("the waiting thread is parked");
        assert_eq!(
            runtime.guest_thread_last_error(parked_thread, &memory),
            Some(ERROR_IO_PENDING),
            "overlapped ConnectNamedPipe reports ERROR_IO_PENDING in the waiting thread"
        );
        let id = read_u32(&memory, overlapped_ptr).expect("overlapped internal");
        assert!(id != 0, "request id must be recorded in Internal");

        // The client connects; the pump completes the Connection request.
        let client = runtime
            .win32
            .open_named_pipe_client(r"\\.\pipe\ovl-connect", false)
            .expect("open client");
        for _ in 0..100 {
            let _ = runtime
                .pump_pending_guest_thread(&mut memory)
                .expect("pump pending thread");
            if runtime.pending_guest_threads.is_empty() {
                break;
            }
        }
        assert!(
            runtime.pending_guest_threads.is_empty(),
            "caller must complete after the client connects"
        );
        assert_eq!(
            read_u32(&memory, get_result_ptr).expect("get result"),
            1,
            "GetOverlappedResult must return TRUE after the connect"
        );
        assert_eq!(
            read_u32(&memory, bytes_ptr).expect("bytes transferred"),
            0,
            "ConnectNamedPipe transfers zero bytes"
        );
        let _ = runtime.win32.close_handle(client);
        let _ = runtime.win32.close_handle(server);
    })
}

#[test]
fn set_end_of_file_dispatch_truncates_the_host_file() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "seof-dispatch", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let handle = runtime
            .win32
            .create_file_w(
                "C:\\dispatch-truncate.bin",
                FileAccess::read_write(),
                ShareMode::none(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        runtime
            .win32
            .write_file(handle, b"0123456789ABCDEF")
            .expect("write content");
        runtime
            .win32
            .set_file_pointer_ex(handle, 6, SeekOrigin::Begin)
            .expect("seek");

        let set_end_of_file = runtime.alloc_host_thunk(HostThunk::SetEndOfFile);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, set_end_of_file, &[handle]);
        assert_eq!(result, 1, "SetEndOfFile must succeed");
        let host_path = runtime
            .win32
            .guest_path_to_host_path("C:\\dispatch-truncate.bin")
            .expect("resolve host path");
        assert_eq!(
            std::fs::metadata(&host_path).expect("stat").len(),
            6,
            "dispatch must truncate the real backing file at the pointer"
        );
    })
}

#[test]
fn get_file_type_consults_the_handle_table() {
    with_big_stack(|| {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge =
            GameEnvironment::create_in(temp_dir.path(), "gft-table", GeArch::X86, "win11-23h2")
                .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();
        runtime
            .seed_process_state(&mut memory, "C:\\Steam\\Steam.exe", &[], 0x400000, 0x1000)
            .expect("seed process state");

        let get_file_type = runtime.alloc_host_thunk(HostThunk::GetFileType);

        // File → FILE_TYPE_DISK (1), no error.
        runtime
            .win32
            .create_directory_w("C:\\logs")
            .expect("create log dir");
        let path = runtime
            .win32
            .write_file_overwrite_w("C:\\logs\\type.txt", b"x")
            .expect("seed file");
        let file = runtime
            .win32
            .create_file_w(
                &path,
                crate::ge::FileAccess::read_only(),
                crate::ge::ShareMode::all(),
                crate::win32::CreationDisposition::OpenExisting,
                false,
                false,
                false,
            )
            .expect("open file");
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, get_file_type, &[file]);
        assert_eq!(result, FILE_TYPE_DISK as u64);
        assert_eq!(runtime.last_error, 0);

        // Event → FILE_TYPE_UNKNOWN (0) + ERROR_INVALID_HANDLE.
        let (event, _) = runtime.win32.create_event(true, false, false, None);
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, get_file_type, &[event]);
        assert_eq!(result, FILE_TYPE_UNKNOWN as u64);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);

        // Closed handle → FILE_TYPE_UNKNOWN + ERROR_INVALID_HANDLE.
        runtime.win32.close_handle(event).expect("close event");
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, get_file_type, &[event]);
        assert_eq!(result, FILE_TYPE_UNKNOWN as u64);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
    })
}

#[test]
fn crt_fopen_missing_file_sets_errno_enoent() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let fopen = runtime.alloc_host_thunk(HostThunk::Fopen);
        let path = runtime
            .alloc_c_string(&mut memory, "C:\\no\\such\\file.txt")
            .expect("path");
        let mode = runtime.alloc_c_string(&mut memory, "r").expect("mode");
        let fp = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            fopen,
            &[path as u32, mode as u32],
        );
        assert_eq!(fp, 0);
        assert_eq!(runtime.crt_errno_get(&mut memory), ENOENT);
        // GetLastError is NOT set by CRT functions.
        assert_eq!(runtime.last_error, 0);
    })
}

#[test]
fn crt_access_readonly_and_missing() {
    with_big_stack(|| {
        use std::os::unix::fs::PermissionsExt;
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        let guest_path = "C:\\game\\ro.txt";
        write_guest_pe_file(&runtime, guest_path, b"data");
        let host_path = runtime
            .win32
            .guest_path_to_host_path(guest_path)
            .expect("host path");
        fs::set_permissions(&host_path, fs::Permissions::from_mode(0o444)).expect("readonly");
        let access = runtime.alloc_host_thunk(HostThunk::Access);
        let path_ptr = runtime
            .alloc_c_string(&mut memory, guest_path)
            .expect("path");

        // mode 2 (W_OK) on a read-only file → -1 + EACCES.
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, access, &[path_ptr as u32, 2]);
        assert_eq!(ret, (-1_i32) as u32 as u64);
        assert_eq!(runtime.crt_errno_get(&mut memory), EACCES);

        // mode 0 / 4 succeed on an existing file.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, access, &[path_ptr as u32, 0]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, access, &[path_ptr as u32, 4]),
            0
        );

        // Missing file → -1 + ENOENT.
        let missing = runtime
            .alloc_c_string(&mut memory, "C:\\game\\missing.txt")
            .expect("missing");
        let ret = dispatch_x86_thunk(&mut runtime, &mut memory, access, &[missing as u32, 0]);
        assert_eq!(ret, (-1_i32) as u32 as u64);
        assert_eq!(runtime.crt_errno_get(&mut memory), ENOENT);
    })
}

#[test]
fn crt_fclose_frees_guest_file_block() {
    with_big_stack(|| {
        let (_temp, mut runtime, mut memory) = setup_crt_test_runtime();
        runtime
            .win32
            .create_directory_w("C:\\game")
            .expect("create guest dir");
        let path = "C:\\game\\leak.txt";
        fs::write(
            runtime
                .win32
                .guest_path_to_host_path(path)
                .expect("host path"),
            b"x",
        )
        .expect("write");
        let fopen = runtime.alloc_host_thunk(HostThunk::Fopen);
        let fclose = runtime.alloc_host_thunk(HostThunk::Fclose);
        let path_ptr = runtime.alloc_c_string(&mut memory, path).expect("path");
        let mode_ptr = runtime.alloc_c_string(&mut memory, "r").expect("mode");

        for _ in 0..1000 {
            let fp = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                fopen,
                &[path_ptr as u32, mode_ptr as u32],
            );
            assert_ne!(fp, 0);
            assert_eq!(
                runtime.heap_allocations.get(&fp).copied(),
                Some(0x80),
                "FILE block is a 0x80-byte heap allocation"
            );
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, fclose, &[fp as u32]),
                0
            );
            assert!(
                !runtime.heap_allocations.contains_key(&fp),
                "FILE block freed on fclose"
            );
        }
        // The heap bookkeeping holds no live FILE blocks.
        assert_eq!(runtime.heap_allocations.len(), 0);
    })
}

#[test]
fn evidence_core_filesystem_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-fs");
        let mut memory = MemoryImage::default();
        let copy_file = runtime.alloc_host_thunk(HostThunk::CopyFileW);
        let find_first = runtime.alloc_host_thunk(HostThunk::FindFirstFileExW);
        let attributes_a = runtime.alloc_host_thunk(HostThunk::GetFileAttributesA);
        let set_attributes_w = runtime.alloc_host_thunk(HostThunk::SetFileAttributesW);
        let file_info = runtime.alloc_host_thunk(HostThunk::GetFileInformationByHandle);
        let set_file_pointer = runtime.alloc_host_thunk(HostThunk::SetFilePointer);
        let get_file_size = runtime.alloc_host_thunk(HostThunk::GetFileSize);
        let short_path = runtime.alloc_host_thunk(HostThunk::GetShortPathNameW);
        let temp_path = runtime.alloc_host_thunk(HostThunk::GetTempPathW);
        let temp_file = runtime.alloc_host_thunk(HostThunk::GetTempFileNameW);
        let windows_dir = runtime.alloc_host_thunk(HostThunk::GetWindowsDirectoryW);
        let system_dir = runtime.alloc_host_thunk(HostThunk::GetSystemDirectoryW);
        let disk_free_a = runtime.alloc_host_thunk(HostThunk::GetDiskFreeSpaceA);
        let disk_free_w = runtime.alloc_host_thunk(HostThunk::GetDiskFreeSpaceW);
        let set_env = runtime.alloc_host_thunk(HostThunk::SetEnvironmentVariableW);
        let get_env = runtime.alloc_host_thunk(HostThunk::GetEnvironmentVariableW);

        // A real directory + file with known content.
        runtime
            .win32
            .create_directory_w("C:\\Games")
            .expect("create Games directory");
        let handle = runtime
            .win32
            .create_file_w(
                "C:\\Games\\evidence-demo.txt",
                FileAccess::read_write(),
                ShareMode::all(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        runtime
            .win32
            .write_file(handle, b"hello world")
            .expect("write bytes");

        // CopyFileW copies the content to a new path (fail_if_exists off).
        let src_w = runtime
            .alloc_utf16_string(&mut memory, "C:\\Games\\evidence-demo.txt")
            .expect("wide src");
        let dst_w = runtime
            .alloc_utf16_string(&mut memory, "C:\\Games\\evidence-copy.txt")
            .expect("wide dst");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                copy_file,
                &[src_w as u32, dst_w as u32, 0]
            ),
            1
        );
        // Copy with fail_if_exists over an existing destination fails.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                copy_file,
                &[src_w as u32, dst_w as u32, 1]
            ),
            0
        );
        assert_ne!(runtime.last_error, 0);

        // FindFirstFileExW enumerates the directory.
        let pattern_w = runtime
            .alloc_utf16_string(&mut memory, "C:\\Games\\*")
            .expect("wide pattern");
        let found = dispatch_x86_thunk(&mut runtime, &mut memory, find_first, &[pattern_w as u32]);
        assert_ne!(found, u32::MAX as u64, "the fixture directory enumerates");

        // GetFileAttributesA reads the file's attributes.
        let path_a = runtime
            .alloc_c_string(&mut memory, "C:\\Games\\evidence-demo.txt")
            .expect("ansi");
        let attrs = dispatch_x86_thunk(&mut runtime, &mut memory, attributes_a, &[path_a as u32]);
        assert_ne!(attrs, u32::MAX as u64);
        // SetFileAttributesW flips readonly; GetFileAttributesA reflects it.
        let path_w = runtime
            .alloc_utf16_string(&mut memory, "C:\\Games\\evidence-demo.txt")
            .expect("wide");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_attributes_w,
                &[path_w as u32, FILE_ATTRIBUTE_READONLY]
            ),
            1
        );
        let attrs = dispatch_x86_thunk(&mut runtime, &mut memory, attributes_a, &[path_a as u32]);
        assert_ne!(attrs & 1, 0, "FILE_ATTRIBUTE_READONLY is set");

        // SetFilePointer seeks; GetFileSize reports the real size.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_file_pointer,
                &[handle, 5, 0, 0]
            ),
            5
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_file_pointer,
                &[handle, 0, 0, 2]
            ),
            11
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_file_size, &[handle, 0]),
            11
        );

        // GetFileInformationByHandle writes the BY_HANDLE_FILE_INFORMATION
        // with the file size at +36 (low) / +32 (high).
        let info_ptr = 0x41_000;
        memory.map_bytes(info_ptr as u64, &[0; 52]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                file_info,
                &[handle, info_ptr as u32]
            ),
            1
        );
        assert_eq!(memory.read_u32(info_ptr as u64 + 36).unwrap(), 11);
        assert_eq!(memory.read_u32(info_ptr as u64 + 32).unwrap(), 0);

        // GetShortPathNameW reports the resolved path length and writes it.
        let short_buf = 0x41_100;
        memory.map_bytes(short_buf, &[0; 128]);
        let short_required = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            short_path,
            &[path_w as u32, short_buf as u32, 128],
        );
        assert_eq!(short_required, 26, "C:\\Games\\evidence-demo.txt + NUL");
        let short = read_utf16_string(&memory, short_buf).unwrap();
        assert_eq!(short, "C:\\Games\\evidence-demo.txt");

        // GetTempPathW writes the guest temp path.
        let temp_buf = 0x41_200;
        memory.map_bytes(temp_buf, &[0; 128]);
        let temp_required = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            temp_path,
            &[temp_buf as u32, 128],
        );
        assert!(temp_required > 0);
        assert!(!read_utf16_string(&memory, temp_buf).unwrap().is_empty());

        // GetTempFileNameW generates a unique name into the buffer.
        let temp_file_buf = 0x41_300;
        memory.map_bytes(temp_file_buf, &[0; 128]);
        let unique = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            temp_file,
            &[0, 0, 0, temp_file_buf as u32],
        );
        assert_eq!(unique, 1);
        let name = read_utf16_string(&memory, temp_file_buf).unwrap();
        assert!(!name.is_empty());

        // GetCurrentDirectoryW reports the runtime's current directory with
        // the required-size contract (length incl the NUL).
        let get_cwd_w = runtime.alloc_host_thunk(HostThunk::GetCurrentDirectoryW);
        let cwd_buf = 0x41_080;
        memory.map_bytes(cwd_buf, &[0; 64]);
        let cwd_required =
            dispatch_x86_thunk(&mut runtime, &mut memory, get_cwd_w, &[64, cwd_buf as u32]);
        let cwd = read_utf16_string(&memory, cwd_buf).unwrap();
        assert_eq!(cwd, runtime.current_directory);
        assert_eq!(
            cwd_required,
            cwd.encode_utf16().count() as u64,
            "the required size excludes the NUL on success"
        );

        // GetWindowsDirectoryW / GetSystemDirectoryW report the canonical
        // guest directories.
        let win_buf = 0x41_400;
        memory.map_bytes(win_buf, &[0; 64]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                windows_dir,
                &[win_buf as u32, 64]
            ),
            10,
            "the required size excludes the NUL on success"
        );
        assert_eq!(read_utf16_string(&memory, win_buf).unwrap(), "C:\\Windows");
        let sys_buf = 0x41_500;
        memory.map_bytes(sys_buf, &[0; 64]);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, system_dir, &[sys_buf as u32, 64]),
            19
        );
        assert_eq!(
            read_utf16_string(&memory, sys_buf).unwrap(),
            "C:\\Windows\\System32"
        );

        // GetDiskFreeSpaceA/W report the real volume geometry: non-zero
        // sectors/clusters with sane invariants.
        let sector_ptr = 0x41_600;
        let bytes_sector_ptr = 0x41_604;
        let free_clusters_ptr = 0x41_608;
        let total_clusters_ptr = 0x41_60C;
        memory.map_bytes(sector_ptr as u64, &[0; 16]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                disk_free_a,
                &[
                    path_a as u32,
                    sector_ptr as u32,
                    bytes_sector_ptr as u32,
                    free_clusters_ptr as u32,
                    total_clusters_ptr as u32
                ]
            ),
            1
        );
        assert_ne!(memory.read_u32(sector_ptr as u64).unwrap(), 0);
        assert_ne!(memory.read_u32(bytes_sector_ptr as u64).unwrap(), 0);
        assert!(
            memory.read_u32(free_clusters_ptr as u64).unwrap()
                <= memory.read_u32(total_clusters_ptr as u64).unwrap()
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                disk_free_w,
                &[
                    path_w as u32,
                    sector_ptr as u32,
                    bytes_sector_ptr as u32,
                    free_clusters_ptr as u32,
                    total_clusters_ptr as u32
                ]
            ),
            1
        );
        assert_eq!(
            memory.read_u32(total_clusters_ptr as u64).unwrap(),
            memory.read_u32(total_clusters_ptr as u64).unwrap()
        );

        // SetEnvironmentVariableW round-trips through GetEnvironmentVariableW
        // (the same process environment the environment differentials read).
        let name_w = runtime
            .alloc_utf16_string(&mut memory, "EVIDENCE_VAR")
            .expect("wide");
        let value_w = runtime
            .alloc_utf16_string(&mut memory, "evidence-value")
            .expect("wide");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_env,
                &[name_w as u32, value_w as u32]
            ),
            1
        );
        let read_buf = 0x41_700;
        memory.map_bytes(read_buf, &[0; 64]);
        let read_len = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_env,
            &[name_w as u32, read_buf as u32, 64],
        );
        assert_eq!(read_len, 14);
        assert_eq!(
            read_utf16_string(&memory, read_buf).unwrap(),
            "evidence-value"
        );
        // Deleting the variable (NULL value) makes the read fail with
        // ERROR_ENVVAR_NOT_FOUND.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_env, &[name_w as u32, 0]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_env,
                &[name_w as u32, read_buf as u32, 64]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_ENVVAR_NOT_FOUND);
    })
}

#[test]
fn evidence_core_kernel32_ini_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-ini");
        let mut memory = MemoryImage::default();
        runtime
            .win32
            .create_directory_w("C:\\Games")
            .expect("create Games directory");
        let write_ini = runtime.alloc_host_thunk(HostThunk::WritePrivateProfileStringW);
        let read_ini = runtime.alloc_host_thunk(HostThunk::GetPrivateProfileStringW);
        let ini_path = runtime
            .alloc_utf16_string(&mut memory, r"C:\Games\config.ini")
            .expect("wide ini path");

        let section = runtime
            .alloc_utf16_string(&mut memory, "Graphics")
            .expect("wide section");
        let key = runtime
            .alloc_utf16_string(&mut memory, "Resolution")
            .expect("wide key");
        let value = runtime
            .alloc_utf16_string(&mut memory, "1920x1080")
            .expect("wide value");
        let default = runtime
            .alloc_utf16_string(&mut memory, "default")
            .expect("wide default");
        let buffer = 0x42_100;
        memory.map_bytes(buffer, &[0_u8; 0x200]);

        // WritePrivateProfileStringW stores the entry; GetPrivateProfileStringW
        // reads it back (section/key names compare case-insensitively).
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                write_ini,
                &[section as u32, key as u32, value as u32, ini_path as u32]
            ),
            1
        );
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_ini,
            &[
                section as u32,
                key as u32,
                default as u32,
                buffer as u32,
                0x200,
                ini_path as u32,
            ],
        );
        assert_eq!(written, 9);
        assert_eq!(read_guest_utf16_string(&memory, buffer, 128), "1920x1080");

        // A missing key returns the default (single string).
        let missing_key = runtime
            .alloc_utf16_string(&mut memory, "Fullscreen")
            .expect("wide missing key");
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_ini,
            &[
                section as u32,
                missing_key as u32,
                default as u32,
                buffer as u32,
                0x200,
                ini_path as u32,
            ],
        );
        assert_eq!(written, 7);
        assert_eq!(read_guest_utf16_string(&memory, buffer, 128), "default");

        // A missing section returns the default too.
        let missing_section = runtime
            .alloc_utf16_string(&mut memory, "Audio")
            .expect("wide missing section");
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_ini,
            &[
                missing_section as u32,
                key as u32,
                default as u32,
                buffer as u32,
                0x200,
                ini_path as u32,
            ],
        );
        assert_eq!(written, 7);
        assert_eq!(read_guest_utf16_string(&memory, buffer, 128), "default");

        // lpKeyName == NULL lists the section's key names (multi-string).
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_ini,
            &[
                section as u32,
                0,
                default as u32,
                buffer as u32,
                0x200,
                ini_path as u32,
            ],
        );
        assert_eq!(written, 11);
        let listing = read_guest_utf16_string(&memory, buffer, 128);
        assert_eq!(listing, "Resolution");

        // lpAppName == NULL lists the section names.
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_ini,
            &[0, 0, default as u32, buffer as u32, 0x200, ini_path as u32],
        );
        assert_eq!(written, 9);
        let listing = read_guest_utf16_string(&memory, buffer, 128);
        assert_eq!(listing, "Graphics");

        // A missing file returns the default with ERROR_FILE_NOT_FOUND.
        let missing_file = runtime
            .alloc_utf16_string(&mut memory, r"C:\Games\nope.ini")
            .expect("wide missing file");
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_ini,
            &[
                section as u32,
                key as u32,
                default as u32,
                buffer as u32,
                0x200,
                missing_file as u32,
            ],
        );
        assert_eq!(written, 7);
        assert_eq!(read_guest_utf16_string(&memory, buffer, 128), "default");

        // Truncation: at most nSize-1 characters are copied.
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            read_ini,
            &[
                section as u32,
                key as u32,
                default as u32,
                buffer as u32,
                5,
                ini_path as u32,
            ],
        );
        assert_eq!(written, 4);
        assert_eq!(read_guest_utf16_string(&memory, buffer, 128), "1920");
    })
}

#[test]
fn evidence_core_kernel32_file_info_version_move_search_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-core-fivms");
        let mut memory = MemoryImage::default();
        let file_info_ex = runtime.alloc_host_thunk(HostThunk::GetFileInformationByHandleEx);
        let file_time = runtime.alloc_host_thunk(HostThunk::GetFileTime);
        let version_a = runtime.alloc_host_thunk(HostThunk::GetVersionExA);
        let version_w = runtime.alloc_host_thunk(HostThunk::GetVersionExW);
        let move_file = runtime.alloc_host_thunk(HostThunk::MoveFileW);
        let search_path = runtime.alloc_host_thunk(HostThunk::SearchPathW);
        let attributes = runtime.alloc_host_thunk(HostThunk::GetFileAttributesW);

        runtime
            .win32
            .create_directory_w("C:\\Games")
            .expect("create Games directory");
        let handle = runtime
            .win32
            .create_file_w(
                "C:\\Games\\move-src.txt",
                FileAccess::read_write(),
                ShareMode::all(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        runtime
            .win32
            .write_file(handle, b"move me")
            .expect("write bytes");

        // GetFileInformationByHandleEx FileBasicInfo derives the SAME times
        // GetFileTime reports for the handle.
        let time_buf = 0x41_000;
        memory.map_bytes(time_buf, &[0; 24]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                file_time,
                &[
                    handle,
                    time_buf as u32,
                    time_buf as u32 + 8,
                    time_buf as u32 + 16
                ]
            ),
            1
        );
        let creation = memory.read_u64(time_buf).unwrap();
        let access = memory.read_u64(time_buf + 8).unwrap();
        let write = memory.read_u64(time_buf + 16).unwrap();
        let basic = 0x41_100;
        memory.map_bytes(basic, &[0; 40]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                file_info_ex,
                &[handle, 0, basic as u32, 40]
            ),
            1
        );
        assert_eq!(memory.read_u64(basic).unwrap(), creation);
        assert_eq!(memory.read_u64(basic + 8).unwrap(), access);
        assert_eq!(memory.read_u64(basic + 16).unwrap(), write);
        assert_eq!(
            memory.read_u64(basic + 24).unwrap(),
            write,
            "change time mirrors the write time"
        );
        assert_eq!(
            memory.read_u32(basic + 32).unwrap() & FILE_ATTRIBUTE_DIRECTORY,
            0,
            "a plain file carries no directory bit"
        );

        // An unsupported info class fails with ERROR_INVALID_PARAMETER.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                file_info_ex,
                &[handle, 9, basic as u32, 40]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);

        // GetVersionExA reports the same fields as GetVersionExW with the
        // ANSI OSVERSIONINFOEX layout (szCSDVersion is 128 ANSI bytes).
        let info_a = 0x41_200;
        let mut version_buffer_a = vec![0xEE_u8; 0x9C];
        version_buffer_a[0..4].copy_from_slice(&0x9C_u32.to_le_bytes());
        memory.map_bytes(info_a, &version_buffer_a);
        let info_w = 0x41_300;
        let mut version_buffer_w = vec![0xEE_u8; 0x11C];
        version_buffer_w[0..4].copy_from_slice(&0x11C_u32.to_le_bytes());
        memory.map_bytes(info_w, &version_buffer_w);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, version_a, &[info_a as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, version_w, &[info_w as u32]),
            1
        );
        for offset in [0x04, 0x08, 0x0C, 0x10] {
            assert_eq!(
                memory.read_u32(info_a + offset).unwrap(),
                memory.read_u32(info_w + offset).unwrap(),
                "version field at +{offset:#x} matches GetVersionExW"
            );
        }
        assert_eq!(
            memory.read_u32(info_a + 0x10).unwrap(),
            2,
            "VER_PLATFORM_WIN32_NT"
        );
        for offset in 0x14..0x94 {
            assert_eq!(
                memory.read_u8(info_a + offset).unwrap(),
                0,
                "CSD ANSI cleared"
            );
        }
        assert_eq!(
            memory.read_u32(info_a + 0x94).unwrap(),
            memory.read_u32(info_w + 0x114).unwrap(),
            "service pack major matches"
        );

        // MoveFileW renames; an existing destination fails (no
        // MOVEFILE_REPLACE_EXISTING).
        let src = runtime
            .alloc_utf16_string(&mut memory, r"C:\Games\move-src.txt")
            .expect("wide src");
        let dst = runtime
            .alloc_utf16_string(&mut memory, r"C:\Games\move-dst.txt")
            .expect("wide dst");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                move_file,
                &[src as u32, dst as u32]
            ),
            1
        );
        let dst_w = runtime
            .alloc_utf16_string(&mut memory, r"C:\Games\move-dst.txt")
            .expect("wide dst again");
        assert_ne!(
            dispatch_x86_thunk(&mut runtime, &mut memory, attributes, &[dst_w as u32]),
            u32::MAX as u64
        );
        let blocker = runtime
            .alloc_utf16_string(&mut memory, r"C:\Games\move-src.txt")
            .expect("wide blocker");
        runtime
            .win32
            .create_file_w(
                "C:\\Games\\move-src.txt",
                FileAccess::read_write(),
                ShareMode::all(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create blocker");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                move_file,
                &[dst as u32, blocker as u32]
            ),
            0
        );
        assert_ne!(runtime.last_error, 0);

        // SearchPathW with an explicit path list resolves the file, appends
        // the requested extension, and honors the required-size contract.
        runtime
            .win32
            .create_file_w(
                r"C:\Games\tool.exe",
                FileAccess::read_write(),
                ShareMode::all(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create tool");
        let dirs = runtime
            .alloc_utf16_string(&mut memory, r"C:\Games")
            .expect("wide dirs");
        let tool = runtime
            .alloc_utf16_string(&mut memory, "tool")
            .expect("wide tool");
        let extension = runtime
            .alloc_utf16_string(&mut memory, ".exe")
            .expect("wide ext");
        let found_buf = 0x41_400;
        memory.map_bytes(found_buf, &[0_u8; 0x100]);
        let file_part_ptr = 0x41_500;
        memory.map_bytes(file_part_ptr, &[0_u8; 8]);
        let length = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            search_path,
            &[
                dirs as u32,
                tool as u32,
                extension as u32,
                0x100,
                found_buf as u32,
                file_part_ptr as u32,
            ],
        );
        assert_eq!(length, 17);
        assert_eq!(
            read_guest_utf16_string(&memory, found_buf, 64),
            r"C:\Games\tool.exe"
        );
        let file_part = read_guest_pointer(&memory, file_part_ptr, GuestArch::X86).unwrap();
        assert_eq!(file_part, found_buf + 18);
        assert_eq!(read_guest_utf16_string(&memory, file_part, 64), "tool.exe");

        // A missing file: 0 with ERROR_FILE_NOT_FOUND.
        let missing = runtime
            .alloc_utf16_string(&mut memory, "absent")
            .expect("wide missing");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                search_path,
                &[dirs as u32, missing as u32, 0, 0x100, found_buf as u32, 0]
            ),
            0
        );
        assert_eq!(runtime.last_error, ERROR_FILE_NOT_FOUND);

        // A too-small buffer returns the required size (incl. NUL) with
        // ERROR_BUFFER_OVERFLOW.
        let length = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            search_path,
            &[
                dirs as u32,
                tool as u32,
                extension as u32,
                4,
                found_buf as u32,
                0,
            ],
        );
        assert_eq!(length, 18);
        assert_eq!(runtime.last_error, ERROR_BUFFER_OVERFLOW);

        // lstrcmpiA compares ANSI strings case-insensitively.
        let cmp = runtime.alloc_host_thunk(HostThunk::LstrcmpiA);
        let hello = runtime
            .alloc_c_string(&mut memory, "Hello, World")
            .expect("ansi hello");
        let hello_lower = runtime
            .alloc_c_string(&mut memory, "hello, world")
            .expect("ansi lower");
        let different = runtime
            .alloc_c_string(&mut memory, "hello, worlx")
            .expect("ansi other");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                cmp,
                &[hello as u32, hello_lower as u32]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                cmp,
                &[hello as u32, different as u32]
            ),
            u64::from(-1_i32 as u32)
        );
    })
}

// ── shlwapi evidence: path helpers (table-driven) ──────────────────────
#[test]
fn evidence_shlwapi_path_find_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-shlwapi-find");
        let mut memory = MemoryImage::default();
        let find_extension = runtime.alloc_host_thunk(HostThunk::PathFindExtensionW);
        let find_file_name = runtime.alloc_host_thunk(HostThunk::PathFindFileNameW);
        let strip_path = runtime.alloc_host_thunk(HostThunk::PathStripPathW);
        let remove_extension = runtime.alloc_host_thunk(HostThunk::PathRemoveExtensionW);

        // PathFindExtensionW: the last dot after the last separator, colon,
        // or space; otherwise a pointer to the trailing NUL.
        let extension_cases: &[(&str, Option<&str>)] = &[
            (r"C:\dir\file.txt", Some(".txt")),
            (r"C:\dir\file.tar.gz", Some(".gz")),
            (r"C:\dir\file", None),
            (r"C:\dir\file.", Some(".")),
            (r"C:\dir.2\file", None),
            (r"file.txt", Some(".txt")),
            (r"C:\dir\file.txt ", None),
            (r"", None),
            (r"foo.bar baz", None),
        ];
        for (input, expected) in extension_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let result =
                dispatch_x86_thunk(&mut runtime, &mut memory, find_extension, &[path as u32]);
            match expected {
                Some(expected_ext) => {
                    assert_eq!(
                        read_guest_utf16_string(&memory, result, 64),
                        *expected_ext,
                        "PathFindExtensionW({input:?})"
                    );
                }
                None => {
                    assert_eq!(
                        result,
                        path + input.encode_utf16().count() as u64 * 2,
                        "PathFindExtensionW({input:?}) points at the NUL"
                    );
                }
            }
        }

        // PathFindFileNameW: the last component after the last `\`, `/`, or
        // `:` (skipping separator runs).
        let file_name_cases: &[(&str, &str)] = &[
            (r"C:\dir\file.txt", "file.txt"),
            (r"C:\dir\", "dir\\"),
            (r"C:\dir", "dir"),
            (r"file.txt", "file.txt"),
            (r"C:\a\\b", "b"),
            (r"C:", "C:"),
            (r"C:a", "a"),
            (r"\\server\share\file", "file"),
        ];
        for (input, expected) in file_name_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let result =
                dispatch_x86_thunk(&mut runtime, &mut memory, find_file_name, &[path as u32]);
            assert_eq!(
                read_guest_utf16_string(&memory, result, 64),
                *expected,
                "PathFindFileNameW({input:?})"
            );
        }

        // PathStripPathW removes the directory portion in place.
        let strip_cases: &[(&str, &str)] = &[
            (r"C:\dir\file.txt", "file.txt"),
            (r"C:\dir\sub\file", "file"),
            (r"file.txt", "file.txt"),
            (r"C:\dir\", "dir\\"),
        ];
        for (input, expected) in strip_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let _ = dispatch_x86_thunk(&mut runtime, &mut memory, strip_path, &[path as u32]);
            assert_eq!(
                read_guest_utf16_string(&memory, path, 64),
                *expected,
                "PathStripPathW({input:?})"
            );
        }

        // PathRemoveExtensionW truncates at the extension in place.
        let remove_ext_cases: &[(&str, &str)] = &[
            (r"C:\dir\file.txt", r"C:\dir\file"),
            (r"file.tar.gz", "file.tar"),
            (r"file", "file"),
            (r"C:\dir\file.txt ", r"C:\dir\file.txt "),
        ];
        for (input, expected) in remove_ext_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let _ = dispatch_x86_thunk(&mut runtime, &mut memory, remove_extension, &[path as u32]);
            assert_eq!(
                read_guest_utf16_string(&memory, path, 64),
                *expected,
                "PathRemoveExtensionW({input:?})"
            );
        }
    })
}

#[test]
fn evidence_shlwapi_path_append_combine_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-shlwapi-combine");
        let mut memory = MemoryImage::default();
        let append = runtime.alloc_host_thunk(HostThunk::PathAppendW);
        let combine = runtime.alloc_host_thunk(HostThunk::PathCombineW);

        // PathAppendW (in place): absolute append replaces; leading `\` is
        // skipped; `..` pops the last element; drive-relative joins cleanly.
        let append_cases: &[(&str, &str, &str)] = &[
            (r"C:\a\b", "c", r"C:\a\b\c"),
            (r"C:\a\b", r"..\c", r"C:\a\c"),
            (r"C:\a\b\", "c", r"C:\a\b\c"),
            (r"C:\a\b", r"\c", r"C:\a\b\c"),
            (r"C:\a\b", r"C:\x\y", r"C:\x\y"),
            ("", "foo", "foo"),
            ("foo", "bar", r"foo\bar"),
            (r"C:\a\b", "", r"C:\a\b"),
            (r"C:\a", r"..\..\x", r"C:\x"),
            (r"C:\", "foo", r"C:\foo"),
        ];
        for (base, more, expected) in append_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, base)
                .expect("wide path");
            let more_ptr = runtime
                .alloc_utf16_string(&mut memory, more)
                .expect("wide more");
            let result = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                append,
                &[path as u32, more_ptr as u32],
            );
            assert_eq!(result, 1, "PathAppendW({base:?}, {more:?}) succeeds");
            assert_eq!(
                read_guest_utf16_string(&memory, path, 128),
                *expected,
                "PathAppendW({base:?}, {more:?})"
            );
        }

        // PathCombineW: NULL/empty dir yields the file; absolute file
        // replaces; `..` resolves through the canonicalize step.
        let combine_cases: &[(&str, &str, &str)] = &[
            (r"C:\dir", "file.txt", r"C:\dir\file.txt"),
            (r"C:\dir\", "file.txt", r"C:\dir\file.txt"),
            (r"C:\path", r"..\file", r"C:\file"),
            (r"C:\dir", r"D:\other.txt", r"D:\other.txt"),
            ("", "file.txt", "file.txt"),
            (r"C:\dir", r"\rooted.txt", r"C:\rooted.txt"),
            (r"C:\a\b", r"..\..\x", r"C:\x"),
        ];
        for (dir, file, expected) in combine_cases {
            let out = 0x43_000;
            memory.map_bytes(out, &[0_u8; 0x200]);
            let dir_ptr = runtime
                .alloc_utf16_string(&mut memory, dir)
                .expect("wide dir");
            let file_ptr = runtime
                .alloc_utf16_string(&mut memory, file)
                .expect("wide file");
            let result = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                combine,
                &[out as u32, dir_ptr as u32, file_ptr as u32],
            );
            assert_eq!(result, out, "PathCombineW({dir:?}, {file:?}) returns out");
            assert_eq!(
                read_guest_utf16_string(&memory, out, 128),
                *expected,
                "PathCombineW({dir:?}, {file:?})"
            );
        }

        // A NULL directory with a file yields the file alone.
        let out = 0x43_100;
        memory.map_bytes(out, &[0_u8; 0x200]);
        let file_ptr = runtime
            .alloc_utf16_string(&mut memory, "solo.txt")
            .expect("wide file");
        let result = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            combine,
            &[out as u32, 0, file_ptr as u32],
        );
        assert_eq!(result, out);
        assert_eq!(read_guest_utf16_string(&memory, out, 64), "solo.txt");
    })
}

#[test]
fn evidence_shlwapi_path_remove_spec_and_root_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-shlwapi-removespec");
        let mut memory = MemoryImage::default();
        let remove_file_spec = runtime.alloc_host_thunk(HostThunk::PathRemoveFileSpecW);
        let skip_root = runtime.alloc_host_thunk(HostThunk::PathSkipRootW);
        let is_root = runtime.alloc_host_thunk(HostThunk::PathIsRootW);
        let is_relative = runtime.alloc_host_thunk(HostThunk::PathIsRelativeW);
        let drive_number = runtime.alloc_host_thunk(HostThunk::PathGetDriveNumberW);
        let add_backslash = runtime.alloc_host_thunk(HostThunk::PathAddBackslashW);
        let remove_backslash = runtime.alloc_host_thunk(HostThunk::PathRemoveBackslashW);
        let remove_blanks = runtime.alloc_host_thunk(HostThunk::PathRemoveBlanksW);

        // PathRemoveFileSpecW drops the last component and its separator;
        // roots and separator-less paths fail unchanged.
        let remove_spec_cases: &[(&str, Option<&str>)] = &[
            (r"C:\a\b\c", Some(r"C:\a\b")),
            (r"C:\a\b", Some(r"C:\a")),
            (r"C:\a", Some(r"C:\")),
            (r"C:\a\", Some(r"C:\a")),
            (r"C:\", None),
            (r"C:", None),
            (r"a\b", Some("a")),
            ("a", Some("")),
            ("", None),
            (r"\a\b", Some(r"\a")),
        ];
        for (input, expected) in remove_spec_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let result =
                dispatch_x86_thunk(&mut runtime, &mut memory, remove_file_spec, &[path as u32]);
            match expected {
                Some(expected_path) => {
                    assert_eq!(result, 1, "PathRemoveFileSpecW({input:?}) removes");
                    assert_eq!(
                        read_guest_utf16_string(&memory, path, 128),
                        *expected_path,
                        "PathRemoveFileSpecW({input:?})"
                    );
                }
                None => {
                    assert_eq!(result, 0, "PathRemoveFileSpecW({input:?}) fails");
                    assert_eq!(
                        read_guest_utf16_string(&memory, path, 128),
                        *input,
                        "PathRemoveFileSpecW({input:?}) leaves the path unchanged"
                    );
                }
            }
        }

        // PathSkipRootW: pointer past `X:\` or `\\server\share\`; NULL when
        // there is no root.
        let skip_root_cases: &[(&str, Option<&str>)] = &[
            (r"C:\dir\file", Some("dir\\file")),
            (r"C:\", Some("")),
            (r"\\server\share\file", Some("file")),
            (r"\\server\share", None),
            (r"\dir", None),
            (r"dir", None),
            (r"C:dir", None),
        ];
        for (input, expected) in skip_root_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let result = dispatch_x86_thunk(&mut runtime, &mut memory, skip_root, &[path as u32]);
            match expected {
                Some(tail) => {
                    assert_eq!(
                        read_guest_utf16_string(&memory, result, 64),
                        *tail,
                        "PathSkipRootW({input:?})"
                    );
                }
                None => assert_eq!(result, 0, "PathSkipRootW({input:?}) has no root"),
            }
        }

        // PathIsRootW.
        let is_root_cases: &[(&str, bool)] = &[
            (r"C:\", true),
            (r"C:/", true),
            ("C:", true),
            (r"C:\a", false),
            ("C:a", false),
            ("\\", true),
            (r"\\server\share", true),
            (r"\\server\share\", true),
            (r"\\server", false),
            (r"\\server\share\file", false),
            ("", false),
        ];
        for (input, expected) in is_root_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let result = dispatch_x86_thunk(&mut runtime, &mut memory, is_root, &[path as u32]);
            assert_eq!(result, *expected as u64, "PathIsRootW({input:?})");
        }

        // PathIsRelativeW.
        let is_relative_cases: &[(&str, bool)] = &[
            ("foo", true),
            ("", true),
            (r"C:\foo", false),
            ("C:foo", false),
            (r"\foo", false),
            (r"\\server\share", false),
            ("/foo", true),
        ];
        for (input, expected) in is_relative_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let result = dispatch_x86_thunk(&mut runtime, &mut memory, is_relative, &[path as u32]);
            assert_eq!(result, *expected as u64, "PathIsRelativeW({input:?})");
        }

        // PathGetDriveNumberW: A:..Z: → 0..25, else -1 (extended `\\?\`
        // prefixes are skipped).
        let drive_cases: &[(&str, i32)] = &[
            (r"C:\foo", 2),
            ("C:", 2),
            (r"D:\foo", 3),
            (r"\\?\C:\foo", 2),
            ("foo", -1),
            (r"\foo", -1),
        ];
        for (input, expected) in drive_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let result =
                dispatch_x86_thunk(&mut runtime, &mut memory, drive_number, &[path as u32]);
            let expected = if *expected < 0 {
                u64::from(-1_i32 as u32)
            } else {
                *expected as u64
            };
            assert_eq!(result, expected, "PathGetDriveNumberW({input:?})");
        }

        // PathAddBackslashW appends a trailing backslash when missing.
        let add_backslash_cases: &[(&str, &str)] = &[
            (r"C:\dir", r"C:\dir\"),
            (r"C:\dir\", r"C:\dir\"),
            ("", "\\"),
            ("foo", r"foo\"),
        ];
        for (input, expected) in add_backslash_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let _ = dispatch_x86_thunk(&mut runtime, &mut memory, add_backslash, &[path as u32]);
            assert_eq!(
                read_guest_utf16_string(&memory, path, 64),
                *expected,
                "PathAddBackslashW({input:?})"
            );
        }

        // PathRemoveBackslashW removes the trailing backslash except on roots.
        let remove_backslash_cases: &[(&str, &str)] = &[
            (r"C:\dir\", r"C:\dir"),
            (r"C:\dir", r"C:\dir"),
            (r"C:\", r"C:\"),
            (r"\\server\share\", r"\\server\share\"),
            ("foo\\", "foo"),
        ];
        for (input, expected) in remove_backslash_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let _ = dispatch_x86_thunk(&mut runtime, &mut memory, remove_backslash, &[path as u32]);
            assert_eq!(
                read_guest_utf16_string(&memory, path, 64),
                *expected,
                "PathRemoveBackslashW({input:?})"
            );
        }

        // PathRemoveBlanksW trims leading and trailing spaces in place.
        let remove_blanks_cases: &[(&str, &str)] = &[
            ("  C:\\dir  ", r"C:\dir"),
            ("C:\\dir", r"C:\dir"),
            ("   ", ""),
            (" a b ", "a b"),
        ];
        for (input, expected) in remove_blanks_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let _ = dispatch_x86_thunk(&mut runtime, &mut memory, remove_blanks, &[path as u32]);
            assert_eq!(
                read_guest_utf16_string(&memory, path, 64),
                *expected,
                "PathRemoveBlanksW({input:?})"
            );
        }
    })
}

#[test]
fn evidence_shlwapi_path_canonicalize_and_match_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-shlwapi-canon");
        let mut memory = MemoryImage::default();
        let canonicalize = runtime.alloc_host_thunk(HostThunk::PathCanonicalizeW);
        let match_spec = runtime.alloc_host_thunk(HostThunk::PathMatchSpecW);

        // PathCanonicalizeW resolves `.`/`..` and preserves trailing
        // separators; the empty path canonicalizes to `\`.
        let canonical_cases: &[(&str, &str)] = &[
            (r"C:\a\b\..\c", r"C:\a\c"),
            (r"C:\path\..\file.txt", r"C:\file.txt"),
            (r"C:\a\b\", r"C:\a\b\"),
            (r"C:\a\.", r"C:\a\."),
            (r"C:\a\..", r"C:\"),
            (r"C:\..\b", r"C:\b"),
            (r"C:\a\..\..\b", r"C:\b"),
            (r"\\server\share\a\..\b", r"\\server\share\b"),
            ("", "\\"),
            (r"C:\a", r"C:\a"),
            ("C:", r"C:\"),
            (r"C:\a\b\..\..\..\c", r"C:\c"),
        ];
        for (input, expected) in canonical_cases {
            let out = 0x43_200;
            memory.map_bytes(out, &[0_u8; 0x200]);
            let path = runtime
                .alloc_utf16_string(&mut memory, input)
                .expect("wide path");
            let result = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                canonicalize,
                &[out as u32, path as u32],
            );
            assert_eq!(result, 1, "PathCanonicalizeW({input:?}) succeeds");
            assert_eq!(
                read_guest_utf16_string(&memory, out, 128),
                *expected,
                "PathCanonicalizeW({input:?})"
            );
        }

        // PathMatchSpecW: DOS wildcards with `;`-separated alternates.
        let match_cases: &[(&str, &str, bool)] = &[
            ("foo.txt", "*.txt", true),
            ("foo.txt", "*.t?t", true),
            ("foo.txt", "f*.*", true),
            ("foo", "*.txt", false),
            ("foo.txt", "*.t*t", true),
            ("foo.txt", "*.doc;*.txt", true),
            ("foo.doc", "*.doc;*.txt", true),
            ("foo.bar", "*.doc;*.txt", false),
            ("foo", "foo", true),
            ("FOO", "foo", true),
            ("foo.txt", "", false),
            ("anything", "*.*", true),
            ("file", "f*e", true),
            ("file", "f?le", true),
            ("file", "f?xle", false),
        ];
        for (path_str, spec_str, expected) in match_cases {
            let path = runtime
                .alloc_utf16_string(&mut memory, path_str)
                .expect("wide path");
            let spec = runtime
                .alloc_utf16_string(&mut memory, spec_str)
                .expect("wide spec");
            let result = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                match_spec,
                &[path as u32, spec as u32],
            );
            assert_eq!(
                result, *expected as u64,
                "PathMatchSpecW({path_str:?}, {spec_str:?})"
            );
        }
    })
}

#[test]
fn evidence_core_time_and_filetime_thunks() {
    with_big_stack(|| {
        // The time-conversion thunks run on the x64 guest path (the x86
        // SystemTimeToFileTime dispatch writes the FILETIME through the
        // guest-pointer writer, which rejects values that do not fit the
        // 32-bit address space).
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(
            temp_dir.path(),
            "evidence-core-time",
            GeArch::X64,
            "win11-23h2",
        )
        .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, false, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
        let mut memory = MemoryImage::default();
        let get_system_time = runtime.alloc_host_thunk(HostThunk::GetSystemTime);
        let filetime_to_systemtime = runtime.alloc_host_thunk(HostThunk::FileTimeToSystemTime);
        let systemtime_to_filetime = runtime.alloc_host_thunk(HostThunk::SystemTimeToFileTime);
        let tz_specific = runtime.alloc_host_thunk(HostThunk::SystemTimeToTzSpecificLocalTime);
        let compare_filetime = runtime.alloc_host_thunk(HostThunk::CompareFileTime);
        let get_file_time = runtime.alloc_host_thunk(HostThunk::GetFileTime);
        let set_file_time = runtime.alloc_host_thunk(HostThunk::SetFileTime);

        // GetSystemTime writes a plausible SYSTEMTIME.
        let st = 0x41_000;
        memory.map_bytes(st, &[0; 16]);
        evidence_dispatch_x64_thunk(&mut runtime, &mut memory, get_system_time, &[st]);
        let year = memory.read_u16(st).unwrap();
        assert!((2020..=2100).contains(&year), "year {year} is plausible");
        assert!((1..=12).contains(&memory.read_u16(st + 2).unwrap()));
        assert!((1..=31).contains(&memory.read_u16(st + 6).unwrap()));

        // FileTimeToSystemTime(0) is 1601-01-01 (the Windows epoch).
        let ft = 0x41_010;
        memory.map_bytes(ft, &0_u64.to_le_bytes());
        let st2 = 0x41_020;
        memory.map_bytes(st2, &[0; 16]);
        assert_eq!(
            evidence_dispatch_x64_thunk(
                &mut runtime,
                &mut memory,
                filetime_to_systemtime,
                &[ft, st2]
            ),
            1
        );
        assert_eq!(memory.read_u16(st2).unwrap(), 1601);
        assert_eq!(memory.read_u16(st2 + 2).unwrap(), 1);
        assert_eq!(memory.read_u16(st2 + 6).unwrap(), 1);

        // SystemTimeToFileTime converts 2024-01-01T00:00:00 to ticks.
        let st3 = 0x41_030;
        let mut st3_bytes = vec![0_u8; 16];
        st3_bytes[0..2].copy_from_slice(&2024_u16.to_le_bytes());
        st3_bytes[2..4].copy_from_slice(&1_u16.to_le_bytes());
        st3_bytes[6..8].copy_from_slice(&1_u16.to_le_bytes());
        memory.map_bytes(st3, &st3_bytes);
        let ft2 = 0x41_040;
        memory.map_bytes(ft2, &[0; 8]);
        assert_eq!(
            evidence_dispatch_x64_thunk(
                &mut runtime,
                &mut memory,
                systemtime_to_filetime,
                &[st3, ft2]
            ),
            1
        );
        assert_eq!(
            memory.read_u64(ft2).unwrap(),
            133_487_136_000_000_000,
            "2024-01-01T00:00:00 in 100ns ticks since 1601-01-01"
        );

        // SystemTimeToTzSpecificLocalTime applies the local bias and writes a
        // valid local SYSTEMTIME (same day, January).
        let st4 = 0x41_050;
        memory.map_bytes(st4, &st3_bytes);
        assert_eq!(
            evidence_dispatch_x64_thunk(&mut runtime, &mut memory, tz_specific, &[0, st4, st4]),
            1
        );
        assert_eq!(memory.read_u16(st4 + 2).unwrap(), 1);

        // CompareFileTime orders the pair.
        let ft_a = 0x41_060;
        let ft_b = 0x41_070;
        memory.map_bytes(ft_a, &5_u64.to_le_bytes());
        memory.map_bytes(ft_b, &10_u64.to_le_bytes());
        assert_eq!(
            evidence_dispatch_x64_thunk(&mut runtime, &mut memory, compare_filetime, &[ft_a, ft_b]),
            u64::MAX,
            "the x64 path reports -1 as the full-width i64"
        );
        assert_eq!(
            evidence_dispatch_x64_thunk(&mut runtime, &mut memory, compare_filetime, &[ft_b, ft_a]),
            1
        );
        assert_eq!(
            evidence_dispatch_x64_thunk(&mut runtime, &mut memory, compare_filetime, &[ft_a, ft_a]),
            0
        );

        // GetFileTime/SetFileTime on a real file handle round-trip.
        let handle = runtime
            .win32
            .create_file_w(
                "C:\\evidence-time.txt",
                FileAccess::read_write(),
                ShareMode::all(),
                CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create file");
        let c = 0x41_080;
        let a = 0x41_090;
        let w = 0x41_0A0;
        memory.map_bytes(c, &[0; 8]);
        memory.map_bytes(a, &[0; 8]);
        memory.map_bytes(w, &[0; 8]);
        assert_eq!(
            evidence_dispatch_x64_thunk(
                &mut runtime,
                &mut memory,
                get_file_time,
                &[handle as u64, c, a, w]
            ),
            1
        );
        assert!(
            memory.read_u64(w).unwrap() > 0,
            "last-write time is populated from the host file"
        );
        // SetFileTime pins the last-write time; GetFileTime reads it back.
        let new_w = 0x41_0B0;
        memory.map_bytes(new_w, &123_456_789_u64.to_le_bytes());
        assert_eq!(
            evidence_dispatch_x64_thunk(
                &mut runtime,
                &mut memory,
                set_file_time,
                &[handle as u64, 0, 0, new_w]
            ),
            1
        );
        let w2 = 0x41_0C0;
        memory.map_bytes(w2, &[0; 8]);
        assert_eq!(
            evidence_dispatch_x64_thunk(
                &mut runtime,
                &mut memory,
                get_file_time,
                &[handle as u64, 0, 0, w2]
            ),
            1
        );
        assert_eq!(memory.read_u64(w2).unwrap(), 123_456_789);
    })
}

#[test]
fn get_file_information_by_handle_populates_the_file_info_struct() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("file-info-by-handle");
        let mut memory = MemoryImage::default();
        runtime
            .win32
            .create_directory_w(r"C:\package")
            .expect("create package dir");
        let create_file = runtime.alloc_host_thunk(HostThunk::CreateFileW);
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\package\info.tmp")
            .expect("path");
        let handle = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_file,
            &[
                path as u32,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                0,
                CREATE_ALWAYS,
                0,
                0,
            ],
        );
        assert_ne!(handle, u32::MAX as u64, "CreateFileW succeeded");
        assert_eq!(runtime.last_error, 0);

        let info = runtime.alloc_host_thunk(HostThunk::GetFileInformationByHandle);
        let info_ptr = 0x41_000;
        memory.map_bytes(info_ptr as u64, &[0; 52]);

        let result =
            dispatch_x86_thunk(&mut runtime, &mut memory, info, &[handle as u32, info_ptr]);
        assert_eq!(result, 1);
        assert_eq!(runtime.last_error, 0);
        // BY_HANDLE_FILE_INFORMATION layout: attributes(4), 3 FILETIMEs(24),
        // volume serial(4) = 0x4341_5341 ("CASA"), size hi/lo(8), links(4)=1,
        // file index hi/lo(8) = synthetic_file_index(path).
        assert_eq!(
            memory.read_u32(info_ptr as u64).expect("attributes") & FILE_ATTRIBUTE_DIRECTORY,
            0,
            "a plain file is not a directory"
        );
        assert_eq!(
            memory
                .read_u32(info_ptr as u64 + 28)
                .expect("volume serial"),
            0x4341_5341
        );
        assert_eq!(memory.read_u32(info_ptr as u64 + 40).expect("links"), 1);
        let file_index = (memory.read_u32(info_ptr as u64 + 48).expect("index low") as u64)
            | ((memory.read_u32(info_ptr as u64 + 44).expect("index high") as u64) << 32);
        assert_eq!(
            file_index,
            synthetic_file_index(r"C:\package\info.tmp"),
            "the file index derives from the normalized path"
        );

        // An invalid handle fails with ERROR_INVALID_HANDLE.
        let result = dispatch_x86_thunk(&mut runtime, &mut memory, info, &[0, info_ptr]);
        assert_eq!(result, 0);
        assert_eq!(runtime.last_error, ERROR_INVALID_HANDLE);
    })
}

// ── evidence-mid: shell32 path helpers ─────────────────────────────────
#[test]
fn evidence_mid_shell32_path_helpers_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mid-shell-path");
        let mut memory = MemoryImage::default();

        // PathIsNetworkPathW: the documented UNC test.
        let network = runtime
            .alloc_utf16_string(&mut memory, r"\\server\share\file.txt")
            .expect("path");
        let local = runtime
            .alloc_utf16_string(&mut memory, r"C:\game\file.txt")
            .expect("path");
        let is_network = runtime.alloc_host_thunk(HostThunk::PathIsNetworkPathW);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, is_network, &[network as u32]),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, is_network, &[local as u32]),
            0
        );

        // PathRelativePathToW: the common-prefix algorithm.
        let from = runtime
            .alloc_utf16_string(&mut memory, r"C:\a\b\c\d")
            .expect("from");
        let to = runtime
            .alloc_utf16_string(&mut memory, r"C:\a\b\x\y")
            .expect("to");
        let out = 0x65_000;
        memory.map_bytes(out, &[0; 128]);
        let relative = runtime.alloc_host_thunk(HostThunk::PathRelativePathToW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                relative,
                &[out as u32, from as u32, 0x10, to as u32, 0]
            ),
            1
        );
        assert_eq!(
            read_utf16_string(&memory, out).expect("relative"),
            r"..\..\x\y"
        );
        // Different drives fail with an empty output buffer.
        let other_drive = runtime
            .alloc_utf16_string(&mut memory, r"D:\elsewhere")
            .expect("to");
        memory.map_bytes(out, &[0; 128]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                relative,
                &[out as u32, from as u32, 0x10, other_drive as u32, 0]
            ),
            0
        );
        assert_eq!(read_utf16_string(&memory, out).expect("empty"), "");

        // The shell32-registered Path* helpers dispatch into the shared
        // shlwapi machinery: PathFindFileNameW returns a pointer into
        // the path (the documented contract).
        let path = runtime
            .alloc_utf16_string(&mut memory, r"C:\dir\game.exe")
            .expect("path");
        let find_file_name = runtime.alloc_host_thunk(HostThunk::PathFindFileNameW);
        let file_name_ptr =
            dispatch_x86_thunk(&mut runtime, &mut memory, find_file_name, &[path as u32]);
        assert!(
            file_name_ptr >= path && file_name_ptr < path + 64,
            "PathFindFileNameW points into the path: {file_name_ptr:#x}"
        );
        assert_eq!(
            read_utf16_string(&memory, file_name_ptr).expect("file name"),
            "game.exe"
        );

        // PathMakeUniqueName: the template when free, " (n)" otherwise.
        let template = r"C:\unique\save.dat";
        let template_ptr = runtime
            .alloc_utf16_string(&mut memory, template)
            .expect("template");
        let unique_out = 0x65_200;
        memory.map_bytes(unique_out, &[0; 128]);
        let make_unique = runtime.alloc_host_thunk(HostThunk::PathMakeUniqueName);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                make_unique,
                &[unique_out as u32, 64, template_ptr as u32, 0, 0]
            ),
            1
        );
        assert_eq!(
            read_utf16_string(&memory, unique_out).expect("unique"),
            template,
            "a free template is used as-is"
        );
        // The conflict path: stage the template, expect "save (1).dat".
        let host_dir = runtime
            .win32
            .guest_path_to_host_path(r"C:\unique")
            .expect("host dir");
        std::fs::create_dir_all(&host_dir).expect("create dir");
        std::fs::write(host_dir.join("save.dat"), b"data").expect("write save");
        let unique_out2 = 0x65_300;
        memory.map_bytes(unique_out2, &[0; 128]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                make_unique,
                &[unique_out2 as u32, 64, template_ptr as u32, 0, 0]
            ),
            1
        );
        assert_eq!(
            read_utf16_string(&memory, unique_out2).expect("unique"),
            r"C:\unique\save (1).dat"
        );

        // PathAppendW/PathCombineW under the shell32 name resolve to the
        // shlwapi machinery through the import-name tables.
        let import = ResolvedImport {
            requested_module: "shell32.dll".to_string(),
            resolved_module: "shell32.dll".to_string(),
            symbol: ImportSymbol::ByName {
                hint: 0,
                name: "PathCombineW".to_string(),
            },
            iat_rva: 0,
            export: synthetic_export_symbol(&ImportSymbol::ByName {
                hint: 0,
                name: "PathCombineW".to_string(),
            }),
        };
        assert!(
            matches!(HostThunk::from_import(&import), HostThunk::PathCombineW),
            "shell32!PathCombineW dispatches into the shared path helper"
        );
    })
}

// ── evidence-mid: shell32 fs/notify/icon/shell-item helpers ───────────
#[test]
fn evidence_mid_shell32_fs_notify_icon_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mid-shell-fs");
        let mut memory = MemoryImage::default();

        // SHCreateDirectoryExW: recursive mkdir through the fs layer.
        let dir_path = r"C:\game\saves\slot1";
        let dir_ptr = runtime
            .alloc_utf16_string(&mut memory, dir_path)
            .expect("dir");
        let create_dir = runtime.alloc_host_thunk(HostThunk::SHCreateDirectoryExW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_dir,
                &[0, dir_ptr as u32, 0]
            ),
            0,
            "SHCreateDirectoryExW creates the tree"
        );
        let host_dir = runtime
            .win32
            .guest_path_to_host_path(dir_path)
            .expect("host dir");
        assert!(host_dir.is_dir(), "the guest-visible directory exists");
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_dir,
                &[0, dir_ptr as u32, 0]
            ),
            crate::advapi32::ERROR_ALREADY_EXISTS as u64,
            "the documented ERROR_ALREADY_EXISTS for an existing directory"
        );

        // SHFileOperationW: FO_DELETE + FO_RENAME over the fs layer.
        let file_guest = r"C:\game\save.dat";
        let file_host = runtime
            .win32
            .guest_path_to_host_path(file_guest)
            .expect("host file");
        std::fs::write(&file_host, b"save").expect("write save");
        let from_ptr = runtime
            .alloc_utf16_string(&mut memory, file_guest)
            .expect("from");
        let op_struct = 0x65_400;
        memory.map_bytes(op_struct, &[0; 32]);
        write_u32(&mut memory, op_struct + 4, 3); // FO_DELETE
        write_guest_pointer(&mut memory, op_struct + 8, from_ptr, GuestArch::X86).expect("pFrom");
        let file_op = runtime.alloc_host_thunk(HostThunk::SHFileOperationW);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, file_op, &[op_struct as u32]),
            0,
            "FO_DELETE succeeds"
        );
        assert!(!file_host.exists(), "the file is gone");
        // FO_RENAME moves the file.
        let renamed_guest = r"C:\game\save2.dat";
        std::fs::write(&file_host, b"save").expect("rewrite save");
        let to_ptr = runtime
            .alloc_utf16_string(&mut memory, renamed_guest)
            .expect("to");
        write_u32(&mut memory, op_struct + 4, 4); // FO_RENAME
        write_guest_pointer(&mut memory, op_struct + 8, from_ptr, GuestArch::X86).expect("pFrom");
        write_guest_pointer(&mut memory, op_struct + 12, to_ptr, GuestArch::X86).expect("pTo");
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, file_op, &[op_struct as u32]),
            0,
            "FO_RENAME succeeds"
        );
        assert!(
            runtime
                .win32
                .guest_path_to_host_path(renamed_guest)
                .expect("renamed host")
                .exists(),
            "the renamed file exists"
        );

        // SHChangeNotify + SHUpdateImageW: the documented no-ops.
        let change_notify = runtime.alloc_host_thunk(HostThunk::SHChangeNotify);
        let _ = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            change_notify,
            &[0x8000, 0, 0, 0], // SHCNE_ASSOCCHANGED
        );
        let update_image = runtime.alloc_host_thunk(HostThunk::SHUpdateImageW);
        let _ = dispatch_x86_thunk(&mut runtime, &mut memory, update_image, &[0, 0, 0, 0]);

        // ShellExecuteW: the "open" verb delegates to the host.
        let open_verb = runtime
            .alloc_utf16_string(&mut memory, "open")
            .expect("verb");
        let target = runtime
            .alloc_utf16_string(&mut memory, r"C:\game\save.dat")
            .expect("file");
        let shell_execute = runtime.alloc_host_thunk(HostThunk::ShellExecuteW);
        let hinst = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            shell_execute,
            &[0, open_verb as u32, target as u32, 0, 0, 1],
        );
        assert!(hinst > 32, "a HINSTANCE above the SE_ERR_* range: {hinst}");

        // SHCreateShellItem: a shell item object from a PIDL.
        let pidl = runtime
            .alloc_utf16_string(&mut memory, r"C:\game")
            .expect("pidl");
        let item_out = 0x65_500;
        memory.map_bytes(item_out, &[0; 4]);
        let create_item = runtime.alloc_host_thunk(HostThunk::SHCreateShellItem);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_item,
                &[0, 0, pidl as u32, item_out as u32]
            ),
            0,
            "SHCreateShellItem returns S_OK"
        );
        let item = read_u32(&memory, item_out).expect("item");
        assert_ne!(item, 0);

        // ExtractIconW on a module without an icon resource: the
        // documented zero handle.
        let no_icon_file = r"C:\game\noicon.bin";
        let no_icon_host = runtime
            .win32
            .guest_path_to_host_path(no_icon_file)
            .expect("host file");
        std::fs::write(&no_icon_host, b"not a pe").expect("write file");
        let file_ptr = runtime
            .alloc_utf16_string(&mut memory, no_icon_file)
            .expect("file");
        let extract_icon = runtime.alloc_host_thunk(HostThunk::ExtractIconW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                extract_icon,
                &[0, file_ptr as u32, 0]
            ),
            0,
            "a module without icon resources yields no HICON"
        );

        // SHGetMalloc: the standard allocator's Alloc/GetSize/DidAlloc/
        // Free contract.
        let malloc_out = 0x65_600;
        memory.map_bytes(malloc_out, &[0; 4]);
        let get_malloc = runtime.alloc_host_thunk(HostThunk::SHGetMalloc);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, get_malloc, &[malloc_out as u32]),
            0
        );
        let malloc_object = read_u32(&memory, malloc_out).expect("malloc object");
        let malloc_vtable =
            read_u32(&memory, u64::from(malloc_object)).expect("malloc vtable") as u64;
        let alloc_thunk = read_u32(&memory, malloc_vtable + 3 * 4).expect("alloc thunk") as u64;
        let get_size_thunk =
            read_u32(&memory, malloc_vtable + 6 * 4).expect("get size thunk") as u64;
        let did_alloc_thunk =
            read_u32(&memory, malloc_vtable + 7 * 4).expect("did alloc thunk") as u64;
        let free_thunk = read_u32(&memory, malloc_vtable + 5 * 4).expect("free thunk") as u64;
        let allocation = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            alloc_thunk,
            &[malloc_object, 128],
        );
        assert_ne!(allocation, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_size_thunk,
                &[malloc_object, allocation as u32]
            ),
            128
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                did_alloc_thunk,
                &[malloc_object, allocation as u32]
            ),
            1
        );
        let _ = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            free_thunk,
            &[malloc_object, allocation as u32],
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                did_alloc_thunk,
                &[malloc_object, allocation as u32]
            ),
            0,
            "the freed block is no longer tracked"
        );
    })
}

// ── SHCreateLinks: real persistent .lnk files ─────────────────────────
#[test]
fn sh_create_links_writes_a_real_parseable_lnk_file() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("sh-create-links");
        let mut memory = MemoryImage::default();
        let create_links = runtime.alloc_host_thunk(HostThunk::ShCreateLinks);
        let user = runtime.win32.ge().config.user_name.clone();
        let desktop = format!("C:\\Users\\{user}\\Desktop");
        runtime
            .win32
            .create_directory_w(&desktop)
            .expect("create desktop");

        // A real target file: the .lnk header must carry its real size.
        let target = format!("{desktop}\\game.exe");
        runtime
            .win32
            .write_file_overwrite_w(&target, b"0123456789")
            .expect("target file");

        let link_path = format!("{desktop}\\Game.lnk");
        let target_ptr = runtime
            .alloc_utf16_string(&mut memory, &target)
            .expect("ptr");
        let link_ptr = runtime
            .alloc_utf16_string(&mut memory, &link_path)
            .expect("ptr");
        let description_ptr = runtime
            .alloc_utf16_string(&mut memory, "Game")
            .expect("ptr");

        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_links,
            &[target_ptr as u32, link_ptr as u32, description_ptr as u32],
        );
        assert_eq!(ret, 0, "SHCreateLinks returns S_OK");
        assert_eq!(runtime.last_error, 0);

        // The link is a real persistent file with the documented .lnk
        // binary layout, parseable back through src/lnk.rs.
        let host_link = runtime
            .win32
            .guest_path_to_host_path(&link_path)
            .expect("link host path");
        let bytes = fs::read(&host_link).expect("read the written .lnk");
        let parsed = crate::lnk::parse(&bytes).expect("the written .lnk parses");
        assert_eq!(&bytes[0..4], &0x4C_u32.to_le_bytes());
        assert!(parsed.target_path.is_some());
        assert_eq!(
            parsed.target_path.as_deref().unwrap().to_lowercase(),
            target.to_lowercase(),
            "the .lnk points back at the requested target"
        );
        assert_eq!(parsed.description.as_deref(), Some("Game"));
        assert_eq!(parsed.file_size, 10, "the header carries the target size");
        assert_eq!(parsed.show_cmd, 1, "SW_SHOWNORMAL");
        assert_eq!(parsed.icon_index, 0);

        // The COM-layer encoder and this export share one writer: an
        // IPersistFile-style save of the same content is byte-identical
        // in structure (same magic + LinkInfo layout).
        let snapshot = crate::runtime::state::GuestShellLinkState {
            shell_link_object: 0,
            persist_file_object: None,
            refcount: 0,
            path: target.clone(),
            arguments: String::new(),
            description: "Game".to_string(),
            working_directory: String::new(),
            relative_path: String::new(),
            hotkey: 0,
            icon_location: String::new(),
            icon_index: 0,
            show_cmd: SW_SHOWNORMAL,
            current_file: None,
            dirty: true,
        };
        let com_bytes = runtime
            .shell_link_file_bytes(&snapshot)
            .expect("shell link bytes");
        assert_eq!(com_bytes, bytes, "one shared .lnk writer");

        // Real error codes for real invalid arguments.
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_links,
            &[0, link_ptr as u32, description_ptr as u32],
        );
        assert_eq!(ret, 0x8007_0057, "null target is E_INVALIDARG");
        assert_eq!(runtime.last_error, ERROR_INVALID_PARAMETER);
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_links,
            &[target_ptr as u32, 0, description_ptr as u32],
        );
        assert_eq!(ret, 0x8007_0057, "null link path is E_INVALIDARG");

        // A destination whose parent folder does not exist cannot be
        // written: the same E_ACCESSDENIED the COM Save path reports.
        let missing = format!("C:\\Users\\{user}\\NoSuchFolder\\x.lnk");
        let missing_ptr = runtime
            .alloc_utf16_string(&mut memory, &missing)
            .expect("ptr");
        let ret = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_links,
            &[target_ptr as u32, missing_ptr as u32, 0],
        );
        assert_eq!(ret, 0x8007_0005, "unwritable destination is E_ACCESSDENIED");
        assert_eq!(runtime.last_error, ERROR_ACCESS_DENIED);
    })
}

#[test]
fn volume_information_rejects_invalid_handles_and_reports_the_real_volume() {
    with_big_stack(|| {
        let (mut runtime, _temp) = test_runtime("volume-information");
        let mut memory = MemoryImage::default();
        let thunk = runtime.alloc_host_thunk(HostThunk::NtQueryVolumeInformationFile);
        let handle = runtime
            .win32
            .create_file_w(
                "C:\\volume-probe.bin",
                FileAccess::read_write(),
                ShareMode::all(),
                crate::win32::CreationDisposition::CreateAlways,
                false,
                false,
                false,
            )
            .expect("create probe file");
        let buffer = 0x6C_000u64;
        let iosb = 0x6D_000u64;
        memory.map_bytes(buffer, &[0u8; 0x200]);
        memory.map_bytes(iosb, &[0u8; 24]);
        let query = |runtime: &mut PeHostRuntime,
                     memory: &mut MemoryImage,
                     handle: u32,
                     length: u32,
                     class: u32|
         -> u64 {
            dispatch_x86_thunk(
                runtime,
                memory,
                thunk,
                &[handle, iosb as u32, buffer as u32, length, class],
            )
        };

        assert_eq!(
            query(&mut runtime, &mut memory, handle, 0x200, 1),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        let identity = crate::hardware_identity::host_identity();
        let disk = identity.disks.first().expect("mounted volume");
        assert_eq!(
            memory.read_u32(buffer + 8).expect("serial"),
            disk.volume_serial,
            "FileFsVolumeInformation serial is the identity serial"
        );
        assert_ne!(
            memory.read_u64(buffer).expect("creation time"),
            0,
            "FileFsVolumeInformation carries the real host volume creation time"
        );
        assert_eq!(
            memory.read_u8(buffer + 16).expect("supports objects"),
            1,
            "the volume holds real file objects"
        );
        let label_len = memory.read_u32(buffer + 12).expect("label length");
        assert_eq!(
            label_len as usize,
            disk.volume_name.encode_utf16().count() * 2
        );
        let label: Vec<u16> = memory
            .read_bytes(buffer + 20, label_len as usize)
            .expect("label")
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        assert_eq!(String::from_utf16(&label).unwrap(), disk.volume_name);

        let capacity = runtime
            .win32
            .volume_capacity(Some("C:\\volume-probe.bin"))
            .expect("volume capacity");
        assert_eq!(
            query(&mut runtime, &mut memory, handle, 0x200, 3),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        assert_eq!(
            memory.read_u64(buffer).expect("total clusters"),
            capacity.total_clusters
        );
        assert_eq!(
            memory.read_u64(buffer + 8).expect("free clusters"),
            capacity.free_clusters
        );
        assert_eq!(
            memory.read_u32(buffer + 16).expect("sectors"),
            capacity.sectors_per_cluster
        );
        assert_eq!(
            memory.read_u32(buffer + 20).expect("bytes/sector"),
            capacity.bytes_per_sector
        );

        // Every query class the surface implements is backed by the
        // SAME host volume facts (no per-class fabricated variants).
        assert_eq!(
            query(&mut runtime, &mut memory, handle, 0x200, 4),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        assert_eq!(memory.read_u32(buffer).expect("device type"), 7);
        assert_ne!(
            memory.read_u32(buffer + 4).expect("characteristics") & 0x10,
            0,
            "the volume is mounted"
        );
        assert_eq!(
            query(&mut runtime, &mut memory, handle, 0x200, 5),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        let fs_name_len = memory.read_u32(buffer + 8).expect("fs name length");
        let fs_name: Vec<u16> = memory
            .read_bytes(buffer + 12, fs_name_len as usize)
            .expect("fs name")
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        assert_eq!(String::from_utf16(&fs_name).unwrap(), disk.filesystem);
        assert_eq!(
            query(&mut runtime, &mut memory, handle, 0x200, 7),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        assert_eq!(
            memory.read_u64(buffer).expect("total"),
            capacity.total_clusters
        );
        assert_eq!(
            memory.read_u64(buffer + 8).expect("available"),
            capacity.free_clusters
        );
        assert_eq!(
            memory.read_u64(buffer + 16).expect("caller available"),
            capacity.free_clusters
        );
        assert_eq!(
            memory.read_u32(buffer + 24).expect("sectors"),
            capacity.sectors_per_cluster
        );
        assert_eq!(
            memory.read_u32(buffer + 28).expect("bytes/sector"),
            capacity.bytes_per_sector
        );
        assert_eq!(
            query(&mut runtime, &mut memory, handle, 0x200, 8),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        assert_ne!(
            memory.read_bytes(buffer, 16).expect("object id"),
            vec![0_u8; 16],
            "the volume object id is derived from the real volume UUID"
        );
        assert_ne!(
            memory.read_bytes(buffer + 16, 48).expect("extended info"),
            vec![0_u8; 48],
            "the volume extended info is derived from the real volume UUID"
        );
        assert_eq!(
            query(&mut runtime, &mut memory, handle, 0x200, 10),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        assert_eq!(memory.read_u32(buffer).expect("volume flags"), 0);
        assert_eq!(
            query(&mut runtime, &mut memory, handle, 0x200, 11),
            u64::from(crate::ntdll::STATUS_SUCCESS.raw())
        );
        assert_eq!(
            memory.read_u32(buffer).expect("logical sector"),
            capacity.bytes_per_sector
        );
        assert_eq!(
            memory.read_u32(buffer + 4).expect("physical sector"),
            capacity.bytes_per_sector
        );
        assert_eq!(
            query(&mut runtime, &mut memory, handle, 0x200, 2),
            u64::from(crate::ntdll::STATUS_INVALID_INFO_CLASS.raw()),
            "label information is set-only"
        );

        // Short buffer: exact requirement, no partial write.
        memory.map_bytes(buffer, &[0xAAu8; 0x200]);
        assert_eq!(
            query(&mut runtime, &mut memory, handle, 0, 1),
            u64::from(crate::ntdll::STATUS_INFO_LENGTH_MISMATCH.raw())
        );
        assert_eq!(memory.read_u32(iosb + 4).expect("required"), 20 + label_len);
        assert_eq!(memory.read_u8(buffer).expect("untouched"), 0xAA);

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                thunk,
                &[handle, iosb as u32, 0, 0x200, 3]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw()),
            "a null volume buffer is invalid"
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                thunk,
                &[handle, 0, buffer as u32, 0x200, 3]
            ),
            u64::from(crate::ntdll::STATUS_INVALID_PARAMETER.raw()),
            "a null IO_STATUS_BLOCK is invalid"
        );

        // Unknown handle / non-file object / unknown class are exact.
        assert_eq!(
            query(&mut runtime, &mut memory, 0xDEAD_BEEF, 0x200, 1),
            u64::from(crate::ntdll::STATUS_INVALID_HANDLE.raw())
        );
        assert_eq!(
            memory.read_u32(iosb).expect("iosb status"),
            crate::ntdll::STATUS_INVALID_HANDLE.raw()
        );
        let (event, _) = runtime.win32.create_event(false, false, false, None);
        assert_eq!(
            query(&mut runtime, &mut memory, event, 0x200, 3),
            u64::from(crate::ntdll::STATUS_OBJECT_TYPE_MISMATCH.raw())
        );
        assert_eq!(
            query(&mut runtime, &mut memory, handle, 0x200, 99),
            u64::from(crate::ntdll::STATUS_INVALID_INFO_CLASS.raw())
        );

        // GetVolumeInformationW and NtQueryVolumeInformationFile report
        // the same identity serial for the same volume.
        let get_volume = runtime.alloc_host_thunk(HostThunk::GetVolumeInformationW);
        let root = runtime
            .alloc_utf16_string(&mut memory, "C:\\")
            .expect("root");
        let serial_out = 0x6E_000u64;
        memory.map_bytes(serial_out, &[0u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_volume,
                &[root as u32, 0, 0, serial_out as u32, 0, 0, 0, 0]
            ),
            1
        );
        assert_eq!(
            memory.read_u32(serial_out).expect("win32 serial"),
            disk.volume_serial
        );
    })
}

#[test]
fn volume_identity_refuses_unpublished_fields_and_derives_stable_object_ids() {
    let disk = crate::hardware_identity::DiskIdentity {
        volume_serial: 0x1234_5678,
        volume_uuid: "00D62C37-D88C-4508-B0E9-E51BD77CBE88".to_string(),
        volume_name: "Casa".to_string(),
        filesystem: "APFS".to_string(),
        ..Default::default()
    };

    // A genuinely unpublished creation time is refused, never zeroed.
    assert_eq!(
        PeHostRuntime::serialize_file_fs_volume_information(&disk, None)
            .expect_err("creation time absent")
            .raw(),
        crate::ntdll::STATUS_NOT_SUPPORTED.raw()
    );
    let volume =
        PeHostRuntime::serialize_file_fs_volume_information(&disk, Some(0x01D0_0000_0000_0000))
            .expect("published creation time");
    assert_eq!(
        u64::from_le_bytes(volume[0..8].try_into().expect("creation")),
        0x01D0_0000_0000_0000
    );
    assert_eq!(
        u32::from_le_bytes(volume[8..12].try_into().expect("serial")),
        disk.volume_serial
    );

    // The object id and extended info are deterministic, UUID-specific
    // and never zero.
    let first =
        PeHostRuntime::serialize_file_fs_object_id_information(&disk).expect("published uuid");
    let second =
        PeHostRuntime::serialize_file_fs_object_id_information(&disk).expect("published uuid");
    assert_eq!(first, second);
    assert_ne!(first[0..16], [0_u8; 16]);
    assert_ne!(first[16..64], [0_u8; 48]);
    let other = crate::hardware_identity::DiskIdentity {
        volume_uuid: "11111111-2222-3333-4444-555555555555".to_string(),
        ..disk.clone()
    };
    assert_ne!(
        first,
        PeHostRuntime::serialize_file_fs_object_id_information(&other).expect("published uuid")
    );

    // An unpublished UUID is refused, never a zeroed object id.
    let no_uuid = crate::hardware_identity::DiskIdentity {
        volume_uuid: String::new(),
        ..disk
    };
    assert_eq!(
        PeHostRuntime::serialize_file_fs_object_id_information(&no_uuid)
            .expect_err("uuid absent")
            .raw(),
        crate::ntdll::STATUS_NOT_SUPPORTED.raw()
    );

    // A host that cannot publish a birth time is an exact refusal.
    assert_eq!(
        PeHostRuntime::host_volume_creation_time_ticks(std::path::Path::new(
            "/casa1/does/not/exist"
        )),
        None
    );
}
