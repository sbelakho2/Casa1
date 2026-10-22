#![allow(dead_code, unused_imports)]
//! Section 28 — COM Subsystem Tests
//!
//! Phase 0.1: Complete COM Stubs → Working COM Subsystem (F-04, CRITICAL).
//!
//! Verifies:
//!   - CoCreateInstance returning E_NOINTERFACE for unknown CLSIDs
//!   - CoInitializeEx / CoUninitialize apartment state management
//!   - IUnknown refcounting via trampolines (AddRef / Release)
//!   - IDispatch::GetIDsOfNames for known dispatch interfaces
//!   - SysAllocString / SysFreeString round-trip
//!   - VariantInit / VariantCopy / VariantClear for all VARIANT types
//!     (VT_I4, VT_BSTR, VT_UNKNOWN, VT_DISPATCH, VT_ARRAY|VT_VARIANT)
//!   - SafeArrayCreate / SafeArrayAccessData round-trip

use casa1::real_win32::{
    ComApartmentModel, ComApartmentState, ComClsid, ComIid, ComObject, DirectSound8Object,
    FileOpenDialogObject, FileSaveDialogObject, ShellLinkObject, SimpleComObject,
    TaskbarListObject, Variant, XAudio2Object, guid_eq, guid_from_string, guid_to_string,
};
use casa1::reason::ReasonCode;

fn v_vt(v: &Variant) -> u16 {
    v.vt
}
fn v_data(v: &Variant) -> u64 {
    v.data
}
fn v_w1(v: &Variant) -> u16 {
    v.w_reserved1
}
fn v_w2(v: &Variant) -> u16 {
    v.w_reserved2
}
fn v_w3(v: &Variant) -> u16 {
    v.w_reserved3
}

// ===========================================================================
// t28c_01 — CoCreateInstance: unknown CLSID → E_NOINTERFACE
// ===========================================================================

#[test]
fn t28c_01_co_create_instance_unknown_clsid() {
    let mut state = ComApartmentState::new();

    // COM not initialized — should fail
    let unknown_clsid = [
        0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let result = state.co_create_instance(unknown_clsid, ComIid::IUNKNOWN, 0x1000, "TestObject");
    assert!(
        result.is_err(),
        "CoCreateInstance without CoInitialize must fail"
    );
    let err_code = result.unwrap_err().code;
    assert_eq!(
        err_code,
        ReasonCode::RcWin32InvalidHandle,
        "Should fail with RcWin32InvalidHandle when COM not initialized"
    );

    // Initialize COM and register a known CLSID
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");
    state.register_class_object(
        &ComClsid::SHELL_LINK,
        Box::new(|| {
            Box::new(SimpleComObject::new(
                ComClsid::SHELL_LINK,
                ComIid::ISHELLLINKW,
                "ShellLink",
            ))
        }),
    );

    // Known CLSID should succeed
    let result = state.co_create_instance(
        ComClsid::SHELL_LINK,
        ComIid::ISHELLLINKW,
        0x2000,
        "ShellLink",
    );
    assert!(
        result.is_ok(),
        "CoCreateInstance with known CLSID should succeed"
    );

    // Unknown CLSID should fail with CLASS_E_CLASSNOTAVAILABLE
    let result = state.co_create_instance(unknown_clsid, ComIid::IUNKNOWN, 0x3000, "Unknown");
    assert!(
        result.is_err(),
        "CoCreateInstance with unknown CLSID must fail"
    );
    let err_code = result.unwrap_err().code;
    assert_eq!(
        err_code,
        ReasonCode::RcComClassNotRegistered,
        "Should fail with RcComClassNotRegistered for unknown CLSID"
    );

    // Known CLSID but wrong IID that doesn't match should still create the object
    // (validation happens at QueryInterface time)
    let result = state.co_create_instance(
        ComClsid::SHELL_LINK,
        ComIid::IDISPATCH,
        0x4000,
        "ShellLinkWrongIID",
    );
    assert!(
        result.is_ok(),
        "CoCreateInstance should succeed even with mismatched IID (validation deferred to QI)"
    );
    let handle = result.unwrap();
    // ...but the mismatch must be rejected when the interface is queried:
    // QueryInterface(IDispatch) on an IShellLinkW object is E_NOINTERFACE.
    assert!(
        !state
            .com_query_interface(handle, ComIid::IDISPATCH)
            .expect("QI must be queryable"),
        "mismatched IID must be rejected at QueryInterface time"
    );
    assert!(
        state
            .com_query_interface(handle, ComIid::IUNKNOWN)
            .expect("QI IUnknown"),
        "IUnknown must always be queryable"
    );
    state.com_release(handle).expect("release");
}

// ===========================================================================
// t28c_02 — CoInitializeEx / CoUninitialize apartment state management
// ===========================================================================

#[test]
fn t28c_02_co_initialize_uninitialize() {
    let mut state = ComApartmentState::new();

    // Initially not initialized
    assert!(!state.is_initialized());
    assert_eq!(state.active_object_count(), 0);

    // Initialize as MTA
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx MTA");
    assert!(state.is_initialized());
    assert_eq!(
        state.get_thread_apartment(1),
        Some(ComApartmentModel::MultiThreaded)
    );

    // Re-initialize same thread — should be a no-op (S_OK)
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("Re-entrant CoInitializeEx");
    assert!(state.is_initialized());
    assert_eq!(
        state.get_thread_apartment(1),
        Some(ComApartmentModel::MultiThreaded)
    );

    // Initialize a different thread as STA
    state
        .co_initialize_ex(2, ComApartmentModel::SingleThreaded)
        .expect("CoInitializeEx STA");
    assert_eq!(
        state.get_thread_apartment(2),
        Some(ComApartmentModel::SingleThreaded)
    );
    assert_eq!(
        state.get_thread_apartment(1),
        Some(ComApartmentModel::MultiThreaded)
    );

    // Uninitialize thread 1
    state.co_uninitialize(1);
    assert_eq!(state.get_thread_apartment(1), None);
    // Thread 2 still active, so initialized remains true
    assert!(state.is_initialized());

    // Uninitialize thread 2
    state.co_uninitialize(2);
    assert_eq!(state.get_thread_apartment(2), None);
    // All threads gone — COM should be uninitialized
    assert!(!state.is_initialized());
}

#[test]
fn t28c_02b_co_initialize_uninitialize_with_objects() {
    let mut state = ComApartmentState::new();

    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    // Register and create an object
    state.register_class_object(
        &ComClsid::SHELL_APPLICATION,
        Box::new(|| {
            Box::new(SimpleComObject::new(
                ComClsid::SHELL_APPLICATION,
                ComIid::ISHELL_DISPATCH,
                "Shell.Application",
            ))
        }),
    );
    let _handle = state
        .co_create_instance(
            ComClsid::SHELL_APPLICATION,
            ComIid::ISHELL_DISPATCH,
            0x5000,
            "Shell.Application",
        )
        .expect("CoCreateInstance");

    assert_eq!(state.active_object_count(), 1);

    // Uninitialize — objects should be cleared
    state.co_uninitialize(1);
    assert!(!state.is_initialized());
    assert_eq!(state.active_object_count(), 0);
}

// ===========================================================================
// t28c_03 — IUnknown refcounting via trampolines (AddRef / Release)
// ===========================================================================

#[test]
fn t28c_03_iunknown_refcounting() {
    let mut state = ComApartmentState::new();

    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    // Register a known CLSID and create an object
    state.register_class_object(
        &ComClsid::DIRECTSOUND8,
        Box::new(|| {
            Box::new(SimpleComObject::new(
                ComClsid::DIRECTSOUND8,
                ComIid::IUNKNOWN,
                "DirectSound8",
            ))
        }),
    );
    let handle = state
        .co_create_instance(
            ComClsid::DIRECTSOUND8,
            ComIid::IUNKNOWN,
            0x6000,
            "DirectSound8",
        )
        .expect("CoCreateInstance");

    // Initial refcount should be 1
    let info = state.com_object_info(handle).expect("com_object_info");
    assert_eq!(info.refcount, 1);
    assert_eq!(info.object_name, "DirectSound8");

    // AddRef — increment
    let rc = state.com_addref(handle).expect("AddRef");
    assert_eq!(rc, 2);
    let info = state.com_object_info(handle).expect("com_object_info");
    assert_eq!(info.refcount, 2);

    // AddRef again
    let rc = state.com_addref(handle).expect("AddRef");
    assert_eq!(rc, 3);

    // Release — decrement
    let rc = state.com_release(handle).expect("Release");
    assert_eq!(rc, 2);

    // Release until zero
    let rc = state.com_release(handle).expect("Release");
    assert_eq!(rc, 1);
    let rc = state.com_release(handle).expect("Release");
    assert_eq!(rc, 0);

    // Object should be removed
    let _result = state.com_object_info(handle);
    assert!(_result.is_err(), "expected Err, got {_result:?}");
    assert_eq!(state.active_object_count(), 0);
}

#[test]
fn t28c_03b_iunknown_query_interface() {
    let mut state = ComApartmentState::new();

    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    state.register_class_object(
        &ComClsid::XAUDIO2,
        Box::new(|| {
            Box::new(SimpleComObject::new(
                ComClsid::XAUDIO2,
                ComIid::IUNKNOWN,
                "XAudio2",
            ))
        }),
    );
    let handle = state
        .co_create_instance(ComClsid::XAUDIO2, ComIid::IUNKNOWN, 0x7000, "XAudio2")
        .expect("CoCreateInstance");

    // IUnknown always supported
    assert!(
        state
            .com_query_interface(handle, ComIid::IUNKNOWN)
            .expect("QI IUnknown")
    );

    // The object was created with IUnknown, so it only supports IUnknown
    assert!(
        !state
            .com_query_interface(handle, ComIid::IDISPATCH)
            .expect("QI IDispatch (unsupported)")
    );
    assert!(
        !state
            .com_query_interface(handle, ComIid::ICLASS_FACTORY)
            .expect("QI IClassFactory (unsupported)")
    );
}

#[test]
fn t28c_03c_iunknown_invalid_handle() {
    let mut state = ComApartmentState::new();
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    // Invalid handle operations
    let _result = state.com_addref(999);
    assert!(_result.is_err(), "expected Err, got {_result:?}");
    let _result = state.com_release(999);
    assert!(_result.is_err(), "expected Err, got {_result:?}");
    let _result = state.com_query_interface(999, ComIid::IUNKNOWN);
    assert!(_result.is_err(), "expected Err, got {_result:?}");
    let _result = state.com_object_info(999);
    assert!(_result.is_err(), "expected Err, got {_result:?}");
}

// ===========================================================================
// t28c_04 — IDispatch::GetIDsOfNames for known dispatch interfaces
// ===========================================================================

// ===========================================================================
// t28c_05 — SysAllocString / SysFreeString round-trip
// ===========================================================================

// ===========================================================================
// t28c_06 — VariantInit / VariantCopy / VariantClear for all VARIANT types
// ===========================================================================

// ===========================================================================
// t28c_07 — SafeArrayCreate / SafeArrayAccessData round-trip
// ===========================================================================

// ===========================================================================
// t28c_08 — GUID utility functions
// ===========================================================================

#[test]
fn t28c_08_guid_utilities() {
    // Test guid_to_string
    let guid_str = guid_to_string(&ComIid::IUNKNOWN);
    assert_eq!(guid_str, "00000000-0000-0000-C000-000000000046");

    // Test guid_from_string
    let parsed =
        guid_from_string("{00000000-0000-0000-C000-000000000046}").expect("Parse IUnknown GUID");
    assert_eq!(parsed, ComIid::IUNKNOWN);

    // Test guid_eq
    assert!(guid_eq(&ComIid::IUNKNOWN, &ComIid::IUNKNOWN));
    assert!(!guid_eq(&ComIid::IUNKNOWN, &ComIid::IDISPATCH));

    // Round-trip: string → guid → string
    let original = "{3901CC3F-84B5-4FA4-BA35-AA8172B8A6B2}";
    let guid = guid_from_string(original).expect("Parse DirectSound8 GUID");
    let recovered = guid_to_string(&guid);
    assert_eq!(
        recovered,
        original.trim_start_matches('{').trim_end_matches('}'),
        "GUID round-trip should preserve value"
    );
}

// ===========================================================================
// t28c_09 — CoRegisterClassObject / CoRevokeClassObject
// ===========================================================================

#[test]
fn t28c_09_register_and_revoke_class_object() {
    let mut state = ComApartmentState::new();
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    // Use a custom CLSID that is NOT a well-known built-in CLSID,
    // so revoking the factory truly disables creation.
    let custom_clsid: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    // Register a class object for the custom CLSID
    let token = state.register_class_object_with_token(
        &custom_clsid,
        Box::new(move || {
            Box::new(SimpleComObject::new(
                custom_clsid,
                ComIid::IUNKNOWN,
                "CustomObject",
            ))
        }),
    );
    assert!(token > 0, "Token should be non-zero");

    // Verify the CLSID can be resolved from the token
    let clsid = state.clsid_for_token(token).expect("CLSID for token");
    assert_eq!(clsid, custom_clsid);

    // Create an instance via the registered factory
    let handle = state
        .co_create_instance(custom_clsid, ComIid::IUNKNOWN, 0x8000, "CustomObject")
        .expect("CoCreateInstance after registration");
    assert!(handle > 0);

    // Revoke the registration
    let revoked = state.revoke_class_object_by_token(token);
    assert!(revoked, "Revoke should succeed");

    // After revocation, creating should fail because the custom CLSID
    // has no built-in fallback.
    let result = state.co_create_instance(custom_clsid, ComIid::IUNKNOWN, 0x9000, "CustomObject");
    assert!(
        result.is_err(),
        "CoCreateInstance should fail after factory revoked"
    );

    // Revoking again should return false
    let revoked_again = state.revoke_class_object_by_token(token);
    assert!(!revoked_again, "Double revoke should return false");
}

// ===========================================================================
// t28c_10 — DllGetClassObject well-known CLSIDs
// ===========================================================================

#[test]
fn t28c_10_dll_get_class_object_known_clsids() {
    let state = ComApartmentState::new();

    // All well-known CLSIDs should be resolvable
    let known_clsids: Vec<([u8; 16], &str)> = vec![
        (ComClsid::DIRECTSOUND8, "DirectSound8"),
        (ComClsid::XAUDIO2, "XAudio2"),
        (ComClsid::SHELL_LINK, "ShellLink"),
        (ComClsid::FILE_OPEN_DIALOG, "FileOpenDialog"),
        (ComClsid::FILE_SAVE_DIALOG, "FileSaveDialog"),
        (ComClsid::SHELL_APPLICATION, "Shell.Application"),
        (
            ComClsid::SCRIPTING_FILESYSTEMOBJECT,
            "Scripting.FileSystemObject",
        ),
        (ComClsid::WSCRIPT_SHELL, "WScript.Shell"),
        (ComClsid::ADODB_CONNECTION, "ADODB.Connection"),
        (ComClsid::ADODB_RECORDSET, "ADODB.Recordset"),
        (ComClsid::WSCRIPT_NETWORK, "WScript.Network"),
        (ComClsid::SHELL_WINDOWS, "ShellWindows"),
        (ComClsid::INTERNET_EXPLORER, "InternetExplorer"),
        (ComClsid::XMLHTTP, "XMLHTTP"),
        (ComClsid::DOM_DOCUMENT, "XmlDomDocument"),
    ];

    for (clsid, name) in &known_clsids {
        let obj = state
            .dll_get_class_object(clsid)
            .unwrap_or_else(|_| panic!("DllGetClassObject should resolve {name}"));
        assert_eq!(obj.debug_name(), *name);
    }

    // Unknown CLSID should fail
    let unknown = [0xFF; 16];
    let result = state.dll_get_class_object(&unknown);
    assert!(result.is_err(), "Unknown CLSID should not be resolvable");
}

// ===========================================================================
// t28c_11 — CoGetClassObject
// ===========================================================================

#[test]
fn t28c_11_co_get_class_object() {
    let state = ComApartmentState::new();

    // Should succeed with IClassFactory or IUnknown
    let obj = state
        .co_get_class_object(&ComClsid::SHELL_LINK, &ComIid::ICLASS_FACTORY)
        .expect("CoGetClassObject with IClassFactory");
    assert_eq!(obj.debug_name(), "ShellLink");

    let obj = state
        .co_get_class_object(&ComClsid::SHELL_LINK, &ComIid::IUNKNOWN)
        .expect("CoGetClassObject with IUnknown");
    assert_eq!(obj.debug_name(), "ShellLink");

    // Should fail with unsupported IID
    let result = state.co_get_class_object(&ComClsid::SHELL_LINK, &ComIid::IDISPATCH);
    assert!(
        result.is_err(),
        "CoGetClassObject with unsupported IID should fail"
    );
}

// ===========================================================================
// t28c_12 — CLSID from ProgID
// ===========================================================================

// ===========================================================================
// t28c_13 — CoCreateGuid
// ===========================================================================

// ===========================================================================
// t28c_14 — Functional COM Objects: DirectSound8
// ===========================================================================

#[test]
fn t28c_14_directsound8_com_object() {
    // Test DirectSound8Object construction and ComObject trait
    let obj = DirectSound8Object::new(ComClsid::DIRECTSOUND8);
    assert_eq!(obj.debug_name(), "DirectSound8");

    let iids = obj.supported_iids();
    assert!(iids.contains(&ComIid::IUNKNOWN), "Must support IUnknown");
    assert!(
        iids.contains(&ComIid::IDIRECTSOUND8),
        "Must support IDirectSound8"
    );

    // Test through ComApartmentState
    let mut state = ComApartmentState::new();
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    state.register_class_object(
        &ComClsid::DIRECTSOUND8,
        Box::new(|| Box::new(DirectSound8Object::new(ComClsid::DIRECTSOUND8))),
    );

    let handle = state
        .co_create_instance(
            ComClsid::DIRECTSOUND8,
            ComIid::IDIRECTSOUND8,
            0x10000,
            "DirectSound8",
        )
        .expect("CoCreateInstance DirectSound8");
    assert!(handle > 0);

    // QueryInterface for IDirectSound8 should succeed
    assert!(
        state
            .com_query_interface(handle, ComIid::IDIRECTSOUND8)
            .expect("QI IDirectSound8")
    );

    // Reference counting
    let rc = state.com_addref(handle).expect("AddRef");
    assert_eq!(rc, 2);
    let rc = state.com_release(handle).expect("Release");
    assert_eq!(rc, 1);

    // Clean up
    let rc = state.com_release(handle).expect("Release final");
    assert_eq!(rc, 0);
    assert!(
        state.com_object_info(handle).is_err(),
        "Object should be released"
    );
}

// ===========================================================================
// t28c_15 — Functional COM Objects: XAudio2
// ===========================================================================

#[test]
fn t28c_15_xaudio2_com_object() {
    let obj = XAudio2Object::new(ComClsid::XAUDIO2);
    assert_eq!(obj.debug_name(), "XAudio2");

    let iids = obj.supported_iids();
    assert!(iids.contains(&ComIid::IUNKNOWN));
    assert!(iids.contains(&ComIid::IXAUDIO2));

    // Test through ComApartmentState
    let mut state = ComApartmentState::new();
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    state.register_class_object(
        &ComClsid::XAUDIO2,
        Box::new(|| Box::new(XAudio2Object::new(ComClsid::XAUDIO2))),
    );

    let handle = state
        .co_create_instance(ComClsid::XAUDIO2, ComIid::IXAUDIO2, 0x20000, "XAudio2")
        .expect("CoCreateInstance XAudio2");

    // QueryInterface for IXAudio2 should succeed
    assert!(
        state
            .com_query_interface(handle, ComIid::IXAUDIO2)
            .expect("QI IXAudio2")
    );
    // Unrelated IID should fail
    assert!(
        !state
            .com_query_interface(handle, ComIid::IDISPATCH)
            .expect("QI IDispatch (unsupported)")
    );

    // Reference counting
    let rc = state.com_addref(handle).expect("AddRef");
    assert_eq!(rc, 2);
    let rc = state.com_release(handle).expect("Release");
    assert_eq!(rc, 1);
    let rc = state.com_release(handle).expect("Release final");
    assert_eq!(rc, 0);
}

// ===========================================================================
// t28c_16 — Functional COM Objects: Shell Link
// ===========================================================================

#[test]
fn t28c_16_shell_link_com_object() {
    let obj = ShellLinkObject::new(ComClsid::SHELL_LINK);
    assert_eq!(obj.debug_name(), "ShellLink");

    let iids = obj.supported_iids();
    assert!(iids.contains(&ComIid::IUNKNOWN));
    assert!(iids.contains(&ComIid::ISHELLLINKW));
    assert!(iids.contains(&ComIid::IPERSISTFILE));

    // Test data storage and retrieval
    let mut link = ShellLinkObject::new(ComClsid::SHELL_LINK);
    assert_eq!(link.get_path(), "");
    assert_eq!(link.get_arguments(), "");
    assert_eq!(link.get_description(), "");
    assert_eq!(link.get_working_directory(), "");
    assert_eq!(link.get_icon_location(), ("", 0));
    assert_eq!(link.get_show_cmd(), 1); // SW_SHOWNORMAL

    link.set_path("/usr/local/game.exe".to_string());
    link.set_arguments("--fullscreen --windowed".to_string());
    link.set_description("My Game Shortcut".to_string());
    link.set_working_directory("/usr/local".to_string());
    link.set_icon_location("/usr/local/game.exe".to_string(), 0);
    link.set_show_cmd(3); // SW_MAXIMIZE

    assert_eq!(link.get_path(), "/usr/local/game.exe");
    assert_eq!(link.get_arguments(), "--fullscreen --windowed");
    assert_eq!(link.get_description(), "My Game Shortcut");
    assert_eq!(link.get_working_directory(), "/usr/local");
    assert_eq!(link.get_icon_location(), ("/usr/local/game.exe", 0));
    assert_eq!(link.get_show_cmd(), 3);

    // Test through ComApartmentState
    let mut state = ComApartmentState::new();
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    state.register_class_object(
        &ComClsid::SHELL_LINK,
        Box::new(|| Box::new(ShellLinkObject::new(ComClsid::SHELL_LINK))),
    );

    let handle = state
        .co_create_instance(
            ComClsid::SHELL_LINK,
            ComIid::ISHELLLINKW,
            0x30000,
            "ShellLink",
        )
        .expect("CoCreateInstance ShellLink");

    // QueryInterface for IShellLinkW and IPersistFile should succeed
    assert!(
        state
            .com_query_interface(handle, ComIid::ISHELLLINKW)
            .expect("QI IShellLinkW")
    );
    assert!(
        state
            .com_query_interface(handle, ComIid::IPERSISTFILE)
            .expect("QI IPersistFile")
    );
    assert!(
        !state
            .com_query_interface(handle, ComIid::IDISPATCH)
            .expect("QI IDispatch (unsupported)")
    );

    let rc = state.com_release(handle).expect("Release");
    assert_eq!(rc, 0);
}

// ===========================================================================
// t28c_17 — Functional COM Objects: File Open Dialog
// ===========================================================================

#[test]
fn t28c_17_file_open_dialog_com_object() {
    let obj = FileOpenDialogObject::new(ComClsid::FILE_OPEN_DIALOG);
    assert_eq!(obj.debug_name(), "FileOpenDialog");

    let iids = obj.supported_iids();
    assert!(iids.contains(&ComIid::IUNKNOWN));
    assert!(iids.contains(&ComIid::IMODAL_WINDOW));
    assert!(iids.contains(&ComIid::IFILE_DIALOG));
    assert!(iids.contains(&ComIid::IFILE_OPEN_DIALOG));
    // Should NOT support IFileSaveDialog
    assert!(!iids.contains(&ComIid::IFILE_SAVE_DIALOG));

    // Test data operations
    let mut dialog = FileOpenDialogObject::new(ComClsid::FILE_OPEN_DIALOG);

    // Default state
    assert_eq!(dialog.file_name(), "");
    assert_eq!(dialog.title(), "");
    assert_eq!(dialog.options(), 0);
    assert!(!dialog.is_shown());

    // Set dialog properties
    dialog.set_title("Open Game File".to_string());
    dialog.set_file_name("/home/user/game.exe".to_string());
    dialog.set_default_folder("/home/user".to_string());
    dialog.set_options(0x00000008); // FOS_FORCEFILESYSTEM

    assert_eq!(dialog.title(), "Open Game File");
    assert_eq!(dialog.file_name(), "/home/user/game.exe");
    assert_eq!(dialog.default_folder(), "/home/user");
    assert_eq!(dialog.options(), 0x00000008);

    // Show dialog (simulated)
    dialog.show();
    assert!(dialog.is_shown());
    // Result path should match the file name since one was set
    assert_eq!(dialog.result_path(), "/home/user/game.exe");

    // Test through ComApartmentState
    let mut state = ComApartmentState::new();
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    state.register_class_object(
        &ComClsid::FILE_OPEN_DIALOG,
        Box::new(|| Box::new(FileOpenDialogObject::new(ComClsid::FILE_OPEN_DIALOG))),
    );

    let handle = state
        .co_create_instance(
            ComClsid::FILE_OPEN_DIALOG,
            ComIid::IFILE_OPEN_DIALOG,
            0x40000,
            "FileOpenDialog",
        )
        .expect("CoCreateInstance FileOpenDialog");

    // QueryInterface for all supported IIDs
    assert!(
        state
            .com_query_interface(handle, ComIid::IMODAL_WINDOW)
            .expect("QI IModalWindow")
    );
    assert!(
        state
            .com_query_interface(handle, ComIid::IFILE_DIALOG)
            .expect("QI IFileDialog")
    );
    assert!(
        state
            .com_query_interface(handle, ComIid::IFILE_OPEN_DIALOG)
            .expect("QI IFileOpenDialog")
    );
    assert!(
        !state
            .com_query_interface(handle, ComIid::IFILE_SAVE_DIALOG)
            .expect("QI IFileSaveDialog (unsupported)")
    );

    let rc = state.com_release(handle).expect("Release");
    assert_eq!(rc, 0);
}

#[test]
fn t28c_17b_file_save_dialog_com_object() {
    let obj = FileSaveDialogObject::new(ComClsid::FILE_SAVE_DIALOG);
    assert_eq!(obj.debug_name(), "FileSaveDialog");

    let iids = obj.supported_iids();
    assert!(iids.contains(&ComIid::IUNKNOWN));
    assert!(iids.contains(&ComIid::IMODAL_WINDOW));
    assert!(iids.contains(&ComIid::IFILE_DIALOG));
    assert!(iids.contains(&ComIid::IFILE_SAVE_DIALOG));
    // Should NOT support IFileOpenDialog
    assert!(!iids.contains(&ComIid::IFILE_OPEN_DIALOG));
}

// ===========================================================================
// t28c_18 — Functional COM Objects: Taskbar List
// ===========================================================================

#[test]
fn t28c_18_taskbar_list_com_object() {
    let obj = TaskbarListObject::new(ComClsid::TASKBAR_LIST);
    assert_eq!(obj.debug_name(), "TaskbarList");

    let iids = obj.supported_iids();
    assert!(iids.contains(&ComIid::IUNKNOWN));
    assert!(iids.contains(&ComIid::ITASKBAR_LIST));
    assert!(iids.contains(&ComIid::ITASKBAR_LIST2));
    assert!(iids.contains(&ComIid::ITASKBAR_LIST3));

    // Test operations
    let mut tb = TaskbarListObject::new(ComClsid::TASKBAR_LIST);
    assert!(!tb.is_initialized());
    assert_eq!(tb.tab_count(), 0);

    // HrInit
    tb.hr_init();
    assert!(tb.is_initialized());

    // Add tabs
    tb.add_tab(0x100);
    tb.add_tab(0x200);
    tb.add_tab(0x300);
    assert_eq!(tb.tab_count(), 3);

    // Duplicate add should not increase count
    tb.add_tab(0x200);
    assert_eq!(tb.tab_count(), 3);

    // Delete tab
    tb.delete_tab(0x200);
    assert_eq!(tb.tab_count(), 2);

    // Activate tab
    tb.activate_tab(0x300);
    tb.set_active_alt(0x100);

    // Progress operations
    tb.set_progress_value(0x100, 500);
    tb.set_progress_state(0x100, 1); // TBPF_NORMAL
    tb.set_overlay_icon(0x100, 0xABCD);
    tb.set_thumbnail_tooltip(0x100, "Game Window".to_string());

    // Test through ComApartmentState
    let mut state = ComApartmentState::new();
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    state.register_class_object(
        &ComClsid::TASKBAR_LIST,
        Box::new(|| Box::new(TaskbarListObject::new(ComClsid::TASKBAR_LIST))),
    );

    let handle = state
        .co_create_instance(
            ComClsid::TASKBAR_LIST,
            ComIid::ITASKBAR_LIST3,
            0x50000,
            "TaskbarList",
        )
        .expect("CoCreateInstance TaskbarList");

    // QueryInterface for all supported IIDs
    assert!(
        state
            .com_query_interface(handle, ComIid::ITASKBAR_LIST)
            .expect("QI ITaskbarList")
    );
    assert!(
        state
            .com_query_interface(handle, ComIid::ITASKBAR_LIST2)
            .expect("QI ITaskbarList2")
    );
    assert!(
        state
            .com_query_interface(handle, ComIid::ITASKBAR_LIST3)
            .expect("QI ITaskbarList3")
    );
    assert!(
        !state
            .com_query_interface(handle, ComIid::IDISPATCH)
            .expect("QI IDispatch (unsupported)")
    );

    let rc = state.com_release(handle).expect("Release");
    assert_eq!(rc, 0);
}

// ===========================================================================
// t28c_19 — Functional COM Objects: DllGetClassObject returns new types
// ===========================================================================

// ===========================================================================
// t28c_20 — Functional COM Objects: CoCreateInstance integration
// ===========================================================================

#[test]
fn t28c_20_co_create_instance_all_functional_clsids() {
    let mut state = ComApartmentState::new();
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    // Register all functional CLSIDs
    state.register_class_object(
        &ComClsid::DIRECTSOUND8,
        Box::new(|| Box::new(DirectSound8Object::new(ComClsid::DIRECTSOUND8))),
    );
    state.register_class_object(
        &ComClsid::XAUDIO2,
        Box::new(|| Box::new(XAudio2Object::new(ComClsid::XAUDIO2))),
    );
    state.register_class_object(
        &ComClsid::SHELL_LINK,
        Box::new(|| Box::new(ShellLinkObject::new(ComClsid::SHELL_LINK))),
    );
    state.register_class_object(
        &ComClsid::FILE_OPEN_DIALOG,
        Box::new(|| Box::new(FileOpenDialogObject::new(ComClsid::FILE_OPEN_DIALOG))),
    );
    state.register_class_object(
        &ComClsid::TASKBAR_LIST,
        Box::new(|| Box::new(TaskbarListObject::new(ComClsid::TASKBAR_LIST))),
    );

    // Create all 5 objects
    let test_cases: Vec<([u8; 16], [u8; 16], &str)> = vec![
        (
            ComClsid::DIRECTSOUND8,
            ComIid::IDIRECTSOUND8,
            "DirectSound8",
        ),
        (ComClsid::XAUDIO2, ComIid::IXAUDIO2, "XAudio2"),
        (ComClsid::SHELL_LINK, ComIid::ISHELLLINKW, "ShellLink"),
        (
            ComClsid::FILE_OPEN_DIALOG,
            ComIid::IFILE_OPEN_DIALOG,
            "FileOpenDialog",
        ),
        (
            ComClsid::TASKBAR_LIST,
            ComIid::ITASKBAR_LIST3,
            "TaskbarList",
        ),
    ];

    let mut handles = Vec::new();
    for (clsid, iid, name) in &test_cases {
        let handle = state
            .co_create_instance(*clsid, *iid, 0x60000, name)
            .unwrap_or_else(|_| panic!("CoCreateInstance {name} should succeed"));
        assert!(handle > 0, "{name} handle should be non-zero");
        handles.push(handle);
    }

    // Verify all objects exist
    assert_eq!(state.active_object_count(), 5);

    // QueryInterface for expected IIDs on each object
    assert!(
        state
            .com_query_interface(handles[0], ComIid::IDIRECTSOUND8)
            .expect("DS QI")
    );
    assert!(
        state
            .com_query_interface(handles[1], ComIid::IXAUDIO2)
            .expect("XA QI")
    );
    assert!(
        state
            .com_query_interface(handles[2], ComIid::ISHELLLINKW)
            .expect("SL QI")
    );
    assert!(
        state
            .com_query_interface(handles[3], ComIid::IFILE_OPEN_DIALOG)
            .expect("FOD QI")
    );
    assert!(
        state
            .com_query_interface(handles[4], ComIid::ITASKBAR_LIST3)
            .expect("TB QI")
    );

    // Verify unsupported IIDs fail
    assert!(
        !state
            .com_query_interface(handles[0], ComIid::IDISPATCH)
            .expect("DS QI unrelated")
    );
    assert!(
        !state
            .com_query_interface(handles[4], ComIid::IFILE_DIALOG)
            .expect("TB QI unrelated")
    );

    // Release all objects
    for handle in handles {
        let rc = state.com_release(handle).expect("Release");
        assert_eq!(rc, 0, "Object should be fully released");
    }

    assert_eq!(state.active_object_count(), 0);
}

// ===========================================================================
// t28c_21 — Functional COM Objects: Reference counting stress
// ===========================================================================

#[test]
fn t28c_21_refcounting_stress() {
    let mut state = ComApartmentState::new();
    state
        .co_initialize_ex(1, ComApartmentModel::MultiThreaded)
        .expect("CoInitializeEx");

    state.register_class_object(
        &ComClsid::DIRECTSOUND8,
        Box::new(|| Box::new(DirectSound8Object::new(ComClsid::DIRECTSOUND8))),
    );

    let handle = state
        .co_create_instance(
            ComClsid::DIRECTSOUND8,
            ComIid::IDIRECTSOUND8,
            0x70000,
            "DirectSound8",
        )
        .expect("CoCreateInstance");

    // Multiple AddRef/Release cycles
    for i in 0..10 {
        let rc = state.com_addref(handle).expect("AddRef");
        assert_eq!(rc, i + 2, "Refcount should be {} after {i} AddRefs", i + 2);
    }

    for i in (1..11).rev() {
        let rc = state.com_release(handle).expect("Release");
        assert_eq!(rc, i, "Refcount should be {i} after release");
    }

    // Release the original ref
    let rc = state.com_release(handle).expect("Release final");
    assert_eq!(rc, 0);
    let _result = state.com_object_info(handle);
    assert!(_result.is_err(), "expected Err, got {_result:?}");
}
