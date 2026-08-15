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
    ComApartmentModel, ComApartmentState, ComClsid, ComIid, ComObject, DISPATCH_PROPERTYGET,
    DISPATCH_PROPERTYPUT, DISPID_UNKNOWN, DISPID_VALUE, DirectSound8Object,
    DirectSoundBuffer8Object, DispatchInterface, FileOpenDialogObject, FileSaveDialogObject,
    ShellLinkObject, SimpleComObject, TaskbarListObject, VT_ARRAY, VT_BOOL, VT_BSTR, VT_DISPATCH,
    VT_EMPTY, VT_I4, VT_NULL, VT_UNKNOWN, VT_VARIANT, Variant, XAudio2MasteringVoiceObject,
    XAudio2Object, XAudio2SourceVoiceObject, XAudio2SubmixVoiceObject, dispatch_get_ids_of_names,
    dispatch_invoke, guid_eq, guid_from_string, guid_to_string, safe_array_access_data,
    safe_array_create_vector, safe_array_destroy, safe_array_get_element, safe_array_get_lbound,
    safe_array_get_ubound, safe_array_put_element, safe_array_unaccess_data, sys_alloc_string,
    sys_alloc_string_len, sys_free_string, sys_string_len, variant_clear, variant_copy,
    variant_init,
};
use casa1::reason::ReasonCode;
use std::collections::BTreeMap;

/// Copy Variant.vt to a local to avoid packed-field reference UB.
fn v_vt(v: &Variant) -> u16 {
    v.vt
}
/// Copy Variant.data to a local to avoid packed-field reference UB.
fn v_data(v: &Variant) -> u64 {
    v.data
}
/// Copy Variant.w_reserved1 to a local.
fn v_w1(v: &Variant) -> u16 {
    v.w_reserved1
}
/// Copy Variant.w_reserved2 to a local.
fn v_w2(v: &Variant) -> u16 {
    v.w_reserved2
}
/// Copy Variant.w_reserved3 to a local.
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

#[test]
fn t28c_04_dispatch_get_ids_of_names() {
    // Create a PropertyBag dispatch interface with some known properties
    let mut bag: BTreeMap<String, Variant> = BTreeMap::new();
    bag.insert(
        "name".to_string(),
        Variant {
            vt: VT_BSTR,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: 0,
        },
    );
    bag.insert(
        "value".to_string(),
        Variant {
            vt: VT_I4,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: 42,
        },
    );
    bag.insert(
        "enabled".to_string(),
        Variant {
            vt: VT_BOOL,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: 1,
        },
    );

    let dispatch = DispatchInterface::PropertyBag(bag);

    // Test known names
    let ids = dispatch_get_ids_of_names(
        &dispatch,
        &[
            "name".to_string(),
            "value".to_string(),
            "enabled".to_string(),
        ],
    )
    .expect("GetIDsOfNames for known names");

    assert_eq!(ids.rgdispid.len(), 3);
    assert!(ids.rgdispid[0] > 0, "name should have a valid DISPID");
    assert!(ids.rgdispid[1] > 0, "value should have a valid DISPID");
    assert!(ids.rgdispid[2] > 0, "enabled should have a valid DISPID");

    // Test unknown name → DISPID_UNKNOWN
    let ids = dispatch_get_ids_of_names(&dispatch, &["nonexistent".to_string()])
        .expect("GetIDsOfNames for unknown name");

    assert_eq!(ids.rgdispid.len(), 1);
    assert_eq!(ids.rgdispid[0], DISPID_UNKNOWN);

    // Test mixed known/unknown
    let ids = dispatch_get_ids_of_names(
        &dispatch,
        &[
            "value".to_string(),
            "unknown1".to_string(),
            "name".to_string(),
        ],
    )
    .expect("GetIDsOfNames for mixed names");

    assert_eq!(ids.rgdispid.len(), 3);
    assert!(ids.rgdispid[0] > 0, "known name should get valid DISPID");
    assert_eq!(ids.rgdispid[1], DISPID_UNKNOWN);
    assert!(ids.rgdispid[2] > 0, "known name should get valid DISPID");

    // Test empty name → DISPID_VALUE
    let ids = dispatch_get_ids_of_names(&dispatch, &["".to_string()])
        .expect("GetIDsOfNames for empty name (DISPID_VALUE)");
    assert_eq!(ids.rgdispid[0], DISPID_VALUE);
}

#[test]
fn t28c_04b_dispatch_invoke_property_get() {
    let mut bag: BTreeMap<String, Variant> = BTreeMap::new();
    bag.insert(
        "count".to_string(),
        Variant {
            vt: VT_I4,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: 100,
        },
    );

    let mut dispatch = DispatchInterface::PropertyBag(bag);

    // Get IDs first
    let ids = dispatch_get_ids_of_names(&dispatch, &["count".to_string()]).expect("GetIDsOfNames");
    let dispid = ids.rgdispid[0];
    assert!(dispid > 0);

    // Invoke property get
    let result = dispatch_invoke(
        &mut dispatch,
        dispid,
        0, // lcid
        DISPATCH_PROPERTYGET,
        &[], // no params for property get
    )
    .expect("Invoke property get");

    assert_eq!(v_vt(&result.result), VT_I4);
    assert_eq!(v_data(&result.result), 100);
    assert!(result.excp_info.is_none());
}

#[test]
fn t28c_04c_dispatch_invoke_property_put() {
    let mut bag: BTreeMap<String, Variant> = BTreeMap::new();
    bag.insert(
        "enabled".to_string(),
        Variant {
            vt: VT_BOOL,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: 0,
        },
    );

    let mut dispatch = DispatchInterface::PropertyBag(bag);

    // Get IDs first
    let ids =
        dispatch_get_ids_of_names(&dispatch, &["enabled".to_string()]).expect("GetIDsOfNames");
    let dispid = ids.rgdispid[0];
    assert!(dispid > 0);

    // Invoke property put
    let new_val = Variant {
        vt: VT_BOOL,
        w_reserved1: 0,
        w_reserved2: 0,
        w_reserved3: 0,
        data: 1,
    };
    let result = dispatch_invoke(
        &mut dispatch,
        dispid,
        0, // lcid
        DISPATCH_PROPERTYPUT,
        &[new_val],
    )
    .expect("Invoke property put");

    assert_eq!(v_vt(&result.result), VT_EMPTY);

    // Verify the value was updated by reading it back
    let ids2 = dispatch_get_ids_of_names(&dispatch, &["enabled".to_string()])
        .expect("GetIDsOfNames (re-read)");
    let read_result = dispatch_invoke(
        &mut dispatch,
        ids2.rgdispid[0],
        0,
        DISPATCH_PROPERTYGET,
        &[],
    )
    .expect("Invoke property get (re-read)");

    assert_eq!(
        v_data(&read_result.result),
        1,
        "Property value should have been updated"
    );
}

// ===========================================================================
// t28c_05 — SysAllocString / SysFreeString round-trip
// ===========================================================================

#[test]
fn t28c_05_sys_alloc_string_round_trip() {
    // Test empty string
    let empty: Vec<u16> = vec![];
    let bstr = sys_alloc_string(&empty);
    // BSTR: 4 bytes length prefix (0), then null terminator (2 bytes)
    assert!(
        bstr.len() >= 4,
        "BSTR must have at least a 4-byte length prefix"
    );
    let bstr_len = u32::from_le_bytes([bstr[0], bstr[1], bstr[2], bstr[3]]);
    assert_eq!(bstr_len, 0, "Empty BSTR should have length 0");
    assert_eq!(
        sys_string_len(&bstr),
        0,
        "SysStringLen should return 0 for empty BSTR"
    );

    // Free should be a no-op (no crash)
    sys_free_string(0);

    // Test with a simple ASCII string
    let hello: Vec<u16> = "Hello".encode_utf16().collect();
    let bstr = sys_alloc_string(&hello);
    let bstr_len = u32::from_le_bytes([bstr[0], bstr[1], bstr[2], bstr[3]]);
    assert_eq!(
        bstr_len, 10,
        "BSTR byte-length prefix should be 10 for 'Hello' (5 UTF-16 chars × 2)"
    );
    assert_eq!(
        sys_string_len(&bstr),
        5,
        "SysStringLen should return 5 characters for 'Hello'"
    );

    // Verify the string content (after 4-byte length prefix)
    let content: Vec<u16> = bstr[4..]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    assert_eq!(content, hello);

    // Test with Unicode characters
    let unicode: Vec<u16> = "Café".encode_utf16().collect();
    let bstr = sys_alloc_string(&unicode);
    assert_eq!(
        sys_string_len(&bstr),
        4,
        "BSTR length should be 4 for 'Café'"
    );
}

#[test]
fn t28c_05b_sys_alloc_string_len() {
    // Allocate with explicit length (shorter than source)
    let wide: Vec<u16> = "Hello World".encode_utf16().collect();
    let bstr = sys_alloc_string_len(&wide, 5);
    assert_eq!(
        sys_string_len(&bstr),
        5,
        "SysAllocStringLen with limit should return 5"
    );

    // Allocate with length longer than source
    let short: Vec<u16> = "Hi".encode_utf16().collect();
    let bstr = sys_alloc_string_len(&short, 10);
    assert_eq!(
        sys_string_len(&bstr),
        2,
        "SysAllocStringLen should clamp to source length"
    );
}

// ===========================================================================
// t28c_06 — VariantInit / VariantCopy / VariantClear for all VARIANT types
// ===========================================================================

#[test]
fn t28c_06_variant_init() {
    let v = variant_init();
    assert_eq!(v_vt(&v), VT_EMPTY);
    assert_eq!(v_data(&v), 0);
    assert_eq!(v_w1(&v), 0);
    assert_eq!(v_w2(&v), 0);
    assert_eq!(v_w3(&v), 0);
}

#[test]
fn t28c_06b_variant_i4_copy_clear() {
    // VT_I4
    let src = Variant {
        vt: VT_I4,
        w_reserved1: 0,
        w_reserved2: 0,
        w_reserved3: 0,
        data: 42,
    };
    let mut dst = variant_init();
    variant_copy(&mut dst, &src);
    assert_eq!(v_vt(&dst), VT_I4);
    assert_eq!(v_data(&dst), 42);

    // Clear should reset to empty
    variant_clear(&mut dst);
    assert_eq!(v_vt(&dst), VT_EMPTY);
    // src should be unchanged
    assert_eq!(v_vt(&src), VT_I4);
    assert_eq!(v_data(&src), 42);
}

#[test]
fn t28c_06c_variant_bstr_copy_clear() {
    // Simulate a BSTR pointer in a variant
    let src = Variant {
        vt: VT_BSTR,
        w_reserved1: 0,
        w_reserved2: 0,
        w_reserved3: 0,
        data: 0x1234,
    };
    let mut dst = variant_init();
    variant_copy(&mut dst, &src);
    assert_eq!(v_vt(&dst), VT_BSTR);
    assert_eq!(v_data(&dst), 0x1234);

    // Clear should zero the data field
    variant_clear(&mut dst);
    assert_eq!(v_vt(&dst), VT_EMPTY);
    let dst_data = v_data(&dst);
    assert_eq!(dst_data, 0);
}

#[test]
fn t28c_06d_variant_unknown_copy_clear() {
    let src = Variant {
        vt: VT_UNKNOWN,
        w_reserved1: 0,
        w_reserved2: 0,
        w_reserved3: 0,
        data: 0xDEAD,
    };
    let mut dst = variant_init();
    variant_copy(&mut dst, &src);
    assert_eq!(v_vt(&dst), VT_UNKNOWN);
    assert_eq!(v_data(&dst), 0xDEAD);

    variant_clear(&mut dst);
    assert_eq!(v_vt(&dst), VT_EMPTY);
}

#[test]
fn t28c_06e_variant_dispatch_copy_clear() {
    let src = Variant {
        vt: VT_DISPATCH,
        w_reserved1: 0,
        w_reserved2: 0,
        w_reserved3: 0,
        data: 0xBEEF,
    };
    let mut dst = variant_init();
    variant_copy(&mut dst, &src);
    assert_eq!(v_vt(&dst), VT_DISPATCH);
    assert_eq!(v_data(&dst), 0xBEEF);

    variant_clear(&mut dst);
    assert_eq!(v_vt(&dst), VT_EMPTY);
}

#[test]
fn t28c_06f_variant_array_variant_copy_clear() {
    // VT_ARRAY | VT_VARIANT — an array of variants
    let vt_array_variant = VT_ARRAY | VT_VARIANT;
    let src = Variant {
        vt: vt_array_variant,
        w_reserved1: 0,
        w_reserved2: 0,
        w_reserved3: 0,
        data: 0xCAFE,
    };
    let mut dst = variant_init();
    variant_copy(&mut dst, &src);
    assert_eq!(v_vt(&dst), vt_array_variant);
    assert_eq!(v_data(&dst), 0xCAFE);

    variant_clear(&mut dst);
    assert_eq!(v_vt(&dst), VT_EMPTY);
}

#[test]
fn t28c_06g_variant_multiple_types() {
    let test_cases: Vec<(u16, u64, &str)> = vec![
        (VT_I4, 42, "VT_I4"),
        (VT_BSTR, 0x1000, "VT_BSTR"),
        (VT_UNKNOWN, 0x2000, "VT_UNKNOWN"),
        (VT_DISPATCH, 0x3000, "VT_DISPATCH"),
        (VT_ARRAY | VT_VARIANT, 0x4000, "VT_ARRAY|VT_VARIANT"),
        (VT_NULL, 0, "VT_NULL"),
        (VT_EMPTY, 0, "VT_EMPTY"),
    ];

    for (vt, data, label) in &test_cases {
        let src = Variant {
            vt: *vt,
            w_reserved1: 0,
            w_reserved2: 0,
            w_reserved3: 0,
            data: *data,
        };
        let mut dst = variant_init();
        variant_copy(&mut dst, &src);
        assert_eq!(v_vt(&dst), *vt, "{label}: vt mismatch after copy");
        assert_eq!(v_data(&dst), *data, "{label}: data mismatch after copy");

        variant_clear(&mut dst);
        assert_eq!(
            v_vt(&dst),
            VT_EMPTY,
            "{label}: vt should be VT_EMPTY after clear"
        );
        let dst_data = v_data(&dst);
        assert_eq!(dst_data, 0, "{label}: data should be 0 after clear");

        // Source should be unchanged
        assert_eq!(v_vt(&src), *vt, "{label}: source vt must be preserved");
        assert_eq!(
            v_data(&src),
            *data,
            "{label}: source data must be preserved"
        );
    }
}

// ===========================================================================
// t28c_07 — SafeArrayCreate / SafeArrayAccessData round-trip
// ===========================================================================

#[test]
fn t28c_07_safe_array_create_vector() {
    // Create a vector SAFEARRAY of 4 INTs
    let sa = safe_array_create_vector(VT_I4, 4);
    assert!(
        sa.len() >= 24,
        "SAFEARRAY must have at least descriptor size (24 bytes)"
    );

    // Check descriptor fields
    let c_dims = u16::from_le_bytes([sa[2], sa[3]]);
    assert_eq!(c_dims, 1, "Vector SAFEARRAY should have 1 dimension");

    let cb_elements = u16::from_le_bytes([sa[6], sa[7]]);
    assert_eq!(
        cb_elements as usize,
        casa1::real_win32::element_size(VT_I4),
        "Element size should match VT_I4"
    );

    // Check bounds
    let lbound = safe_array_get_lbound(&sa, 1).expect("GetLBound");
    assert_eq!(lbound, 0, "Vector lower bound should be 0");
    let ubound = safe_array_get_ubound(&sa, 1).expect("GetUBound");
    assert_eq!(
        ubound, 3,
        "Vector upper bound should be num_elements - 1 = 3"
    );

    // Check data access
    let data_offset = safe_array_access_data(&sa).expect("AccessData");
    assert!(
        data_offset >= 24,
        "Data offset should be past the descriptor"
    );
}

#[test]
fn t28c_07b_safe_array_create_read_write_elements() {
    // Create a SAFEARRAY of 3 I4 elements
    let mut sa = safe_array_create_vector(VT_I4, 3);

    // Write elements 0, 1, 2 with values 100, 200, 300
    safe_array_put_element(&mut sa, &[0], &100u32.to_le_bytes()).expect("Put element 0");
    safe_array_put_element(&mut sa, &[1], &200u32.to_le_bytes()).expect("Put element 1");
    safe_array_put_element(&mut sa, &[2], &300u32.to_le_bytes()).expect("Put element 2");

    // Read them back
    let elem0 = safe_array_get_element(&sa, &[0]).expect("Get element 0");
    let val0 = u32::from_le_bytes([elem0[0], elem0[1], elem0[2], elem0[3]]);
    assert_eq!(val0, 100);

    let elem1 = safe_array_get_element(&sa, &[1]).expect("Get element 1");
    let val1 = u32::from_le_bytes([elem1[0], elem1[1], elem1[2], elem1[3]]);
    assert_eq!(val1, 200);

    let elem2 = safe_array_get_element(&sa, &[2]).expect("Get element 2");
    let val2 = u32::from_le_bytes([elem2[0], elem2[1], elem2[2], elem2[3]]);
    assert_eq!(val2, 300);

    // Access data and verify directly
    let data_offset = safe_array_access_data(&sa).expect("AccessData") as usize;
    let data_bytes = &sa[data_offset..data_offset + 12]; // 3 * 4 bytes
    let data: Vec<u32> = data_bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    assert_eq!(
        data,
        vec![100, 200, 300],
        "Direct data access should match written values"
    );

    safe_array_unaccess_data(0);
    safe_array_destroy(0);
}

#[test]
fn t28c_07c_safe_array_bounds_checks() {
    // Create an empty array
    let sa = safe_array_create_vector(VT_I4, 0);
    let ubound = safe_array_get_ubound(&sa, 1).expect("GetUBound (empty)");
    assert_eq!(ubound, -1, "Upper bound of empty array should be -1");

    // Create array with 1 element
    let sa = safe_array_create_vector(VT_I4, 1);
    let lbound = safe_array_get_lbound(&sa, 1).expect("GetLBound");
    assert_eq!(lbound, 0);
    let ubound = safe_array_get_ubound(&sa, 1).expect("GetUBound");
    assert_eq!(ubound, 0, "Upper bound of 1-element array should be 0");
}

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

#[test]
fn t28c_12_clsid_from_progid() {
    let state = ComApartmentState::new();

    // Known ProgIDs
    assert_eq!(
        state.clsid_from_progid("Shell.Application"),
        Some(ComClsid::SHELL_APPLICATION)
    );
    assert_eq!(
        state.clsid_from_progid("shell.application"),
        Some(ComClsid::SHELL_APPLICATION)
    );
    assert_eq!(
        state.clsid_from_progid("Scripting.FileSystemObject"),
        Some(ComClsid::SCRIPTING_FILESYSTEMOBJECT)
    );
    assert_eq!(
        state.clsid_from_progid("WScript.Shell"),
        Some(ComClsid::WSCRIPT_SHELL)
    );
    assert_eq!(
        state.clsid_from_progid("ADODB.Connection"),
        Some(ComClsid::ADODB_CONNECTION)
    );
    assert_eq!(
        state.clsid_from_progid("ShellLink"),
        Some(ComClsid::SHELL_LINK)
    );
    assert_eq!(
        state.clsid_from_progid("InternetExplorer"),
        Some(ComClsid::INTERNET_EXPLORER)
    );
    assert_eq!(
        state.clsid_from_progid("DOMDocument"),
        Some(ComClsid::DOM_DOCUMENT)
    );
    assert_eq!(state.clsid_from_progid("XMLHTTP"), Some(ComClsid::XMLHTTP));

    // Unknown ProgID
    assert_eq!(state.clsid_from_progid("NonExistent.Application"), None);
}

// ===========================================================================
// t28c_13 — CoCreateGuid
// ===========================================================================

#[test]
fn t28c_13_co_create_guid() {
    let guid1 = ComApartmentState::co_create_guid();
    let guid2 = ComApartmentState::co_create_guid();

    // GUIDs should be 16 bytes
    assert_eq!(guid1.len(), 16);
    assert_eq!(guid2.len(), 16);

    // Consecutive GUIDs should be different
    assert_ne!(guid1, guid2, "GUIDs must be unique");

    // GUID should convert to a valid string
    let s = guid_to_string(&guid1);
    assert_eq!(s.len(), 36);
    assert_eq!(s.chars().filter(|&c| c == '-').count(), 4);
}

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

#[test]
fn t28c_14b_directsound_buffer8_com_object() {
    // Test DirectSoundBuffer8Object construction
    let obj = DirectSoundBuffer8Object::new(ComClsid::DIRECTSOUND8);
    assert_eq!(obj.debug_name(), "DirectSoundBuffer8");

    let iids = obj.supported_iids();
    assert!(iids.contains(&ComIid::IUNKNOWN));
    assert!(iids.contains(&ComIid::IDIRECTSOUNDBUFFER8));
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

#[test]
fn t28c_15b_xaudio2_voice_objects() {
    let mastering = XAudio2MasteringVoiceObject::new(ComClsid::XAUDIO2);
    assert_eq!(mastering.debug_name(), "XAudio2MasteringVoice");
    assert!(
        mastering
            .supported_iids()
            .contains(&ComIid::IXAUDIO2_MASTERING_VOICE)
    );

    let source = XAudio2SourceVoiceObject::new(ComClsid::XAUDIO2);
    assert_eq!(source.debug_name(), "XAudio2SourceVoice");
    assert!(
        source
            .supported_iids()
            .contains(&ComIid::IXAUDIO2_SOURCE_VOICE)
    );

    let submix = XAudio2SubmixVoiceObject::new(ComClsid::XAUDIO2);
    assert_eq!(submix.debug_name(), "XAudio2SubmixVoice");
    assert!(
        submix
            .supported_iids()
            .contains(&ComIid::IXAUDIO2_SUBMIX_VOICE)
    );
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

#[test]
fn t28c_19_dll_get_class_object_returns_functional_types() {
    let state = ComApartmentState::new();

    // All functional CLSIDs should return objects with proper IID support
    let ds = state
        .dll_get_class_object(&ComClsid::DIRECTSOUND8)
        .expect("DllGetClassObject DirectSound8");
    let ds_iids = ds.supported_iids();
    assert!(
        ds_iids.contains(&ComIid::IDIRECTSOUND8),
        "DirectSound8 should report IDIRECTSOUND8 support"
    );

    let xa = state
        .dll_get_class_object(&ComClsid::XAUDIO2)
        .expect("DllGetClassObject XAudio2");
    let xa_iids = xa.supported_iids();
    assert!(
        xa_iids.contains(&ComIid::IXAUDIO2),
        "XAudio2 should report IXAUDIO2 support"
    );

    let sl = state
        .dll_get_class_object(&ComClsid::SHELL_LINK)
        .expect("DllGetClassObject ShellLink");
    let sl_iids = sl.supported_iids();
    assert!(
        sl_iids.contains(&ComIid::ISHELLLINKW),
        "ShellLink should report ISHELLLINKW support"
    );
    assert!(
        sl_iids.contains(&ComIid::IPERSISTFILE),
        "ShellLink should report IPERSISTFILE support"
    );

    let fod = state
        .dll_get_class_object(&ComClsid::FILE_OPEN_DIALOG)
        .expect("DllGetClassObject FileOpenDialog");
    let fod_iids = fod.supported_iids();
    assert!(
        fod_iids.contains(&ComIid::IFILE_OPEN_DIALOG),
        "FileOpenDialog should report IFILE_OPEN_DIALOG support"
    );
    assert!(
        fod_iids.contains(&ComIid::IFILE_DIALOG),
        "FileOpenDialog should report IFILE_DIALOG support"
    );

    let tb = state
        .dll_get_class_object(&ComClsid::TASKBAR_LIST)
        .expect("DllGetClassObject TaskbarList");
    let tb_iids = tb.supported_iids();
    assert!(
        tb_iids.contains(&ComIid::ITASKBAR_LIST3),
        "TaskbarList should report ITASKBAR_LIST3 support"
    );
    assert!(
        tb_iids.contains(&ComIid::ITASKBAR_LIST),
        "TaskbarList should report ITASKBAR_LIST support"
    );
}

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
