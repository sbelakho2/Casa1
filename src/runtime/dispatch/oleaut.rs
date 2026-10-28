//! OLE Automation `IUnknown` preamble evidence for the runtime's live
//! `IDispatch`, `IEnumVARIANT` and `IConnectionPoint` objects.
//!
//! The method registry's nine unproven `oleaut32` rows are exactly the
//! `QueryInterface`/`AddRef`/`Release` slots of those three interfaces (the
//! interface-specific methods are already proven by
//! `com_method_evidence_idispatch_enum_connection_points_reject_invalid_inputs`).
//! These tests drive the real vtable slots on freshly allocated runtime
//! objects and pin the exact refcount and `E_NOINTERFACE` results.

#[cfg(test)]
mod tests {
    use super::super::super::*;
    use super::super::test_support::{Fixture, dispatch_x86, with_big_stack, x86_fixture};

    const OUT: u64 = 0x80_000;
    const IID_PTR: u64 = 0x80_100;

    const IID_IUNKNOWN: &str = "{00000000-0000-0000-C000-000000000046}";
    const IID_IDISPATCH: &str = "{00020400-0000-0000-C000-000000000046}";
    const IID_IENUMVARIANT: &str = "{00020404-0000-0000-C000-000000000046}";
    const IID_ICONNECTIONPOINT: &str = "{B196B286-BAB4-101A-B69C-00AA00341D07}";
    const E_NOINTERFACE: u32 = 0x8000_4002;

    fn call_slot(fixture: &mut Fixture, object: u64, slot: u64, args: &[u32]) -> u32 {
        let vtable = read_guest_pointer(&fixture.memory, object, GuestArch::X86).expect("vtable");
        let function = read_guest_pointer(&fixture.memory, vtable + slot * 4, GuestArch::X86)
            .expect("slot thunk");
        let thunk = fixture
            .runtime
            .host_thunks
            .get(&function)
            .cloned()
            .unwrap_or_else(|| panic!("vtable slot {slot} is not a host thunk"));
        dispatch_x86(fixture, thunk, args) as u32
    }

    fn query(fixture: &mut Fixture, object: u64, iid: &str) -> (u32, u64) {
        let bytes = crate::real_win32::guid_from_string(iid).expect("guid");
        fixture.memory.map_bytes(IID_PTR, &bytes);
        fixture.memory.map_bytes(OUT, &[0_u8; 4]);
        let hr = call_slot(
            fixture,
            object,
            0,
            &[object as u32, IID_PTR as u32, OUT as u32],
        );
        let out = read_guest_pointer(&fixture.memory, OUT, GuestArch::X86).expect("out");
        (hr, out)
    }

    fn preamble(fixture: &mut Fixture, object: u64, own_iid: &str, expected_iid: Option<&str>) {
        // QueryInterface: the own-IID succeeds and adds a reference.
        let (hr, out) = query(fixture, object, own_iid);
        assert_eq!(hr, 0, "{own_iid} must be supported");
        assert_eq!(out, object);
        assert_eq!(
            call_slot(fixture, object, 2, &[object as u32]),
            1,
            "the QI reference must be released back to one"
        );

        // IUnknown is supported by every live object.
        let (hr, out) = query(fixture, object, IID_IUNKNOWN);
        assert_eq!(hr, 0);
        assert_eq!(out, object);
        assert_eq!(call_slot(fixture, object, 2, &[object as u32]), 1);

        // A foreign IID is E_NOINTERFACE and clears the out pointer.
        let (hr, out) = query(fixture, object, "{11111111-2222-3333-4444-555555555555}");
        assert_eq!(hr, E_NOINTERFACE);
        assert_eq!(out, 0);

        // AddRef/Release are the real guest-object refcount transitions.
        assert_eq!(call_slot(fixture, object, 1, &[object as u32]), 2);
        assert_eq!(call_slot(fixture, object, 2, &[object as u32]), 1);
        let _ = expected_iid;
    }

    #[test]
    fn oleaut_idispatch_preamble_rejects_invalid_iid_and_pins_refcounts() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("oleaut-idispatch-preamble");
            let server = fixture
                .runtime
                .alloc_com_automation_server(&mut fixture.memory, "ICasa1Automation")
                .expect("dispatch server");
            preamble(&mut fixture, server, IID_IDISPATCH, None);
            let (hr, _) = query(
                &mut fixture,
                server,
                "{11111111-2222-3333-4444-555555555555}",
            );
            assert_eq!(hr, E_NOINTERFACE);
        });
    }

    #[test]
    fn oleaut_ienumvariant_preamble_rejects_invalid_iid_and_pins_refcounts() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("oleaut-enum-preamble");
            let enumerator = fixture
                .runtime
                .alloc_com_enum_object(&mut fixture.memory, Vec::new())
                .expect("enum");
            preamble(&mut fixture, enumerator, IID_IENUMVARIANT, None);
            let (hr, _) = query(
                &mut fixture,
                enumerator,
                "{11111111-2222-3333-4444-555555555555}",
            );
            assert_eq!(hr, E_NOINTERFACE);
        });
    }

    #[test]
    fn oleaut_iconnectionpoint_preamble_rejects_invalid_iid_and_pins_refcounts() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("oleaut-point-preamble");
            let server = fixture
                .runtime
                .alloc_com_automation_server(&mut fixture.memory, "ICasa1Automation")
                .expect("dispatch server");
            let point = fixture
                .runtime
                .alloc_com_connection_point(
                    &mut fixture.memory,
                    server,
                    crate::real_win32::guid_from_string(IID_IDISPATCH).expect("iid"),
                )
                .expect("connection point");
            preamble(&mut fixture, point, IID_ICONNECTIONPOINT, None);
            let (hr, _) = query(
                &mut fixture,
                point,
                "{11111111-2222-3333-4444-555555555555}",
            );
            assert_eq!(hr, E_NOINTERFACE);
        });
    }
}
