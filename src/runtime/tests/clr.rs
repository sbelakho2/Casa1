use super::support::*;
use super::*;

#[test]
fn evidence_mscoree_clr_activation_semantics() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mscoree");
        let mut memory = MemoryImage::default();
        let create: u64 = runtime.alloc_host_thunk(HostThunk::ClrCreateInstance);
        let bind: u64 = runtime.alloc_host_thunk(HostThunk::CorBindToRuntimeEx);
        let directory: u64 = runtime.alloc_host_thunk(HostThunk::GetCorSystemDirectory);
        let requested: u64 = runtime.alloc_host_thunk(HostThunk::GetRequestedRuntimeInfo);
        let shim: u64 = runtime.alloc_host_thunk(HostThunk::LoadLibraryShim);

        let out = 0x41_000_u64;
        // CLSID_CLRMetaHost {9280188D-0E8E-4867-B30C-7FA83884E8DE}
        let clsid = 0x41_010_u64;
        memory.map_bytes(
            clsid,
            &[
                0x8D, 0x18, 0x20, 0x92, 0x8E, 0x0E, 0x67, 0x48, 0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84,
                0xE8, 0xDE,
            ],
        );
        // IID_ICLRMetaHost {D332DB9E-B9B3-4125-8207-A14884F53216}
        let meta_iid = 0x41_020_u64;
        memory.map_bytes(
            meta_iid,
            &[
                0x9E, 0xDB, 0x32, 0xD3, 0xB9, 0xB3, 0x25, 0x41, 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5,
                0x32, 0x16,
            ],
        );
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create,
            &[clsid as u32, meta_iid as u32, out as u32],
        );
        assert_eq!(hr, 0, "real CLR metadata host");
        assert_ne!(
            read_guest_pointer(&memory, out, GuestArch::X86).unwrap(),
            0,
            "metadata host object returned"
        );

        // Null rclsid/riid is E_POINTER regardless of which runtime is
        // installed: argument validation precedes runtime selection.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                bind,
                &[0, 0, 0, 0, 0, out as u32]
            ),
            0x8000_4003
        );
        assert_eq!(read_guest_pointer(&memory, out, GuestArch::X86).unwrap(), 0);

        // A v4 Framework request binds the real Mono-backed host when Mono is
        // installed; CLSID_CLRRuntimeHost {90F1A06E-...} and
        // IID_ICLRRuntimeHost {D5F0A32B-...}.
        let host_clsid = 0x41_030_u64;
        let host_iid = 0x41_040_u64;
        memory.map_bytes(
            host_clsid,
            &[
                0x6E, 0xA0, 0xF1, 0x90, 0x12, 0x77, 0x62, 0x47, 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B,
                0x65, 0xE6,
            ],
        );
        memory.map_bytes(
            host_iid,
            &[
                0x2B, 0xA3, 0xF0, 0xD5, 0x4D, 0x2E, 0x4B, 0x4E, 0x9B, 0x5C, 0x2D, 0x8B, 0x0B, 0x3B,
                0x6F, 0x5F,
            ],
        );
        let version = runtime
            .alloc_utf16_string(&mut memory, "v4.0.30319")
            .expect("framework version");
        let mono_bind = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            bind,
            &[
                version as u32,
                0,
                0,
                host_clsid as u32,
                host_iid as u32,
                out as u32,
            ],
        );
        let host = read_guest_pointer(&memory, out, GuestArch::X86).unwrap();
        // Mono may be absent on a non-provisioned host: absence is the exact
        // documented failure, presence must be a real host object.
        assert!(
            (mono_bind == 0 && host != 0) || mono_bind == 0x8013_1013,
            "unexpected Framework bind result {mono_bind:#x}"
        );

        // The host has a real CoreCLR, so the directory query succeeds with
        // the installed runtime path (the old no-CLR expectation was stale).
        let buffer = 0x41_100_u64;
        let length_out = 0x41_110_u64;
        memory.map_bytes(buffer, &vec![0_u8; 520]);
        memory.map_bytes(length_out, &[0_u8; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                directory,
                &[buffer as u32, 260, length_out as u32]
            ),
            0,
            "GetCORSystemDirectory reports the installed CoreCLR"
        );
        assert_ne!(read_guest_u32(&memory, length_out).unwrap(), 0);
        let mut path_units = Vec::new();
        let mut cursor = buffer;
        loop {
            let unit = read_guest_u16(&memory, cursor).unwrap();
            if unit == 0 {
                break;
            }
            path_units.push(unit);
            cursor += 2;
        }
        let path = String::from_utf16(&path_units).expect("utf16 path");
        assert!(
            path.contains("Microsoft.NETCore.App"),
            "unexpected CoreCLR directory {path}"
        );

        // A versionless request binds the installed Framework runtime when
        // one is present (Mono), otherwise it keeps the documented absence.
        let requested_hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            requested,
            &[
                0,
                0,
                0,
                0,
                0,
                buffer as u32,
                260,
                length_out as u32,
                0,
                0,
                0,
            ],
        );
        assert!(
            requested_hr == 0 || requested_hr == 0x8013_1013,
            "unexpected requested-runtime result {requested_hr:#x}"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, shim, &[0, 0, 0, 0]),
            0x8000_4005
        );
    })
}
