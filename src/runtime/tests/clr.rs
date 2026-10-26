use super::support::*;
use super::*;

#[test]
fn evidence_mscoree_clr_absent_semantics() {
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

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                bind,
                &[0, 0, 0, 0, 0, out as u32]
            ),
            0x8013_1013
        );
        assert_eq!(read_guest_pointer(&memory, out, GuestArch::X86).unwrap(), 0);

        let buffer = 0x41_100_u64;
        let length_out = 0x41_110_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                directory,
                &[buffer as u32, 260, length_out as u32]
            ),
            0x8000_4005
        );
        assert_eq!(
            read_guest_u16(&memory, buffer).unwrap(),
            0,
            "empty CLR directory"
        );
        assert_eq!(read_guest_u32(&memory, length_out).unwrap(), 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                requested,
                &[0, 0, 0, 0, 0, 0, 0, 0, 0]
            ),
            0x8000_4005
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, shim, &[0, 0, 0, 0]),
            0x8000_4005
        );
    })
}
