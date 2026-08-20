//! Stage 4 — the Ldr loader chain: the NTDLL-native surface ABOVE the
//! loader machinery.
//!
//! ONE loader: every Ldr entry point (`LdrLoadDll`, `LdrUnloadDll`,
//! `LdrGetDllHandle`, `LdrGetProcedureAddress`, the loader-lock protocol,
//! `LdrAddRefDll`/`LdrRemoveRefDll`) is a thin native-protocol wrapper over
//! the SAME machinery the Win32 LoadLibrary/GetProcAddress/FreeLibrary
//! thunks use (resolve_load_library_handle, lookup_module_handle,
//! resolve_proc_address, load_real_dll and the pending-DllMain FIFO).
//!
//! These tests drive the REAL dispatch path through the
//! [`crate::runtime::NtThunkSession`] scratch runtime (a thunk address per
//! API, x64 calling convention, canonical VM attached) and, for the
//! load-order TLS tests, minimal REAL PE32+ DLLs staged into the GE so the
//! TLS callbacks and DllMain entry points execute as guest code.

mod support;

use casa1::ge::{GameEnvironment, GeArch};
use casa1::ntdll::{
    LDR_ADDREF_DLL_PIN, LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED,
    LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, LDR_REMOVE_REF_DLL_PIN, NtStatus, STATUS_DLL_NOT_FOUND,
    STATUS_ENTRYPOINT_NOT_FOUND, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};
use casa1::pe_runtime::{HostThunk, NtThunkSession};
use std::fs;
use tempfile::TempDir;

fn setup_session() -> (TempDir, NtThunkSession) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(temp_dir.path(), "ldr-stage4", GeArch::X64, "win11-23h2")
        .expect("create GE");
    let session = NtThunkSession::new(ge);
    (temp_dir, session)
}

/// The scratch data arena addresses (mapped by the session).
const ARENA: u64 = 0x30_000;
const ARENA2: u64 = 0x40_000;
const ARENA3: u64 = 0x50_000;

/// Guest directory the Ldr tests stage their real DLL fixtures into.
const FIXTURE_DIR: &str = r"C:\Casa1LdrFixtures";

/// Write a real PE DLL into the GE so `LdrLoadDll` can resolve it through
/// the loader's dll-path machinery.
fn write_guest_pe(session: &NtThunkSession, guest_path: &str, bytes: &[u8]) {
    let host_path = session
        .win32()
        .guest_path_to_host_path(guest_path)
        .expect("host path");
    if let Some(parent) = host_path.parent() {
        fs::create_dir_all(parent).expect("create parent dir");
    }
    fs::write(&host_path, bytes).expect("write guest PE");
}

/// Place a UNICODE_STRING header + wide buffer in guest memory; returns
/// the header address.
fn map_unicode_string(session: &mut NtThunkSession, header: u64, buffer: u64, value: &str) {
    let wide: Vec<u8> = value.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    session.map_guest(buffer, &wide);
    session.map_guest(header, &[0_u8; 16]);
    session.map_guest(header, &(wide.len() as u16).to_le_bytes());
    session.map_guest(header + 2, &((wide.len() + 2) as u16).to_le_bytes());
    session.map_guest(header + 8, &buffer.to_le_bytes());
}

/// Place an ANSI_STRING header + buffer in guest memory; returns the
/// header address.
fn map_ansi_string(session: &mut NtThunkSession, header: u64, buffer: u64, value: &str) {
    session.map_guest(buffer, value.as_bytes());
    session.map_guest(header, &[0_u8; 16]);
    session.map_guest(header, &(value.len() as u16).to_le_bytes());
    session.map_guest(header + 2, &((value.len() + 1) as u16).to_le_bytes());
    session.map_guest(header + 8, &buffer.to_le_bytes());
}

// ── Minimal real PE32+ DLL fixture builder ─────────────────────────────────
//
// The fixture is a valid PE32+ DLL the crate's `pe::parse` accepts: one
// named export, a DllMain entry point and ONE TLS callback.  The code
// RVAs are stub bytes in the file; the tests map REAL guest code at
// `handle + rva` (the loader allocates the handle, the test supplies the
// code) so the callbacks execute as guest code during the DllMain drain.

const IMAGE_BASE: u64 = 0x1_4000_0000;
/// DllMain entry-point RVA.
const EP_RVA: u32 = 0x1000;
/// The named export's code RVA.
const EXPORT_FN_RVA: u32 = 0x1050;
/// The TLS callback's code RVA (kept clear of the 42-byte DllMain
/// appender the tests map at EP_RVA).
const TLS_CB_RVA: u32 = 0x1100;

fn build_minimal_dll(export_name: &str, dll_name: &str) -> Vec<u8> {
    let mut buf = vec![0_u8; 0xA00];
    // DOS header.
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    // PE signature + COFF header.
    let pe = 0x80usize;
    buf[pe..pe + 4].copy_from_slice(b"PE\x00\x00");
    buf[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    buf[pe + 6..pe + 8].copy_from_slice(&2u16.to_le_bytes()); // number of sections
    buf[pe + 20..pe + 22].copy_from_slice(&0xF0u16.to_le_bytes()); // optional header size
    buf[pe + 22..pe + 24].copy_from_slice(&0x2002u16.to_le_bytes()); // DLL | EXECUTABLE_IMAGE
    // Optional header PE32+.
    let opt = pe + 24;
    buf[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&EP_RVA.to_le_bytes());
    buf[opt + 24..opt + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
    buf[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
    buf[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes()); // size of image
    buf[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes()); // size of headers
    buf[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes()); // subsystem GUI
    buf[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // rva and sizes
    // Data directories: export at index 0, TLS at index 9.
    let dirs = opt + 112;
    buf[dirs..dirs + 4].copy_from_slice(&0x2000u32.to_le_bytes()); // export RVA
    buf[dirs + 4..dirs + 8].copy_from_slice(&0x60u32.to_le_bytes()); // export size
    buf[dirs + 9 * 8..dirs + 9 * 8 + 4].copy_from_slice(&0x2100u32.to_le_bytes()); // TLS RVA
    buf[dirs + 9 * 8 + 4..dirs + 9 * 8 + 8].copy_from_slice(&0x28u32.to_le_bytes()); // TLS size
    // Section table: .text (RVA 0x1000, raw 0x400) + .rdata (RVA 0x2000, raw 0x600).
    let s1 = pe + 24 + 0xF0;
    buf[s1..s1 + 8].copy_from_slice(b".text\0\0\0");
    buf[s1 + 8..s1 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual size
    buf[s1 + 12..s1 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
    buf[s1 + 16..s1 + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
    buf[s1 + 20..s1 + 24].copy_from_slice(&0x400u32.to_le_bytes()); // raw ptr
    buf[s1 + 36..s1 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    let s2 = s1 + 40;
    buf[s2..s2 + 8].copy_from_slice(b".rdata\0\0");
    buf[s2 + 8..s2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[s2 + 12..s2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[s2 + 16..s2 + 20].copy_from_slice(&0x400u32.to_le_bytes());
    buf[s2 + 20..s2 + 24].copy_from_slice(&0x600u32.to_le_bytes());
    buf[s2 + 36..s2 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
    // .text stub code (the tests remap real code at these RVAs).
    for rva in [EP_RVA, EXPORT_FN_RVA, TLS_CB_RVA] {
        buf[0x400 + (rva - 0x1000) as usize] = 0xC3; // ret
    }
    // .rdata: IMAGE_EXPORT_DIRECTORY at RVA 0x2000.
    let exp = 0x600usize;
    buf[exp + 12..exp + 16].copy_from_slice(&0x2050u32.to_le_bytes()); // Name RVA
    buf[exp + 16..exp + 20].copy_from_slice(&1u32.to_le_bytes()); // Base
    buf[exp + 20..exp + 24].copy_from_slice(&1u32.to_le_bytes()); // NumberOfFunctions
    buf[exp + 24..exp + 28].copy_from_slice(&1u32.to_le_bytes()); // NumberOfNames
    buf[exp + 28..exp + 32].copy_from_slice(&0x2030u32.to_le_bytes()); // AddressOfFunctions
    buf[exp + 32..exp + 36].copy_from_slice(&0x2034u32.to_le_bytes()); // AddressOfNames
    buf[exp + 36..exp + 40].copy_from_slice(&0x2038u32.to_le_bytes()); // AddressOfNameOrdinals
    buf[exp + 0x30..exp + 0x34].copy_from_slice(&EXPORT_FN_RVA.to_le_bytes()); // function[0]
    buf[exp + 0x34..exp + 0x38].copy_from_slice(&0x2040u32.to_le_bytes()); // name[0]
    buf[exp + 0x38..exp + 0x3A].copy_from_slice(&0u16.to_le_bytes()); // ordinal[0]
    buf[exp + 0x40..exp + 0x40 + export_name.len()].copy_from_slice(export_name.as_bytes());
    buf[exp + 0x50..exp + 0x50 + dll_name.len()].copy_from_slice(dll_name.as_bytes());
    // .rdata: IMAGE_TLS_DIRECTORY64 at RVA 0x2100.
    let tls = 0x700usize;
    buf[tls..tls + 8].copy_from_slice(&(IMAGE_BASE + 0x2200).to_le_bytes());
    buf[tls + 8..tls + 16].copy_from_slice(&(IMAGE_BASE + 0x2204).to_le_bytes());
    buf[tls + 16..tls + 24].copy_from_slice(&(IMAGE_BASE + 0x2204).to_le_bytes());
    buf[tls + 24..tls + 32].copy_from_slice(&(IMAGE_BASE + 0x2208).to_le_bytes());
    // .rdata: callback array at RVA 0x2208 — exactly ONE callback.
    let cbs = 0x808usize;
    buf[cbs..cbs + 8].copy_from_slice(&(IMAGE_BASE + u64::from(TLS_CB_RVA)).to_le_bytes());
    buf[cbs + 8..cbs + 16].copy_from_slice(&0u64.to_le_bytes()); // terminator
    buf
}

/// Guest code that appends its `marker` byte to the record buffer:
///
/// ```text
/// mov rax, [len_slot]      ; current record length
/// mov rcx, rax             ; index (the marker index)
/// mov r8d, marker          ; the marker byte (kept OUT of rax so the
///                          ; length can be incremented below)
/// mov rdx, buf
/// mov [rdx+rcx], r8b       ; append the marker
/// inc rax
/// mov [len_slot], rax      ; update the length
/// ret
/// ```
fn record_marker_code(marker: u8, len_slot: u64, buf: u64) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0xA1]); // mov rax, moffs64
    code.extend_from_slice(&len_slot.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x89, 0xC1]); // mov rcx, rax
    code.extend_from_slice(&[0x41, 0xB8, marker, 0, 0, 0]); // mov r8d, marker
    code.extend_from_slice(&[0x48, 0xBA]); // mov rdx, imm64
    code.extend_from_slice(&buf.to_le_bytes());
    code.extend_from_slice(&[0x44, 0x88, 0x04, 0x0A]); // mov [rdx+rcx], r8b
    code.extend_from_slice(&[0x48, 0xFF, 0xC0]); // inc rax
    code.extend_from_slice(&[0x48, 0xA3]); // mov [len_slot], rax (moffs64)
    code.extend_from_slice(&len_slot.to_le_bytes());
    code.extend_from_slice(&[0xC3]); // ret
    code
}

/// PeHostRuntime is very large; every test runs on a thread with a bigger
/// stack so the scratch runtime never overflows the default test-thread
/// stack (the same pattern the runtime's own unit tests use).
fn run_on_big_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(test)
        .expect("spawn")
        .join()
        .expect("join");
}

// ── Test (a): LdrLoadDll — handle + DllMain fire + refcount semantics ─────

#[test]
fn ldr_load_dll_returns_handle_fires_attach_and_second_load_does_not_refire() {
    run_on_big_stack(|| {
        let (_tmp, mut session) = setup_session();
        let load = session.alloc_thunk(HostThunk::LdrLoadDll);
        let handle_ptr = ARENA;
        session.map_guest(handle_ptr, &[0_u8; 8]);

        // A real DLL staged into the GE: LdrLoadDll resolves it through the
        // loader machinery and queues DLL_PROCESS_ATTACH (DllMain + TLS).
        let dll = build_minimal_dll("SampleExport", "first_fixture.dll");
        let guest_path = format!(r"{FIXTURE_DIR}\first_fixture.dll");
        write_guest_pe(&session, &guest_path, &dll);
        map_unicode_string(&mut session, ARENA2, ARENA3, &guest_path);

        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(
            NtStatus::from_raw(rax as u32),
            STATUS_SUCCESS,
            "rax={rax:#x}"
        );
        let handle = u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap());
        assert_ne!(handle, 0, "LdrLoadDll returns a module handle");
        assert!(session.is_module_loaded(handle));
        assert_eq!(session.real_dll_refcount("first_fixture.dll"), Some(1));
        assert_eq!(session.dll_info_load_count(handle), Some(1));
        // DLL_PROCESS_ATTACH (reason 1) for the new module is queued in load order.
        assert_eq!(
            session.pending_dll_main_calls(),
            vec![(handle, 0x1000, 1)],
            "the first load queues DllMain(DLL_PROCESS_ATTACH)"
        );

        // A SECOND LdrLoadDll returns the SAME handle with a refcount increment
        // ONLY — no re-fired DllMain.
        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let handle2 = u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap());
        assert_eq!(handle2, handle, "the same module returns the same handle");
        assert_eq!(session.real_dll_refcount("first_fixture.dll"), Some(2));
        assert_eq!(session.dll_info_load_count(handle), Some(2));
        assert_eq!(
            session.pending_dll_main_calls(),
            vec![(handle, 0x1000, 1)],
            "a second load must NOT re-fire DllMain"
        );

        // Synthetic modules behave the same way (same handle, count only).
        let synth_name = "kernel32.dll";
        map_unicode_string(&mut session, ARENA2, ARENA3, synth_name);
        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let synth_handle =
            u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap());
        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let synth_handle2 =
            u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap());
        assert_eq!(synth_handle, synth_handle2);
        assert_eq!(session.dll_info_load_count(synth_handle), Some(2));

        // An unknown module fails with STATUS_DLL_NOT_FOUND.
        map_unicode_string(&mut session, ARENA2, ARENA3, "absent_module.dll");
        session.map_guest(handle_ptr, &[0_u8; 8]);
        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_DLL_NOT_FOUND);
        assert_eq!(
            u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap()),
            0,
            "the out handle is cleared on failure"
        );
    });
}

// ── Test (b): LdrGetDllHandle — lookup only, never loads ──────────────────

#[test]
fn ldr_get_dll_handle_finds_loaded_modules_and_fails_for_unknown() {
    run_on_big_stack(|| {
        let (_tmp, mut session) = setup_session();
        let load = session.alloc_thunk(HostThunk::LdrLoadDll);
        let get_handle = session.alloc_thunk(HostThunk::LdrGetDllHandle);
        let handle_ptr = ARENA;
        session.map_guest(handle_ptr, &[0_u8; 8]);

        let dll = build_minimal_dll("SampleExport", "second_fixture.dll");
        let guest_path = format!(r"{FIXTURE_DIR}\second_fixture.dll");
        write_guest_pe(&session, &guest_path, &dll);
        map_unicode_string(&mut session, ARENA2, ARENA3, &guest_path);
        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let handle = u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap());

        // Case-insensitive lookup of the loaded module (path and bare name).
        for probe in [
            &guest_path,
            r"{FIXTURE_DIR}\SECOND_FIXTURE.DLL",
            "second_fixture.dll",
            "SECOND_FIXTURE.DLL",
        ] {
            map_unicode_string(&mut session, ARENA2, ARENA3, probe);
            session.map_guest(handle_ptr, &[0_u8; 8]);
            let rax = session.call(get_handle, &[0, 0, ARENA2, handle_ptr]);
            assert_eq!(
                NtStatus::from_raw(rax as u32),
                STATUS_SUCCESS,
                "probe {probe}"
            );
            assert_eq!(
                u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap()),
                handle,
                "probe {probe}"
            );
        }

        // An unknown module is STATUS_DLL_NOT_FOUND and NEVER loads anything.
        map_unicode_string(&mut session, ARENA2, ARENA3, "not_loaded.dll");
        session.map_guest(handle_ptr, &[0xFF; 8]);
        let rax = session.call(get_handle, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_DLL_NOT_FOUND);
        assert_eq!(
            u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap()),
            0,
            "the out handle is cleared"
        );
        assert!(!session.is_module_loaded(0), "nothing was loaded");
    });
}

// ── Test (c): LdrGetProcedureAddress — name + ordinal resolution ──────────

#[test]
fn ldr_get_procedure_address_resolves_by_name_and_ordinal() {
    run_on_big_stack(|| {
        let (_tmp, mut session) = setup_session();
        let load = session.alloc_thunk(HostThunk::LdrLoadDll);
        let get_proc = session.alloc_thunk(HostThunk::LdrGetProcedureAddress);
        let handle_ptr = ARENA;
        let proc_ptr = ARENA + 8;
        session.map_guest(handle_ptr, &[0_u8; 16]);

        // Real DLL export by NAME.
        let dll = build_minimal_dll("SampleExport", "third_fixture.dll");
        let guest_path = format!(r"{FIXTURE_DIR}\third_fixture.dll");
        write_guest_pe(&session, &guest_path, &dll);
        map_unicode_string(&mut session, ARENA2, ARENA3, &guest_path);
        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let handle = u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap());

        map_ansi_string(&mut session, ARENA2, ARENA3, "SampleExport");
        let rax = session.call(get_proc, &[handle, ARENA2, 0, proc_ptr]);
        assert_eq!(
            NtStatus::from_raw(rax as u32),
            STATUS_SUCCESS,
            "rax={rax:#x}"
        );
        let address = u64::from_le_bytes(session.read_guest(proc_ptr, 8).try_into().unwrap());
        assert_ne!(address, 0, "the export resolves to a thunk address");

        // Unknown export name → STATUS_ENTRYPOINT_NOT_FOUND.
        map_ansi_string(&mut session, ARENA2, ARENA3, "MissingExport");
        let rax = session.call(get_proc, &[handle, ARENA2, 0, proc_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_ENTRYPOINT_NOT_FOUND);
        assert_eq!(
            u64::from_le_bytes(session.read_guest(proc_ptr, 8).try_into().unwrap()),
            0
        );

        // Ordinal resolution through the loader's ordinal machinery: a
        // synthetic module with an ordinal-mapped export (oleaut32 ordinal 9 →
        // VariantClear, the same arm static ordinal imports use).
        map_unicode_string(&mut session, ARENA2, ARENA3, "oleaut32.dll");
        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let ole_handle = u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap());
        let rax = session.call(get_proc, &[ole_handle, 0, 9, proc_ptr]);
        assert_eq!(
            NtStatus::from_raw(rax as u32),
            STATUS_SUCCESS,
            "rax={rax:#x}"
        );
        let ordinal_addr = u64::from_le_bytes(session.read_guest(proc_ptr, 8).try_into().unwrap());
        assert_ne!(
            ordinal_addr, 0,
            "ordinal 9 resolves like a static ordinal import"
        );

        // A name lookup on the same synthetic module also resolves (VariantClear
        // is the ordinal 9 export).
        map_ansi_string(&mut session, ARENA2, ARENA3, "VariantClear");
        let rax = session.call(get_proc, &[ole_handle, ARENA2, 0, proc_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);

        // Unknown ordinal → STATUS_ENTRYPOINT_NOT_FOUND.
        let rax = session.call(get_proc, &[ole_handle, 0, 0x7FFF, proc_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_ENTRYPOINT_NOT_FOUND);

        // Unknown MODULE → STATUS_DLL_NOT_FOUND (Wine behavior).
        map_ansi_string(&mut session, ARENA2, ARENA3, "SampleExport");
        let rax = session.call(get_proc, &[0x1234_5678, ARENA2, 0, proc_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_DLL_NOT_FOUND);

        // No name AND no ordinal → STATUS_INVALID_PARAMETER.
        let rax = session.call(get_proc, &[ole_handle, 0, 0, proc_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_INVALID_PARAMETER);
    });
}

// ── Test (d): LdrUnloadDll — DETACH, module removal, main-module refusal ──

#[test]
fn ldr_unload_dll_fires_detach_removes_module_and_refuses_the_main_module() {
    run_on_big_stack(|| {
        let (_tmp, mut session) = setup_session();
        let load = session.alloc_thunk(HostThunk::LdrLoadDll);
        let unload = session.alloc_thunk(HostThunk::LdrUnloadDll);
        let get_handle = session.alloc_thunk(HostThunk::LdrGetDllHandle);
        let handle_ptr = ARENA;
        session.map_guest(handle_ptr, &[0_u8; 8]);

        let dll = build_minimal_dll("SampleExport", "fourth_fixture.dll");
        let guest_path = format!(r"{FIXTURE_DIR}\fourth_fixture.dll");
        write_guest_pe(&session, &guest_path, &dll);
        map_unicode_string(&mut session, ARENA2, ARENA3, &guest_path);
        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let handle = u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap());

        // One refcount held: unload succeeds, DLL_PROCESS_DETACH (reason 0) is
        // queued and the module is removed.
        let rax = session.call(unload, &[handle]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        assert_eq!(session.dll_info_load_count(handle), Some(0));
        assert_eq!(
            session.real_dll_refcount("fourth_fixture.dll"),
            None,
            "the RealDllState moved out of the loaded table"
        );
        assert_eq!(
            session.detached_real_dll_count(),
            1,
            "the host-backed state is parked in the detach-only list"
        );
        assert_eq!(
            session.pending_dll_main_calls(),
            vec![(handle, 0x1000, 1), (handle, 0x1000, 0)],
            "the load queued ATTACH; the last unload appends DllMain(DLL_PROCESS_DETACH)"
        );
        assert!(
            !session.is_module_loaded(handle),
            "the module handle is gone after the last unload"
        );
        assert!(
            session.module_handle("fourth_fixture.dll").is_none(),
            "LdrGetDllHandle can no longer find the module"
        );

        // LdrGetDllHandle now reports STATUS_DLL_NOT_FOUND.
        map_unicode_string(&mut session, ARENA2, ARENA3, "fourth_fixture.dll");
        session.map_guest(handle_ptr, &[0_u8; 8]);
        let rax = session.call(get_handle, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_DLL_NOT_FOUND);

        // A second unload of the same handle fails (module already gone).
        let rax = session.call(unload, &[handle]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_DLL_NOT_FOUND);

        // The MAIN module can never be unloaded (STATUS_INVALID_PARAMETER —
        // documented in crate::ntdll::ldr: real Windows pins the main image;
        // no authoritative NTSTATUS is documented, so the wrapper refuses).
        session.install_main_module(0x400000, "game.exe");
        let rax = session.call(unload, &[0x400000]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_INVALID_PARAMETER);
        assert!(
            !session
                .pending_dll_main_calls()
                .iter()
                .any(|(base, _, _)| *base == 0x400000),
            "the main module unload must never fire DLL_PROCESS_DETACH"
        );
        assert!(
            session.is_module_loaded(0x400000),
            "the main module stays loaded"
        );
    });
}

// ── Test (e): loader-lock protocol — cookie sanity + reentrancy depth ─────

#[test]
fn ldr_loader_lock_round_trips_with_cookie_sanity_and_reentrancy() {
    run_on_big_stack(|| {
        let (_tmp, mut session) = setup_session();
        let lock = session.alloc_thunk(HostThunk::LdrLockLoaderLock);
        let unlock = session.alloc_thunk(HostThunk::LdrUnlockLoaderLock);
        let disposition = ARENA;
        let cookie_ptr = ARENA + 4;
        session.map_guest(ARENA, &[0_u8; 16]);

        // Acquire: STATUS_SUCCESS, disposition LOCK_ACQUIRED, cookie minted.
        let rax = session.call(lock, &[0, disposition, cookie_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        assert_eq!(
            u32::from_le_bytes(session.read_guest(disposition, 4).try_into().unwrap()),
            LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED
        );
        let cookie1 = u64::from_le_bytes(session.read_guest(cookie_ptr, 8).try_into().unwrap());
        assert_ne!(cookie1, 0);
        assert_eq!(session.loader_lock_depth(), 1);

        // Reentrant acquire succeeds (real LdrLockLoaderLock is reentrant).
        let rax = session.call(lock, &[0, disposition, cookie_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let cookie2 = u64::from_le_bytes(session.read_guest(cookie_ptr, 8).try_into().unwrap());
        assert_ne!(cookie2, 0);
        assert_eq!(session.loader_lock_depth(), 2);

        // Unlock both levels; the depth returns to 0.
        let rax = session.call(unlock, &[0, cookie2]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        assert_eq!(session.loader_lock_depth(), 1);
        let rax = session.call(unlock, &[0, cookie1]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        assert_eq!(session.loader_lock_depth(), 0);

        // A NULL cookie is a no-op success; a bogus cookie is rejected.
        let rax = session.call(unlock, &[0, 0]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let rax = session.call(unlock, &[0, 0x1234_5678]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_INVALID_PARAMETER);

        // Protocol validation: NULL cookie pointer, TRY_ONLY without a
        // disposition pointer, and invalid flags all fail.
        let rax = session.call(lock, &[0, 0, 0]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_INVALID_PARAMETER);
        let rax = session.call(
            lock,
            &[u64::from(LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY), 0, cookie_ptr],
        );
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_INVALID_PARAMETER);
        let rax = session.call(lock, &[0x40, disposition, cookie_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_INVALID_PARAMETER);
        let rax = session.call(unlock, &[0x40, 0]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_INVALID_PARAMETER);
        assert_eq!(
            session.loader_lock_depth(),
            0,
            "failed calls change nothing"
        );
    });
}

#[test]
fn single_dll_drain_runs_tls_then_dllmain() {
    run_on_big_stack(|| {
        let (_tmp, mut session) = setup_session();
        let load = session.alloc_thunk(HostThunk::LdrLoadDll);
        let handle_ptr = ARENA;
        session.map_guest(handle_ptr, &[0_u8; 8]);

        let dll = build_minimal_dll("ExportA", "solo.dll");
        let path = format!(r"{FIXTURE_DIR}\solo.dll");
        write_guest_pe(&session, &path, &dll);
        map_unicode_string(&mut session, ARENA2, ARENA3, &path);
        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let handle = u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap());

        session.vm_register_commit(handle, 0x3000);
        let len_slot = 0x40_000;
        let buf = 0x40_008;
        session.map_guest(len_slot, &[0_u8; 16]);
        session.map_guest(
            handle + u64::from(TLS_CB_RVA),
            &record_marker_code(0x41, len_slot, buf),
        );
        session.map_guest(
            handle + u64::from(EP_RVA),
            &record_marker_code(0x44, len_slot, buf),
        );
        let drained = session.drain_dll_main_calls();
        assert_eq!(drained, 1);
        assert_eq!(session.read_guest(buf, 2), vec![0x41, 0x44]);
    });
}

// ── Test (f): load-order — TLS callbacks fire in the order loaded ─────────

#[test]
fn two_ldr_load_dll_calls_fire_tls_callbacks_in_load_order() {
    run_on_big_stack(|| {
        let (_tmp, mut session) = setup_session();
        let load = session.alloc_thunk(HostThunk::LdrLoadDll);
        let handle_ptr = ARENA;
        session.map_guest(handle_ptr, &[0_u8; 8]);

        // Two REAL DLLs, each with a DllMain entry point and one TLS
        // callback that appends its marker to a shared record buffer.
        // The loader queues each module's DLL_PROCESS_ATTACH at the
        // TAIL of the FIFO, so the drain fires TLS callbacks (before
        // each DllMain) in load order.
        let first = build_minimal_dll("ExportA", "order_first.dll");
        let second = build_minimal_dll("ExportB", "order_second.dll");
        let first_path = format!(r"{FIXTURE_DIR}\order_first.dll");
        let second_path = format!(r"{FIXTURE_DIR}\order_second.dll");
        write_guest_pe(&session, &first_path, &first);
        write_guest_pe(&session, &second_path, &second);

        map_unicode_string(&mut session, ARENA2, ARENA3, &first_path);
        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let first_handle =
            u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap());
        map_unicode_string(&mut session, ARENA2, ARENA3, &second_path);
        let rax = session.call(load, &[0, 0, ARENA2, handle_ptr]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        let second_handle =
            u64::from_le_bytes(session.read_guest(handle_ptr, 8).try_into().unwrap());
        assert_ne!(first_handle, second_handle);

        // The pending queue pins the load order: FIRST then SECOND.
        assert_eq!(
            session.pending_dll_main_calls(),
            vec![(first_handle, 0x1000, 1), (second_handle, 0x1000, 1),],
            "a later LdrLoadDll appends AFTER the currently loaded modules"
        );

        // Make the module regions guest-executable and place real code
        // at the entry-point / TLS-callback RVAs.
        for handle in [first_handle, second_handle] {
            session.vm_register_commit(handle, 0x3000);
            session.map_guest(handle + u64::from(EP_RVA), &[0xC3]); // DllMain: ret
        }
        // TLS callbacks append their marker; DllMains append 0x44 so
        // the full interleave (TLS before DllMain on attach) is
        // observable.
        let len_slot = 0x40_000;
        let buf = 0x40_008;
        session.map_guest(len_slot, &[0_u8; 16]);
        session.map_guest(
            first_handle + u64::from(TLS_CB_RVA),
            &record_marker_code(0x41, len_slot, buf),
        );
        session.map_guest(
            second_handle + u64::from(TLS_CB_RVA),
            &record_marker_code(0x42, len_slot, buf),
        );
        session.map_guest(
            first_handle + u64::from(EP_RVA),
            &record_marker_code(0x44, len_slot, buf),
        );
        session.map_guest(
            second_handle + u64::from(EP_RVA),
            &record_marker_code(0x44, len_slot, buf),
        );

        // Drain: TLS(first), DllMain(first), TLS(second),
        // DllMain(second) — the order the loader queued them.
        let drained = session.drain_dll_main_calls();
        assert_eq!(drained, 2, "both queued entry points ran");
        assert_eq!(
            session.read_guest(buf, 4),
            vec![0x41, 0x44, 0x42, 0x44],
            "TLS callbacks fire in load order, TLS before DllMain on attach"
        );

        // LdrAddRefDll / LdrRemoveRefDll are the same refcount
        // primitives the Win32 path counts with: pin, then unpin, then
        // unload to 0.
        let add_ref = session.alloc_thunk(HostThunk::LdrAddRefDll);
        let remove_ref = session.alloc_thunk(HostThunk::LdrRemoveRefDll);
        let unload = session.alloc_thunk(HostThunk::LdrUnloadDll);
        let rax = session.call(add_ref, &[u64::from(LDR_ADDREF_DLL_PIN), first_handle]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        assert_eq!(session.dll_info_load_count(first_handle), Some(u32::MAX));
        let rax = session.call(
            remove_ref,
            &[u64::from(LDR_REMOVE_REF_DLL_PIN), first_handle],
        );
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        assert_eq!(session.dll_info_load_count(first_handle), Some(1));
        let rax = session.call(unload, &[first_handle]);
        assert_eq!(NtStatus::from_raw(rax as u32), STATUS_SUCCESS);
        assert!(!session.is_module_loaded(first_handle));
    });
}
