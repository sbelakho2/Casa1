//! Shell-link COM surface evidence: the real `IShellLinkW` +
//! `IPersistFile` object behind `CLSID_ShellLink`.
//!
//! The implementation lives with the runtime's guest-object machinery (the
//! shell-link state machine handles every vtable slot, persists genuine
//! `.lnk` bytes through `src/lnk.rs`, and now loads/resolves them back).
//! This module is the adversarial conformance contract for that surface: it
//! drives each slot through the real import dispatch, pins the exact
//! success values/artifacts and the exact invalid-input failures.

#[cfg(test)]
mod tests {
    use super::super::super::*;
    use super::super::test_support::{Fixture, dispatch_x86, with_big_stack, x86_fixture};

    const OUT: u64 = 0x70_000;
    const TEXT: u64 = 0x71_000;
    const FIND: u64 = 0x72_000;
    const CLSID: u64 = 0x73_000;
    const IID: u64 = 0x74_000;
    const IID2: u64 = 0x74_100;

    const CLSID_SHELL_LINK: &str = "{00021401-0000-0000-C000-000000000046}";
    const IID_ISHELLLINKW: &str = "{000214F9-0000-0000-C000-000000000046}";
    const IID_IPERSISTFILE: &str = "{0000010B-0000-0000-C000-000000000046}";
    const IID_IUNKNOWN: &str = "{00000000-0000-0000-C000-000000000046}";

    fn write_iid(fixture: &mut Fixture, address: u64, iid: &str) {
        let bytes = crate::real_win32::guid_from_string(iid).expect("guid");
        fixture.memory.map_bytes(address, &bytes);
    }

    fn wide(fixture: &mut Fixture, text: &str) -> u64 {
        fixture
            .runtime
            .alloc_utf16_string(&mut fixture.memory, text)
            .expect("wide string")
    }

    fn read_out_pointer(fixture: &Fixture, address: u64) -> u64 {
        read_guest_pointer(&fixture.memory, address, GuestArch::X86).expect("pointer")
    }

    fn read_out_string(fixture: &Fixture, address: u64) -> String {
        let ptr = read_out_pointer(fixture, address);
        read_utf16_string(&fixture.memory, ptr).expect("utf16")
    }

    /// Create the CLSID_ShellLink object and its IPersistFile interface.
    fn create(fixture: &mut Fixture) -> (u64, u64) {
        write_iid(fixture, CLSID, CLSID_SHELL_LINK);
        write_iid(fixture, IID, IID_ISHELLLINKW);
        fixture.memory.map_bytes(OUT, &[0_u8; 4]);
        let created = dispatch_x86(
            fixture,
            HostThunk::CoCreateInstance,
            &[CLSID as u32, 0, 1, IID as u32, OUT as u32],
        );
        assert_eq!(created, 0, "CoCreateInstance(CLSID_ShellLink)");
        let shell_link = read_out_pointer(fixture, OUT);

        write_iid(fixture, IID2, IID_IPERSISTFILE);
        fixture.memory.map_bytes(OUT, &[0_u8; 4]);
        let queried = dispatch_x86(
            fixture,
            HostThunk::ShellLinkQueryInterface,
            &[shell_link as u32, IID2 as u32, OUT as u32],
        );
        assert_eq!(queried, 0, "IShellLinkW::QueryInterface(IPersistFile)");
        let persist = read_out_pointer(fixture, OUT);
        (shell_link, persist)
    }

    fn set_path(fixture: &mut Fixture, shell_link: u64, path: &str) {
        let ptr = wide(fixture, path);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::ShellLinkSetPathW,
                &[shell_link as u32, ptr as u32]
            ),
            0
        );
    }

    #[test]
    fn shell_link_full_vtable_surface_round_trips_and_rejects_invalid_inputs() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("shell-link-surface");
            let (shell_link, persist) = create(&mut fixture);

            // IUnknown.
            for iid in [IID_IUNKNOWN, IID_ISHELLLINKW] {
                write_iid(&mut fixture, IID, iid);
                fixture.memory.map_bytes(OUT, &[0_u8; 4]);
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::ShellLinkQueryInterface,
                        &[shell_link as u32, IID as u32, OUT as u32]
                    ),
                    0
                );
                assert_eq!(read_out_pointer(&fixture, OUT), shell_link);
                let referenced = read_out_pointer(&fixture, OUT);
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkRelease,
                    &[referenced as u32],
                );
            }
            write_iid(&mut fixture, IID, "{11111111-2222-3333-4444-555555555555}");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkQueryInterface,
                    &[shell_link as u32, IID as u32, OUT as u32]
                ),
                0x8000_4002
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkQueryInterface,
                    &[shell_link as u32, IID as u32, 0]
                ),
                0x8007_0057
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkAddRef,
                    &[shell_link as u32]
                ),
                3
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkRelease,
                    &[shell_link as u32]
                ),
                2
            );

            // Target path + GetPath/WIN32_FIND_DATAW.
            set_path(&mut fixture, shell_link, "C:\\shell-target.exe");
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetPathW,
                    &[shell_link as u32, OUT as u32, 260, FIND as u32, 0]
                ),
                19
            );
            assert_eq!(
                read_utf16_string(&fixture.memory, OUT).unwrap(),
                "C:\\shell-target.exe"
            );
            assert_eq!(fixture.memory.read_u32(FIND).unwrap(), 0x80);
            let name_units: Vec<u16> = (0..16)
                .map(|index| fixture.memory.read_u16(FIND + 44 + index * 2).unwrap())
                .collect();
            let name = String::from_utf16_lossy(&name_units);
            assert_eq!(name, "shell-target.exe");

            // Description.
            let description = wide(&mut fixture, "A shortcut");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkSetDescriptionW,
                    &[shell_link as u32, description as u32]
                ),
                0
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetDescriptionW,
                    &[shell_link as u32, OUT as u32, 260]
                ),
                10
            );
            assert_eq!(
                read_utf16_string(&fixture.memory, OUT).unwrap(),
                "A shortcut"
            );

            // Working directory.
            let working = wide(&mut fixture, "C:\\work");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkSetWorkingDirectoryW,
                    &[shell_link as u32, working as u32]
                ),
                0
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetWorkingDirectoryW,
                    &[shell_link as u32, OUT as u32, 260]
                ),
                7
            );
            assert_eq!(read_utf16_string(&fixture.memory, OUT).unwrap(), "C:\\work");

            // Arguments.
            let arguments = wide(&mut fixture, "-silent");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkSetArgumentsW,
                    &[shell_link as u32, arguments as u32]
                ),
                0
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetArgumentsW,
                    &[shell_link as u32, OUT as u32, 260]
                ),
                7
            );
            assert_eq!(read_utf16_string(&fixture.memory, OUT).unwrap(), "-silent");

            // Hotkey.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkSetHotkey,
                    &[shell_link as u32, 0x0341]
                ),
                0
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetHotkey,
                    &[shell_link as u32, OUT as u32]
                ),
                0
            );
            assert_eq!(fixture.memory.read_u16(OUT).unwrap(), 0x0341);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetHotkey,
                    &[shell_link as u32, 0]
                ),
                0x8007_0057
            );

            // Show command.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkSetShowCmd,
                    &[shell_link as u32, 7]
                ),
                0
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetShowCmd,
                    &[shell_link as u32, OUT as u32]
                ),
                0
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 7);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetShowCmd,
                    &[shell_link as u32, 0]
                ),
                0x8007_0057
            );

            // Icon location/index.
            let icon = wide(&mut fixture, "C:\\icons.dll");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkSetIconLocationW,
                    &[shell_link as u32, icon as u32, 3]
                ),
                0
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            fixture.memory.map_bytes(TEXT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetIconLocationW,
                    &[shell_link as u32, OUT as u32, 260, TEXT as u32]
                ),
                12
            );
            assert_eq!(
                read_utf16_string(&fixture.memory, OUT).unwrap(),
                "C:\\icons.dll"
            );
            assert_eq!(fixture.memory.read_u32(TEXT).unwrap(), 3);

            // ID list (the runtime's guest PIDL is the path payload).
            let id_source = wide(&mut fixture, "C:\\id-payload.exe");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkSetIDList,
                    &[shell_link as u32, id_source as u32]
                ),
                0
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetIDList,
                    &[shell_link as u32, OUT as u32]
                ),
                0
            );
            assert_eq!(read_out_string(&fixture, OUT), "C:\\id-payload.exe");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetIDList,
                    &[shell_link as u32, 0]
                ),
                0x8007_0057
            );
            set_path(&mut fixture, shell_link, "C:\\shell-target.exe");

            // Relative path + resolve success/failure and the persisted bytes.
            let target = fixture._temp.path().join("resolved.exe");
            std::fs::write(&target, b"MZ").expect("target");
            fixture
                .runtime
                .win32
                .stage_host_file_w(&target, "C:\\work\\resolved.exe")
                .expect("stage target");
            set_path(&mut fixture, shell_link, "C:\\work\\missing.exe");
            let relative = wide(&mut fixture, "resolved.exe");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkSetRelativePath,
                    &[shell_link as u32, relative as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkResolve,
                    &[shell_link as u32, 0]
                ),
                0
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetPathW,
                    &[shell_link as u32, OUT as u32, 260, 0, 0]
                ),
                20
            );
            assert_eq!(
                read_utf16_string(&fixture.memory, OUT).unwrap(),
                "C:\\work\\resolved.exe"
            );
            // A genuinely unresolvable relative path reports S_FALSE.
            let missing = wide(&mut fixture, "no-such.exe");
            set_path(&mut fixture, shell_link, "C:\\work\\also-missing.exe");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkSetRelativePath,
                    &[shell_link as u32, missing as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkResolve,
                    &[shell_link as u32, 0]
                ),
                1
            );
            let _ = persist;
        });
    }

    #[test]
    fn shell_link_persist_file_save_load_and_invalid_streams_are_exact() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("shell-link-persist");
            let (shell_link, persist) = create(&mut fixture);
            assert_ne!(persist, 0);

            // GetClassID: valid buffer and null.
            fixture.memory.map_bytes(CLSID, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistGetClassID,
                    &[persist as u32, CLSID as u32]
                ),
                0
            );
            assert_eq!(fixture.memory.read_u8(CLSID).unwrap(), 0x01);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistGetClassID,
                    &[persist as u32, 0]
                ),
                0x8007_0057
            );

            // IsDirty: fresh S_FALSE, after SetPath S_OK.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistIsDirty,
                    &[persist as u32]
                ),
                1
            );
            set_path(&mut fixture, shell_link, "C:\\persist-target.exe");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistIsDirty,
                    &[persist as u32]
                ),
                0
            );

            // Save to a real guest path (with the persisted relative path).
            let relative_path = wide(&mut fixture, "persist-target.exe");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkSetRelativePath,
                    &[shell_link as u32, relative_path as u32]
                ),
                0
            );
            let link = wide(&mut fixture, "C:\\saved-link.lnk");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistSave,
                    &[persist as u32, link as u32, 1]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistIsDirty,
                    &[persist as u32]
                ),
                1
            );
            let host_link = fixture
                .runtime
                .win32
                .guest_path_to_host_path("C:\\saved-link.lnk")
                .expect("host link");
            let bytes = std::fs::read(&host_link).expect("read link");
            let parsed = crate::lnk::parse(&bytes).expect("parse link");
            assert_eq!(
                parsed.target_path.as_deref(),
                Some("C:\\persist-target.exe")
            );
            assert_eq!(parsed.relative_path.as_deref(), Some("persist-target.exe"));

            // GetCurFile.
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistGetCurFile,
                    &[persist as u32, OUT as u32]
                ),
                0
            );
            assert_eq!(read_out_string(&fixture, OUT), "C:\\saved-link.lnk");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistGetCurFile,
                    &[persist as u32, 0]
                ),
                0x8007_0057
            );

            // SaveCompleted clears the dirty state and records the path.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistSaveCompleted,
                    &[persist as u32, link as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistIsDirty,
                    &[persist as u32]
                ),
                1
            );

            // Save without a target and to an unwritable path.
            let (empty_link, empty_persist) = create(&mut fixture);
            let unwritable = wide(&mut fixture, "C:\\saved-link.lnk");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistSave,
                    &[empty_persist as u32, unwritable as u32, 1]
                ),
                0x8007_0057
            );
            set_path(&mut fixture, empty_link, "C:\\persist-target.exe");
            let denied = wide(&mut fixture, "C:\\missing-dir\\denied.lnk");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistSave,
                    &[empty_persist as u32, denied as u32, 1]
                ),
                0x8007_0005
            );

            // Load restores every persisted field; malformed streams fail.
            let (loaded_link, loaded_persist) = create(&mut fixture);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistLoad,
                    &[loaded_persist as u32, link as u32]
                ),
                0
            );
            fixture.memory.map_bytes(OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkGetPathW,
                    &[loaded_link as u32, OUT as u32, 260, 0, 0]
                ),
                21
            );
            assert_eq!(
                read_utf16_string(&fixture.memory, OUT).unwrap(),
                "C:\\persist-target.exe"
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistIsDirty,
                    &[loaded_persist as u32]
                ),
                1
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistLoad,
                    &[loaded_persist as u32, 0]
                ),
                0x8007_0057
            );
            fixture
                .runtime
                .win32
                .write_file_overwrite_w("C:\\bad-link.lnk", b"not a link")
                .expect("write malformed");
            let malformed = wide(&mut fixture, "C:\\bad-link.lnk");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistLoad,
                    &[loaded_persist as u32, malformed as u32]
                ),
                0x8000_4005
            );
            let missing = wide(&mut fixture, "C:\\no-such-link.lnk");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ShellLinkPersistLoad,
                    &[loaded_persist as u32, missing as u32]
                ),
                0x8000_4005
            );
        });
    }
}
