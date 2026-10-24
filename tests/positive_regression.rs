use casa1::audio_activation::{IID_IAUDIO_CLIENT, WAVE_FORMAT_IEEE_FLOAT, parse_wave_format};
use casa1::cpu::{GuestArch, IrInstruction, MemoryImage, MemoryOperand, Register};
use casa1::d3d11::{DeviceCreationRequest, FeatureLevel, d3d11_create_device};
use casa1::d3d12::{
    D3d12Runtime, DxgiFormat, HeapType, ResourceDesc, ResourceState, ResourceUsageHint,
};
use casa1::ge::{GameEnvironment, GeArch};
use casa1::gfx::{BufferRole, ResourceUsageHint as GfxResourceUsageHint};
use casa1::jit::{JitExitReason, JitRuntime};
use casa1::media::{MF_MT_MAJOR_TYPE, MF_MT_SAMPLE_RATE, MFMediaType_Video};
use casa1::pe_runtime::{HostThunk, NtThunkSession};
use casa1::real_audio::RealAudioBackend;
use casa1::wddm::{
    CreateAllocationRequest, CreateDeviceRequest, SEGMENT_LOCAL, STATUS_INVALID_HANDLE,
    STATUS_TIMEOUT, WddmSubsystem,
};
use std::fs;
use tempfile::TempDir;

const INVALID_HANDLE_VALUE: u64 = u64::MAX;
const STATUS_SUCCESS: i32 = 0;
const STATUS_DEVICE_BUSY: i32 = 0x8000_0011_u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034_u32 as i32;
const STATUS_IMAGE_ALREADY_LOADED: i32 = 0xC000_010E_u32 as i32;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const REG_CREATED_NEW_KEY: u32 = 1;
const HKEY_CURRENT_USER: u64 = 0x8000_0001;
const CLSID_FILTER_GRAPH_BYTES: [u8; 16] = [
    0xB3, 0xEB, 0x36, 0xE4, 0x4F, 0x52, 0xCE, 0x11, 0x9F, 0x53, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70,
];
const IID_IGRAPH_BUILDER_BYTES: [u8; 16] = [
    0xA9, 0xA8, 0x68, 0x56, 0xD4, 0x0A, 0xCE, 0x11, 0xB0, 0x3A, 0x00, 0x20, 0xAF, 0x0B, 0xA7, 0x70,
];

fn with_big_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    let handle = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .name("positive-regression".to_string())
        .spawn(body)
        .expect("spawn test thread");
    match handle.join() {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn session(name: &str) -> (TempDir, NtThunkSession) {
    let directory = TempDir::new().expect("temporary directory");
    let ge = GameEnvironment::create_in(directory.path(), name, GeArch::X64, "win11-23h2")
        .expect("game environment");
    (directory, NtThunkSession::new(ge))
}

fn session_with_ge<F: FnOnce(&mut GameEnvironment)>(
    name: &str,
    configure: F,
) -> (TempDir, NtThunkSession) {
    let directory = TempDir::new().expect("temporary directory");
    let mut ge = GameEnvironment::create_in(directory.path(), name, GeArch::X64, "win11-23h2")
        .expect("game environment");
    configure(&mut ge);
    (directory, NtThunkSession::new(ge))
}

fn map_utf16(session: &mut NtThunkSession, address: u64, text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    session.map_guest(address, &bytes);
    bytes
}

fn read_utf16(session: &NtThunkSession, address: u64) -> String {
    let mut units = Vec::new();
    let mut offset = 0;
    loop {
        let unit = session.read_guest(address + offset, 2);
        let value = u16::from_le_bytes([unit[0], unit[1]]);
        if value == 0 {
            break;
        }
        units.push(value);
        offset += 2;
    }
    String::from_utf16(&units).expect("valid utf16")
}

fn map_bytes(session: &mut NtThunkSession, address: u64, bytes: &[u8]) {
    session.map_guest(address, bytes);
}

fn read_u32(session: &NtThunkSession, address: u64) -> u32 {
    let bytes = session.read_guest(address, 4);
    u32::from_le_bytes(bytes.try_into().unwrap())
}

fn read_u64(session: &NtThunkSession, address: u64) -> u64 {
    let bytes = session.read_guest(address, 8);
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn write_u32(session: &mut NtThunkSession, address: u64, value: u32) {
    session.map_guest(address, &value.to_le_bytes());
}

fn write_u64(session: &mut NtThunkSession, address: u64, value: u64) {
    session.map_guest(address, &value.to_le_bytes());
}

fn guest_unicode_string(session: &mut NtThunkSession, header: u64, text: &str) {
    let units: Vec<u16> = text.encode_utf16().collect();
    let buffer = header + 0x100;
    let mut payload = Vec::new();
    for unit in &units {
        payload.extend_from_slice(&unit.to_le_bytes());
    }
    payload.extend_from_slice(&0_u16.to_le_bytes());
    session.map_guest(buffer, &payload);
    let mut bytes = [0_u8; 16];
    bytes[0..2].copy_from_slice(&((units.len() * 2) as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&(((units.len() + 1) * 2) as u16).to_le_bytes());
    bytes[8..16].copy_from_slice(&buffer.to_le_bytes());
    session.map_guest(header, &bytes);
}

fn call(session: &mut NtThunkSession, thunk: HostThunk, args: &[u64]) -> u64 {
    let address = session.alloc_thunk(thunk);
    session.call(address, args)
}

#[test]
fn win32_file_io_create_write_read_seek_set_end_close() {
    with_big_stack(|| {
        let (_directory, mut session) = session("positive-win32-file");
        let directory_path = 0x30_000;
        map_utf16(&mut session, directory_path, "C:\\positive");
        assert_eq!(
            call(&mut session, HostThunk::CreateDirectoryW, &[directory_path]),
            1
        );

        let path = 0x31_000;
        map_utf16(&mut session, path, "C:\\positive\\file.bin");
        let handle = call(
            &mut session,
            HostThunk::CreateFileW,
            &[path, 0x4000_0000 | 0x8000_0000, 7, 0, 2, 0x80, 0],
        );
        assert_ne!(handle, 0);
        assert_ne!(handle, INVALID_HANDLE_VALUE);

        let payload = b"CASA1-FILE";
        let buffer = 0x32_000;
        map_bytes(&mut session, buffer, payload);
        let written = 0x33_000;
        map_bytes(&mut session, written, &[0; 4]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::WriteFile,
                &[handle, buffer, payload.len() as u64, written, 0],
            ),
            1
        );
        assert_eq!(read_u32(&session, written), payload.len() as u32);

        let size_out = 0x33_100;
        map_bytes(&mut session, size_out, &[0; 8]);
        assert_eq!(
            call(&mut session, HostThunk::GetFileSizeEx, &[handle, size_out]),
            1
        );
        assert_eq!(read_u64(&session, size_out), payload.len() as u64);

        let position_out = 0x33_200;
        map_bytes(&mut session, position_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::SetFilePointerEx,
                &[handle, 4, 0, 0, position_out],
            ),
            1
        );
        assert_eq!(read_u64(&session, position_out), 4);

        let read_buffer = 0x34_000;
        map_bytes(&mut session, read_buffer, &[0; 8]);
        let bytes_read = 0x33_300;
        map_bytes(&mut session, bytes_read, &[0; 4]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::ReadFile,
                &[handle, read_buffer, 4, bytes_read, 0],
            ),
            1
        );
        assert_eq!(read_u32(&session, bytes_read), 4);
        assert_eq!(session.read_guest(read_buffer, 4), payload[4..8].to_vec());

        assert_eq!(
            call(
                &mut session,
                HostThunk::SetFilePointerEx,
                &[handle, 6, 0, 0, position_out],
            ),
            1
        );
        assert_eq!(read_u64(&session, position_out), 6);
        assert_eq!(call(&mut session, HostThunk::SetEndOfFile, &[handle]), 1);
        assert_eq!(
            call(&mut session, HostThunk::GetFileSizeEx, &[handle, size_out]),
            1
        );
        assert_eq!(read_u64(&session, size_out), 6);
        assert_eq!(call(&mut session, HostThunk::CloseHandle, &[handle]), 1);

        let reopened = call(
            &mut session,
            HostThunk::CreateFileW,
            &[path, 0x8000_0000, 7, 0, 3, 0x80, 0],
        );
        assert_ne!(reopened, INVALID_HANDLE_VALUE);
        let final_buffer = 0x35_000;
        map_bytes(&mut session, final_buffer, &[0; 8]);
        map_bytes(&mut session, bytes_read, &[0; 4]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::ReadFile,
                &[reopened, final_buffer, 8, bytes_read, 0],
            ),
            1
        );
        assert_eq!(read_u32(&session, bytes_read), 6);
        assert_eq!(session.read_guest(final_buffer, 6), b"CASA1-".to_vec());
        assert_eq!(call(&mut session, HostThunk::CloseHandle, &[reopened]), 1);
        let host_path = session
            .win32()
            .guest_path_to_host_path("C:\\positive\\file.bin")
            .expect("guest path");
        assert_eq!(fs::read(host_path).unwrap(), b"CASA1-");
    });
}

#[test]
fn win32_move_file_ex_rename_and_replace() {
    with_big_stack(|| {
        let (_directory, mut session) = session("positive-win32-move");
        let directory_path = 0x30_000;
        map_utf16(&mut session, directory_path, "C:\\positive");
        assert_eq!(
            call(&mut session, HostThunk::CreateDirectoryW, &[directory_path]),
            1
        );

        let source = 0x31_000;
        let destination = 0x32_000;
        map_utf16(&mut session, source, "C:\\positive\\source.bin");
        map_utf16(&mut session, destination, "C:\\positive\\dest.bin");

        let handle = call(
            &mut session,
            HostThunk::CreateFileW,
            &[source, 0x4000_0000, 0, 0, 2, 0x80, 0],
        );
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        let buffer = 0x33_000;
        map_bytes(&mut session, buffer, b"first");
        let written = 0x34_000;
        write_u32(&mut session, written, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::WriteFile,
                &[handle, buffer, 5, written, 0],
            ),
            1
        );
        assert_eq!(call(&mut session, HostThunk::CloseHandle, &[handle]), 1);

        assert_eq!(
            call(
                &mut session,
                HostThunk::MoveFileExW,
                &[source, destination, 0],
            ),
            1
        );
        assert!(
            !session
                .win32()
                .guest_path_to_host_path("C:\\positive\\source.bin")
                .unwrap()
                .exists()
        );
        assert_eq!(
            fs::read(
                session
                    .win32()
                    .guest_path_to_host_path("C:\\positive\\dest.bin")
                    .unwrap()
            )
            .unwrap(),
            b"first"
        );

        let source_two = 0x35_000;
        map_utf16(&mut session, source_two, "C:\\positive\\source2.bin");
        let handle = call(
            &mut session,
            HostThunk::CreateFileW,
            &[source_two, 0x4000_0000, 0, 0, 2, 0x80, 0],
        );
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        map_bytes(&mut session, buffer, b"second");
        assert_eq!(
            call(
                &mut session,
                HostThunk::WriteFile,
                &[handle, buffer, 6, written, 0],
            ),
            1
        );
        assert_eq!(call(&mut session, HostThunk::CloseHandle, &[handle]), 1);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MoveFileExW,
                &[source_two, destination, 1],
            ),
            1
        );
        assert_eq!(
            fs::read(
                session
                    .win32()
                    .guest_path_to_host_path("C:\\positive\\dest.bin")
                    .unwrap()
            )
            .unwrap(),
            b"second"
        );
    });
}

#[test]
fn registry_create_set_query_enumerate_delete() {
    with_big_stack(|| {
        let (_directory, mut session) = session("positive-registry");
        let subkey = 0x30_000;
        map_utf16(&mut session, subkey, "Software\\Casa1Positive");
        let key_out = 0x31_000;
        write_u32(&mut session, key_out, 0);
        let disposition = 0x31_100;
        write_u32(&mut session, disposition, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::RegCreateKeyExW,
                &[
                    HKEY_CURRENT_USER,
                    subkey,
                    0,
                    0,
                    0,
                    0x20019,
                    0,
                    key_out,
                    disposition,
                ],
            ),
            0
        );
        let key = read_u32(&session, key_out);
        assert_ne!(key, 0);
        assert_eq!(read_u32(&session, disposition), REG_CREATED_NEW_KEY);

        let greeting = 0x32_000;
        map_utf16(&mut session, greeting, "Greeting");
        let greeting_data = 0x33_000;
        let greeting_bytes: Vec<u8> = "hello"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .chain([0, 0])
            .collect();
        map_bytes(&mut session, greeting_data, &greeting_bytes);
        assert_eq!(
            call(
                &mut session,
                HostThunk::RegSetValueExW,
                &[
                    key as u64,
                    greeting,
                    0,
                    REG_SZ as u64,
                    greeting_data,
                    greeting_bytes.len() as u64,
                ],
            ),
            0
        );

        let answer = 0x32_100;
        map_utf16(&mut session, answer, "Answer");
        let answer_data = 0x33_100;
        map_bytes(&mut session, answer_data, &42_u32.to_le_bytes());
        assert_eq!(
            call(
                &mut session,
                HostThunk::RegSetValueExW,
                &[key as u64, answer, 0, REG_DWORD as u64, answer_data, 4],
            ),
            0
        );

        let type_out = 0x34_000;
        let length_out = 0x34_100;
        let data_out = 0x35_000;
        write_u32(&mut session, type_out, 0);
        write_u32(&mut session, length_out, 64);
        map_bytes(&mut session, data_out, &[0; 64]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::RegQueryValueExW,
                &[key as u64, greeting, 0, type_out, data_out, length_out],
            ),
            0
        );
        assert_eq!(read_u32(&session, type_out), REG_SZ);
        assert_eq!(read_u32(&session, length_out), greeting_bytes.len() as u32);
        assert_eq!(
            session.read_guest(data_out, greeting_bytes.len()),
            greeting_bytes
        );

        write_u32(&mut session, type_out, 0);
        write_u32(&mut session, length_out, 4);
        map_bytes(&mut session, data_out, &[0; 4]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::RegQueryValueExW,
                &[key as u64, answer, 0, type_out, data_out, length_out],
            ),
            0
        );
        assert_eq!(read_u32(&session, type_out), REG_DWORD);
        assert_eq!(read_u32(&session, length_out), 4);
        assert_eq!(read_u32(&session, data_out), 42);

        let name_out = 0x36_000;
        let name_size = 0x36_100;
        let data_size = 0x36_200;
        write_u32(&mut session, name_size, 16);
        write_u32(&mut session, data_size, 16);
        map_bytes(&mut session, name_out, &[0; 32]);
        map_bytes(&mut session, data_out, &[0; 16]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::RegEnumValueW,
                &[
                    key as u64, 0, name_out, name_size, 0, type_out, data_out, data_size,
                ],
            ),
            0
        );
        assert_eq!(read_utf16(&session, name_out), "Answer");
        assert_eq!(read_u32(&session, type_out), REG_DWORD);
        assert_eq!(read_u32(&session, data_out), 42);

        write_u32(&mut session, name_size, 16);
        write_u32(&mut session, data_size, 64);
        map_bytes(&mut session, name_out, &[0; 32]);
        map_bytes(&mut session, data_out, &[0; 64]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::RegEnumValueW,
                &[
                    key as u64, 1, name_out, name_size, 0, type_out, data_out, data_size,
                ],
            ),
            0
        );
        assert_eq!(read_utf16(&session, name_out), "Greeting");
        assert_eq!(read_u32(&session, type_out), REG_SZ);
        assert_eq!(
            session.read_guest(data_out, greeting_bytes.len()),
            greeting_bytes
        );

        assert_eq!(
            call(
                &mut session,
                HostThunk::RegEnumValueW,
                &[
                    key as u64, 2, name_out, name_size, 0, type_out, data_out, data_size,
                ],
            ),
            ERROR_NO_MORE_ITEMS as u64
        );

        assert_eq!(call(&mut session, HostThunk::RegCloseKey, &[key as u64]), 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::RegDeleteKeyW,
                &[HKEY_CURRENT_USER, subkey],
            ),
            0
        );

        write_u32(&mut session, key_out, 0);
        write_u32(&mut session, disposition, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::RegCreateKeyExW,
                &[
                    HKEY_CURRENT_USER,
                    subkey,
                    0,
                    0,
                    0,
                    0x20019,
                    0,
                    key_out,
                    disposition,
                ],
            ),
            0
        );
        let recreated = read_u32(&session, key_out);
        assert_ne!(recreated, 0);
        assert_eq!(read_u32(&session, disposition), REG_CREATED_NEW_KEY);
        assert_eq!(
            call(&mut session, HostThunk::RegCloseKey, &[recreated as u64]),
            0
        );
    });
}

#[test]
fn com_initialize_class_factory_istream_and_moniker() {
    with_big_stack(|| {
        let (_directory, mut session) = session("positive-com");
        assert_eq!(call(&mut session, HostThunk::CoInitialize, &[0]), 0);
        assert_eq!(call(&mut session, HostThunk::CoInitialize, &[0]), 1);
        call(&mut session, HostThunk::CoUninitialize, &[]);
        assert_eq!(call(&mut session, HostThunk::CoInitialize, &[0]), 0);

        let clsid = 0x30_000;
        let iid = 0x30_100;
        map_bytes(&mut session, clsid, &CLSID_FILTER_GRAPH_BYTES);
        map_bytes(&mut session, iid, &IID_IGRAPH_BUILDER_BYTES);
        let factory_out = 0x31_000;
        map_bytes(&mut session, factory_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::DllGetClassObject,
                &[clsid, iid, factory_out],
            ),
            0
        );
        let factory = read_u64(&session, factory_out);
        assert_ne!(factory, 0);

        let object_out = 0x31_100;
        map_bytes(&mut session, object_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::ComFactoryCreateInstance,
                &[factory, 0, iid, object_out],
            ),
            0
        );
        let object = read_u64(&session, object_out);
        assert_ne!(object, 0);

        let stream_out = 0x31_200;
        map_bytes(&mut session, stream_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::CoMarshalInterThreadInterfaceInStream,
                &[iid, factory, stream_out],
            ),
            0
        );
        let stream = read_u64(&session, stream_out);
        assert_ne!(stream, 0);
        let vtable = read_u64(&session, stream);
        assert_ne!(vtable, 0);

        let write_buffer = 0x32_000;
        map_bytes(&mut session, write_buffer, b"CASA");
        let written = 0x32_100;
        write_u32(&mut session, written, 0);
        let write_fn = read_u64(&session, vtable + 4 * 8);
        assert_eq!(
            session.call(write_fn, &[stream, write_buffer, 4, written]),
            0
        );
        assert_eq!(read_u32(&session, written), 4);

        let seek_out = 0x32_200;
        map_bytes(&mut session, seek_out, &[0; 8]);
        let seek_fn = read_u64(&session, vtable + 5 * 8);
        assert_eq!(session.call(seek_fn, &[stream, 0, 0, seek_out]), 0);
        assert_eq!(read_u64(&session, seek_out), 0);

        let read_buffer = 0x33_000;
        map_bytes(&mut session, read_buffer, &[0; 8]);
        let read_out = 0x32_300;
        write_u32(&mut session, read_out, 0);
        let read_fn = read_u64(&session, vtable + 3 * 8);
        assert_eq!(
            session.call(read_fn, &[stream, read_buffer, 4, read_out]),
            0
        );
        assert_eq!(read_u32(&session, read_out), 4);
        assert_eq!(session.read_guest(read_buffer, 4), b"CASA".to_vec());

        let stream_roundtrip = 0x31_300;
        map_bytes(&mut session, stream_roundtrip, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::CoMarshalInterThreadInterfaceInStream,
                &[iid, factory, stream_roundtrip],
            ),
            0
        );
        let roundtrip_stream = read_u64(&session, stream_roundtrip);
        let recovered_out = 0x31_400;
        map_bytes(&mut session, recovered_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::CoGetInterfaceAndReleaseStream,
                &[roundtrip_stream, iid, recovered_out],
            ),
            0
        );
        assert_eq!(read_u64(&session, recovered_out), factory);

        let url = 0x34_000;
        map_utf16(&mut session, url, "http://example.com/game");
        let moniker_out = 0x31_500;
        map_bytes(&mut session, moniker_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::CreateURLMoniker,
                &[0, url, moniker_out],
            ),
            0
        );
        let moniker = read_u64(&session, moniker_out);
        assert_ne!(moniker, 0);
        let display_out = 0x31_600;
        map_bytes(&mut session, display_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MonikerGetDisplayName,
                &[moniker, 0, 0, display_out],
            ),
            0
        );
        let display_name = read_u64(&session, display_out);
        assert_ne!(display_name, 0);
        assert_eq!(
            read_utf16(&session, display_name),
            "http://example.com/game"
        );
    });
}

#[test]
fn media_foundation_objects_and_byte_stream() {
    with_big_stack(|| {
        const MEDIA_BYTES: &[u8] = b"CASA1-MF-BYTES-0123456789";
        let (_directory, mut session) = session_with_ge("positive-mf", |ge| {
            ge.create_directory("C:\\media", true).expect("media dir");
            ge.write_file("C:\\media\\positive.bin", MEDIA_BYTES, true)
                .expect("media file");
        });
        assert_eq!(
            call(&mut session, HostThunk::MfStartup, &[0x0007_0000, 0]),
            0
        );

        let attributes_out = 0x30_000;
        map_bytes(&mut session, attributes_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfCreateAttributes,
                &[attributes_out, 0],
            ),
            0
        );
        assert_ne!(read_u64(&session, attributes_out), 0);

        let media_type_out = 0x30_100;
        map_bytes(&mut session, media_type_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfCreateMediaType,
                &[media_type_out]
            ),
            0
        );
        let media_type = read_u64(&session, media_type_out);
        assert_ne!(media_type, 0);

        let sample_rate_key = 0x31_000;
        map_bytes(
            &mut session,
            sample_rate_key,
            &MF_MT_SAMPLE_RATE.to_bytes_le(),
        );
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfAttrSetUint32,
                &[media_type, sample_rate_key, 48_000],
            ),
            0
        );
        let uint_out = 0x31_100;
        map_bytes(&mut session, uint_out, &[0; 4]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfAttrGetUint32,
                &[media_type, sample_rate_key, uint_out],
            ),
            0
        );
        assert_eq!(read_u32(&session, uint_out), 48_000);

        let major_key = 0x31_200;
        map_bytes(&mut session, major_key, &MF_MT_MAJOR_TYPE.to_bytes_le());
        let video_guid = 0x31_300;
        map_bytes(&mut session, video_guid, &MFMediaType_Video.to_bytes_le());
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfAttrSetGuid,
                &[media_type, major_key, video_guid],
            ),
            0
        );
        let guid_out = 0x31_400;
        map_bytes(&mut session, guid_out, &[0; 16]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfAttrGetGuid,
                &[media_type, major_key, guid_out],
            ),
            0
        );
        assert_eq!(
            session.read_guest(guid_out, 16),
            MFMediaType_Video.to_bytes_le().to_vec()
        );

        let count_out = 0x31_500;
        write_u32(&mut session, count_out, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfAttrGetCount,
                &[media_type, count_out],
            ),
            0
        );
        assert_eq!(read_u32(&session, count_out), 2);

        let buffer_out = 0x30_200;
        map_bytes(&mut session, buffer_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfCreateMemoryBuffer,
                &[64, buffer_out],
            ),
            0
        );
        let buffer = read_u64(&session, buffer_out);
        assert_ne!(buffer, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfBufferSetCurrentLength,
                &[buffer, 6],
            ),
            0
        );
        let max_out = 0x31_600;
        let current_out = 0x31_700;
        write_u32(&mut session, max_out, 0);
        write_u32(&mut session, current_out, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfBufferGetMaxLength,
                &[buffer, max_out],
            ),
            0
        );
        assert_eq!(read_u32(&session, max_out), 64);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfBufferGetCurrentLength,
                &[buffer, current_out],
            ),
            0
        );
        assert_eq!(read_u32(&session, current_out), 6);

        let data_out = 0x32_000;
        let data_max = 0x32_100;
        map_bytes(&mut session, data_out, &[0; 8]);
        write_u32(&mut session, data_max, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfBufferLock,
                &[buffer, data_out, data_max, current_out],
            ),
            0
        );
        let data = read_u64(&session, data_out);
        assert_ne!(data, 0);
        assert_eq!(read_u32(&session, current_out), 6);
        map_bytes(&mut session, data, b"CASA1!");
        assert_eq!(call(&mut session, HostThunk::MfBufferUnlock, &[buffer]), 0);
        map_bytes(&mut session, data_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfBufferLock,
                &[buffer, data_out, data_max, current_out],
            ),
            0
        );
        let data = read_u64(&session, data_out);
        assert_eq!(session.read_guest(data, 6), b"CASA1!".to_vec());
        assert_eq!(call(&mut session, HostThunk::MfBufferUnlock, &[buffer]), 0);

        let sample_out = 0x30_300;
        map_bytes(&mut session, sample_out, &[0; 8]);
        assert_eq!(
            call(&mut session, HostThunk::MfCreateSample, &[sample_out]),
            0
        );
        let sample = read_u64(&session, sample_out);
        assert_ne!(sample, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfSampleSetSampleTime,
                &[sample, 123_456],
            ),
            0
        );
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfSampleSetSampleDuration,
                &[sample, 6_543],
            ),
            0
        );
        let time_out = 0x31_800;
        let duration_out = 0x31_900;
        map_bytes(&mut session, time_out, &[0; 8]);
        map_bytes(&mut session, duration_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfSampleGetSampleTime,
                &[sample, time_out],
            ),
            0
        );
        assert_eq!(read_u64(&session, time_out), 123_456);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfSampleGetSampleDuration,
                &[sample, duration_out],
            ),
            0
        );
        assert_eq!(read_u64(&session, duration_out), 6_543);

        let path = 0x33_000;
        map_utf16(&mut session, path, "C:\\media\\positive.bin");
        let byte_stream_out = 0x30_400;
        map_bytes(&mut session, byte_stream_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfCreateFile,
                &[1, 0, 0, path, byte_stream_out],
            ),
            0
        );
        let byte_stream = read_u64(&session, byte_stream_out);
        assert_ne!(byte_stream, 0);
        let length_out = 0x31_A00;
        map_bytes(&mut session, length_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfByteStreamGetLength,
                &[byte_stream, length_out],
            ),
            0
        );
        assert_eq!(read_u64(&session, length_out), MEDIA_BYTES.len() as u64);

        let stream_buffer = 0x34_000;
        map_bytes(&mut session, stream_buffer, &[0; 16]);
        let stream_read = 0x31_B00;
        write_u32(&mut session, stream_read, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfByteStreamRead,
                &[byte_stream, stream_buffer, 8, stream_read],
            ),
            0
        );
        assert_eq!(read_u32(&session, stream_read), 8);
        assert_eq!(
            session.read_guest(stream_buffer, 8),
            MEDIA_BYTES[..8].to_vec()
        );

        let tail_position = (MEDIA_BYTES.len() - 4) as u64;
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfByteStreamSetCurrentPosition,
                &[byte_stream, tail_position],
            ),
            0
        );
        map_bytes(&mut session, stream_buffer, &[0; 16]);
        write_u32(&mut session, stream_read, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::MfByteStreamRead,
                &[byte_stream, stream_buffer, 4, stream_read],
            ),
            0
        );
        assert_eq!(read_u32(&session, stream_read), 4);
        assert_eq!(
            session.read_guest(stream_buffer, 4),
            MEDIA_BYTES[MEDIA_BYTES.len() - 4..].to_vec()
        );
        assert_eq!(call(&mut session, HostThunk::MfShutdown, &[]), 0);
    });
}

fn build_marker_driver() -> Vec<u8> {
    const TEXT_RVA: u32 = 0x1000;
    const UNLOAD_RVA: u32 = 0x1100;
    const RDATA_RVA: u32 = 0x2000;
    const IMPORT_RVA: u32 = 0x2100;
    const ILT_RVA: u32 = 0x2140;
    const IAT_RVA: u32 = 0x21A0;
    const DLL_NAME_RVA: u32 = 0x2200;
    const DBG_FMT_RVA: u32 = 0x2380;
    const WIDE_DEV_RVA: u32 = 0x23C0;
    const WIDE_LINK_RVA: u32 = 0x2400;
    const DBG_UNLOAD_RVA: u32 = 0x2440;
    const EXPORT_RVA: u32 = 0x2480;
    const DRIVER_PTR_RVA: u32 = 0x3000;
    const US_DEV_RVA: u32 = 0x3008;
    const US_LINK_RVA: u32 = 0x3018;
    const DEV_OBJ_OUT_RVA: u32 = 0x3028;
    const ENTRY_MARKER_RVA: u32 = 0x3030;
    const UNLOAD_MARKER_RVA: u32 = 0x3034;
    const IAT_DBG: u32 = IAT_RVA;
    const IAT_RTL: u32 = IAT_RVA + 8;
    const IAT_IO_CREATE: u32 = IAT_RVA + 16;
    const IAT_IO_SYMLINK: u32 = IAT_RVA + 24;
    const IAT_IO_DELETE: u32 = IAT_RVA + 32;
    const IMPORT_NAMES: [(&str, u32); 5] = [
        ("DbgPrint", 0x2210),
        ("RtlInitUnicodeString", 0x2230),
        ("IoCreateDevice", 0x2250),
        ("IoCreateSymbolicLink", 0x2270),
        ("IoDeleteDevice", 0x2290),
    ];

    fn write_wide(rdata: &mut [u8], offset: usize, text: &str) {
        for (index, unit) in text.encode_utf16().chain([0]).enumerate() {
            rdata[offset + index * 2..offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }

    #[derive(Default)]
    struct CodeBuilder {
        bytes: Vec<u8>,
        fixups: Vec<(usize, u32, usize)>,
    }

    impl CodeBuilder {
        fn raw(&mut self, bytes: &[u8]) {
            self.bytes.extend_from_slice(bytes);
        }

        fn disp(&mut self, target: u32) {
            self.disp_with_trailing(target, 0);
        }

        fn disp_with_trailing(&mut self, target: u32, trailing: usize) {
            let offset = self.bytes.len();
            self.bytes.extend_from_slice(&[0_u8; 4]);
            self.fixups.push((offset, target, trailing));
        }

        fn disp_imm32(&mut self, target: u32, immediate: u32) {
            self.disp_with_trailing(target, 4);
            self.raw(&immediate.to_le_bytes());
        }

        fn call_iat(&mut self, target: u32) {
            self.raw(&[0xFF, 0x15]);
            self.disp(target);
        }

        fn finish(&mut self, rva: u32) -> Vec<u8> {
            for (offset, target, trailing) in self.fixups.drain(..) {
                let end = rva as i64 + offset as i64 + 4 + trailing as i64;
                let displacement = target as i64 - end;
                self.bytes[offset..offset + 4]
                    .copy_from_slice(&(displacement as i32).to_le_bytes());
            }
            self.bytes.clone()
        }
    }

    let mut file = vec![0_u8; 0xC00];
    file[0..2].copy_from_slice(&0x5A4D_u16.to_le_bytes());
    file[0x3C..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
    file[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    file[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
    file[coff + 2..coff + 4].copy_from_slice(&3_u16.to_le_bytes());
    file[coff + 16..coff + 18].copy_from_slice(&0xF0_u16.to_le_bytes());
    file[coff + 18..coff + 20].copy_from_slice(&0x0022_u16.to_le_bytes());
    let optional = coff + 20;
    file[optional..optional + 2].copy_from_slice(&0x020B_u16.to_le_bytes());
    file[optional + 4..optional + 8].copy_from_slice(&0x200_u32.to_le_bytes());
    file[optional + 8..optional + 12].copy_from_slice(&0x800_u32.to_le_bytes());
    file[optional + 16..optional + 20].copy_from_slice(&TEXT_RVA.to_le_bytes());
    file[optional + 20..optional + 24].copy_from_slice(&TEXT_RVA.to_le_bytes());
    file[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000_u64.to_le_bytes());
    file[optional + 32..optional + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
    file[optional + 36..optional + 40].copy_from_slice(&0x200_u32.to_le_bytes());
    file[optional + 48..optional + 50].copy_from_slice(&6_u16.to_le_bytes());
    file[optional + 56..optional + 60].copy_from_slice(&0x4000_u32.to_le_bytes());
    file[optional + 60..optional + 64].copy_from_slice(&0x200_u32.to_le_bytes());
    file[optional + 68..optional + 70].copy_from_slice(&1_u16.to_le_bytes());
    let directory_count = optional + 108;
    file[directory_count..directory_count + 4].copy_from_slice(&16_u32.to_le_bytes());
    let directories = optional + 112;
    file[directories..directories + 4].copy_from_slice(&EXPORT_RVA.to_le_bytes());
    file[directories + 4..directories + 8].copy_from_slice(&0x100_u32.to_le_bytes());
    let import_directory = directories + 8;
    file[import_directory..import_directory + 4].copy_from_slice(&IMPORT_RVA.to_le_bytes());
    file[import_directory + 4..import_directory + 8].copy_from_slice(&0x28_u32.to_le_bytes());

    let section_table = optional + 0xF0;
    let mut write_section = |index: usize,
                             name: &[u8; 8],
                             virtual_size: u32,
                             rva: u32,
                             raw_size: u32,
                             raw: u32,
                             characteristics: u32| {
        let entry = section_table + index * 40;
        file[entry..entry + 8].copy_from_slice(name);
        file[entry + 8..entry + 12].copy_from_slice(&virtual_size.to_le_bytes());
        file[entry + 12..entry + 16].copy_from_slice(&rva.to_le_bytes());
        file[entry + 16..entry + 20].copy_from_slice(&raw_size.to_le_bytes());
        file[entry + 20..entry + 24].copy_from_slice(&raw.to_le_bytes());
        file[entry + 36..entry + 40].copy_from_slice(&characteristics.to_le_bytes());
    };
    write_section(
        0,
        b".text\0\0\0",
        0x200,
        TEXT_RVA,
        0x200,
        0x200,
        0x6000_0020,
    );
    write_section(
        1,
        b".rdata\0\0",
        0x600,
        RDATA_RVA,
        0x600,
        0x400,
        0x4000_0040,
    );
    write_section(2, b".data\0\0\0", 0x200, 0x3000, 0x200, 0xA00, 0xC000_0040);

    let mut code = CodeBuilder::default();
    code.raw(&[0xC7, 0x05]);
    code.disp_imm32(ENTRY_MARKER_RVA, 0xCA5A_0001);
    code.raw(&[0x48, 0x89, 0x0D]);
    code.disp(DRIVER_PTR_RVA);
    code.raw(&[0x48, 0x8D, 0x0D]);
    code.disp(DBG_FMT_RVA);
    code.raw(&[0x31, 0xC0]);
    code.call_iat(IAT_DBG);
    code.raw(&[0x48, 0x8D, 0x0D]);
    code.disp(US_DEV_RVA);
    code.raw(&[0x48, 0x8D, 0x15]);
    code.disp(WIDE_DEV_RVA);
    code.call_iat(IAT_RTL);
    code.raw(&[0x48, 0x8D, 0x0D]);
    code.disp(US_LINK_RVA);
    code.raw(&[0x48, 0x8D, 0x15]);
    code.disp(WIDE_LINK_RVA);
    code.call_iat(IAT_RTL);
    code.raw(&[0x48, 0x83, 0xEC, 0x38]);
    code.raw(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
    code.raw(&[0x48, 0xC7, 0x44, 0x24, 0x28, 0, 0, 0, 0]);
    code.raw(&[0x48, 0x8D, 0x05]);
    code.disp(DEV_OBJ_OUT_RVA);
    code.raw(&[0x48, 0x89, 0x44, 0x24, 0x30]);
    code.raw(&[0x48, 0x8B, 0x0D]);
    code.disp(DRIVER_PTR_RVA);
    code.raw(&[0x31, 0xD2]);
    code.raw(&[0x4C, 0x8D, 0x05]);
    code.disp(US_DEV_RVA);
    code.raw(&[0x41, 0xB9]);
    code.raw(&0x22_u32.to_le_bytes());
    code.call_iat(IAT_IO_CREATE);
    code.raw(&[0x48, 0x83, 0xC4, 0x38]);
    code.raw(&[0x85, 0xC0]);
    code.raw(&[0x79, 0x06]);
    code.raw(&[0xB8]);
    code.raw(&(STATUS_UNSUCCESSFUL).to_le_bytes());
    code.raw(&[0xC3]);
    code.raw(&[0x48, 0x8D, 0x0D]);
    code.disp(US_LINK_RVA);
    code.raw(&[0x48, 0x8D, 0x15]);
    code.disp(US_DEV_RVA);
    code.call_iat(IAT_IO_SYMLINK);
    code.raw(&[0xC3]);
    let entry = code.finish(TEXT_RVA);
    assert!(entry.len() <= 0x100);

    let mut unload = CodeBuilder::default();
    unload.raw(&[0x31, 0xC0]);
    unload.raw(&[0x48, 0x8D, 0x0D]);
    unload.disp(DBG_UNLOAD_RVA);
    unload.call_iat(IAT_DBG);
    unload.raw(&[0xC7, 0x05]);
    unload.disp_imm32(UNLOAD_MARKER_RVA, 0xCA5A_0002);
    unload.raw(&[0x48, 0x8B, 0x0D]);
    unload.disp(DEV_OBJ_OUT_RVA);
    unload.raw(&[0x48, 0x85, 0xC9]);
    unload.raw(&[0x74, 0x06]);
    unload.call_iat(IAT_IO_DELETE);
    unload.raw(&[0xC3]);
    let unload = unload.finish(UNLOAD_RVA);
    assert!(unload.len() <= 0x100);

    file[0x200..0x200 + entry.len()].copy_from_slice(&entry);
    file[0x300..0x300 + unload.len()].copy_from_slice(&unload);

    let mut rdata = vec![0_u8; 0x600];
    let rva = |address: u32| (address - RDATA_RVA) as usize;
    let descriptor = rva(IMPORT_RVA);
    rdata[descriptor..descriptor + 4].copy_from_slice(&ILT_RVA.to_le_bytes());
    rdata[descriptor + 12..descriptor + 16].copy_from_slice(&DLL_NAME_RVA.to_le_bytes());
    rdata[descriptor + 16..descriptor + 20].copy_from_slice(&IAT_RVA.to_le_bytes());
    for (index, (_, hint)) in IMPORT_NAMES.iter().enumerate() {
        rdata[rva(ILT_RVA) + index * 8..rva(ILT_RVA) + index * 8 + 8]
            .copy_from_slice(&(*hint as u64).to_le_bytes());
        rdata[rva(IAT_RVA) + index * 8..rva(IAT_RVA) + index * 8 + 8]
            .copy_from_slice(&(*hint as u64).to_le_bytes());
    }
    rdata[rva(DLL_NAME_RVA)..rva(DLL_NAME_RVA) + 13].copy_from_slice(b"ntoskrnl.exe\0");
    for (name, hint) in IMPORT_NAMES.iter() {
        let offset = rva(*hint);
        rdata[offset..offset + 2].copy_from_slice(&0_u16.to_le_bytes());
        rdata[offset + 2..offset + 2 + name.len()].copy_from_slice(name.as_bytes());
        rdata[offset + 2 + name.len()] = 0;
    }
    rdata[rva(DBG_FMT_RVA)..rva(DBG_FMT_RVA) + 22].copy_from_slice(b"CasaTest DriverEntry\n\0");
    write_wide(&mut rdata, rva(WIDE_DEV_RVA), "\\Device\\CasaTest");
    write_wide(&mut rdata, rva(WIDE_LINK_RVA), "\\??\\CasaTest");
    rdata[rva(DBG_UNLOAD_RVA)..rva(DBG_UNLOAD_RVA) + 23]
        .copy_from_slice(b"CasaTest DriverUnload\n\0");

    let export = rva(EXPORT_RVA);
    let export_name = 0x24F0_u32;
    let functions = 0x24B0_u32;
    let names = 0x24B8_u32;
    let ordinals = 0x24C0_u32;
    rdata[export + 12..export + 16].copy_from_slice(&export_name.to_le_bytes());
    rdata[export + 16..export + 20].copy_from_slice(&1_u32.to_le_bytes());
    rdata[export + 20..export + 24].copy_from_slice(&2_u32.to_le_bytes());
    rdata[export + 24..export + 28].copy_from_slice(&2_u32.to_le_bytes());
    rdata[export + 28..export + 32].copy_from_slice(&functions.to_le_bytes());
    rdata[export + 32..export + 36].copy_from_slice(&names.to_le_bytes());
    rdata[export + 36..export + 40].copy_from_slice(&ordinals.to_le_bytes());
    rdata[rva(functions)..rva(functions) + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());
    rdata[rva(functions) + 4..rva(functions) + 8].copy_from_slice(&UNLOAD_RVA.to_le_bytes());
    rdata[rva(names)..rva(names) + 4].copy_from_slice(&0x24D0_u32.to_le_bytes());
    rdata[rva(names) + 4..rva(names) + 8].copy_from_slice(&0x24E0_u32.to_le_bytes());
    rdata[rva(ordinals)..rva(ordinals) + 2].copy_from_slice(&0_u16.to_le_bytes());
    rdata[rva(ordinals) + 2..rva(ordinals) + 4].copy_from_slice(&1_u16.to_le_bytes());
    rdata[rva(0x24D0)..rva(0x24D0) + 12].copy_from_slice(b"DriverEntry\0");
    rdata[rva(0x24E0)..rva(0x24E0) + 13].copy_from_slice(b"DriverUnload\0");
    rdata[rva(export_name)..rva(export_name) + 13].copy_from_slice(b"CasaTest.sys\0");
    file[0x400..0xA00].copy_from_slice(&rdata);
    file
}

#[test]
fn driver_island_loads_marker_driver_creates_device_and_unloads() {
    with_big_stack(|| {
        let image = build_marker_driver();
        let (_directory, mut session) = session_with_ge("positive-driver", |ge| {
            ge.create_directory("C:\\Windows\\System32\\drivers", true)
                .expect("driver directory");
            ge.write_file("C:\\Windows\\System32\\drivers\\casa_nt.sys", &image, true)
                .expect("driver image");
            ge.registry_create_key(
                "HKLM",
                "SYSTEM\\CurrentControlSet\\Services\\CasaPositive",
                casa1::ge::RegistryView::Native,
            )
            .expect("service key");
            ge.registry_set_value(
                "HKLM",
                "SYSTEM\\CurrentControlSet\\Services\\CasaPositive",
                "ImagePath",
                "REG_SZ",
                serde_json::json!("\\SystemRoot\\System32\\drivers\\casa_nt.sys"),
                casa1::ge::RegistryView::Native,
            )
            .expect("image path");
            ge.registry_set_value(
                "HKLM",
                "SYSTEM\\CurrentControlSet\\Services\\CasaPositive",
                "Type",
                "REG_DWORD",
                serde_json::json!(1),
                casa1::ge::RegistryView::Native,
            )
            .expect("service type");
        });
        let service_path = 0x40_000;
        guest_unicode_string(
            &mut session,
            service_path,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\CasaPositive",
        );
        assert_eq!(
            call(&mut session, HostThunk::NtLoadDriver, &[service_path]),
            STATUS_SUCCESS as u64
        );
        let image_base = 0x1_4000_0000_u64;
        assert_eq!(read_u32(&session, image_base + 0x3030), 0xCA5A_0001);
        assert_eq!(
            call(&mut session, HostThunk::NtLoadDriver, &[service_path]),
            STATUS_IMAGE_ALREADY_LOADED as u32 as u64
        );

        let device_name = 0x41_000;
        guest_unicode_string(&mut session, device_name, "\\Device\\CasaTest");
        let attributes = 0x42_000;
        map_bytes(&mut session, attributes, &[0; 48]);
        write_u32(&mut session, attributes, 48);
        write_u64(&mut session, attributes + 16, device_name);
        let handle_out = 0x43_000;
        write_u32(&mut session, handle_out, 0);
        let iosb = 0x43_100;
        map_bytes(&mut session, iosb, &[0; 24]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::NtCreateFile,
                &[
                    handle_out,
                    0x0012_0000,
                    attributes,
                    iosb,
                    0,
                    0,
                    0,
                    1,
                    0,
                    0,
                    0,
                ],
            ),
            STATUS_SUCCESS as u64
        );
        let handle = read_u32(&session, handle_out);
        assert_ne!(handle, 0);
        assert_eq!(
            call(&mut session, HostThunk::NtUnloadDriver, &[service_path]),
            STATUS_DEVICE_BUSY as u32 as u64
        );
        assert_eq!(
            call(&mut session, HostThunk::NtClose, &[handle as u64]),
            STATUS_SUCCESS as u64
        );
        assert_eq!(
            call(&mut session, HostThunk::NtClose, &[handle as u64]),
            STATUS_INVALID_HANDLE as u32 as u64
        );
        assert_eq!(
            call(&mut session, HostThunk::NtUnloadDriver, &[service_path]),
            STATUS_SUCCESS as u64
        );
        assert_eq!(read_u32(&session, image_base + 0x3034), 0xCA5A_0002);
        assert_eq!(
            call(&mut session, HostThunk::NtUnloadDriver, &[service_path]),
            STATUS_OBJECT_NAME_NOT_FOUND as u32 as u64
        );
    });
}

#[test]
fn audio_endpoint_activation_and_client_lifecycle() {
    with_big_stack(|| {
        let backend = match RealAudioBackend::new() {
            Ok(backend) => backend,
            Err(error) => {
                eprintln!("skip: real audio backend is unavailable: {error}");
                return;
            }
        };
        let device = backend
            .activation_device_snapshot()
            .into_iter()
            .find(|device| device.is_default);
        let Some(device) = device else {
            eprintln!("skip: no default audio output device is present on this host");
            return;
        };
        let (_directory, mut session) = session("positive-audio");

        session.vm_register_commit(0xf000, 0x1000);
        session.map_guest(0xf000, &vec![0_u8; 0x1000]);
        session.vm_register_commit(0x80_000, 0x5000);
        let marker = 0x80_500_u64;
        let stub_address = 0x80_000_u64;
        let mut stub = vec![0xB8, 0x01, 0x00, 0x00, 0x00];
        stub.push(0xB9);
        stub.extend_from_slice(&(marker as u32).to_le_bytes());
        stub.extend_from_slice(&[0x89, 0x01, 0x31, 0xC0, 0xC3]);
        session.map_guest(stub_address, &stub);
        write_u32(&mut session, marker, 0);
        let handler_vtable = 0x81_000_u64;
        let handler_object = 0x82_000_u64;
        write_u64(&mut session, handler_object, handler_vtable);
        write_u64(&mut session, handler_vtable + 3 * 8, stub_address);

        let riid = 0x83_000;
        map_bytes(&mut session, riid, &IID_IAUDIO_CLIENT);
        let operation_out = 0x83_100;
        map_bytes(&mut session, operation_out, &[0; 8]);
        assert_eq!(
            call(
                &mut session,
                HostThunk::ActivateAudioInterfaceAsync,
                &[0, riid, 0, handler_object, operation_out],
            ),
            0
        );
        let operation = read_u64(&session, operation_out);
        assert_ne!(operation, 0);
        assert_eq!(read_u32(&session, marker), 0);

        let class_name = 0x83_500;
        map_utf16(&mut session, class_name, "STATIC");
        let hwnd = call(
            &mut session,
            HostThunk::CreateWindowExW,
            &[0, class_name, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0],
        ) as u32;
        assert_ne!(hwnd, 0);
        assert_eq!(
            call(&mut session, HostThunk::SetTimer, &[hwnd as u64, 1, 100, 0]),
            1
        );
        let message = 0x83_700;
        map_bytes(&mut session, message, &[0; 48]);
        for _ in 0..8 {
            assert_eq!(
                call(&mut session, HostThunk::GetMessageA, &[message, 0, 0, 0]),
                1
            );
            if read_u32(&session, marker) == 1 {
                break;
            }
        }
        assert_eq!(read_u32(&session, marker), 1);

        let activate_result = 0x83_200;
        let activate_interface = 0x83_208;
        write_u32(&mut session, activate_result, 0xFFFF_FFFF);
        write_u64(&mut session, activate_interface, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::AudioActivationOperationGetActivateResult,
                &[operation, activate_result, activate_interface],
            ),
            0
        );
        assert_eq!(read_u32(&session, activate_result), 0);
        let endpoint = read_u64(&session, activate_interface);
        assert_ne!(endpoint, 0);

        let format_out = 0x83_300;
        write_u64(&mut session, format_out, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::AudioClientGetMixFormat,
                &[endpoint, format_out],
            ),
            0
        );
        let format_ptr = read_u64(&session, format_out);
        assert_ne!(format_ptr, 0);
        let format_bytes = session.read_guest(format_ptr, 40);
        let format = parse_wave_format(&format_bytes).expect("parse mix format");
        assert_eq!(format.channels, device.channels);
        assert_eq!(format.sample_rate, device.sample_rate);
        assert_eq!(format.wave_format_tag, WAVE_FORMAT_IEEE_FLOAT);
        assert_eq!(format.bits_per_sample, 32);

        let init_format = 0x84_000;
        let mut pcm = Vec::new();
        pcm.extend_from_slice(&1_u16.to_le_bytes());
        pcm.extend_from_slice(&device.channels.to_le_bytes());
        pcm.extend_from_slice(&device.sample_rate.to_le_bytes());
        let block_align = (device.channels as u32) * 2;
        pcm.extend_from_slice(&(device.sample_rate * block_align).to_le_bytes());
        pcm.extend_from_slice(&(block_align as u16).to_le_bytes());
        pcm.extend_from_slice(&16_u16.to_le_bytes());
        pcm.extend_from_slice(&0_u16.to_le_bytes());
        map_bytes(&mut session, init_format, &pcm);
        assert_eq!(
            call(
                &mut session,
                HostThunk::AudioClientInitialize,
                &[endpoint, 0, 0, 100_000, 0, init_format, 0],
            ),
            0
        );
        let frames_out = 0x83_400;
        write_u32(&mut session, frames_out, 0);
        assert_eq!(
            call(
                &mut session,
                HostThunk::AudioClientGetBufferSize,
                &[endpoint, frames_out],
            ),
            0
        );
        assert_eq!(read_u32(&session, frames_out), device.sample_rate / 100);
        assert_eq!(
            call(&mut session, HostThunk::AudioClientStart, &[endpoint]),
            0
        );
        assert_eq!(
            call(&mut session, HostThunk::AudioClientStop, &[endpoint]),
            0
        );
    });
}

#[test]
fn d3d11_device_and_buffer_map_unmap_bytes() {
    with_big_stack(|| {
        let mut device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("D3D11 device");
        assert_eq!(device.feature_level(), FeatureLevel::Level10_1);

        let buffer = device
            .create_buffer(
                "positive-buffer",
                64,
                GfxResourceUsageHint::Buffer {
                    role: BufferRole::Vertex,
                    cpu_write_frequent: true,
                },
            )
            .expect("D3D11 buffer");
        {
            let mapped = device.map(buffer).expect("map");
            assert_eq!(mapped.len(), 64);
            assert_eq!(&*mapped, &[0_u8; 64]);
        }
        device.unmap(buffer).expect("clear initial map");

        let bytes = [1_u8, 2, 3, 4, 5, 6, 7, 8];
        drop(device.map(buffer).expect("map for explicit unmap"));
        device.unmap_with_bytes(buffer, &bytes).expect("unmap");
        device
            .unmap(buffer)
            .expect_err("unmap without map must fail");
        {
            let mapped = device.map(buffer).expect("remap");
            assert_eq!(mapped.len(), 64);
            assert_eq!(&mapped[..8], &bytes);
            assert_eq!(&mapped[8..], &vec![0_u8; 56]);
        }
        device.unmap(buffer).expect("final unmap");
    });
}

#[test]
fn d3d12_device_queue_and_allocation_bytes() {
    with_big_stack(|| {
        let mut runtime = D3d12Runtime::new();
        let device_info = runtime.device_info();
        assert!(!device_info.adapter.name.is_empty());
        let queue = runtime.create_command_queue();
        assert_ne!(queue, 0);
        let allocator = runtime.create_command_allocator();
        assert_ne!(allocator, 0);

        let resource = match runtime.create_committed_resource(ResourceDesc {
            name: "positive-d3d12".to_string(),
            format: DxgiFormat::R8G8B8A8Unorm,
            heap: HeapType::Readback,
            size: 64,
            subresources: 1,
            initial_state: ResourceState::CopyDest,
            usage_hint: ResourceUsageHint::Generic,
        }) {
            Ok(resource) => resource,
            Err(error) => {
                eprintln!("skip: D3D12 allocation is not available: {error}");
                return;
            }
        };
        let payload = [0xA5_u8, 0x5A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        runtime
            .overwrite_resource_bytes(resource, &payload)
            .expect("resource bytes");
        let fence = runtime.create_fence(0);
        runtime.signal_fence(fence, 1).expect("signal fence");
        assert_eq!(runtime.fence_value(fence).unwrap(), 1);
        let readback = runtime.readback(resource, fence, 1).expect("readback");
        assert_eq!(readback.len(), 64);
        assert_eq!(&readback[..8], &payload);
        assert_eq!(&readback[8..], &[0_u8; 56]);
    });
}

#[test]
fn wddm_adapter_device_allocation_residency_and_fence() {
    with_big_stack(|| {
        let subsystem = WddmSubsystem::new();
        let adapters = subsystem.d3dkmt_enum_adapters();
        let Some(adapter_info) = adapters.first().cloned() else {
            eprintln!("skip: no Metal adapter is present for the WDDM facade");
            return;
        };
        let adapter = subsystem
            .d3dkmt_open_adapter_from_luid(adapter_info.luid)
            .expect("open adapter");
        let device = subsystem
            .d3dkmt_create_device(CreateDeviceRequest {
                adapter,
                shareable: false,
                owner_process: 7,
            })
            .expect("create device");
        let info = subsystem.device_info(device).expect("device info");
        assert_eq!(info.shareable, false);
        assert_eq!(info.owner_process, 7);

        let allocation = subsystem
            .d3dkmt_create_allocation(CreateAllocationRequest {
                device,
                size: 4096,
                segment: SEGMENT_LOCAL,
                resource_id: 42,
                shareable: true,
                owner_process: 7,
            })
            .expect("create allocation");
        assert_eq!(
            subsystem
                .d3dkmt_query_allocation_residency(allocation)
                .unwrap(),
            0
        );
        assert_eq!(subsystem.d3dkmt_make_resident(allocation, 7).unwrap(), 1);
        assert_eq!(
            subsystem
                .d3dkmt_query_allocation_residency(allocation)
                .unwrap(),
            1
        );
        assert_eq!(subsystem.d3dkmt_evict(allocation, 7).unwrap(), 0);

        let sync = subsystem
            .d3dkmt_create_synchronization_object(device, 0)
            .expect("create fence");
        subsystem
            .d3dkmt_signal_synchronization_object(sync, 5)
            .expect("signal fence");
        subsystem
            .d3dkmt_wait_for_synchronization_object(sync, 5, 0)
            .expect("wait for reached value");
        let timeout = subsystem
            .d3dkmt_wait_for_synchronization_object(sync, 6, 0)
            .expect_err("unreached fence value");
        assert_eq!(timeout.status(), STATUS_TIMEOUT);

        subsystem
            .d3dkmt_destroy_device(device)
            .expect("destroy device");
        let error = subsystem
            .device_info(device)
            .expect_err("destroyed device handle");
        assert_eq!(error.status(), STATUS_INVALID_HANDLE);
    });
}

#[test]
fn jit_arithmetic_loop_accumulates_exactly() {
    with_big_stack(|| {
        if !casa1::jit::jit_execution_available() {
            eprintln!("skip: no executable-memory mechanism is available for the JIT");
            return;
        }
        let mut runtime = JitRuntime::new(GuestArch::X64);
        let ir = vec![
            IrInstruction::AddImm {
                dst: Register::Rax,
                value: 3,
                width: 8,
            },
            IrInstruction::AddImm {
                dst: Register::Rcx,
                value: 1,
                width: 8,
            },
        ];
        let block = runtime
            .get_or_compile(&ir, 0x1000, GuestArch::X64, None)
            .expect("compile loop block")
            .clone();
        let mut state = casa1::cpu::CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        for _ in 0..7 {
            state.rip = 0x1000;
            let reason = unsafe { runtime.execute_block(&block, &mut state, &mut memory) };
            assert!(matches!(reason, JitExitReason::Normal { .. }));
        }
        assert_eq!(state.get(Register::Rax), 21);
        assert_eq!(state.get(Register::Rcx), 7);
    });
}

#[test]
fn jit_guest_memory_writes_and_reads_are_coherent() {
    with_big_stack(|| {
        if !casa1::jit::jit_execution_available() {
            eprintln!("skip: no executable-memory mechanism is available for the JIT");
            return;
        }
        let address = 0x20_000_u64;
        let mut memory = MemoryImage::default();
        memory.map_bytes(address, &[0_u8; 8]);
        let mut runtime = JitRuntime::new(GuestArch::X64);
        runtime.sync_all_pages_to_flat(&memory);
        let operand = MemoryOperand {
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            rip_relative: false,
            rip_base: 0,
            segment: None,
            address_size_32: false,
            absolute_address: Some(address),
        };
        let store_ir = vec![
            IrInstruction::MovImm {
                dst: Register::Rcx,
                value: 0x1122_3344_5566_7788,
            },
            IrInstruction::StoreMemory {
                src: Register::Rcx,
                address: operand.clone(),
                width: 8,
            },
        ];
        let store = runtime
            .get_or_compile(&store_ir, 0x2000, GuestArch::X64, None)
            .expect("compile store")
            .clone();
        let mut state = casa1::cpu::CpuState::new(GuestArch::X64);
        state.rip = 0x2000;
        let reason = unsafe { runtime.execute_block(&store, &mut state, &mut memory) };
        assert!(matches!(reason, JitExitReason::Normal { .. }));
        assert_eq!(memory.read_u64(address).unwrap(), 0x1122_3344_5566_7788);

        memory.write_u64(address, 0x99AA_BBCC_DDEE_FF00);
        let load_ir = vec![IrInstruction::LoadMemory {
            dst: Register::Rdx,
            address: operand,
            width: 8,
        }];
        let load = runtime
            .get_or_compile(&load_ir, 0x3000, GuestArch::X64, None)
            .expect("compile load")
            .clone();
        state.rip = 0x3000;
        let reason = unsafe { runtime.execute_block(&load, &mut state, &mut memory) };
        assert!(matches!(reason, JitExitReason::Normal { .. }));
        assert_eq!(state.get(Register::Rdx), 0x99AA_BBCC_DDEE_FF00);
    });
}
