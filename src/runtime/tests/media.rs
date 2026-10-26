use super::support::*;
use super::*;

// ── evidence-mid: winmmbase IN-device family ──────────────────────────
#[test]
fn evidence_mid_winmmbase_device_thunks() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mid-winmmbase");
        let mut memory = MemoryImage::default();

        // The winmmbase export names resolve into the shared device
        // model through the import-name tables.
        let resolved = |name: &str| {
            let import = ResolvedImport {
                requested_module: "winmmbase.dll".to_string(),
                resolved_module: "winmmbase.dll".to_string(),
                symbol: ImportSymbol::ByName {
                    hint: 0,
                    name: name.to_string(),
                },
                iat_rva: 0,
                export: synthetic_export_symbol(&ImportSymbol::ByName {
                    hint: 0,
                    name: name.to_string(),
                }),
            };
            HostThunk::from_import(&import)
        };
        assert!(matches!(resolved("waveInOpen"), HostThunk::WaveInOpen));
        assert!(matches!(
            resolved("waveInAddBuffer"),
            HostThunk::WaveInAddBuffer
        ));
        assert!(matches!(
            resolved("midiOutShortMsg"),
            HostThunk::MidiOutShortMsg
        ));
        assert!(matches!(resolved("midiInReset"), HostThunk::MidiInReset));
        assert!(matches!(
            resolved("waveOutGetNumDevs"),
            HostThunk::WaveOutGetNumDevs
        ));
        assert!(
            !matches!(resolved("waveInOpen"), HostThunk::Unsupported { .. }),
            "winmmbase exports dispatch into the shared winmm device model"
        );

        // waveOutGetNumDevs: the device enumeration.
        let get_num_devs = runtime.alloc_host_thunk(HostThunk::WaveOutGetNumDevs);
        let num_out = dispatch_x86_thunk(&mut runtime, &mut memory, get_num_devs, &[]);
        assert!(num_out >= 1, "at least one wave-out device");

        // waveOutOpen + waveOutWrite + waveOutReset + waveOutClose:
        // the OUT device lifecycle.
        let format_ptr = 0x67_000;
        let format = crate::winmm::WaveFormatEx::pcm(2, 44100, 16);
        let format_bytes = unsafe {
            std::slice::from_raw_parts(
                &format as *const crate::winmm::WaveFormatEx as *const u8,
                std::mem::size_of::<crate::winmm::WaveFormatEx>(),
            )
        };
        memory.map_bytes(format_ptr, format_bytes);
        let handle_out = 0x67_100;
        memory.map_bytes(handle_out, &[0; 4]);
        let wave_out_open = runtime.alloc_host_thunk(HostThunk::WaveOutOpen);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                wave_out_open,
                &[handle_out as u32, 0, format_ptr as u32, 0, 0, 0]
            ),
            0
        );
        let wave_out = read_u32(&memory, handle_out).expect("wave out handle");
        assert_ne!(wave_out, 0);
        // waveOutGetVolume/SetVolume ride the same model (before close).
        let volume_out = 0x67_800;
        memory.map_bytes(volume_out, &[0; 4]);
        let get_volume = runtime.alloc_host_thunk(HostThunk::WaveOutGetVolume);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_volume,
                &[wave_out, volume_out as u32]
            ),
            0
        );
        let wave_out_close = runtime.alloc_host_thunk(HostThunk::WaveOutClose);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wave_out_close, &[wave_out]),
            0
        );

        // waveInOpen/PrepareHeader/AddBuffer: the deterministic model —
        // the buffer stays queued (no real audio input).
        let wave_in_open = runtime.alloc_host_thunk(HostThunk::WaveInOpen);
        let in_handle_out = 0x67_200;
        memory.map_bytes(in_handle_out, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                wave_in_open,
                &[in_handle_out as u32, 0, format_ptr as u32, 0, 0, 0]
            ),
            0
        );
        let wave_in = read_u32(&memory, in_handle_out).expect("wave in handle");
        let header = 0x67_300;
        let data_buf = 0x67_400;
        memory.map_bytes(header, &[0; 32]);
        memory.map_bytes(data_buf, &[0; 128]);
        write_u64(&mut memory, header, data_buf);
        write_u32(&mut memory, header + 8, 128);
        let prepare = runtime.alloc_host_thunk(HostThunk::WaveInPrepareHeader);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                prepare,
                &[wave_in, header as u32, 32]
            ),
            0
        );
        let add_buffer = runtime.alloc_host_thunk(HostThunk::WaveInAddBuffer);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                add_buffer,
                &[wave_in, header as u32, 32]
            ),
            0
        );
        // The deterministic model: with no real audio input the buffer
        // stays parked in the device queue.
        {
            let winmm = runtime.audio.winmm.read().unwrap();
            let device = winmm
                .wave_in_devices
                .iter()
                .find(|device| device.handle == wave_in)
                .expect("wave-in device");
            assert!(
                device.buffers.iter().any(|buffer| buffer.is_queued),
                "the buffer is parked until input data arrives"
            );
        }
        let start = runtime.alloc_host_thunk(HostThunk::WaveInStart);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, start, &[wave_in]),
            0
        );
        let stop = runtime.alloc_host_thunk(HostThunk::WaveInStop);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, stop, &[wave_in]),
            0
        );
        // Stop dequeues the parked buffer (still no WIM_DATA delivered).
        {
            let winmm = runtime.audio.winmm.read().unwrap();
            let device = winmm
                .wave_in_devices
                .iter()
                .find(|device| device.handle == wave_in)
                .expect("wave-in device");
            assert!(
                !device.buffers.iter().any(|buffer| buffer.is_queued),
                "stop dequeues the parked buffer"
            );
        }
        let wave_in_close = runtime.alloc_host_thunk(HostThunk::WaveInClose);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, wave_in_close, &[wave_in]),
            0
        );

        // waveInGetDevCapsW: the documented WAVEINCAPSW layout.
        let caps_out = 0x67_500;
        memory.map_bytes(caps_out, &[0; 80]);
        let get_in_caps = runtime.alloc_host_thunk(HostThunk::WaveInGetDevCapsW);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_in_caps,
                &[0, caps_out as u32, 80]
            ),
            0
        );
        assert_eq!(
            read_u16(&memory, caps_out + 4).expect("driver version"),
            0x0100
        );
        assert_eq!(read_u16(&memory, caps_out + 76).expect("channels"), 0x000F);

        // midiOutOpen → midiOutShortMsg → midiOutReset → midiOutClose.
        let midi_out_open = runtime.alloc_host_thunk(HostThunk::MidiOutOpen);
        let midi_handle_out = 0x67_600;
        memory.map_bytes(midi_handle_out, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                midi_out_open,
                &[midi_handle_out as u32, 0, 0, 0, 0]
            ),
            0
        );
        let midi_out = read_u32(&memory, midi_handle_out).expect("midi out handle");
        let short_msg = runtime.alloc_host_thunk(HostThunk::MidiOutShortMsg);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                short_msg,
                &[midi_out, 0x0078_3C90] // note-on, channel 0, note 60, vel 120
            ),
            0
        );
        let midi_out_reset = runtime.alloc_host_thunk(HostThunk::MidiOutReset);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, midi_out_reset, &[midi_out]),
            0
        );
        let midi_out_close = runtime.alloc_host_thunk(HostThunk::MidiOutClose);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, midi_out_close, &[midi_out]),
            0
        );

        // midiInOpen → Start → Stop → Reset → Close: the IN device.
        let midi_in_open = runtime.alloc_host_thunk(HostThunk::MidiInOpen);
        let midi_in_handle_out = 0x67_700;
        memory.map_bytes(midi_in_handle_out, &[0; 4]);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                midi_in_open,
                &[midi_in_handle_out as u32, 0, 0, 0, 0]
            ),
            0
        );
        let midi_in = read_u32(&memory, midi_in_handle_out).expect("midi in handle");
        let midi_in_start = runtime.alloc_host_thunk(HostThunk::MidiInStart);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, midi_in_start, &[midi_in]),
            0
        );
        let midi_in_stop = runtime.alloc_host_thunk(HostThunk::MidiInStop);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, midi_in_stop, &[midi_in]),
            0
        );
        let midi_in_reset = runtime.alloc_host_thunk(HostThunk::MidiInReset);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, midi_in_reset, &[midi_in]),
            0
        );
        let midi_in_close = runtime.alloc_host_thunk(HostThunk::MidiInClose);
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, midi_in_close, &[midi_in]),
            0
        );
        let _ = format;
        let _ = format_bytes;
    })
}

#[test]
fn evidence_mf_startup_media_type_attributes_and_sample() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mf");
        let mut memory = MemoryImage::default();
        let startup: u64 = runtime.alloc_host_thunk(HostThunk::MfStartup);
        let shutdown: u64 = runtime.alloc_host_thunk(HostThunk::MfShutdown);
        let create_type: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateMediaType);
        let create_buffer: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateMemoryBuffer);
        let create_sample: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateSample);

        dispatch_x86_thunk(&mut runtime, &mut memory, startup, &[0x0007_0000, 0]);
        assert!(runtime.mf_runtime.started);

        let mt_out = 0x41_000;
        dispatch_x86_thunk(&mut runtime, &mut memory, create_type, &[mt_out as u32]);
        let mt = read_guest_pointer(&memory, mt_out, GuestArch::X86).unwrap();
        assert_ne!(mt, 0);
        assert!(runtime.mf_media_types.contains_key(&mt));

        let buf_out = 0x41_100;
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_buffer,
            &[128, buf_out as u32],
        );
        let buffer = read_guest_pointer(&memory, buf_out, GuestArch::X86).unwrap();
        assert_ne!(buffer, 0);
        assert_eq!(
            runtime
                .mf_media_buffers
                .get(&buffer)
                .map(|b| b.get_max_length()),
            Some(128)
        );

        let sample_out = 0x41_200;
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_sample,
            &[sample_out as u32],
        );
        let sample = read_guest_pointer(&memory, sample_out, GuestArch::X86).unwrap();
        assert_ne!(sample, 0);

        dispatch_x86_thunk(&mut runtime, &mut memory, shutdown, &[]);
        assert!(!runtime.mf_runtime.started);
    })
}

#[test]
fn evidence_mf_source_reader_and_sink_writer_objects() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mf-rw");
        let mut memory = MemoryImage::default();
        let create_reader: u64 =
            runtime.alloc_host_thunk(HostThunk::MfCreateSourceReaderFromByteStream);
        let create_writer: u64 =
            runtime.alloc_host_thunk(HostThunk::MfCreateSinkWriterFromMediaSink);
        let get_current_type: u64 =
            runtime.alloc_host_thunk(HostThunk::MfSourceReaderGetCurrentMediaType);

        let stream_obj = 0x42_000_u64;
        runtime.com_streams.insert(
            stream_obj,
            ComStreamState {
                data: crate::media::minimal_mp4_fixture(),
                ..Default::default()
            },
        );
        // Wrap the IStream payload in a real IMFByteStream, then build the
        // source-reader graph over it (which parses the real container).
        let create_byte_stream: u64 =
            runtime.alloc_host_thunk(HostThunk::MfCreateMfByteStreamOnStream);
        let byte_stream_out = 0x41_050;
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_byte_stream,
            &[stream_obj as u32, byte_stream_out as u32],
        );
        assert_eq!(hr, 0, "MFCreateMFByteStreamOnStream");
        let byte_stream = read_guest_pointer(&memory, byte_stream_out, GuestArch::X86).unwrap();
        assert_ne!(byte_stream, 0);
        let reader_out = 0x41_000;
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_reader,
            &[byte_stream as u32, 0, reader_out as u32],
        );
        assert_eq!(hr, 0, "MFCreateSourceReaderFromByteStream");
        let reader = read_guest_pointer(&memory, reader_out, GuestArch::X86).unwrap();
        assert_ne!(reader, 0);
        assert!(runtime.mf_source_readers.contains_key(&reader));

        let type_out = 0x41_100;
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_current_type,
            &[reader as u32, 0, type_out as u32],
        );
        let mt = read_guest_pointer(&memory, type_out, GuestArch::X86).unwrap();
        assert_ne!(mt, 0);
        assert!(runtime.mf_media_types.contains_key(&mt));

        let writer_out = 0x41_200;
        dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_writer,
            &[0, 0, writer_out as u32],
        );
        let writer = read_guest_pointer(&memory, writer_out, GuestArch::X86).unwrap();
        assert_ne!(writer, 0);
        assert!(runtime.mf_sink_writers.contains_key(&writer));
    })
}

#[test]
fn evidence_mf_periodic_callbacks_and_system_time() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mf-clock");
        let mut memory = MemoryImage::default();
        let add: u64 = runtime.alloc_host_thunk(HostThunk::MfAddPeriodicCallback);
        let cancel: u64 = runtime.alloc_host_thunk(HostThunk::MfCancelPeriodicCallback);
        let system_time: u64 = runtime.alloc_host_thunk(HostThunk::MfGetSystemTime);

        let key_out = 0x41_000;
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            add,
            &[0x7a00, 0x4242, key_out as u32],
        );
        assert_eq!(hr, 0);
        let key = read_guest_u32(&memory, key_out).unwrap();
        assert_eq!(key, 0);
        assert_eq!(runtime.mf_runtime.periodic_callbacks.len(), 1);
        let cb = runtime
            .mf_runtime
            .periodic_callbacks
            .get(&key)
            .copied()
            .unwrap();
        assert_eq!(cb.callback, 0x7a00);
        assert_eq!(cb.context, 0x4242);

        let time_out = 0x41_100;
        dispatch_x86_thunk(&mut runtime, &mut memory, system_time, &[time_out as u32]);
        let ticks = read_guest_u64(&memory, time_out).unwrap();
        assert!(ticks > 116_444_736_000_000_000_u64, "ticks since 1601");

        dispatch_x86_thunk(&mut runtime, &mut memory, cancel, &[key]);
        assert!(runtime.mf_runtime.periodic_callbacks.is_empty());
    })
}

#[test]
fn evidence_mf_dxgi_device_manager_handles_and_reset() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mf-dxgi");
        let mut memory = MemoryImage::default();
        let create: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateDxgiDeviceManager);
        let open_handle: u64 =
            runtime.alloc_host_thunk(HostThunk::MfDxgiDeviceManagerOpenDeviceHandle);
        let test_device: u64 = runtime.alloc_host_thunk(HostThunk::MfDxgiDeviceManagerTestDevice);
        let close_handle: u64 =
            runtime.alloc_host_thunk(HostThunk::MfDxgiDeviceManagerCloseDeviceHandle);
        let reset: u64 = runtime.alloc_host_thunk(HostThunk::MfDxgiDeviceManagerResetDevice);
        let lock: u64 = runtime.alloc_host_thunk(HostThunk::MfDxgiDeviceManagerLockDevice);
        let get_service: u64 =
            runtime.alloc_host_thunk(HostThunk::MfDxgiDeviceManagerGetVideoService);

        let obj_out = 0x41_000;
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create,
            &[0x1122_3344, obj_out as u32],
        );
        assert_eq!(hr, 0);
        let manager = read_guest_pointer(&memory, obj_out, GuestArch::X86).unwrap();
        assert_ne!(manager, 0);
        assert_eq!(
            runtime
                .mf_dxgi_device_managers
                .get(&manager)
                .unwrap()
                .reset_token,
            0x1122_3344
        );

        let handle_out = 0x41_100;
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            open_handle,
            &[manager as u32, handle_out as u32],
        );
        assert_eq!(hr, 0);
        let handle = read_guest_pointer(&memory, handle_out, GuestArch::X86).unwrap();
        assert_eq!(handle, 0);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                test_device,
                &[manager as u32, handle as u32]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                test_device,
                &[manager as u32, 0x7fff]
            ),
            0x8007_0057
        );

        let lock_out = 0x41_200;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                lock,
                &[manager as u32, handle as u32, 0, lock_out as u32]
            ),
            0x8000_4002
        );
        assert_eq!(
            read_guest_pointer(&memory, lock_out, GuestArch::X86).unwrap(),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[manager as u32, handle as u32, 0, lock_out as u32]
            ),
            0xC00D_36BA // MF_E_UNSUPPORTED_SERVICE (mferror.h)
        );

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                close_handle,
                &[manager as u32, handle as u32]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                test_device,
                &[manager as u32, handle as u32]
            ),
            0x8007_0057
        );

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                reset,
                &[manager as u32, 0x5566_7788]
            ),
            0
        );
        assert_eq!(
            runtime
                .mf_dxgi_device_managers
                .get(&manager)
                .unwrap()
                .reset_token,
            0x5566_7788
        );
    })
}

#[test]
fn evidence_dshow_module_server_surface() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-dshow");
        let mut memory = MemoryImage::default();
        assert_eq!(runtime.com_server_lock_count, 0, "fresh runtime lock count");
        let get_class_object: u64 = runtime.alloc_host_thunk(HostThunk::DllGetClassObject);
        let can_unload: u64 = runtime.alloc_host_thunk(HostThunk::DllCanUnloadNow);
        let create_instance: u64 = runtime.alloc_host_thunk(HostThunk::ComFactoryCreateInstance);
        let render_file: u64 = runtime.alloc_host_thunk(HostThunk::DshowFilterGraphRenderFile);
        let error_text: u64 = runtime.alloc_host_thunk(HostThunk::AmGetErrorTextW);

        // CLSID_FilterGraph {e436ebb3-524f-11ce-9f53-0020af0ba770}
        let clsid = 0x41_000_u64;
        memory.map_bytes(
            clsid,
            &[
                0xb3, 0xeb, 0x36, 0xe4, 0x4f, 0x52, 0xce, 0x11, 0x9f, 0x53, 0x00, 0x20, 0xaf, 0x0b,
                0xa7, 0x70,
            ],
        );
        // IID_IGraphBuilder {56a868a9-0ad4-11ce-b03a-0020af0ba770}
        let iid = 0x41_100_u64;
        memory.map_bytes(
            iid,
            &[
                0xa9, 0xa8, 0x68, 0x56, 0xd4, 0x0a, 0xce, 0x11, 0xb0, 0x3a, 0x00, 0x20, 0xaf, 0x0b,
                0xa7, 0x70,
            ],
        );
        let out = 0x41_200_u64;
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            get_class_object,
            &[clsid as u32, iid as u32, out as u32],
        );
        assert_eq!(hr, 0, "DllGetClassObject succeeds");
        let factory = read_guest_pointer(&memory, out, GuestArch::X86).unwrap();
        assert_ne!(factory, 0);
        assert_eq!(runtime.com_server_lock_count, 0, "after DllGetClassObject");

        let graph_out = 0x41_300_u64;
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            create_instance,
            &[factory as u32, 0, iid as u32, graph_out as u32],
        );
        assert_eq!(hr, 0, "IClassFactory::CreateInstance succeeds");
        let graph = read_guest_pointer(&memory, graph_out, GuestArch::X86).unwrap();
        assert_ne!(graph, 0);
        assert_eq!(runtime.com_server_lock_count, 0, "after CreateInstance");

        // No filters are registered: RenderFile answers VFW_E_NO_FILTERS.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                render_file,
                &[graph as u32, 0, 0]
            ),
            0x8004_0227
        );

        // AMGetErrorTextW formats that error.
        let text = 0x41_400_u64;
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            error_text,
            &[0x8004_0227, text as u32, 64],
        );
        assert!(written > 0);
        let bytes = memory.read_bytes(text, written as usize * 2).unwrap();
        let decoded = String::from_utf16_lossy(
            &bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        );
        assert!(decoded.contains("No filters"), "error text: {decoded}");
        // The shared in-process server contract: the DLL stays resident
        // (S_FALSE) — the runtime never unloads a loaded module.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, can_unload, &[]),
            1,
            "S_FALSE"
        );
    })
}

#[test]
fn evidence_codec_components_surfaces() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-codecs");
        let mut memory = MemoryImage::default();

        // ── wmcodecdsp: the codec factory ──
        let create_decoder: u64 = runtime.alloc_host_thunk(HostThunk::WmcdspCreateDecoder);
        let decoder_out = 0x41_000_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_decoder,
                &[0, decoder_out as u32]
            ),
            0
        );
        assert_ne!(
            read_guest_pointer(&memory, decoder_out, GuestArch::X86).unwrap(),
            0
        );

        // ── wmvcore: the reader/writer factories ──
        let create_reader: u64 = runtime.alloc_host_thunk(HostThunk::WmCreateReader);
        let create_writer: u64 = runtime.alloc_host_thunk(HostThunk::WmCreateWriter);
        let is_protected: u64 = runtime.alloc_host_thunk(HostThunk::WmIsContentProtected);
        let reader_out = 0x41_100_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_reader,
                &[0, 0, reader_out as u32]
            ),
            0
        );
        assert_ne!(
            read_guest_pointer(&memory, reader_out, GuestArch::X86).unwrap(),
            0
        );
        let writer_out = 0x41_110_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_writer,
                &[0, writer_out as u32]
            ),
            0
        );
        assert_ne!(
            read_guest_pointer(&memory, writer_out, GuestArch::X86).unwrap(),
            0
        );
        let protected_out = 0x41_120_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                is_protected,
                &[0x41_130, protected_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, protected_out).unwrap(),
            0,
            "not protected"
        );

        // ── msdmo: the DMO registry ──
        let dmo_enum: u64 = runtime.alloc_host_thunk(HostThunk::DmoEnum);
        let dmo_to_str: u64 = runtime.alloc_host_thunk(HostThunk::DmoGuidToStr);
        let count_out = 0x41_200_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                dmo_enum,
                &[0, 0, count_out as u32, 0, 0]
            ),
            0
        );
        assert_eq!(read_guest_u32(&memory, count_out).unwrap(), 0, "no DMOs");
        let guid_ptr = 0x41_210_u64;
        memory.map_bytes(
            guid_ptr,
            &[
                0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x46,
            ],
        );
        let str_out = 0x41_220_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                dmo_to_str,
                &[guid_ptr as u32, str_out as u32]
            ),
            0
        );
        let str_ptr = read_guest_pointer(&memory, str_out, GuestArch::X86).unwrap();
        assert_eq!(
            read_utf16_string(&memory, str_ptr).unwrap(),
            "{0000000c-0000-0000-c000-000000000046}"
        );

        // ── evr: the video factories ──
        let create_media_type: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateVideoMediaType);
        let create_renderer: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateVideoRenderer);
        let mt_out = 0x41_300_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_media_type,
                &[0, mt_out as u32]
            ),
            0
        );
        assert_ne!(
            read_guest_pointer(&memory, mt_out, GuestArch::X86).unwrap(),
            0
        );
        let renderer_out = 0x41_310_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_renderer,
                &[0, renderer_out as u32]
            ),
            0
        );
        assert_ne!(
            read_guest_pointer(&memory, renderer_out, GuestArch::X86).unwrap(),
            0
        );

        // ── dxva2: the device manager reuses the DXGI machinery ──
        let dxva2_create: u64 =
            runtime.alloc_host_thunk(HostThunk::Dxva2CreateDirect3DDeviceManager9);
        let manager_out = 0x41_400_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                dxva2_create,
                &[1, manager_out as u32]
            ),
            0
        );
        assert_ne!(
            read_guest_pointer(&memory, manager_out, GuestArch::X86).unwrap(),
            0
        );

        // ── qedit: the ANSI error text ──
        let am_error: u64 = runtime.alloc_host_thunk(HostThunk::AmGetErrorText);
        let text_out = 0x41_500_u64;
        let written = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            am_error,
            &[0x8004_0227, text_out as u32, 64],
        );
        assert!(written > 0);
        let text = memory.read_bytes(text_out, written as usize).unwrap();
        assert!(String::from_utf8_lossy(&text).contains("No filters"));

        // ── a codec module's DllGetClassObject (the shared server
        //    contract: no codec classes are registered) ──
        let dll_class: u64 = runtime.alloc_host_thunk(HostThunk::DllGetClassObject);
        let clsid_out = 0x41_600_u64;
        let hr = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            dll_class,
            &[0x41_610, 0x41_620, clsid_out as u32],
        );
        assert_eq!(
            hr, 0,
            "the shared class-object contract answers every CLSID"
        );
    })
}

#[test]
fn x3daudio_calculate_dispatch_writes_real_dsp_values() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("x3daudio-dispatch");
        let mut memory = MemoryImage::default();
        let calc = runtime.alloc_host_thunk(HostThunk::X3dAudioCalculate);
        let (handle, listener, emitter, dsp, matrix, delays) = x3daudio_guest_scene(&mut memory);

        // All DSP outputs: MATRIX|DELAY|LPF_DIRECT|LPF_REVERB|REVERB|
        // DOPPLER|EMITTER_ANGLE = 0x7f.
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            calc,
            &[
                handle as u32,
                listener as u32,
                emitter as u32,
                0x7f,
                dsp as u32,
            ],
        );
        assert_eq!(status, 0, "the calculation succeeds");

        // Emitter→listener distance: 6 units, always written.
        let distance = read_guest_f32_or_panic(&memory, dsp + 36);
        assert!((distance - 6.0).abs() < 1.0e-5);
        // Emitter-to-listener angle: the emitter faces +z, the listener
        // sits along +x → π/2.
        let angle = read_guest_f32_or_panic(&memory, dsp + 32);
        assert!((angle - std::f32::consts::FRAC_PI_2).abs() < 1.0e-5);
        // Matrix (dst-major, 1×2): hard-left source at distance 6 with
        // CurveDistanceScaler 3 → volume 0.5 entirely in FL.
        let m_left = read_guest_f32_or_panic(&memory, matrix);
        let m_right = read_guest_f32_or_panic(&memory, matrix + 4);
        assert!(
            (m_left - 0.5).abs() < 1.0e-5,
            "FL receives the -6 dB rolloff"
        );
        assert!(m_right.abs() < 1.0e-6, "FR silent for a hard-left source");
        // Delay times (stereo field): FL speaker is 5 units from the
        // emitter, FR 7 → FL delayed by 2/343.5 s ≈ 5.82 ms.
        let delay_left = read_guest_f32_or_panic(&memory, delays);
        let delay_right = read_guest_f32_or_panic(&memory, delays + 4);
        assert!(
            (delay_left - 5.8224).abs() < 0.01,
            "left delay {delay_left}"
        );
        assert!(delay_right.abs() < 1.0e-5, "farthest speaker has no delay");
        // LPF direct/reverb at scaled distance 2: 0.75 / 0.75.
        assert!((read_guest_f32_or_panic(&memory, dsp + 16) - 0.75).abs() < 1.0e-6);
        assert!((read_guest_f32_or_panic(&memory, dsp + 20) - 0.75).abs() < 1.0e-6);
        // Reverb level at scaled distance 2: 0 (linear curve reaches 0
        // at one scaler unit).
        assert!(read_guest_f32_or_panic(&memory, dsp + 24).abs() < 1.0e-6);
        // Doppler: approaching at 3 units/s → 1 + 3/343.5.
        let doppler = read_guest_f32_or_panic(&memory, dsp + 28);
        assert!((doppler - (1.0 + 3.0 / 343.5)).abs() < 1.0e-4);
        // Velocity components along the emitter→listener axis.
        assert!((read_guest_f32_or_panic(&memory, dsp + 40) - 3.0).abs() < 1.0e-5);
        assert!(read_guest_f32_or_panic(&memory, dsp + 44).abs() < 1.0e-6);

        // Deterministic: a second call reproduces the same DSP memory.
        let snapshot = memory.read_bytes(dsp, 48).expect("dsp bytes");
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            calc,
            &[
                handle as u32,
                listener as u32,
                emitter as u32,
                0x7f,
                dsp as u32,
            ],
        );
        assert_eq!(status, 0);
        assert_eq!(
            memory.read_bytes(dsp, 48).expect("dsp bytes"),
            snapshot,
            "the DSP output must be deterministic"
        );

        // Flag-gated outputs: with only MATRIX|EMITTER_ANGLE the scalar
        // coefficients the guest did not request stay untouched (they
        // keep their pre-call sentinel values).
        write_guest_f32(&mut memory, dsp + 16, 1.0).unwrap(); // sentinel
        let status = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            calc,
            &[
                handle as u32,
                listener as u32,
                emitter as u32,
                0x41,
                dsp as u32,
            ],
        );
        assert_eq!(status, 0);
        assert_eq!(
            read_guest_f32_or_panic(&memory, dsp + 16),
            1.0,
            "LPF direct not requested must not be written"
        );
    })
}

#[test]
fn evidence_mf_transform_pipeline() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mft");
        let mut memory = MemoryImage::default();
        let enum_ex: u64 = runtime.alloc_host_thunk(HostThunk::MftEnumEx);
        let activate_object: u64 = runtime.alloc_host_thunk(HostThunk::MfActivateActivateObject);
        let get_guid: u64 = runtime.alloc_host_thunk(HostThunk::MfActivateGetGuid);
        let set_input: u64 = runtime.alloc_host_thunk(HostThunk::MfTransformSetInputType);
        let set_output: u64 = runtime.alloc_host_thunk(HostThunk::MfTransformSetOutputType);
        let get_input_status: u64 = runtime.alloc_host_thunk(HostThunk::MfTransformGetInputStatus);
        let process_input: u64 = runtime.alloc_host_thunk(HostThunk::MfTransformProcessInput);
        let process_output: u64 = runtime.alloc_host_thunk(HostThunk::MfTransformProcessOutput);
        let get_output_status: u64 =
            runtime.alloc_host_thunk(HostThunk::MfTransformGetOutputStatus);
        let process_message: u64 = runtime.alloc_host_thunk(HostThunk::MfTransformProcessMessage);
        let shutdown: u64 = runtime.alloc_host_thunk(HostThunk::MfActivateShutdownObject);

        // MFTEnumEx with MFT_CATEGORY_VIDEO_DECODER
        // {d6c02d4b-6833-45b4-971a-05a4b04bab91}
        let category = 0x41_000_u64;
        memory.map_bytes(
            category,
            &[
                0x4b, 0x2d, 0xc0, 0xd6, 0x33, 0x68, 0xb4, 0x45, 0x97, 0x1a, 0x05, 0xa4, 0xb0, 0x4b,
                0xab, 0x91,
            ],
        );
        let activate_out = 0x41_100_u64;
        let count_out = 0x41_110_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                enum_ex,
                &[
                    category as u32,
                    0,
                    0,
                    0,
                    activate_out as u32,
                    count_out as u32
                ]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, count_out).unwrap(),
            1,
            "one MFT enumerated"
        );
        let activate = read_guest_pointer(&memory, activate_out, GuestArch::X86).unwrap();
        assert_ne!(activate, 0);

        // The activation's CLSID.
        let clsid_out = 0x41_120_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_guid,
                &[activate as u32, 0, clsid_out as u32]
            ),
            0
        );
        assert_eq!(
            memory.read_bytes(clsid_out, 16).unwrap()[0],
            0xe3,
            "the decoder CLSID"
        );

        // ActivateObject creates the transform.
        let transform_out = 0x41_200_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                activate_object,
                &[activate as u32, 0, transform_out as u32]
            ),
            0
        );
        let transform = read_guest_pointer(&memory, transform_out, GuestArch::X86).unwrap();
        assert_ne!(transform, 0);

        // The media types: a video H264 input + NV12 output (registered
        // through the runtime's media-type store).
        let mut input_mt = crate::media::ImfMediaType::new();
        input_mt.set_guid(
            crate::media::MF_MT_MAJOR_TYPE,
            crate::media::MFMediaType_Video,
        );
        input_mt.set_guid(
            crate::media::MF_MT_SUBTYPE,
            crate::media::MFVideoFormat_H264,
        );
        let input_type = runtime
            .alloc_guest_object(&mut memory, GuestObjectKind::ImfMediaType, 0)
            .unwrap();
        runtime.mf_media_types.insert(input_type, input_mt);
        let mut output_mt = crate::media::ImfMediaType::new();
        output_mt.set_guid(
            crate::media::MF_MT_MAJOR_TYPE,
            crate::media::MFMediaType_Video,
        );
        output_mt.set_guid(
            crate::media::MF_MT_SUBTYPE,
            crate::media::MFVideoFormat_NV12,
        );
        let output_type = runtime
            .alloc_guest_object(&mut memory, GuestObjectKind::ImfMediaType, 0)
            .unwrap();
        runtime.mf_media_types.insert(output_type, output_mt);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_input,
                &[transform as u32, 0, input_type as u32, 0]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_output,
                &[transform as u32, 0, output_type as u32, 0]
            ),
            0
        );

        // Input accepts data; then a sample is processed through.
        let status_out = 0x41_500_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_input_status,
                &[transform as u32, 0, status_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, status_out).unwrap(),
            1,
            "accepts input"
        );

        // A source sample with payload bytes.
        let sample = runtime
            .alloc_guest_object(&mut memory, GuestObjectKind::ImfSample, 0)
            .unwrap();
        runtime.mf_samples.insert(
            sample,
            crate::media::ImfSample {
                buffer: b"decoded-frame-bytes".to_vec(),
                sample_time: 1000,
                sample_duration: 333333,
                flags: 0,
            },
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                process_input,
                &[transform as u32, 0, sample as u32, 0]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_input_status,
                &[transform as u32, 0, status_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, status_out).unwrap(),
            0,
            "not accepting while buffered"
        );
        let pending_out = 0x41_510_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_output_status,
                &[transform as u32, pending_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, pending_out).unwrap(),
            1,
            "output pending"
        );

        // ProcessOutput produces the sample with the copied bytes.
        let output_buffer = 0x41_600_u64;
        let status_out2 = 0x41_620_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                process_output,
                &[
                    transform as u32,
                    0,
                    1,
                    output_buffer as u32,
                    status_out2 as u32
                ]
            ),
            0
        );
        let output_sample = read_guest_pointer(&memory, output_buffer + 8, GuestArch::X86).unwrap();
        assert_ne!(output_sample, 0);
        assert_eq!(
            read_guest_u32(&memory, output_buffer + 16).unwrap(),
            0x1,
            "MF_SAMPLE_SAMPLE_READY"
        );
        assert_eq!(
            runtime.mf_samples.get(&output_sample).unwrap().buffer,
            b"decoded-frame-bytes",
            "the passthrough output"
        );
        assert_eq!(
            runtime.mf_samples.get(&output_sample).unwrap().sample_time,
            1000
        );

        // Flush + shutdown.
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                process_message,
                &[transform as u32, 0x0000_0001, 0]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, shutdown, &[activate as u32]),
            0
        );
        assert!(!runtime.mf_activates.contains_key(&activate));
    })
}

#[test]
fn evidence_mf_attributes_full_surface() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("evidence-mf-attrs");
        let mut memory = MemoryImage::default();
        let create_type: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateMediaType);
        let _set_guid: u64 = runtime.alloc_host_thunk(HostThunk::MfAttrSetGuid);
        let set_string: u64 = runtime.alloc_host_thunk(HostThunk::MfAttrSetString);
        let get_item: u64 = runtime.alloc_host_thunk(HostThunk::MfAttrGetItem);
        let get_item_type: u64 = runtime.alloc_host_thunk(HostThunk::MfAttrGetItemType);
        let get_allocated_string: u64 =
            runtime.alloc_host_thunk(HostThunk::MfAttrGetAllocatedString);
        let get_count: u64 = runtime.alloc_host_thunk(HostThunk::MfAttrGetCount);
        let delete_all: u64 = runtime.alloc_host_thunk(HostThunk::MfAttrDeleteAllItems);
        let lock: u64 = runtime.alloc_host_thunk(HostThunk::MfAttrLockStore);
        let sample_flags_get: u64 = runtime.alloc_host_thunk(HostThunk::MfSampleGetSampleFlags);
        let sample_flags_set: u64 = runtime.alloc_host_thunk(HostThunk::MfSampleSetSampleFlags);
        let total_length: u64 = runtime.alloc_host_thunk(HostThunk::MfSampleGetTotalLength);
        let to_buffer: u64 = runtime.alloc_host_thunk(HostThunk::MfSampleCopyToBuffer);
        let contiguous: u64 =
            runtime.alloc_host_thunk(HostThunk::MfSampleConvertToContiguousBuffer);

        let type_out = 0x41_000_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, create_type, &[type_out as u32]),
            0
        );
        let mt = read_guest_pointer(&memory, type_out, GuestArch::X86).unwrap();
        assert_ne!(mt, 0);

        // SetItem: the major type GUID through the PROPVARIANT path.
        let key = 0x41_100_u64;
        memory.map_bytes(
            key,
            &[
                0x21, 0x27, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38,
                0x9b, 0x71,
            ],
        );
        let value = 0x41_200_u64;
        write_guest_u32(&mut memory, value, 72).ok(); // VT_CLSID
        let video: [u8; 16] = [
            0x76, 0x69, 0x64, 0x73, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38,
            0x9b, 0x71,
        ];
        memory.map_bytes(0x41_210_u64, &video);
        write_guest_pointer(&mut memory, value + 8, 0x41_210_u64, GuestArch::X86).ok();
        let set_item: u64 = runtime.alloc_host_thunk(HostThunk::MfAttrSetItem);
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_item,
                &[mt as u32, key as u32, value as u32]
            ),
            0
        );

        // GetItemType returns VT_CLSID; GetItem writes the GUID.
        let type_out2 = 0x41_300_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_item_type,
                &[mt as u32, key as u32, type_out2 as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, type_out2).unwrap(),
            72,
            "MF_ATTRIBUTE_GUID"
        );
        let item_out = 0x41_310_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_item,
                &[mt as u32, key as u32, item_out as u32]
            ),
            0
        );
        assert_eq!(read_guest_u32(&memory, item_out).unwrap(), 72);

        // A string attribute + the allocated copy.
        let name_key = 0x41_400_u64;
        memory.map_bytes(
            name_key,
            &[
                0x4a, 0x59, 0x4b, 0x5e, 0x78, 0x55, 0x9c, 0x44, 0x91, 0x53, 0x22, 0x55, 0x09, 0x3c,
                0x8c, 0x9a,
            ],
        );
        let name = 0x41_410_u64;
        let name_wide: Vec<u16> = "Test String".encode_utf16().chain([0]).collect();
        for (i, unit) in name_wide.iter().enumerate() {
            write_guest_u16(&mut memory, name + (i as u64 * 2), *unit).ok();
        }
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_string,
                &[mt as u32, name_key as u32, name as u32]
            ),
            0
        );
        let alloc_out = 0x41_500_u64;
        let len_out = 0x41_510_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_allocated_string,
                &[mt as u32, name_key as u32, alloc_out as u32, len_out as u32]
            ),
            0
        );
        let alloc_ptr = read_guest_pointer(&memory, alloc_out, GuestArch::X86).unwrap();
        assert_eq!(
            read_utf16_string(&memory, alloc_ptr).unwrap(),
            "Test String"
        );
        assert_eq!(read_guest_u32(&memory, len_out).unwrap(), 11);

        // The store lock + count + delete-all.
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, lock, &[mt as u32]),
            0
        );
        let count_out = 0x41_600_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_count,
                &[mt as u32, count_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, count_out).unwrap(),
            2,
            "two attributes"
        );
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, delete_all, &[mt as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_count,
                &[mt as u32, count_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, count_out).unwrap(),
            0,
            "empty after DeleteAllItems"
        );

        // The IMFSample flags/length/buffer-conversion surface.
        let sample = runtime
            .alloc_guest_object(&mut memory, GuestObjectKind::ImfSample, 0)
            .unwrap();
        runtime.mf_samples.insert(
            sample,
            crate::media::ImfSample {
                buffer: vec![1, 2, 3, 4],
                sample_time: 0,
                sample_duration: 0,
                flags: 0,
            },
        );
        let flags_out = 0x41_700_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sample_flags_set,
                &[sample as u32, 3]
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                sample_flags_get,
                &[sample as u32, flags_out as u32]
            ),
            0
        );
        assert_eq!(read_guest_u32(&memory, flags_out).unwrap(), 3);
        let len_out2 = 0x41_710_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                total_length,
                &[sample as u32, len_out2 as u32]
            ),
            0
        );
        assert_eq!(read_guest_u32(&memory, len_out2).unwrap(), 4);
        let buffer_out = 0x41_720_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                contiguous,
                &[sample as u32, buffer_out as u32]
            ),
            0
        );
        let buffer = read_guest_pointer(&memory, buffer_out, GuestArch::X86).unwrap();
        assert_eq!(
            runtime.mf_media_buffers.get(&buffer).unwrap().data,
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                to_buffer,
                &[sample as u32, buffer as u32]
            ),
            0
        );

        // The completed session surface: a session + a topology.
        let create_session: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateMediaSession);
        let create_topology: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateTopology);
        let session_set_topology: u64 = runtime.alloc_host_thunk(HostThunk::MfSessionSetTopology);
        let session_caps: u64 =
            runtime.alloc_host_thunk(HostThunk::MfSessionGetSessionCapabilities);
        let session_full: u64 = runtime.alloc_host_thunk(HostThunk::MfSessionGetFullTopology);
        let session_out = 0x41_800_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_session,
                &[0, session_out as u32]
            ),
            0
        );
        let session = read_guest_pointer(&memory, session_out, GuestArch::X86).unwrap();
        assert_ne!(session, 0);
        let topo_out = 0x41_810_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_topology,
                &[topo_out as u32]
            ),
            0
        );
        let topology = read_guest_pointer(&memory, topo_out, GuestArch::X86).unwrap();
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                session_set_topology,
                &[session as u32, 0, topology as u32]
            ),
            0
        );
        let caps_out = 0x41_820_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                session_caps,
                &[session as u32, caps_out as u32]
            ),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, caps_out).unwrap() & 0x1,
            0x1,
            "MFSESSIONCAP_SEEK"
        );
        let full_out = 0x41_830_u64;
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                session_full,
                &[session as u32, 0, 0, full_out as u32]
            ),
            0
        );
        let full = read_guest_pointer(&memory, full_out, GuestArch::X86).unwrap();
        assert_ne!(full, 0);

        // The IDispatch typeinfo surface.
        let id_count: u64 = runtime.alloc_host_thunk(HostThunk::IDispatchGetTypeInfoCount);
        let count_out = 0x41_900_u64;
        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, id_count, &[0, count_out as u32]),
            0
        );
        assert_eq!(
            read_guest_u32(&memory, count_out).unwrap(),
            0,
            "no typeinfo"
        );
    })
}

#[test]
fn audio_client_start_advances_padding_over_real_elapsed_time() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("audio-client-clock");
        let mut memory = MemoryImage::default();
        let (endpoint, buffer_address, buffer_frames) =
            initialized_audio_client_endpoint(&mut runtime, &mut memory, 8_000, 1_000_000, 0);
        assert_eq!(buffer_frames, 800, "100 ms at 8 kHz");
        memory.map_bytes(
            AUDIO_CLIENT_RIID_ADDR,
            &crate::audio_activation::IID_IAUDIO_RENDER_CLIENT,
        );
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0_u8; 8]);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientGetService,
            &[
                endpoint as u32,
                AUDIO_CLIENT_RIID_ADDR as u32,
                AUDIO_CLIENT_OUT_ADDR as u32,
            ],
        );
        assert_eq!(hr, 0);
        let service = read_guest_pointer(&memory, AUDIO_CLIENT_OUT_ADDR, GuestArch::X86).unwrap();

        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientStart,
            &[endpoint as u32],
        );
        assert_eq!(hr, 0, "Start succeeds");

        // Hand out the real buffer, write a real PCM16 frame pattern and
        // release it: the padding is real committed-frame accounting.
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioRenderClientGetBuffer,
            &[service as u32, buffer_frames, AUDIO_CLIENT_OUT_ADDR as u32],
        );
        assert_eq!(hr, 0);
        let data = read_guest_pointer(&memory, AUDIO_CLIENT_OUT_ADDR, GuestArch::X86).unwrap();
        assert_eq!(data, buffer_address, "GetBuffer hands out the bound buffer");
        let byte_len = buffer_frames as usize * 4;
        let mut pcm = Vec::with_capacity(byte_len);
        for index in 0..buffer_frames {
            let sample = ((index % 16) as i16 - 8) * 100;
            pcm.extend_from_slice(&sample.to_le_bytes());
            pcm.extend_from_slice(&sample.to_le_bytes());
        }
        memory.map_bytes(data, &pcm);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioRenderClientReleaseBuffer,
            &[service as u32, buffer_frames, 0],
        );
        assert_eq!(hr, 0, "ReleaseBuffer accepts the written frames");
        assert_eq!(
            crate::audio_activation::test_client_snapshot(runtime.guest_pid, endpoint)
                .unwrap()
                .submitted_frames,
            buffer_frames as u64,
            "the released frames are committed"
        );
        // The bytes the guest wrote stayed in the real guest buffer.
        let readback = memory.read_bytes(data, byte_len).expect("buffer bytes");
        assert_eq!(readback, pcm, "GetBuffer/ReleaseBuffer round-trip bytes");

        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientGetCurrentPadding,
            &[endpoint as u32, AUDIO_CLIENT_OUT_ADDR as u32],
        );
        assert_eq!(hr, 0);
        let padding = read_u32(&memory, AUDIO_CLIENT_OUT_ADDR).unwrap();
        assert!(padding > 0, "committed frames are padded");

        // Poll with a bounded loop: the real playback clock drains the
        // buffer (100 ms of audio at 8 kHz).
        let mut drained = false;
        for _ in 0..400 {
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioClientGetCurrentPadding,
                &[endpoint as u32, AUDIO_CLIENT_OUT_ADDR as u32],
            );
            if read_u32(&memory, AUDIO_CLIENT_OUT_ADDR).unwrap() == 0 {
                drained = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(drained, "the real clock drained the committed buffer");

        // Stop halts the advance: a new submission stays padded.
        memory.map_bytes(data, &pcm);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioRenderClientGetBuffer,
            &[service as u32, buffer_frames, AUDIO_CLIENT_OUT_ADDR as u32],
        );
        assert_eq!(hr, 0);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioRenderClientReleaseBuffer,
            &[service as u32, buffer_frames, 0],
        );
        assert_eq!(hr, 0);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientStop,
            &[endpoint as u32],
        );
        assert_eq!(hr, 0, "Stop succeeds");
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientGetCurrentPadding,
            &[endpoint as u32, AUDIO_CLIENT_OUT_ADDR as u32],
        );
        assert_eq!(hr, 0);
        let frozen = read_u32(&memory, AUDIO_CLIENT_OUT_ADDR).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientGetCurrentPadding,
            &[endpoint as u32, AUDIO_CLIENT_OUT_ADDR as u32],
        );
        assert_eq!(
            read_u32(&memory, AUDIO_CLIENT_OUT_ADDR).unwrap(),
            frozen,
            "a stopped client's padding never advances"
        );

        // Reset discards the buffered frames; Reset while running fails.
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientReset,
            &[endpoint as u32],
        );
        assert_eq!(hr, 0, "Reset while stopped succeeds");
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientGetCurrentPadding,
            &[endpoint as u32, AUDIO_CLIENT_OUT_ADDR as u32],
        );
        assert_eq!(hr, 0);
        assert_eq!(read_u32(&memory, AUDIO_CLIENT_OUT_ADDR).unwrap(), 0);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientStart,
            &[endpoint as u32],
        );
        assert_eq!(hr, 0);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientReset,
            &[endpoint as u32],
        );
        assert_eq!(
            hr,
            crate::audio_activation::AUDCLNT_E_NOT_STOPPED as u64,
            "Reset while running is rejected"
        );
    })
}

#[test]
fn audio_client_set_event_handle_signals_the_real_guest_event() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("audio-client-event");
        let mut memory = MemoryImage::default();
        let (handle, _existed) = runtime.win32.create_event(true, false, false, None);
        let (endpoint, _buffer_address, _buffer_frames) = initialized_audio_client_endpoint(
            &mut runtime,
            &mut memory,
            48_000,
            100_000,
            crate::audio_activation::AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
        );
        assert!(!runtime.win32.event_previous_state(handle).unwrap());
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientSetEventHandle,
            &[endpoint as u32, handle],
        );
        assert_eq!(hr, 0, "SetEventHandle stores the real guest event");
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientStart,
            &[endpoint as u32],
        );
        assert_eq!(hr, 0);
        assert!(
            runtime.win32.event_previous_state(handle).unwrap(),
            "the buffer-ready event is signaled through the runtime event machinery"
        );
        assert_eq!(
            crate::audio_activation::test_client_snapshot(runtime.guest_pid, endpoint)
                .unwrap()
                .event_handle,
            u64::from(handle)
        );
    })
}

#[test]
fn audio_client_initialize_rejects_unsupported_formats() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("audio-client-bad-format");
        let mut memory = MemoryImage::default();
        let endpoint = runtime
            .alloc_audio_client_endpoint(
                &mut memory,
                &audio_client_test_device(),
                crate::audio_activation::IID_IAUDIO_CLIENT,
            )
            .expect("alloc endpoint");

        // Unbacked compressed format tag (ADPCM).
        let mut adpcm = pcm16_wave_format_bytes(2, 48_000);
        adpcm[0] = 0x02;
        memory.map_bytes(AUDIO_CLIENT_FMT_ADDR, &adpcm);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientInitialize,
            &[
                endpoint as u32,
                crate::audio_activation::AUDCLNT_SHAREMODE_SHARED,
                0,
                100_000,
                0,
                AUDIO_CLIENT_FMT_ADDR as u32,
                0,
            ],
        );
        assert_eq!(
            hr,
            crate::audio_activation::AUDCLNT_E_UNSUPPORTED_FORMAT as u64,
            "ADPCM is not backed"
        );

        // Zero channels.
        let mut zero_channels = pcm16_wave_format_bytes(0, 48_000);
        zero_channels[12] = 0;
        zero_channels[13] = 0;
        memory.map_bytes(AUDIO_CLIENT_FMT_ADDR, &zero_channels);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientInitialize,
            &[
                endpoint as u32,
                crate::audio_activation::AUDCLNT_SHAREMODE_SHARED,
                0,
                100_000,
                0,
                AUDIO_CLIENT_FMT_ADDR as u32,
                0,
            ],
        );
        assert_eq!(
            hr,
            crate::audio_activation::AUDCLNT_E_UNSUPPORTED_FORMAT as u64
        );

        // IsFormatSupported reports the same unbacked format.
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientIsFormatSupported,
            &[
                endpoint as u32,
                crate::audio_activation::AUDCLNT_SHAREMODE_SHARED,
                AUDIO_CLIENT_FMT_ADDR as u32,
                0,
            ],
        );
        assert_eq!(
            hr,
            crate::audio_activation::AUDCLNT_E_UNSUPPORTED_FORMAT as u64
        );

        // A double Initialize on a valid format is rejected.
        memory.map_bytes(AUDIO_CLIENT_FMT_ADDR, &pcm16_wave_format_bytes(2, 48_000));
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientInitialize,
            &[
                endpoint as u32,
                crate::audio_activation::AUDCLNT_SHAREMODE_SHARED,
                0,
                100_000,
                0,
                AUDIO_CLIENT_FMT_ADDR as u32,
                0,
            ],
        );
        assert_eq!(hr, 0);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientInitialize,
            &[
                endpoint as u32,
                crate::audio_activation::AUDCLNT_SHAREMODE_SHARED,
                0,
                100_000,
                0,
                AUDIO_CLIENT_FMT_ADDR as u32,
                0,
            ],
        );
        assert_eq!(
            hr,
            crate::audio_activation::AUDCLNT_E_ALREADY_INITIALIZED as u64
        );
    })
}

#[test]
fn audio_client2_and_3_extension_methods_are_real() {
    with_big_stack(|| {
        let (mut runtime, _tmp) = test_runtime("audio-client-extensions");
        let mut memory = MemoryImage::default();
        let device = audio_client_test_device();
        let endpoint = runtime
            .alloc_audio_client_endpoint(
                &mut memory,
                &device,
                crate::audio_activation::IID_IAUDIO_CLIENT_3,
            )
            .expect("alloc endpoint");
        memory.map_bytes(
            AUDIO_CLIENT_FMT_ADDR,
            &pcm16_wave_format_bytes(device.channels, device.sample_rate),
        );

        // IAudioClient3::GetSharedModeEnginePeriod — real frame periods at
        // the requested format's rate.
        let fundamental_out = AUDIO_CLIENT_OUT_ADDR + 4;
        let minimum_out = AUDIO_CLIENT_OUT_ADDR + 8;
        let maximum_out = AUDIO_CLIENT_OUT_ADDR + 12;
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0_u8; 32]);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientGetSharedModeEnginePeriod,
            &[
                endpoint as u32,
                AUDIO_CLIENT_FMT_ADDR as u32,
                AUDIO_CLIENT_OUT_ADDR as u32,
                fundamental_out as u32,
                minimum_out as u32,
                maximum_out as u32,
            ],
        );
        assert_eq!(hr, 0, "GetSharedModeEnginePeriod succeeds");
        let default_frames = read_u32(&memory, AUDIO_CLIENT_OUT_ADDR).unwrap();
        let fundamental_frames = read_u32(&memory, fundamental_out).unwrap();
        let minimum_frames = read_u32(&memory, minimum_out).unwrap();
        let maximum_frames = read_u32(&memory, maximum_out).unwrap();
        assert!(default_frames > 0, "real default engine period");
        assert_eq!(fundamental_frames, minimum_frames);
        assert!(minimum_frames <= default_frames);
        assert!(maximum_frames >= default_frames);

        // IAudioClient3::GetCurrentSharedModeEnginePeriod — real mix
        // format plus the current engine period.
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0_u8; 16]);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientGetCurrentSharedModeEnginePeriod,
            &[
                endpoint as u32,
                AUDIO_CLIENT_OUT_ADDR as u32,
                (AUDIO_CLIENT_OUT_ADDR + 8) as u32,
            ],
        );
        assert_eq!(hr, 0);
        let mix_ptr = read_guest_pointer(&memory, AUDIO_CLIENT_OUT_ADDR, GuestArch::X86).unwrap();
        let mix =
            crate::audio_activation::parse_wave_format(&memory.read_bytes(mix_ptr, 40).unwrap())
                .expect("current mix format parses");
        assert_eq!(mix.channels, device.channels);
        assert_eq!(mix.sample_rate, device.sample_rate);
        assert!(mix.is_float());
        assert_eq!(
            read_u32(&memory, AUDIO_CLIENT_OUT_ADDR + 8).unwrap(),
            default_frames,
            "the current engine period is the default period"
        );

        // IAudioClient2::GetBufferSizeLimits — real minimum period up to
        // the engine's two-second maximum.
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0_u8; 16]);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientGetBufferSizeLimits,
            &[
                endpoint as u32,
                AUDIO_CLIENT_FMT_ADDR as u32,
                0,
                AUDIO_CLIENT_OUT_ADDR as u32,
                (AUDIO_CLIENT_OUT_ADDR + 8) as u32,
            ],
        );
        assert_eq!(hr, 0);
        let minimum_hns = read_u64(&memory, AUDIO_CLIENT_OUT_ADDR).unwrap();
        let maximum_hns = read_u64(&memory, AUDIO_CLIENT_OUT_ADDR + 8).unwrap();
        assert!(minimum_hns > 0);
        assert_eq!(maximum_hns, 20_000_000, "the engine max is two seconds");

        // IAudioClient2::IsOffloadCapable — no host offload engine, so the
        // real answer is FALSE (never a canned success).
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0xFF_u8; 4]);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientIsOffloadCapable,
            &[endpoint as u32, 0, AUDIO_CLIENT_OUT_ADDR as u32],
        );
        assert_eq!(hr, 0);
        assert_eq!(read_u32(&memory, AUDIO_CLIENT_OUT_ADDR).unwrap(), 0);

        // IAudioClient2::SetClientProperties — a real property structure.
        let props = AUDIO_CLIENT_OUT_ADDR + 16;
        memory.map_bytes(props, &[12, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0]);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientSetClientProperties,
            &[endpoint as u32, props as u32],
        );
        assert_eq!(hr, 0);

        // The Windows 8.1+ 16-byte property block carries
        // AUDCLNT_STREAMOPTIONS at offset 12.  An offload request is
        // rejected with the exact non-offload status (the host has no
        // offload engine), and a raw/bitstream request with the exact raw
        // status; neither is silently accepted.
        let wide_props = AUDIO_CLIENT_OUT_ADDR + 16;
        memory.map_bytes(
            wide_props,
            &[
                16, 0, 0, 0, // cbSize
                1, 0, 0, 0, // bIsOffload = TRUE
                3, 0, 0, 0, // eCategory = AudioCategory_Media
                0, 0, 0, 0, // Options = 0
            ],
        );
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientSetClientProperties,
            &[endpoint as u32, wide_props as u32],
        );
        assert_eq!(
            hr,
            u64::from(crate::audio_activation::AUDCLNT_E_NONOFFLOAD_MODE_ONLY),
            "offload without a host engine is rejected exactly"
        );
        memory.map_bytes(
            wide_props,
            &[
                16, 0, 0, 0, // cbSize
                0, 0, 0, 0, // bIsOffload = FALSE
                3, 0, 0, 0, // eCategory = AudioCategory_Media
                1, 0, 0, 0, // Options = AUDCLNT_STREAMOPTIONS_RAW
            ],
        );
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientSetClientProperties,
            &[endpoint as u32, wide_props as u32],
        );
        assert_eq!(
            hr,
            u64::from(crate::audio_activation::AUDCLNT_E_RAW_MODE_UNSUPPORTED),
            "bitstream/raw is rejected exactly"
        );
        // A 16-byte property size whose Options field is unmapped is a
        // pointer error, never a partial read or silent acceptance.
        let truncated_props = AUDIO_CLIENT_OUT_ADDR + 40;
        memory.map_bytes(
            truncated_props,
            &[
                16, 0, 0, 0, // cbSize says 16
                0, 0, 0, 0, // bIsOffload = FALSE
                3, 0, 0, 0, // eCategory
            ],
        );
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientSetClientProperties,
            &[endpoint as u32, truncated_props as u32],
        );
        assert_eq!(
            hr,
            u64::from(crate::audio_activation::AUDCLNT_E_POINTER),
            "an unavailable Options field is AUDCLNT_E_POINTER"
        );

        // IAudioClient3::InitializeSharedAudioStream — a real shared-mode
        // initialization at the requested period in frames.
        let stream_endpoint = runtime
            .alloc_audio_client_endpoint(
                &mut memory,
                &device,
                crate::audio_activation::IID_IAUDIO_CLIENT_3,
            )
            .expect("alloc endpoint");
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientInitializeSharedAudioStream,
            &[
                stream_endpoint as u32,
                0,
                240,
                AUDIO_CLIENT_FMT_ADDR as u32,
                0,
            ],
        );
        assert_eq!(hr, 0, "InitializeSharedAudioStream succeeds");
        assert_eq!(
            crate::audio_activation::test_client_snapshot(runtime.guest_pid, stream_endpoint)
                .unwrap()
                .buffer_frames,
            240,
            "the requested period is the real buffer size"
        );
    })
}

#[test]
fn activation_endpoint_exposes_real_audio_client_methods() {
    with_big_stack(|| {
        if !real_default_device_available() {
            eprintln!("skipping activation endpoint test: no real default render device");
            return;
        }
        let (mut runtime, _tmp) = test_runtime("audio-client-activation");
        let mut memory = MemoryImage::default();
        install_audio_activation_handler(&mut memory);
        memory.map_bytes(
            AUDIO_CLIENT_RIID_ADDR,
            &crate::audio_activation::IID_IAUDIO_CLIENT,
        );
        memory.map_bytes(AUDIO_CLIENT_OP_OUT, &[0_u8; 8]);
        let stack = 0x50_000_u64;
        memory.map_bytes(stack, &[0_u8; 0x200]);
        write_u32(&mut memory, stack, 0xDEAD_BEEF);
        write_guest_pointer(&mut memory, stack + 4, 0, GuestArch::X86).unwrap();
        write_guest_pointer(
            &mut memory,
            stack + 8,
            AUDIO_CLIENT_RIID_ADDR,
            GuestArch::X86,
        )
        .unwrap();
        write_guest_pointer(&mut memory, stack + 12, 0, GuestArch::X86).unwrap();
        write_guest_pointer(
            &mut memory,
            stack + 16,
            AUDIO_CLIENT_HANDLER_OBJECT,
            GuestArch::X86,
        )
        .unwrap();
        write_guest_pointer(&mut memory, stack + 20, AUDIO_CLIENT_OP_OUT, GuestArch::X86).unwrap();
        let thunk = runtime.alloc_host_thunk(HostThunk::ActivateAudioInterfaceAsync);
        let mut cpu = CpuState::new(GuestArch::X86);
        cpu.set(Register::Rsp, stack);
        runtime
            .dispatch_import(thunk, &mut cpu, &mut memory)
            .expect("dispatch ActivateAudioInterfaceAsync");
        assert_eq!(cpu.get(Register::Rax), 0, "activation starts (S_OK)");
        let operation = read_guest_pointer(&memory, AUDIO_CLIENT_OP_OUT, GuestArch::X86).unwrap();
        assert_ne!(operation, 0, "the activation produced an operation object");
        let endpoint =
            crate::audio_activation::activation_operation_interface(runtime.guest_pid, operation)
                .expect("operation bound to the activated endpoint");
        assert_ne!(endpoint, 0, "the operation carries the endpoint");
        // Before the completion is delivered, GetActivateResult reports the
        // documented illegal-call error.
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0_u8; 16]);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioActivationOperationGetActivateResult,
            &[
                operation as u32,
                AUDIO_CLIENT_OUT_ADDR as u32,
                (AUDIO_CLIENT_OUT_ADDR + 8) as u32,
            ],
        );
        assert_eq!(
            hr,
            u64::from(crate::audio_activation::E_ILLEGAL_METHOD_CALL),
            "GetActivateResult before completion"
        );
        let record = crate::audio_activation::endpoint_record(runtime.guest_pid, endpoint)
            .expect("real device record bound to the endpoint");
        assert_eq!(
            record.requested_riid,
            crate::audio_activation::IID_IAUDIO_CLIENT
        );
        // The activation attached the real method surface (slot 3 is
        // IAudioClient::Initialize).
        let vtable = read_guest_pointer(&memory, endpoint, GuestArch::X86).expect("vtable");
        let initialize_thunk = read_guest_pointer(&memory, vtable + 12, GuestArch::X86).unwrap();
        let resolved = runtime
            .host_thunks
            .get(&initialize_thunk)
            .expect("Initialize dispatches to a host thunk");
        assert_eq!(
            std::mem::discriminant(resolved),
            std::mem::discriminant(&HostThunk::AudioClientInitialize),
            "the activated endpoint's vtable carries the real methods"
        );
        let snapshot = crate::audio_activation::test_client_snapshot(runtime.guest_pid, endpoint)
            .expect("client state attached");
        assert!(
            snapshot.submitted_frames == 0,
            "the activated client is fresh"
        );

        // GetMixFormat on the activated endpoint reports the real device
        // rate and channel count.
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0_u8; 8]);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientGetMixFormat,
            &[endpoint as u32, AUDIO_CLIENT_OUT_ADDR as u32],
        );
        assert_eq!(hr, 0);
        let format_ptr =
            read_guest_pointer(&memory, AUDIO_CLIENT_OUT_ADDR, GuestArch::X86).unwrap();
        let mix =
            crate::audio_activation::parse_wave_format(&memory.read_bytes(format_ptr, 40).unwrap())
                .expect("activated mix format parses");
        assert_eq!(mix.channels, record.device.channels);
        assert_eq!(mix.sample_rate, record.device.sample_rate);

        // Initialize with a real format, start the clock and stop it.
        memory.map_bytes(
            AUDIO_CLIENT_FMT_ADDR,
            &pcm16_wave_format_bytes(record.device.channels, record.device.sample_rate),
        );
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientInitialize,
            &[
                endpoint as u32,
                crate::audio_activation::AUDCLNT_SHAREMODE_SHARED,
                0,
                100_000,
                0,
                AUDIO_CLIENT_FMT_ADDR as u32,
                0,
            ],
        );
        assert_eq!(hr, 0, "Initialize on the activated endpoint");
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientStart,
            &[endpoint as u32],
        );
        assert_eq!(hr, 0);

        // GetService + GetBuffer/ReleaseBuffer on the activated endpoint:
        // the released frames flow into the real output path (silence, so
        // the test is inaudible) and the real clock accounts for them.
        memory.map_bytes(
            AUDIO_CLIENT_RIID_ADDR,
            &crate::audio_activation::IID_IAUDIO_RENDER_CLIENT,
        );
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0_u8; 8]);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientGetService,
            &[
                endpoint as u32,
                AUDIO_CLIENT_RIID_ADDR as u32,
                AUDIO_CLIENT_OUT_ADDR as u32,
            ],
        );
        assert_eq!(hr, 0);
        let service = read_guest_pointer(&memory, AUDIO_CLIENT_OUT_ADDR, GuestArch::X86).unwrap();
        let buffer_frames =
            crate::audio_activation::test_client_snapshot(runtime.guest_pid, endpoint)
                .unwrap()
                .buffer_frames;
        assert!(buffer_frames > 0);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioRenderClientGetBuffer,
            &[service as u32, buffer_frames, AUDIO_CLIENT_OUT_ADDR as u32],
        );
        assert_eq!(hr, 0);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioRenderClientReleaseBuffer,
            &[
                service as u32,
                buffer_frames,
                crate::audio_activation::AUDCLNT_BUFFERFLAGS_SILENT,
            ],
        );
        assert_eq!(hr, 0);
        assert_eq!(
            crate::audio_activation::test_client_snapshot(runtime.guest_pid, endpoint)
                .unwrap()
                .submitted_frames,
            u64::from(buffer_frames),
        );
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientGetCurrentPadding,
            &[endpoint as u32, AUDIO_CLIENT_OUT_ADDR as u32],
        );
        assert_eq!(hr, 0);
        assert!(read_u32(&memory, AUDIO_CLIENT_OUT_ADDR).unwrap() > 0);

        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientStop,
            &[endpoint as u32],
        );
        assert_eq!(hr, 0);

        // The completion handler is delivered from the runtime servicing
        // point (the async contract is untouched by the method surface).
        let mut drain_cpu = CpuState::new(GuestArch::X86);
        drain_cpu.set(Register::Rsp, stack);
        runtime
            .drain_pending_audio_activations(&mut drain_cpu, &mut memory)
            .expect("drain activation completions");
        assert_eq!(read_u32(&memory, 0x44_008).unwrap(), 1);
        assert_eq!(
            read_u32(&memory, 0x44_004).unwrap(),
            operation as u32,
            "the handler receives the operation object"
        );
        // After completion, GetActivateResult returns the real activation
        // HRESULT and the activated endpoint, exactly once.
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0_u8; 16]);
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioActivationOperationGetActivateResult,
            &[
                operation as u32,
                AUDIO_CLIENT_OUT_ADDR as u32,
                (AUDIO_CLIENT_OUT_ADDR + 8) as u32,
            ],
        );
        assert_eq!(hr, 0, "GetActivateResult after completion");
        assert_eq!(read_u32(&memory, AUDIO_CLIENT_OUT_ADDR).unwrap(), 0);
        assert_eq!(
            read_guest_pointer(&memory, AUDIO_CLIENT_OUT_ADDR + 8, GuestArch::X86).unwrap(),
            endpoint,
            "GetActivateResult hands out the activated interface"
        );
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioActivationOperationGetActivateResult,
            &[
                operation as u32,
                AUDIO_CLIENT_OUT_ADDR as u32,
                (AUDIO_CLIENT_OUT_ADDR + 8) as u32,
            ],
        );
        assert_eq!(
            hr,
            u64::from(crate::audio_activation::E_ILLEGAL_METHOD_CALL),
            "a completed result is returned only once"
        );
    })
}

#[test]
fn loopback_capture_reads_real_render_client_frames() {
    with_big_stack(|| {
        if !real_default_device_available() {
            eprintln!("skipping loopback test: no real default render device");
            return;
        }
        let (mut runtime, _tmp) = test_runtime("audio-client-loopback");
        let mut memory = MemoryImage::default();
        let device = crate::real_audio::RealAudioBackend::new()
            .expect("real audio backend")
            .activation_device_snapshot()
            .into_iter()
            .find(|device| device.is_default)
            .expect("default render device");
        memory.map_bytes(
            AUDIO_CLIENT_FMT_ADDR,
            &pcm16_wave_format_bytes(device.channels, device.sample_rate),
        );

        // Real render client: initialize, start, write a frame pattern and
        // release it into the real output path.
        let render = runtime
            .alloc_audio_client_endpoint(
                &mut memory,
                &device,
                crate::audio_activation::IID_IAUDIO_CLIENT,
            )
            .expect("render endpoint");
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientInitialize,
            &[
                render as u32,
                crate::audio_activation::AUDCLNT_SHAREMODE_SHARED,
                0,
                100_000,
                0,
                AUDIO_CLIENT_FMT_ADDR as u32,
                0,
            ],
        );
        assert_eq!(hr, 0, "render Initialize");
        let render_snapshot =
            crate::audio_activation::test_client_snapshot(runtime.guest_pid, render)
                .expect("render state");
        let buffer_frames = render_snapshot.buffer_frames;
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioClientStart,
                &[render as u32],
            ),
            0
        );
        memory.map_bytes(
            AUDIO_CLIENT_RIID_ADDR,
            &crate::audio_activation::IID_IAUDIO_RENDER_CLIENT,
        );
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0_u8; 8]);
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioClientGetService,
                &[
                    render as u32,
                    AUDIO_CLIENT_RIID_ADDR as u32,
                    AUDIO_CLIENT_OUT_ADDR as u32,
                ],
            ),
            0
        );
        let render_service =
            read_guest_pointer(&memory, AUDIO_CLIENT_OUT_ADDR, GuestArch::X86).unwrap();
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioRenderClientGetBuffer,
                &[
                    render_service as u32,
                    buffer_frames,
                    AUDIO_CLIENT_OUT_ADDR as u32,
                ],
            ),
            0
        );
        let data = read_guest_pointer(&memory, AUDIO_CLIENT_OUT_ADDR, GuestArch::X86).unwrap();
        let mut pcm = Vec::new();
        for frame in 0..buffer_frames {
            let sample = ((frame % 16) as i16 - 8) * 400;
            for _ in 0..device.channels {
                pcm.extend_from_slice(&sample.to_le_bytes());
            }
        }
        memory.map_bytes(data, &pcm);
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioRenderClientReleaseBuffer,
                &[render_service as u32, buffer_frames, 0],
            ),
            0,
            "the render client releases real frames"
        );

        // Loopback capture on the same render endpoint reads those frames.
        let capture = runtime
            .alloc_audio_client_endpoint(
                &mut memory,
                &device,
                crate::audio_activation::IID_IAUDIO_CLIENT,
            )
            .expect("capture endpoint");
        let hr = audio_client_call(
            &mut runtime,
            &mut memory,
            HostThunk::AudioClientInitialize,
            &[
                capture as u32,
                crate::audio_activation::AUDCLNT_SHAREMODE_SHARED,
                crate::audio_activation::AUDCLNT_STREAMFLAGS_LOOPBACK
                    | crate::audio_activation::AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
                100_000,
                0,
                AUDIO_CLIENT_FMT_ADDR as u32,
                0,
            ],
        );
        assert_eq!(hr, 0, "loopback Initialize");
        let (event, _) = runtime.win32.create_event(true, false, false, None);
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioClientSetEventHandle,
                &[capture as u32, event],
            ),
            0
        );
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioClientStart,
                &[capture as u32],
            ),
            0
        );
        assert!(
            runtime.win32.event_previous_state(event).unwrap(),
            "loopback capture signals its event for the queued render frames"
        );
        memory.map_bytes(
            AUDIO_CLIENT_RIID_ADDR,
            &crate::audio_activation::IID_IAUDIO_CAPTURE_CLIENT,
        );
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0_u8; 8]);
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioClientGetService,
                &[
                    capture as u32,
                    AUDIO_CLIENT_RIID_ADDR as u32,
                    AUDIO_CLIENT_OUT_ADDR as u32,
                ],
            ),
            0,
            "loopback exposes IAudioCaptureClient"
        );
        let capture_service =
            read_guest_pointer(&memory, AUDIO_CLIENT_OUT_ADDR, GuestArch::X86).unwrap();
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioCaptureClientGetNextPacketSize,
                &[capture_service as u32, AUDIO_CLIENT_OUT_ADDR as u32],
            ),
            0
        );
        let available = read_u32(&memory, AUDIO_CLIENT_OUT_ADDR).unwrap();
        assert!(
            available > 0,
            "GetNextPacketSize reflects the real loopback queue"
        );
        memory.map_bytes(AUDIO_CLIENT_OUT_ADDR, &[0_u8; 32]);
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioCaptureClientGetBuffer,
                &[
                    capture_service as u32,
                    AUDIO_CLIENT_OUT_ADDR as u32,
                    (AUDIO_CLIENT_OUT_ADDR + 4) as u32,
                    (AUDIO_CLIENT_OUT_ADDR + 8) as u32,
                    (AUDIO_CLIENT_OUT_ADDR + 16) as u32,
                    (AUDIO_CLIENT_OUT_ADDR + 24) as u32,
                ],
            ),
            0
        );
        let frames = read_u32(&memory, AUDIO_CLIENT_OUT_ADDR + 4).unwrap();
        let flags = read_u32(&memory, AUDIO_CLIENT_OUT_ADDR + 8).unwrap();
        assert_eq!(frames, available);
        assert_eq!(flags, 0, "real render frames are not silent");
        let samples_ptr =
            read_guest_pointer(&memory, AUDIO_CLIENT_OUT_ADDR, GuestArch::X86).unwrap();
        let expected = crate::real_audio::pcm_bytes_to_float(&pcm, 1, 16, device.channels);
        let sample_count = frames as usize * device.channels as usize;
        let captured_bytes = memory
            .read_bytes(samples_ptr, sample_count * 2)
            .expect("loopback samples");
        let captured_f32 =
            crate::real_audio::pcm_bytes_to_float(&captured_bytes, 1, 16, device.channels);
        assert_eq!(captured_f32.len(), expected.len());
        for (captured, expected) in captured_f32.iter().zip(expected.iter()) {
            assert!(
                (captured - expected).abs() < 1.0e-4,
                "loopback frame {captured} != render frame {expected}"
            );
        }
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioCaptureClientReleaseBuffer,
                &[capture_service as u32, frames, 0],
            ),
            0
        );
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioClientStop,
                &[capture as u32],
            ),
            0
        );
        assert_eq!(
            audio_client_call(
                &mut runtime,
                &mut memory,
                HostThunk::AudioClientReset,
                &[capture as u32],
            ),
            0
        );
    })
}
