use super::*;

pub(super) fn test_runtime(name: &str) -> (PeHostRuntime, TempDir) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(temp_dir.path(), name, GeArch::X86, "win11-23h2")
        .expect("create ge");
    let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
    configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
    (runtime, temp_dir)
}

pub(super) fn build_root_signature(
    root_constants: u32,
    descriptors: &[(u8, u8, u8, u8, u8, u8)],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&(descriptors.len() as u32).to_le_bytes());
    bytes.extend(&root_constants.to_le_bytes());
    for descriptor in descriptors {
        bytes.extend([
            descriptor.0,
            descriptor.1,
            descriptor.2,
            descriptor.3,
            descriptor.4,
            descriptor.5,
        ]);
    }
    bytes
}

pub(super) fn configure_runtime_for_test_arch(runtime: &mut PeHostRuntime, guest_arch: GuestArch) {
    runtime.guest_arch = guest_arch;
    runtime.next_thunk_address = thunk_base_for_arch(guest_arch);
    runtime.next_data_address = data_base_for_arch(guest_arch);
    runtime.next_heap_address = heap_base_for_arch(guest_arch);
    runtime
        .win32
        .reset_address_space(private_pages_base_for_arch(guest_arch));
    runtime.x86_heap_region = 0;
}

pub(super) fn write_test_guid(memory: &mut MemoryImage, address: u64, data1: u32) {
    write_u32(memory, address, data1);
    memory.map_bytes(address + 4, &0_u16.to_le_bytes());
    memory.map_bytes(address + 6, &0_u16.to_le_bytes());
    memory.map_bytes(
        address + 8,
        &[0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
    );
}

pub(super) fn dispatch_x86_thunk(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    thunk: u64,
    args: &[u32],
) -> u64 {
    let stack = 0x50_000;
    memory.map_bytes(stack, &[0_u8; 0x200]);
    write_u32(memory, stack, 0xDEAD_BEEF);
    for (index, arg) in args.iter().enumerate() {
        write_u32(memory, stack + 4 + (index as u64 * 4), *arg);
    }
    let mut state = CpuState::new(GuestArch::X86);
    state.set(Register::Rsp, stack);
    runtime
        .dispatch_import(thunk, &mut state, memory)
        .unwrap_or_else(|e| panic!("dispatch x86 thunk: {e}"));
    state.get(Register::Rax)
}

pub(super) fn dispatch_x64_thunk(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    thunk: u64,
    args: &[u64],
) -> u64 {
    let stack = 0x58_000;
    memory.map_bytes(stack, &[0_u8; 0x400]);
    write_u64(memory, stack, 0xDEAD_BEEF);
    // Win64 shadow space.
    memory.map_bytes(stack + 8, &[0_u8; 0x20]);
    for (index, arg) in args.iter().enumerate() {
        if index >= 4 {
            write_u64(memory, stack + 0x20 + (index as u64 - 4) * 8, *arg);
        }
    }
    let mut state = CpuState::new(GuestArch::X64);
    state.set(Register::Rsp, stack);
    if let Some(arg) = args.first() {
        state.set(Register::Rcx, *arg);
    }
    if let Some(arg) = args.get(1) {
        state.set(Register::Rdx, *arg);
    }
    if let Some(arg) = args.get(2) {
        state.set(Register::R8, *arg);
    }
    if let Some(arg) = args.get(3) {
        state.set(Register::R9, *arg);
    }
    runtime
        .dispatch_import(thunk, &mut state, memory)
        .unwrap_or_else(|e| panic!("dispatch x64 thunk: {e}"));
    state.get(Register::Rax)
}

pub(super) fn dispatch_x86_thunk_regs(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    thunk: u64,
    regs: &[(Register, u64)],
) -> u64 {
    let stack = 0x50_000;
    memory.map_bytes(stack, &[0_u8; 0x200]);
    write_u32(memory, stack, 0xDEAD_BEEF);
    let mut state = CpuState::new(GuestArch::X86);
    state.set(Register::Rsp, stack);
    for (reg, value) in regs {
        state.set(*reg, *value);
    }
    runtime
        .dispatch_import(thunk, &mut state, memory)
        .expect("dispatch x86 thunk");
    state.get(Register::Rax)
}

pub(super) fn minimal_unsigned_pe() -> Vec<u8> {
    let mut pe = vec![0u8; 0x200];
    pe[0] = b'M';
    pe[1] = b'Z';
    let e_lfanew: u32 = 0x40;
    pe[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    let e = e_lfanew as usize;
    pe[e..e + 4].copy_from_slice(b"PE\0\0");
    let coff = e + 4;
    let size_of_optional: u16 = 0xE0;
    pe[coff + 16..coff + 18].copy_from_slice(&size_of_optional.to_le_bytes());
    let opt = coff + 20;
    pe[opt..opt + 2].copy_from_slice(&0x10b_u16.to_le_bytes()); // PE32 magic
    // SECURITY data directory entry (index 4) left zeroed → no signature.
    pe
}

pub(super) fn pe_with_garbage_certificate_table() -> Vec<u8> {
    let mut pe = minimal_unsigned_pe();
    let e = 0x40usize;
    let coff = e + 4;
    let opt = coff + 20;
    let dd_offset = opt + 96; // PE32 data directories
    let sec_entry = dd_offset + 4 * 8; // IMAGE_DIRECTORY_ENTRY_SECURITY
    let cert_va: u32 = 0x180;
    let cert_size: u32 = 0x20;
    pe[sec_entry..sec_entry + 4].copy_from_slice(&cert_va.to_le_bytes());
    pe[sec_entry + 4..sec_entry + 8].copy_from_slice(&cert_size.to_le_bytes());
    let va = cert_va as usize;
    // WIN_CERTIFICATE: dwLength, wRevision, wCertType=PKCS_SIGNED_DATA, then garbage.
    pe[va..va + 4].copy_from_slice(&cert_size.to_le_bytes());
    pe[va + 4..va + 6].copy_from_slice(&0x0200_u16.to_le_bytes());
    pe[va + 6..va + 8].copy_from_slice(&0x0002_u16.to_le_bytes());
    for byte in pe.iter_mut().skip(va + 8).take((cert_size as usize) - 8) {
        *byte = 0xFF;
    }
    pe
}

pub(super) fn build_x86_wintrust_data(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    guest_path: &str,
    union_choice: u32,
) -> u64 {
    let path_ptr = runtime
        .alloc_utf16_string(memory, guest_path)
        .expect("alloc path");
    let file_info_ptr: u64 = 0x60_000;
    memory.map_bytes(file_info_ptr, &[0u8; 16]);
    write_u32(memory, file_info_ptr, 16); // cbStruct
    write_u32(memory, file_info_ptr + 4, path_ptr as u32); // pcwszFilePath
    let wvt_ptr: u64 = 0x61_000;
    memory.map_bytes(wvt_ptr, &[0u8; 32]);
    write_u32(memory, wvt_ptr, 32); // cbStruct
    write_u32(memory, wvt_ptr + 20, union_choice); // dwUnionChoice
    write_u32(memory, wvt_ptr + 24, file_info_ptr as u32); // union pointer
    wvt_ptr
}

pub(super) fn write_guest_pe_file(runtime: &PeHostRuntime, guest_path: &str, bytes: &[u8]) {
    let host_path = runtime
        .win32
        .guest_path_to_host_path(guest_path)
        .expect("host path");
    if let Some(parent) = host_path.parent() {
        fs::create_dir_all(parent).expect("create parent dir");
    }
    fs::write(&host_path, bytes).expect("write guest PE");
}

pub(super) fn utf16_bytes(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_feature_support_query(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    state: &mut CpuState,
    thunk: u64,
    device_object: u64,
    feature: u32,
    data_ptr: u64,
    data_size: usize,
    return_slot: u64,
) {
    state.set(Register::Rsp, return_slot);
    state.set(Register::Rcx, device_object);
    state.set(Register::Rdx, feature as u64);
    state.set(Register::R8, data_ptr);
    state.set(Register::R9, data_size as u64);
    memory.write_u64(return_slot, 0x3333_0000 + feature as u64);
    runtime
        .dispatch_import(thunk, state, memory)
        .expect("dispatch CheckFeatureSupport");
    assert_eq!(state.get(Register::Rax), 0);
}

pub(super) fn build_program_part(
    instruction_count: u32,
    ir_size: u32,
    threadgroup_size: (u32, u32, u32),
    uses: &[(u8, u8, u8, u8, u8, u16)],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&instruction_count.to_le_bytes());
    bytes.extend(&ir_size.to_le_bytes());
    bytes.extend(&threadgroup_size.0.to_le_bytes());
    bytes.extend(&threadgroup_size.1.to_le_bytes());
    bytes.extend(&threadgroup_size.2.to_le_bytes());
    bytes.extend(&(uses.len() as u32).to_le_bytes());
    for entry in uses {
        bytes.extend([
            entry.0,
            entry.1,
            entry.2,
            entry.3,
            entry.4,
            entry.5 as u8,
            (entry.5 >> 8) as u8,
            0,
        ]);
    }
    bytes
}

pub(super) fn build_container(entry_name: &str, parts: Vec<([u8; 4], Vec<u8>)>) -> Vec<u8> {
    let header_size = 12 + parts.len() * 12;
    let mut offset = header_size as u32;
    let descriptors = parts
        .iter()
        .map(|(kind, payload)| {
            let descriptor = (*kind, offset, payload.len() as u32);
            offset += payload.len() as u32;
            descriptor
        })
        .collect::<Vec<_>>();
    let mut bytes = Vec::new();
    bytes.extend(b"DXIL");
    bytes.extend(&1_u32.to_le_bytes());
    bytes.extend(&(parts.len() as u32).to_le_bytes());
    for (kind, offset, size) in &descriptors {
        bytes.extend(kind);
        bytes.extend(&offset.to_le_bytes());
        bytes.extend(&size.to_le_bytes());
    }
    for (_, payload) in parts {
        bytes.extend(payload);
    }
    let mut meta = vec![entry_name.len() as u8];
    meta.extend(entry_name.as_bytes());
    let parts_without_meta = bytes[12 + descriptors.len() * 12..].to_vec();
    let mut rewritten = Vec::new();
    rewritten.extend(b"DXIL");
    rewritten.extend(&1_u32.to_le_bytes());
    rewritten.extend(&((descriptors.len() + 1) as u32).to_le_bytes());
    let mut running_offset = (12 + (descriptors.len() + 1) * 12) as u32;
    for (kind, _, size) in descriptors {
        rewritten.extend(kind);
        rewritten.extend(&running_offset.to_le_bytes());
        rewritten.extend(&size.to_le_bytes());
        running_offset += size;
    }
    rewritten.extend(*b"META");
    rewritten.extend(&running_offset.to_le_bytes());
    rewritten.extend(&(meta.len() as u32).to_le_bytes());
    rewritten.extend(parts_without_meta);
    rewritten.extend(meta);
    rewritten
}

pub(super) fn embedded_root_pixel_shader_dxil() -> Vec<u8> {
    let root_signature = build_root_signature(4, &[(1, 0, 0, 1, 0, 0)]);
    build_container(
        "main_ps",
        vec![
            (
                *b"PROG",
                build_program_part(12, 256, (1, 1, 1), &[(1, 0, 0, 0, 0, 0)]),
            ),
            (*b"SIGN", b"input-signature-output-signature".to_vec()),
            (*b"ROOT", root_signature),
        ],
    )
}

// -----------------------------------------------------------------------
// Fast-thunk table tests (G5 FastThunk Table Dispatch Integration)
// -----------------------------------------------------------------------
pub(super) fn setup_fast_thunk_runtime() -> (PeHostRuntime, MemoryImage) {
    // JIT is enabled by default in set_guest_arch.
    let ge = GameEnvironment::open("steam-live-run-x86").expect("create ge");
    let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
    runtime.set_guest_arch(GuestArch::X64);
    let memory = MemoryImage::default();
    (runtime, memory)
}

pub(super) fn u16_bytes(units: &[u16]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(units.len() * 2);
    for &unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

// -----------------------------------------------------------------------
// Item 109: Tests for invalid guest pointers on major host thunk families
// -----------------------------------------------------------------------
pub(super) fn make_test_ge() -> GameEnvironment {
    GameEnvironment::open("steam-live-run-x86").expect("create test ge")
}

pub(super) fn make_test_runtime() -> PeHostRuntime {
    let ge = make_test_ge();
    let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
    configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
    runtime
}

pub(super) fn make_test_runtime_x64() -> PeHostRuntime {
    let ge = make_test_ge();
    let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
    configure_runtime_for_test_arch(&mut runtime, GuestArch::X64);
    runtime
}

// -----------------------------------------------------------------------
// Item F1/F4: window-surface pixel provenance.  Host-invented chrome
// (builtin control paints) must never publish to the live channel, and a
// window DC with no REAL surface must never fabricate a blank frame.
// -----------------------------------------------------------------------
pub(super) fn create_probe_window(
    runtime: &mut PeHostRuntime,
    class_name: &str,
    title: &str,
    width: u32,
    height: u32,
) -> u32 {
    const WS_CHILD: u32 = 0x4000_0000;
    runtime.user32.register_class_ex_w(class_name);
    runtime
        .user32
        .create_window_ex_styled(
            class_name, title, width, height, true, false, None, 1, WS_CHILD, 0, None,
        )
        .expect("create probe window")
}

// ═══════════════════════════════════════════════════════════════════════
// Patch 6b: CRT / UCRT / MSVCRT host-thunk surface tests
// ═══════════════════════════════════════════════════════════════════════
pub(super) fn setup_crt_test_runtime() -> (TempDir, PeHostRuntime, MemoryImage) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge = GameEnvironment::create_in(temp_dir.path(), "crt-p6b", GeArch::X86, "win11-23h2")
        .expect("create ge");
    let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
    configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
    let mut memory = MemoryImage::default();
    let static_tls_block = runtime
        .alloc_zeroed(&mut memory, 0x2000, 16)
        .expect("static tls block");
    runtime.tls_vector_ptr = runtime
        .alloc_zeroed(&mut memory, 4096 * 4, 16)
        .expect("tls vector");
    runtime.tls_slots.insert(0, static_tls_block);
    runtime
        .sync_guest_tls_slot(&mut memory, 0, static_tls_block)
        .expect("sync tls slot 0");
    (temp_dir, runtime, memory)
}

pub(super) fn write_x86_stub(memory: &mut MemoryImage, address: u64, bytes: &[u8]) {
    memory.map_bytes(address, bytes);
}

pub(super) fn marker_callback(address: u64, marker: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(0xB8);
    bytes.extend_from_slice(&(address as u32).to_le_bytes());
    bytes.push(0xC7);
    bytes.push(0x00);
    bytes.extend_from_slice(&marker.to_le_bytes());
    bytes.push(0xC3);
    bytes
}

pub(super) fn qsort_compare_stub() -> Vec<u8> {
    vec![
        0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4]  (eax = a)
        0x8B, 0x4C, 0x24, 0x08, // mov ecx, [esp+8]  (ecx = b)
        0x8B, 0x10, // mov edx, [eax]  (edx = *a)
        0x8B, 0x01, // mov eax, [ecx]  (eax = *b)
        0x29, 0xC2, // sub edx, eax    (edx = *a - *b)
        0x89, 0xD0, // mov eax, edx
        0xC3, // ret
    ]
}

pub(super) fn dispatch_x86_thunk_result(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    thunk: u64,
    args: &[u32],
) -> Option<i32> {
    let stack = 0x50_000;
    memory.map_bytes(0x40_000, &[0_u8; 0x12_200]);
    write_u32(memory, stack, 0xDEAD_BEEF);
    for (index, arg) in args.iter().enumerate() {
        write_u32(memory, stack + 4 + (index as u64 * 4), *arg);
    }
    let mut state = CpuState::new(GuestArch::X86);
    state.set(Register::Rsp, stack);
    runtime
        .dispatch_import(thunk, &mut state, memory)
        .expect("dispatch x86 thunk")
}

pub(super) fn with_big_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(body)
        .expect("spawn big-stack thread")
        .join()
        .expect("big-stack thread panicked")
}

pub(super) fn dispatch_x86_thunk_crt(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    thunk: u64,
    args: &[u32],
) -> u64 {
    let stack = 0x50_000;
    memory.map_bytes(0x40_000, &[0_u8; 0x12_200]);
    write_u32(memory, stack, 0xDEAD_BEEF);
    for (index, arg) in args.iter().enumerate() {
        write_u32(memory, stack + 4 + (index as u64 * 4), *arg);
    }
    let mut state = CpuState::new(GuestArch::X86);
    state.set(Register::Rsp, stack);
    runtime
        .dispatch_import(thunk, &mut state, memory)
        .expect("dispatch x86 thunk");
    state.get(Register::Rax)
}

// ── evidence-math-crt: the msvcrt math surface ──────────────────────────
pub(super) fn dispatch_math_x86(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    thunk: u64,
    args: &[f64],
) -> f64 {
    let stack = 0x50_000;
    memory.map_bytes(stack, &[0_u8; 0x200]);
    write_u32(memory, stack, 0xDEAD_BEEF);
    for (index, arg) in args.iter().enumerate() {
        memory.map_bytes(stack + 4 + (index as u64 * 8), &arg.to_bits().to_le_bytes());
    }
    let mut state = CpuState::new(GuestArch::X86);
    state.set(Register::Rsp, stack);
    runtime
        .dispatch_import(thunk, &mut state, memory)
        .expect("dispatch math thunk");
    state.x87.stack.last().copied().unwrap_or(f64::NAN)
}

pub(super) fn dispatch_math_x64(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    thunk: u64,
    args: &[f64],
) -> f64 {
    let stack = 0x50_000;
    memory.map_bytes(stack, &[0_u8; 0x200]);
    write_u64(memory, stack, 0xDEAD_BEEF);
    let mut state = CpuState::new(GuestArch::X64);
    state.set(Register::Rsp, stack);
    for (index, arg) in args.iter().enumerate() {
        state.xmm[index].low = arg.to_bits();
    }
    runtime
        .dispatch_import(thunk, &mut state, memory)
        .expect("dispatch math thunk x64");
    f64::from_bits(state.xmm[0].low)
}

// -- psapi dispatch -------------------------------------------------------
pub(super) fn write_guest_utf16(memory: &mut MemoryImage, address: u64, value: &str) {
    let mut bytes = Vec::new();
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    memory.map_bytes(address, &bytes);
}

// -- version.dll dispatch ------------------------------------------------
pub(super) fn utf16z_bytes_for_test(value: &str) -> Vec<u8> {
    let mut bytes = value
        .encode_utf16()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes
}

pub(super) fn align4_for_test(bytes: &mut Vec<u8>) {
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
}

pub(super) fn version_block_for_test(
    key: &str,
    ty: u16,
    value: &[u8],
    value_length: u16,
    children: Vec<Vec<u8>>,
) -> Vec<u8> {
    let mut bytes = vec![0_u8; 6];
    bytes.extend_from_slice(&utf16z_bytes_for_test(key));
    align4_for_test(&mut bytes);
    bytes.extend_from_slice(value);
    align4_for_test(&mut bytes);
    for child in children {
        bytes.extend_from_slice(&child);
        align4_for_test(&mut bytes);
    }
    let length = bytes.len() as u16;
    bytes[0..2].copy_from_slice(&length.to_le_bytes());
    bytes[2..4].copy_from_slice(&value_length.to_le_bytes());
    bytes[4..6].copy_from_slice(&ty.to_le_bytes());
    bytes
}

pub(super) fn version_fixed_info_for_test(version: &str) -> Vec<u8> {
    let mut parts = version
        .split('.')
        .map(|part| part.parse::<u16>().expect("version part"))
        .collect::<Vec<_>>();
    while parts.len() < 4 {
        parts.push(0);
    }
    let ms = ((parts[0] as u32) << 16) | parts[1] as u32;
    let ls = ((parts[2] as u32) << 16) | parts[3] as u32;
    let mut bytes = Vec::new();
    for value in [
        0xfeef04bd,
        0x0001_0000,
        ms,
        ls,
        ms,
        ls,
        0x0000_003f,
        0,
        0x0004_0004,
        1,
        0,
        0,
        0,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

pub(super) fn version_resource_blob_for_test() -> Vec<u8> {
    let fixed_info = version_fixed_info_for_test("1.2.3.4");
    let string_table = version_block_for_test(
        "040904b0",
        1,
        &[],
        0,
        vec![
            version_block_for_test(
                "ProductName",
                1,
                &utf16z_bytes_for_test("Casa1"),
                ("Casa1".encode_utf16().count() + 1) as u16,
                Vec::new(),
            ),
            version_block_for_test(
                "FileVersion",
                1,
                &utf16z_bytes_for_test("1.2.3.4"),
                ("1.2.3.4".encode_utf16().count() + 1) as u16,
                Vec::new(),
            ),
        ],
    );
    let string_file_info = version_block_for_test("StringFileInfo", 1, &[], 0, vec![string_table]);
    version_block_for_test(
        "VS_VERSION_INFO",
        0,
        &fixed_info,
        fixed_info.len() as u16,
        vec![string_file_info],
    )
}

pub(super) fn version_pe_for_test() -> Vec<u8> {
    let blob = version_resource_blob_for_test();
    let section_rva = 0x1000_u32;
    let root_size = 16 + 8; // one id entry
    let tree_size = root_size + 64;
    let mut rsrc = vec![0_u8; tree_size];
    let mut blob_offset = tree_size;
    while !blob_offset.is_multiple_of(4) {
        blob_offset += 1;
    }
    rsrc.resize(blob_offset, 0);
    let type_dir_offset = root_size;
    let name_dir_offset = type_dir_offset + 24;
    let data_entry_offset = type_dir_offset + 48;

    let write_u16 = |bytes: &mut Vec<u8>, offset: usize, value: u16| {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    };
    let write_u32 = |bytes: &mut Vec<u8>, offset: usize, value: u32| {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    };

    // Resource directory header: NumberOfNamedEntries @12, NumberOfIdEntries @14.
    write_u16(&mut rsrc, 12, 0); // named entries
    write_u16(&mut rsrc, 14, 1); // id entries
    write_u32(&mut rsrc, 16, 16); // RT_VERSION
    write_u32(&mut rsrc, 20, 0x8000_0000 | type_dir_offset as u32);

    // Type directory: name = 1.
    write_u16(&mut rsrc, type_dir_offset + 12, 0);
    write_u16(&mut rsrc, type_dir_offset + 14, 1);
    write_u32(&mut rsrc, type_dir_offset + 16, 1);
    write_u32(
        &mut rsrc,
        type_dir_offset + 20,
        0x8000_0000 | name_dir_offset as u32,
    );

    // Name directory: language = 1033.
    write_u16(&mut rsrc, name_dir_offset + 12, 0);
    write_u16(&mut rsrc, name_dir_offset + 14, 1);
    write_u32(&mut rsrc, name_dir_offset + 16, 1033);
    write_u32(&mut rsrc, name_dir_offset + 20, data_entry_offset as u32);

    // Data entry → blob payload.
    let data_rva = section_rva + blob_offset as u32;
    write_u32(&mut rsrc, data_entry_offset, data_rva);
    write_u32(&mut rsrc, data_entry_offset + 4, blob.len() as u32);
    write_u32(&mut rsrc, data_entry_offset + 8, 1200);
    rsrc.extend_from_slice(&blob);

    let raw_size = rsrc.len().div_ceil(0x200) * 0x200;
    rsrc.resize(raw_size, 0);

    let dos_stub_size = 0x80;
    let pe_offset = dos_stub_size;
    let optional_header_size = 0xE0;
    let section_table_offset = pe_offset + 24 + optional_header_size;
    let size_of_headers = 0x200;
    let mut bytes = vec![0_u8; size_of_headers];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    write_u32(&mut bytes, 0x3C, dos_stub_size as u32);
    bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    write_u16(&mut bytes, pe_offset + 4, 0x014C); // I386
    write_u16(&mut bytes, pe_offset + 6, 1); // one section
    write_u16(&mut bytes, pe_offset + 20, optional_header_size as u16);
    write_u16(&mut bytes, pe_offset + 22, 0x0102); // EXECUTABLE_IMAGE

    let optional = pe_offset + 24;
    write_u16(&mut bytes, optional, 0x010B); // PE32
    write_u32(&mut bytes, optional + 16, 0); // entry point
    write_u32(&mut bytes, optional + 20, 0x0040_0000); // image base
    write_u32(&mut bytes, optional + 32, 0x1000); // section alignment
    write_u32(&mut bytes, optional + 36, 0x200); // file alignment
    write_u32(&mut bytes, optional + 56, 0x3000); // size of image
    write_u32(&mut bytes, optional + 60, size_of_headers as u32); // size of headers
    write_u16(&mut bytes, optional + 68, 3); // console subsystem
    write_u32(&mut bytes, optional + 92, 16); // number of rva+sizes
    // Resource directory (index 2).
    write_u32(&mut bytes, optional + 96 + 2 * 8, section_rva);
    write_u32(&mut bytes, optional + 96 + 2 * 8 + 4, rsrc.len() as u32);

    // Section header: .rsrc
    bytes[section_table_offset..section_table_offset + 8].copy_from_slice(b".rsrc\0\0\0");
    write_u32(&mut bytes, section_table_offset + 8, 0x2000); // virtual size
    write_u32(&mut bytes, section_table_offset + 12, section_rva);
    write_u32(&mut bytes, section_table_offset + 16, rsrc.len() as u32); // raw size
    write_u32(&mut bytes, section_table_offset + 20, 0x200); // raw ptr
    write_u32(&mut bytes, section_table_offset + 36, 0x4000_0040); // readable data

    bytes.extend_from_slice(&rsrc);
    bytes
}

// -- libcef inline thunk dispatch -----------------------------------------
// -- gdiplus dispatch -----------------------------------------------------
pub(super) fn gdiplus_bitmap_pixels(runtime: &PeHostRuntime, bmp_handle: u64) -> Vec<u8> {
    match runtime.user32.gdiplus_state.get(bmp_handle) {
        Some(GdiplusObject::Image(img)) => match &**img {
            GdiplusImage::Bitmap(bmp) => bmp.pixels.clone(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

pub(super) fn gdiplus_pixel(runtime: &PeHostRuntime, bmp_handle: u64, x: u32, y: u32) -> u32 {
    let pixels = gdiplus_bitmap_pixels(runtime, bmp_handle);
    let stride = match runtime.user32.gdiplus_state.get(bmp_handle) {
        Some(GdiplusObject::Image(img)) => match &**img {
            GdiplusImage::Bitmap(bmp) => bmp.stride,
            _ => 0,
        },
        _ => 0,
    };
    let idx = (y as i32 * stride + x as i32 * 4) as usize;
    u32::from_le_bytes([
        pixels[idx],
        pixels[idx + 1],
        pixels[idx + 2],
        pixels[idx + 3],
    ])
}

pub(super) fn f32_bits(value: f32) -> u32 {
    value.to_bits()
}

// ── APC + completion-port scheduler wiring ─────────────────────────────
//
// The GQCS/GQCSEx thunks park on the scheduler's CompletionPort waits;
// `QueueUserAPC` enqueues into the win32 FIFO, and alertable waits
// deliver those APCs through `execute_guest_callback`.
pub(super) const GQCS_CONTINUATION: u64 = 0x42_000;

pub(super) const GQCS_FLAG_PTR: u64 = 0x42_010;

pub(super) fn resume_parked_completion_port_waiter(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
) {
    let mut parked = runtime
        .pending_guest_threads
        .pop_front()
        .expect("a parked completion-port waiter");
    parked.state.rip = GQCS_CONTINUATION;
    parked.state.set(Register::Rsp, 0x10_F00);
    runtime.pending_guest_threads.push_back(parked);
    memory.map_bytes(GQCS_CONTINUATION, &[0xA3, 0x10, 0x20, 0x04, 0x00, 0xC3]);
    memory.map_bytes(GQCS_FLAG_PTR, &[0u8; 4]);
    memory.map_bytes(0x10_F00, &[0u8; 4]);
}

pub(super) fn evidence_utf16(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>()
}

pub(super) fn evidence_x86_state(memory: &mut MemoryImage, args: &[u32]) -> CpuState {
    let stack = 0x50_000;
    memory.map_bytes(stack, &[0_u8; 0x200]);
    write_u32(memory, stack, 0xDEAD_BEEF);
    for (index, arg) in args.iter().enumerate() {
        write_u32(memory, stack + 4 + (index as u64 * 4), *arg);
    }
    let mut state = CpuState::new(GuestArch::X86);
    state.set(Register::Rsp, stack);
    state
}

pub(super) fn evidence_dispatch_x64_thunk(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    thunk: u64,
    args: &[u64],
) -> u64 {
    let stack = 0x50_000;
    memory.map_bytes(stack, &[0_u8; 0x400]);
    write_guest_pointer(memory, stack, 0x1000, GuestArch::X64).expect("return address");
    let mut state = CpuState::new(GuestArch::X64);
    state.set(Register::Rsp, stack);
    for (index, arg) in args.iter().enumerate() {
        match index {
            0 => state.set(Register::Rcx, *arg),
            1 => state.set(Register::Rdx, *arg),
            2 => state.set(Register::R8, *arg),
            3 => state.set(Register::R9, *arg),
            _ => write_guest_pointer(
                memory,
                stack + 0x20 + ((index - 4) as u64 * 8),
                *arg,
                GuestArch::X64,
            )
            .expect("stack arg"),
        }
    }
    runtime
        .dispatch_import(thunk, &mut state, memory)
        .expect("dispatch x64 thunk");
    state.get(Register::Rax)
}

pub(super) fn build_test_pe_with_icon() -> Vec<u8> {
    const SECTION_ALIGN: u32 = 0x1000;
    const FILE_ALIGN: u32 = 0x200;
    const RSRC_RVA: u32 = 0x1000;
    const RSRC_SIZE: u32 = 0x600;
    const RSRC_RAW: u32 = 0x400;

    // The icon payload: BITMAPINFOHEADER + 16×16 BGRA (XOR rows) + AND mask.
    let mut icon_data = Vec::new();
    let mut header = [0u8; 40];
    header[0..4].copy_from_slice(&40_u32.to_le_bytes());
    header[4..8].copy_from_slice(&16_i32.to_le_bytes());
    header[8..12].copy_from_slice(&32_i32.to_le_bytes()); // XOR + AND
    header[12..14].copy_from_slice(&1_u16.to_le_bytes());
    header[14..16].copy_from_slice(&32_u16.to_le_bytes());
    icon_data.extend_from_slice(&header);
    for _ in 0..16 {
        for _ in 0..16 {
            icon_data.extend_from_slice(&[0, 0, 255, 255]); // BGRA red
        }
    }
    icon_data.extend_from_slice(&[0u8; 16 * 4]); // AND mask

    let mut group_icon = Vec::new();
    group_icon.extend_from_slice(&0_u16.to_le_bytes()); // reserved
    group_icon.extend_from_slice(&1_u16.to_le_bytes()); // type = icon
    group_icon.extend_from_slice(&1_u16.to_le_bytes()); // count
    group_icon.extend_from_slice(&[16, 16, 0, 0]); // width, height, colors, reserved
    group_icon.extend_from_slice(&1_u16.to_le_bytes()); // planes
    group_icon.extend_from_slice(&32_u16.to_le_bytes()); // bitcount
    group_icon.extend_from_slice(&(icon_data.len() as u32).to_le_bytes()); // bytesInRes
    group_icon.extend_from_slice(&1_u16.to_le_bytes()); // icon resource ID

    // The resource tree, with every subdirectory/data pointer expressed
    // as a byte offset from the resource root RVA (the parser's
    // convention; the high bit marks a subdirectory pointer):
    //
    //   0x00 root directory (2 type entries)
    //   0x40 RT_ICON name directory (name ID 1)
    //   0x60 RT_GROUP_ICON name directory (name ID 1)
    //   0x80 icon language directory (lang 0)
    //   0xA0 group language directory (lang 0)
    //   0xC0 icon data entry
    //   0xD0 group data entry
    //   0xE0 group icon payload
    //   0x100 icon payload
    let mut rsrc_bytes = vec![0u8; RSRC_SIZE as usize];
    let mut put = |offset: usize, bytes: &[u8]| {
        rsrc_bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
    };
    // Root directory: 2 ID entries.
    let mut root = Vec::new();
    root.extend_from_slice(&0_u32.to_le_bytes());
    root.extend_from_slice(&0_u32.to_le_bytes());
    root.extend_from_slice(&0_u16.to_le_bytes());
    root.extend_from_slice(&0_u16.to_le_bytes());
    root.extend_from_slice(&0_u16.to_le_bytes()); // no named entries
    root.extend_from_slice(&2_u16.to_le_bytes()); // two ID entries
    root.extend_from_slice(&3_u32.to_le_bytes()); // RT_ICON (id, no name bit)
    root.extend_from_slice(&(0x40_u32 | 0x8000_0000).to_le_bytes()); // → name dir
    root.extend_from_slice(&14_u32.to_le_bytes()); // RT_GROUP_ICON
    root.extend_from_slice(&(0x60_u32 | 0x8000_0000).to_le_bytes()); // → name dir
    put(0x00, &root);
    // RT_ICON name directory: name ID 1 → language dir at 0x80.
    let mut icon_name = Vec::new();
    icon_name.extend_from_slice(&0_u32.to_le_bytes());
    icon_name.extend_from_slice(&0_u32.to_le_bytes());
    icon_name.extend_from_slice(&0_u16.to_le_bytes());
    icon_name.extend_from_slice(&0_u16.to_le_bytes());
    icon_name.extend_from_slice(&0_u16.to_le_bytes());
    icon_name.extend_from_slice(&1_u16.to_le_bytes());
    icon_name.extend_from_slice(&1_u32.to_le_bytes()); // name ID 1
    icon_name.extend_from_slice(&(0x80_u32 | 0x8000_0000).to_le_bytes()); // → lang dir
    put(0x40, &icon_name);
    // RT_GROUP_ICON name directory: name ID 1 → language dir at 0xA0.
    let mut group_name = Vec::new();
    group_name.extend_from_slice(&0_u32.to_le_bytes());
    group_name.extend_from_slice(&0_u32.to_le_bytes());
    group_name.extend_from_slice(&0_u16.to_le_bytes());
    group_name.extend_from_slice(&0_u16.to_le_bytes());
    group_name.extend_from_slice(&0_u16.to_le_bytes());
    group_name.extend_from_slice(&1_u16.to_le_bytes());
    group_name.extend_from_slice(&1_u32.to_le_bytes()); // name ID 1
    group_name.extend_from_slice(&(0xA0_u32 | 0x8000_0000).to_le_bytes()); // → lang dir
    put(0x60, &group_name);
    // Icon language directory: lang 0 → data entry at 0xC0.
    let mut icon_lang = Vec::new();
    icon_lang.extend_from_slice(&0_u32.to_le_bytes());
    icon_lang.extend_from_slice(&0_u32.to_le_bytes());
    icon_lang.extend_from_slice(&0_u16.to_le_bytes());
    icon_lang.extend_from_slice(&0_u16.to_le_bytes());
    icon_lang.extend_from_slice(&0_u16.to_le_bytes());
    icon_lang.extend_from_slice(&1_u16.to_le_bytes());
    icon_lang.extend_from_slice(&0_u32.to_le_bytes()); // language id 0
    icon_lang.extend_from_slice(&0xC0_u32.to_le_bytes()); // → data entry
    put(0x80, &icon_lang);
    // Group language directory: lang 0 → data entry at 0xD0.
    let mut group_lang = Vec::new();
    group_lang.extend_from_slice(&0_u32.to_le_bytes());
    group_lang.extend_from_slice(&0_u32.to_le_bytes());
    group_lang.extend_from_slice(&0_u16.to_le_bytes());
    group_lang.extend_from_slice(&0_u16.to_le_bytes());
    group_lang.extend_from_slice(&0_u16.to_le_bytes());
    group_lang.extend_from_slice(&1_u16.to_le_bytes());
    group_lang.extend_from_slice(&0_u32.to_le_bytes()); // language id 0
    group_lang.extend_from_slice(&0xD0_u32.to_le_bytes()); // → data entry
    put(0xA0, &group_lang);
    // Data entries: (data RVA, size).
    let mut icon_data_entry = Vec::new();
    icon_data_entry.extend_from_slice(&(RSRC_RVA + 0x100).to_le_bytes());
    icon_data_entry.extend_from_slice(&(icon_data.len() as u32).to_le_bytes());
    icon_data_entry.extend_from_slice(&0_u32.to_le_bytes());
    icon_data_entry.extend_from_slice(&0_u32.to_le_bytes());
    put(0xC0, &icon_data_entry);
    let mut group_data_entry = Vec::new();
    group_data_entry.extend_from_slice(&(RSRC_RVA + 0xE0).to_le_bytes());
    group_data_entry.extend_from_slice(&(group_icon.len() as u32).to_le_bytes());
    group_data_entry.extend_from_slice(&0_u32.to_le_bytes());
    group_data_entry.extend_from_slice(&0_u32.to_le_bytes());
    put(0xD0, &group_data_entry);
    // Payloads.
    put(0xE0, &group_icon);
    put(0x100, &icon_data);

    let mut pe = vec![0u8; 0x400];
    pe[0] = b'M';
    pe[1] = b'Z';
    let pe_offset = 0x80_u32;
    pe[0x3c..0x40].copy_from_slice(&pe_offset.to_le_bytes());
    let pe_off = pe_offset as usize;
    pe[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
    pe[pe_off + 4..pe_off + 6].copy_from_slice(&0x014c_u16.to_le_bytes()); // I386
    pe[pe_off + 6..pe_off + 8].copy_from_slice(&1_u16.to_le_bytes()); // one section
    pe[pe_off + 20..pe_off + 22].copy_from_slice(&0xE0_u16.to_le_bytes());
    pe[pe_off + 22..pe_off + 24].copy_from_slice(&0x0102_u16.to_le_bytes());
    let opt_off = pe_off + 24;
    pe[opt_off..opt_off + 2].copy_from_slice(&0x010b_u16.to_le_bytes()); // PE32
    pe[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000_u32.to_le_bytes()); // entry RVA
    pe[opt_off + 28..opt_off + 32].copy_from_slice(&0x0040_0000_u32.to_le_bytes());
    pe[opt_off + 32..opt_off + 36].copy_from_slice(&SECTION_ALIGN.to_le_bytes());
    pe[opt_off + 36..opt_off + 40].copy_from_slice(&FILE_ALIGN.to_le_bytes());
    pe[opt_off + 56..opt_off + 60].copy_from_slice(&0x3000_u32.to_le_bytes()); // size of image
    pe[opt_off + 60..opt_off + 64].copy_from_slice(&0x0400_u32.to_le_bytes()); // size of headers
    pe[opt_off + 92..opt_off + 96].copy_from_slice(&16_u32.to_le_bytes()); // data dirs
    // Data directory 2 = resource table.
    pe[opt_off + 96 + 2 * 8..opt_off + 96 + 2 * 8 + 4].copy_from_slice(&RSRC_RVA.to_le_bytes());
    pe[opt_off + 96 + 2 * 8 + 4..opt_off + 96 + 2 * 8 + 8]
        .copy_from_slice(&RSRC_SIZE.to_le_bytes());
    // Section header ".rsrc".
    let section_off = opt_off + 0xE0;
    pe[section_off..section_off + 8].copy_from_slice(b".rsrc\x00\x00\x00");
    pe[section_off + 8..section_off + 12].copy_from_slice(&RSRC_SIZE.to_le_bytes()); // virtual size
    pe[section_off + 12..section_off + 16].copy_from_slice(&RSRC_RVA.to_le_bytes());
    pe[section_off + 16..section_off + 20].copy_from_slice(&RSRC_SIZE.to_le_bytes()); // raw size
    pe[section_off + 20..section_off + 24].copy_from_slice(&RSRC_RAW.to_le_bytes()); // raw ptr
    pe[section_off + 36..section_off + 40].copy_from_slice(&0x4000_0040_u32.to_le_bytes());
    // Pad to the raw offset and append the resource section.
    pe.resize(RSRC_RAW as usize, 0);
    pe.extend_from_slice(&rsrc_bytes);
    pe
}

// ── X3DAudio guest-dispatch fixtures (packed x86 layouts) ────────────
pub(super) fn x3da_write_vec(memory: &mut MemoryImage, address: u64, x: f32, y: f32, z: f32) {
    write_guest_f32(memory, address, x).unwrap();
    write_guest_f32(memory, address + 4, y).unwrap();
    write_guest_f32(memory, address + 8, z).unwrap();
}

#[allow(clippy::type_complexity)]
pub(super) fn x3daudio_guest_scene(memory: &mut MemoryImage) -> (u64, u64, u64, u64, u64, u64) {
    let handle = 0x60_000_u64;
    let listener = 0x60_100_u64;
    let emitter = 0x60_200_u64;
    let dsp = 0x60_300_u64;
    let matrix = 0x60_400_u64;
    let delays = 0x60_500_u64;
    // X3DAudioInitialize(SPEAKER_STEREO, 343.5, handle).
    write_u32(&mut *memory, handle, 0x3144_3358); // magic "X3D1"
    write_u32(&mut *memory, handle + 4, 0x3); // SPEAKER_STEREO
    write_u32(&mut *memory, handle + 8, 343.5f32.to_bits());
    write_u32(&mut *memory, handle + 12, 0);
    write_u32(&mut *memory, handle + 16, 0);
    // Listener at the origin: front +z, top +y, stationary.
    x3da_write_vec(&mut *memory, listener, 0.0, 0.0, 1.0); // OrientFront
    x3da_write_vec(&mut *memory, listener + 12, 0.0, 1.0, 0.0); // OrientTop
    x3da_write_vec(&mut *memory, listener + 24, 0.0, 0.0, 0.0); // Position
    x3da_write_vec(&mut *memory, listener + 36, 0.0, 0.0, 0.0); // Velocity
    write_u32(&mut *memory, listener + 48, 0); // pCone
    // Single-channel emitter 6 units left, approaching at 3 units/s.
    write_u32(&mut *memory, emitter, 0); // pCone
    x3da_write_vec(&mut *memory, emitter + 4, 0.0, 0.0, 1.0); // OrientFront
    x3da_write_vec(&mut *memory, emitter + 16, 0.0, 1.0, 0.0); // OrientTop
    x3da_write_vec(&mut *memory, emitter + 28, -6.0, 0.0, 0.0); // Position
    x3da_write_vec(&mut *memory, emitter + 40, 3.0, 0.0, 0.0); // Velocity
    write_u32(&mut *memory, emitter + 52, 0.0f32.to_bits()); // InnerRadius
    write_u32(&mut *memory, emitter + 56, 0.0f32.to_bits()); // InnerRadiusAngle
    write_u32(&mut *memory, emitter + 60, 1); // ChannelCount
    write_u32(&mut *memory, emitter + 64, 0.0f32.to_bits()); // ChannelRadius
    write_u32(&mut *memory, emitter + 68, 0); // pChannelAzimuths
    write_u32(&mut *memory, emitter + 72, 0); // pVolumeCurve
    write_u32(&mut *memory, emitter + 76, 0); // pLFECurve
    write_u32(&mut *memory, emitter + 80, 0); // pLPFDirectCurve
    write_u32(&mut *memory, emitter + 84, 0); // pLPFReverbCurve
    write_u32(&mut *memory, emitter + 88, 0); // pReverbCurve
    write_u32(&mut *memory, emitter + 92, 3.0f32.to_bits()); // CurveDistanceScaler
    write_u32(&mut *memory, emitter + 96, 1.0f32.to_bits()); // DopplerScaler
    // DSP settings: 1 source channel → 2 destination channels.
    write_u32(&mut *memory, dsp, matrix as u32); // pMatrixCoefficients
    write_u32(&mut *memory, dsp + 4, delays as u32); // pDelayTimes
    write_u32(&mut *memory, dsp + 8, 1); // SrcChannelCount
    write_u32(&mut *memory, dsp + 12, 2); // DstChannelCount
    (handle, listener, emitter, dsp, matrix, delays)
}

pub(super) fn read_guest_f32_or_panic(memory: &MemoryImage, address: u64) -> f32 {
    read_guest_f32(memory, address).expect("read guest f32")
}

pub(super) fn build_exit_process_pe32(
    entry_exit_code: u32,
    second_exit_code: u32,
) -> (Vec<u8>, u64, u64, u64) {
    const IMAGE_BASE: u32 = 0x0040_0000;
    const ENTRY_RVA: u32 = 0x1000;
    const SECOND_RVA: u32 = 0x1010;
    const RDATA_RVA: u32 = 0x2000;
    const FILE_ALIGN: u32 = 0x200;
    const SECTION_ALIGN: u32 = 0x1000;
    const SIZE_OF_HEADERS: u32 = 0x200;
    // .rdata layout (RVA addrs):
    //   0x2000 import descriptor (ILT 0x2028 / name 0x2038 / IAT 0x2030)
    //   0x2014 null import descriptor
    //   0x2028 ILT entry → 0x2045, terminator
    //   0x2030 IAT entry → 0x2045, terminator
    //   0x2038 "kernel32.dll\0"
    //   0x2045 hint (0) + "ExitProcess\0"
    const IMPORT_DESCRIPTOR_RVA: u32 = RDATA_RVA;
    const ILT_RVA: u32 = RDATA_RVA + 0x28;
    const IAT_RVA: u32 = RDATA_RVA + 0x30;
    const DLL_NAME_RVA: u32 = RDATA_RVA + 0x38;
    const HINT_NAME_RVA: u32 = RDATA_RVA + 0x45;
    const IMPORT_DIRECTORY_SIZE: u32 = RDATA_RVA + 0x53 - RDATA_RVA;

    let mut text = vec![0_u8; FILE_ALIGN as usize];
    // push exit_code; call dword ptr [IAT]; ret
    let iat_va = (IMAGE_BASE + IAT_RVA) as u32;
    let emit_exit_routine = |text: &mut Vec<u8>, offset: usize, code: u32| {
        text[offset] = 0x6A; // push imm8
        text[offset + 1] = code as u8;
        text[offset + 2] = 0xFF; // call dword ptr [abs32]
        text[offset + 3] = 0x15;
        text[offset + 4..offset + 8].copy_from_slice(&iat_va.to_le_bytes());
        text[offset + 8] = 0xC3; // ret
    };
    emit_exit_routine(
        &mut text,
        (ENTRY_RVA - SECTION_ALIGN) as usize,
        entry_exit_code,
    );
    emit_exit_routine(
        &mut text,
        (SECOND_RVA - SECTION_ALIGN) as usize,
        second_exit_code,
    );

    let mut rdata = vec![0_u8; FILE_ALIGN as usize];
    let rdata_offset = |rva: u32| (rva - RDATA_RVA) as usize;
    // Import descriptor: OriginalFirstThunk, TimeDateStamp, ForwarderChain,
    // Name, FirstThunk.
    rdata[rdata_offset(IMPORT_DESCRIPTOR_RVA)..rdata_offset(IMPORT_DESCRIPTOR_RVA) + 4]
        .copy_from_slice(&ILT_RVA.to_le_bytes());
    rdata[rdata_offset(IMPORT_DESCRIPTOR_RVA) + 12..rdata_offset(IMPORT_DESCRIPTOR_RVA) + 16]
        .copy_from_slice(&DLL_NAME_RVA.to_le_bytes());
    rdata[rdata_offset(IMPORT_DESCRIPTOR_RVA) + 16..rdata_offset(IMPORT_DESCRIPTOR_RVA) + 20]
        .copy_from_slice(&IAT_RVA.to_le_bytes());
    // ILT + IAT entries point at the hint/name table.
    rdata[rdata_offset(ILT_RVA)..rdata_offset(ILT_RVA) + 4]
        .copy_from_slice(&HINT_NAME_RVA.to_le_bytes());
    rdata[rdata_offset(IAT_RVA)..rdata_offset(IAT_RVA) + 4]
        .copy_from_slice(&HINT_NAME_RVA.to_le_bytes());
    rdata[rdata_offset(DLL_NAME_RVA)..rdata_offset(DLL_NAME_RVA) + 12]
        .copy_from_slice(b"kernel32.dll");
    // Hint 0 + "ExitProcess" NUL.
    rdata[rdata_offset(HINT_NAME_RVA) + 2..rdata_offset(HINT_NAME_RVA) + 13]
        .copy_from_slice(b"ExitProcess");

    let mut bytes = vec![0_u8; SIZE_OF_HEADERS as usize];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
    bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
    // COFF header.
    bytes[0x44..0x46].copy_from_slice(&0x014c_u16.to_le_bytes()); // i386
    bytes[0x46..0x48].copy_from_slice(&2_u16.to_le_bytes()); // sections
    bytes[0x48..0x4c].copy_from_slice(&0_u32.to_le_bytes()); // timestamp
    bytes[0x54..0x56].copy_from_slice(&0xe0_u16.to_le_bytes()); // optional size
    bytes[0x56..0x58].copy_from_slice(&0x0102_u16.to_le_bytes()); // EXECUTABLE_IMAGE | 32BIT
    // Optional header (PE32).
    let opt = 0x58;
    bytes[opt..opt + 2].copy_from_slice(&0x010b_u16.to_le_bytes());
    bytes[opt + 4..opt + 8].copy_from_slice(&FILE_ALIGN.to_le_bytes()); // SizeOfCode
    bytes[opt + 8..opt + 12].copy_from_slice(&FILE_ALIGN.to_le_bytes()); // SizeOfInitializedData
    bytes[opt + 16..opt + 20].copy_from_slice(&ENTRY_RVA.to_le_bytes());
    bytes[opt + 20..opt + 24].copy_from_slice(&ENTRY_RVA.to_le_bytes()); // BaseOfCode
    bytes[opt + 24..opt + 28].copy_from_slice(&RDATA_RVA.to_le_bytes()); // BaseOfData
    bytes[opt + 28..opt + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    bytes[opt + 32..opt + 36].copy_from_slice(&SECTION_ALIGN.to_le_bytes());
    bytes[opt + 36..opt + 40].copy_from_slice(&FILE_ALIGN.to_le_bytes());
    bytes[opt + 40..opt + 42].copy_from_slice(&6_u16.to_le_bytes()); // OS major
    bytes[opt + 48..opt + 50].copy_from_slice(&6_u16.to_le_bytes()); // subsystem major
    bytes[opt + 56..opt + 60].copy_from_slice(&0x3000_u32.to_le_bytes()); // SizeOfImage
    bytes[opt + 60..opt + 64].copy_from_slice(&SIZE_OF_HEADERS.to_le_bytes());
    bytes[opt + 68..opt + 70].copy_from_slice(&3_u16.to_le_bytes()); // CONSOLE
    bytes[opt + 72..opt + 76].copy_from_slice(&0x10_0000_u32.to_le_bytes()); // stack reserve
    bytes[opt + 76..opt + 80].copy_from_slice(&0x1000_u32.to_le_bytes()); // stack commit
    bytes[opt + 80..opt + 84].copy_from_slice(&0x10_0000_u32.to_le_bytes()); // heap reserve
    bytes[opt + 84..opt + 88].copy_from_slice(&0x1000_u32.to_le_bytes()); // heap commit
    bytes[opt + 92..opt + 96].copy_from_slice(&16_u32.to_le_bytes()); // NumberOfRvaAndSizes
    // DataDirectory[1] = import table (offset 0x60 + 8).
    bytes[opt + 0x68..opt + 0x6c].copy_from_slice(&IMPORT_DESCRIPTOR_RVA.to_le_bytes());
    bytes[opt + 0x6c..opt + 0x70].copy_from_slice(&IMPORT_DIRECTORY_SIZE.to_le_bytes());
    // Section headers.
    let section_table = 0x44 + 20 + 0xe0;
    let section = |name: &[u8; 8],
                   virtual_size: u32,
                   virtual_address: u32,
                   raw_size: u32,
                   raw_ptr: u32,
                   characteristics: u32,
                   at: usize,
                   bytes: &mut Vec<u8>| {
        bytes[at..at + 8].copy_from_slice(name);
        bytes[at + 8..at + 12].copy_from_slice(&virtual_size.to_le_bytes());
        bytes[at + 12..at + 16].copy_from_slice(&virtual_address.to_le_bytes());
        bytes[at + 16..at + 20].copy_from_slice(&raw_size.to_le_bytes());
        bytes[at + 20..at + 24].copy_from_slice(&raw_ptr.to_le_bytes());
        bytes[at + 36..at + 40].copy_from_slice(&characteristics.to_le_bytes());
    };
    section(
        b".text\0\0\0",
        FILE_ALIGN,
        ENTRY_RVA,
        FILE_ALIGN,
        SIZE_OF_HEADERS,
        0x6000_0020,
        section_table as usize,
        &mut bytes,
    );
    section(
        b".rdata\0\0",
        FILE_ALIGN,
        RDATA_RVA,
        FILE_ALIGN,
        SIZE_OF_HEADERS + FILE_ALIGN,
        0x4000_0040,
        section_table as usize + 40,
        &mut bytes,
    );
    bytes.extend_from_slice(&text);
    bytes.extend_from_slice(&rdata);
    (
        bytes,
        IMAGE_BASE as u64,
        (IMAGE_BASE + ENTRY_RVA) as u64,
        (IMAGE_BASE + SECOND_RVA) as u64,
    )
}

#[cfg(unix)]
pub(super) fn stage_guest_script(
    runtime: &PeHostRuntime,
    guest_path: &str,
    script: &str,
) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let host_program = runtime
        .win32
        .guest_path_to_host_path(guest_path)
        .expect("resolve guest script");
    std::fs::create_dir_all(host_program.parent().expect("script parent"))
        .expect("create script dirs");
    std::fs::write(&host_program, script).expect("write guest script");
    let mut permissions = std::fs::metadata(&host_program)
        .expect("script metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&host_program, permissions).expect("make script executable");
    host_program
}

// ── CertSelectCertificate: real certificate selection ────────────────
pub(super) fn build_test_cert_der(
    serial: u64,
    cn: &str,
    nb_offset: i64,
    na_offset: i64,
) -> Vec<u8> {
    use der::{Decode, Encode};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;
    use spki::SubjectPublicKeyInfoOwned;
    use std::str::FromStr;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};

    let mut rng = StdRng::seed_from_u64(0x51A7_0000 + serial);
    let key = RsaPrivateKey::new(&mut rng, 1024).expect("rsa key");
    let signer = SigningKey::<Sha256>::new(key.clone());
    let spki = SubjectPublicKeyInfoOwned::from_der(
        RsaPublicKey::from(&key)
            .to_public_key_der()
            .expect("spki der")
            .as_bytes(),
    )
    .expect("spki");
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock");
    let at = |offset: i64| -> SystemTime {
        if offset >= 0 {
            std::time::UNIX_EPOCH + now + std::time::Duration::from_secs(offset as u64)
        } else {
            std::time::UNIX_EPOCH + now - std::time::Duration::from_secs(offset.unsigned_abs())
        }
    };
    let validity = Validity {
        not_before: Time::try_from(at(nb_offset)).expect("notBefore"),
        not_after: Time::try_from(at(na_offset)).expect("notAfter"),
    };
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(serial as u32),
        validity,
        Name::from_str(&format!("CN={cn}")).expect("subject"),
        spki,
        &signer,
    )
    .expect("builder");
    builder.build().expect("certificate").to_der().expect("der")
}

pub(super) const SEL_X86_CSTORES: u64 = 40;

pub(super) const SEL_X86_RGHSTORES: u64 = 44;

pub(super) const SEL_X86_HSELECTED: u64 = 56;

pub(super) fn write_x86_select_request(
    memory: &mut MemoryImage,
    base: u64,
    stores: &[u64],
    display_stores: &[u64],
) {
    memory.map_bytes(base, &[0; 64]);
    write_u32(memory, base, 60); // dwSize
    write_u32(memory, base + SEL_X86_CSTORES, stores.len() as u32);
    if !stores.is_empty() {
        let array = base + 0x80;
        memory.map_bytes(array, &[0; 64]);
        for (index, store) in stores.iter().enumerate() {
            write_u32(memory, array + (index as u64 * 4), *store as u32);
        }
        write_u32(memory, base + SEL_X86_RGHSTORES, array as u32);
    }
    if !display_stores.is_empty() {
        let array = base + 0xC0;
        memory.map_bytes(array, &[0; 64]);
        for (index, store) in display_stores.iter().enumerate() {
            write_u32(memory, array + (index as u64 * 4), *store as u32);
        }
        write_u32(memory, base + 32, display_stores.len() as u32); // cDisplayStores
        write_u32(memory, base + 36, array as u32); // rghDisplayStores
    }
}

// ── IAudioClient / IAudioRenderClient — real method surface of an
//    activated audio endpoint ────────────────────────────────────────────
pub(super) const AUDIO_CLIENT_FMT_ADDR: u64 = 0x71_000;

pub(super) const AUDIO_CLIENT_OUT_ADDR: u64 = 0x72_000;

pub(super) const AUDIO_CLIENT_RIID_ADDR: u64 = 0x73_000;

pub(super) const AUDIO_CLIENT_HANDLER_OBJECT: u64 = 0x74_000;

pub(super) const AUDIO_CLIENT_HANDLER_VTABLE: u64 = 0x74_100;

pub(super) const AUDIO_CLIENT_HANDLER_STUB: u64 = 0x74_200;

pub(super) const AUDIO_CLIENT_OP_OUT: u64 = 0x75_000;

pub(super) fn audio_client_test_device() -> crate::real_audio::RealAudioDevice {
    crate::real_audio::RealAudioDevice {
        id: 1,
        key: "Casa1 Test Synth|2|48000".to_string(),
        name: "Casa1 Test Synth".to_string(),
        channels: 2,
        sample_rate: 48_000,
        is_default: true,
    }
}

pub(super) fn pcm16_wave_format_bytes(channels: u16, rate: u32) -> Vec<u8> {
    let block_align = channels * 2;
    let mut bytes = Vec::with_capacity(18);
    bytes.extend_from_slice(&crate::audio_activation::WAVE_FORMAT_PCM.to_le_bytes());
    bytes.extend_from_slice(&channels.to_le_bytes());
    bytes.extend_from_slice(&rate.to_le_bytes());
    bytes.extend_from_slice(&(rate * block_align as u32).to_le_bytes());
    bytes.extend_from_slice(&block_align.to_le_bytes());
    bytes.extend_from_slice(&16_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes
}

pub(super) fn audio_client_call(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    method: HostThunk,
    args: &[u32],
) -> u64 {
    let thunk = runtime.alloc_host_thunk(method);
    dispatch_x86_thunk(runtime, memory, thunk, args)
}

pub(super) fn initialized_audio_client_endpoint(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    rate: u32,
    duration_hns: u32,
    stream_flags: u32,
) -> (u64, u64, u32) {
    let device = audio_client_test_device();
    let endpoint = runtime
        .alloc_audio_client_endpoint(
            &mut *memory,
            &device,
            crate::audio_activation::IID_IAUDIO_CLIENT,
        )
        .expect("alloc endpoint");
    memory.map_bytes(
        AUDIO_CLIENT_FMT_ADDR,
        &pcm16_wave_format_bytes(device.channels, rate),
    );
    let hr = audio_client_call(
        runtime,
        memory,
        HostThunk::AudioClientInitialize,
        &[
            endpoint as u32,
            crate::audio_activation::AUDCLNT_SHAREMODE_SHARED,
            stream_flags,
            duration_hns,
            0,
            AUDIO_CLIENT_FMT_ADDR as u32,
            0,
        ],
    );
    assert_eq!(hr, 0, "Initialize succeeds for a real PCM16 format");
    let snapshot = crate::audio_activation::test_client_snapshot(runtime.guest_pid, endpoint)
        .expect("bound client state");
    assert!(snapshot.initialized);
    (endpoint, snapshot.buffer_address, snapshot.buffer_frames)
}

pub(super) fn install_audio_activation_handler(memory: &mut MemoryImage) {
    memory.map_bytes(0x44_000, &[0_u8; 12]);
    memory.map_bytes(AUDIO_CLIENT_HANDLER_OBJECT, &[0_u8; 8]);
    memory.map_bytes(AUDIO_CLIENT_HANDLER_VTABLE, &[0_u8; 16]);
    let mut stub = vec![0x90_u8; 0x40];
    stub[..27].copy_from_slice(&[
        0x8B, 0x44, 0x24, 0x08, // mov eax, [esp+8]   (operation object)
        0xA3, 0x04, 0x40, 0x04, 0x00, // mov [0x44004], eax
        0xA1, 0x08, 0x40, 0x04, 0x00, // mov eax, [0x44008] (count)
        0x05, 0x01, 0x00, 0x00, 0x00, // add eax, 1
        0xA3, 0x08, 0x40, 0x04, 0x00, // mov [0x44008], eax
        0x31, 0xC0, // xor eax, eax
        0xC3, // ret
    ]);
    memory.map_bytes(AUDIO_CLIENT_HANDLER_STUB, &stub);
    write_u32(
        memory,
        AUDIO_CLIENT_HANDLER_OBJECT,
        AUDIO_CLIENT_HANDLER_VTABLE as u32,
    );
    write_u32(
        memory,
        AUDIO_CLIENT_HANDLER_VTABLE + 12,
        AUDIO_CLIENT_HANDLER_STUB as u32,
    );
}

pub(super) fn real_default_device_available() -> bool {
    match crate::real_audio::RealAudioBackend::new() {
        Ok(backend) => backend
            .enumerate_devices()
            .iter()
            .any(|device| device.is_default),
        Err(error) => {
            eprintln!("audio activation test skipped: no audio services ({error})");
            false
        }
    }
}

pub(super) fn create_test_d3d12_device(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    stack: u64,
    out: u64,
) -> u64 {
    memory.map_bytes(stack, &vec![0u8; 0x400]);
    memory.map_bytes(out, &[0u8; 8]);
    let mut state = CpuState::new(GuestArch::X64);
    state.set(Register::Rsp, stack);
    state.set(Register::Rcx, 0);
    state.set(Register::Rdx, 0);
    state.set(Register::R8, 0);
    state.set(Register::R9, out);
    memory.write_u64(stack, 0x1000_0001);
    let thunk = runtime.alloc_host_thunk(HostThunk::D3D12CreateDevice);
    runtime
        .dispatch_import(thunk, &mut state, memory)
        .expect("dispatch D3D12CreateDevice");
    assert_eq!(state.get(Register::Rax), 0);
    memory.read_u64(out).expect("device object")
}

pub(super) fn create_test_d3d12_command_list(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    stack: u64,
    device: u64,
) -> u64 {
    memory.map_bytes(stack, &vec![0u8; 0x600]);
    let allocator_out = stack + 0x300;
    let list_out = stack + 0x308;
    memory.map_bytes(allocator_out, &[0u8; 8]);
    memory.map_bytes(list_out, &[0u8; 8]);
    let device_vtable = memory.read_u64(device).expect("device vtable");
    let create_allocator = memory
        .read_u64(device_vtable + 9 * 8)
        .expect("CreateCommandAllocator");
    let create_list = memory
        .read_u64(device_vtable + 12 * 8)
        .expect("CreateCommandList");
    let mut state = CpuState::new(GuestArch::X64);
    state.set(Register::Rsp, stack);
    state.set(Register::Rcx, device);
    state.set(Register::Rdx, 0);
    state.set(Register::R8, 0);
    state.set(Register::R9, allocator_out);
    memory.write_u64(stack, 0x1000_0002);
    runtime
        .dispatch_import(create_allocator, &mut state, memory)
        .expect("dispatch CreateCommandAllocator");
    assert_eq!(state.get(Register::Rax), 0);
    let allocator = memory.read_u64(allocator_out).expect("allocator");
    state.set(Register::Rsp, stack + 0x40);
    state.set(Register::Rcx, device);
    state.set(Register::Rdx, 0);
    state.set(Register::R8, 0);
    state.set(Register::R9, allocator);
    memory.write_u64(stack + 0x40, 0x1000_0003);
    memory.write_u64(stack + 0x40 + 0x28, 0);
    memory.write_u64(stack + 0x40 + 0x38, list_out);
    runtime
        .dispatch_import(create_list, &mut state, memory)
        .expect("dispatch CreateCommandList");
    assert_eq!(state.get(Register::Rax), 0);
    memory.read_u64(list_out).expect("command list")
}

pub(super) fn make_ray_dxil_container(kind: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"DXIL");
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&3u32.to_le_bytes());
    let descriptors_end = 12u32 + 3 * 12;
    let prog_off = descriptors_end;
    let prog_size: u32 = 24 + 4;
    data.extend_from_slice(b"PROG");
    data.extend_from_slice(&prog_off.to_le_bytes());
    data.extend_from_slice(&prog_size.to_le_bytes());
    let sign_off = prog_off + prog_size;
    data.extend_from_slice(b"SIGN");
    data.extend_from_slice(&sign_off.to_le_bytes());
    data.extend_from_slice(&4u32.to_le_bytes());
    let meta_text = format!("shader_kind={kind}\npayloadSizeInBytes=16\nattributeSizeInBytes=8\n");
    let meta_off = sign_off + 4;
    data.extend_from_slice(b"META");
    data.extend_from_slice(&meta_off.to_le_bytes());
    data.extend_from_slice(&((5 + meta_text.len()) as u32).to_le_bytes());
    while data.len() < prog_off as usize {
        data.push(0);
    }
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&64u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0x4243_C0DEu32.to_be_bytes());
    data.extend_from_slice(b"SIG1");
    data.push(4);
    data.extend_from_slice(b"main");
    data.extend_from_slice(meta_text.as_bytes());
    data
}

pub(super) fn make_test_dxil_container(instruction_count: u32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"DXIL");
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&3u32.to_le_bytes());
    let descriptors_end = 12u32 + 3 * 12;
    let prog_off = descriptors_end;
    let prog_size: u32 = 24 + 4;
    data.extend_from_slice(b"PROG");
    data.extend_from_slice(&prog_off.to_le_bytes());
    data.extend_from_slice(&prog_size.to_le_bytes());
    let sign_off = prog_off + prog_size;
    data.extend_from_slice(b"SIGN");
    data.extend_from_slice(&sign_off.to_le_bytes());
    data.extend_from_slice(&4u32.to_le_bytes());
    let meta_off = sign_off + 4;
    data.extend_from_slice(b"META");
    data.extend_from_slice(&meta_off.to_le_bytes());
    data.extend_from_slice(&5u32.to_le_bytes());
    while data.len() < prog_off as usize {
        data.push(0);
    }
    data.extend_from_slice(&instruction_count.to_le_bytes());
    data.extend_from_slice(&64u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0x4243_C0DEu32.to_be_bytes());
    data.extend_from_slice(b"SIG1");
    data.push(4);
    data.extend_from_slice(b"main");
    data
}

pub(super) fn build_raytracing_state_object_desc(
    memory: &mut MemoryImage,
    base: u64,
    export: &str,
) -> u64 {
    let desc = base;
    let subobjects = base + 0x100;
    let config = base + 0x200;
    let dxil = base + 0x210;
    let shader_config = base + 0x250;
    let pipeline_config = base + 0x258;
    let export_desc = base + 0x260;
    let bytecode = base + 0x1000;
    let export_name = base + 0x1100;
    write_u32(memory, desc, 3); // D3D12_STATE_OBJECT_TYPE_RAYTRACING_PIPELINE
    write_u32(memory, desc + 4, 4);
    write_u64(memory, desc + 8, subobjects);
    write_u32(memory, subobjects, 0); // STATE_OBJECT_CONFIG
    write_u64(memory, subobjects + 8, config);
    write_u32(memory, config, 0x4); // ALLOW_STATE_OBJECT_ADDITIONS
    write_u32(memory, subobjects + 16, 5); // DXIL_LIBRARY
    write_u64(memory, subobjects + 24, dxil);
    write_u64(memory, dxil, bytecode);
    write_u64(memory, dxil + 8, 4);
    write_u32(memory, dxil + 16, 1);
    write_u64(memory, dxil + 24, export_desc);
    for (index, byte) in [0x44u8, 0x58, 0x42, 0x43].iter().enumerate() {
        memory.write_u8(bytecode + index as u64, *byte);
    }
    for (index, unit) in export.encode_utf16().enumerate() {
        memory.write_u16(export_name + index as u64 * 2, unit);
    }
    write_u64(memory, export_desc, export_name);
    write_u64(memory, export_desc + 8, 0);
    write_u32(memory, export_desc + 16, 0);
    write_u32(memory, subobjects + 32, 9); // RAYTRACING_SHADER_CONFIG
    write_u64(memory, subobjects + 40, shader_config);
    write_u32(memory, shader_config, 16);
    write_u32(memory, shader_config + 4, 8);
    write_u32(memory, subobjects + 48, 10); // RAYTRACING_PIPELINE_CONFIG
    write_u64(memory, subobjects + 56, pipeline_config);
    write_u32(memory, pipeline_config, 1);
    desc
}

pub(super) fn build_work_graph_state_object_desc(memory: &mut MemoryImage, base: u64) -> u64 {
    let desc = base;
    let subobjects = base + 0x100;
    let graph = base + 0x200;
    let program_name = base + 0x1000;
    let entrypoint = base + 0x1100;
    let node_name = base + 0x1200;
    let node = base + 0x1300;
    write_u32(memory, desc, 4); // D3D12_STATE_OBJECT_TYPE_EXECUTABLE
    write_u32(memory, desc + 4, 1);
    write_u64(memory, desc + 8, subobjects);
    write_u32(memory, subobjects, 13); // D3D12_STATE_SUBOBJECT_TYPE_WORK_GRAPH
    write_u64(memory, subobjects + 8, graph);
    write_u64(memory, graph, program_name);
    write_u32(memory, graph + 8, 0);
    write_u32(memory, graph + 12, 1);
    write_u64(memory, graph + 16, entrypoint);
    write_u32(memory, graph + 24, 1);
    write_u64(memory, graph + 32, node);
    for (index, unit) in "graph".encode_utf16().enumerate() {
        memory.write_u16(program_name + index as u64 * 2, unit);
    }
    for (index, unit) in "node0".encode_utf16().enumerate() {
        memory.write_u16(node_name + index as u64 * 2, unit);
    }
    write_u64(memory, entrypoint, node_name);
    write_u32(memory, entrypoint + 8, 0);
    write_u32(memory, node, 0); // D3D12_NODE_TYPE_SHADER
    write_u64(memory, node + 8, node_name);
    write_u32(memory, node + 16, 0); // no overrides
    write_u64(memory, node + 24, 0);
    desc
}

pub(super) fn build_dml_identity_operator(memory: &mut MemoryImage, base: u64) -> u64 {
    let tensor = base;
    let buffer_desc = base + 0x40;
    let sizes = base + 0x80;
    let operator = base + 0x200;
    let payload = base + 0x240;
    write_u32(memory, tensor, 1); // DML_TENSOR_TYPE_BUFFER
    write_u64(memory, tensor + 8, buffer_desc);
    write_u32(memory, buffer_desc, 1); // FLOAT32
    write_u32(memory, buffer_desc + 4, 0);
    write_u32(memory, buffer_desc + 8, 4);
    write_u64(memory, buffer_desc + 16, sizes);
    write_u64(memory, buffer_desc + 24, 0);
    write_u64(memory, buffer_desc + 32, 8);
    write_u32(memory, buffer_desc + 40, 0);
    for (index, size) in [2u32, 1, 1, 1].iter().enumerate() {
        write_u32(memory, sizes + index as u64 * 4, *size);
    }
    write_u32(memory, operator, 1); // DML_OPERATOR_ELEMENT_WISE_IDENTITY
    write_u64(memory, operator + 8, payload);
    write_u64(memory, payload, tensor);
    write_u64(memory, payload + 8, tensor);
    operator
}

pub(super) fn runtime_read_u32(memory: &MemoryImage, address: u64) -> u32 {
    let bytes = memory.read_bytes(address, 4).expect("read u32");
    u32::from_le_bytes(bytes.try_into().expect("4 bytes"))
}

pub(super) fn serial_dispatch_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(super) fn install_serial_dispatch_fixture(
    runtime: &mut PeHostRuntime,
    id: u64,
    path: &str,
) -> crate::real_hid::StableDeviceId {
    let info = crate::real_hid::SerialDeviceInfo {
        id: crate::real_hid::StableDeviceId::from_raw(id),
        registry_entry_id: id,
        callout_path: path.to_string(),
        dialin_path: Some(path.replace("/dev/cu.", "/dev/tty.")),
        tty_device: Some(format!("tty-{id:016x}")),
        base_name: Some(format!("base-{id:016x}")),
        client_type: Some("IOSerialBSDClientType".to_string()),
    };
    runtime
        .user32
        .physical_devices_mut()
        .serial_mut()
        .apply(vec![info.clone()]);
    runtime.user32.sync_device_handles();
    info.id
}

pub(super) fn install_usb_dispatch_fixture(
    runtime: &mut PeHostRuntime,
) -> crate::real_hid::StableDeviceId {
    let info = crate::real_hid::UsbDeviceInfo {
        id: crate::real_hid::StableDeviceId::from_raw(0x202),
        registry_entry_id: 0x202,
        descriptor: crate::real_hid::UsbDeviceDescriptor {
            vendor_id: 0x1234,
            product_id: 0x5678,
            bcd_device: 0x0100,
            class: 0,
            subclass: 0,
            protocol: 0,
            max_packet_size0: 64,
            num_configurations: 1,
        },
        manufacturer: Some("Fixture".to_string()),
        product: Some("USB Fixture".to_string()),
        serial_number: None,
        vendor_string: None,
        location_id: None,
        current_configuration: Some(1),
        configurations: vec![crate::real_hid::UsbConfigurationDescriptor {
            value: 1,
            attributes: 0x80,
            max_power_ma: 100,
            interfaces: vec![crate::real_hid::UsbInterfaceDescriptor {
                number: 0,
                alternate_setting: 0,
                class: 3,
                subclass: 0,
                protocol: 0,
                endpoints: vec![crate::real_hid::UsbEndpointDescriptor {
                    address: 0x81,
                    number: 1,
                    direction: crate::real_hid::UsbDirection::In,
                    transfer_type: crate::real_hid::UsbTransferType::Interrupt,
                    attributes: 3,
                    max_packet_size: 8,
                    interval: 10,
                }],
            }],
        }],
        raw_configuration_descriptors: Vec::new(),
    };
    runtime
        .user32
        .physical_devices_mut()
        .usb_mut()
        .apply(vec![info.clone()]);
    runtime.user32.sync_device_handles();
    info.id
}
