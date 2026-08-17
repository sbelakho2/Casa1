//! Extended Criterion benchmarks for the Casa1 performance infrastructure.
//!
//! Covers 5 categories:
//! 1. CPU Engine Throughput — decode, lower-to-IR, and execute pipelines
//! 2. JIT Cache Optimization — compile tiers, constant folding, inline cache
//! 3. PE Loading — parse, section enumeration, import resolution
//! 4. Graphics Pipeline — command batching, shader compiler, upload streaming
//! 5. Startup-to-First-Frame — composite pipeline benchmark

use criterion::{Criterion, criterion_group, criterion_main};
use std::collections::BTreeMap;
use std::hint::black_box as bb;

// ---------------------------------------------------------------------------
// Helpers – synthetic x86-64 byte sequences
// ---------------------------------------------------------------------------

/// Build a block of NOP instructions (`0x90`, 1 byte each).
fn nop_sled(count: usize) -> Vec<u8> {
    vec![0x90u8; count]
}

/// Build a block of `MOV EAX, imm32` instructions (5 bytes each:
/// `0xB8` + 4-byte little-endian immediate).
fn mov_eax_block(count: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(count * 5);
    for i in 0..count {
        bytes.push(0xB8);
        bytes.extend_from_slice(&(i as u32).to_le_bytes());
    }
    bytes
}

/// Build a block that creates dead register assignments for DCE stress.
/// Each triplet: `MOV EAX, imm32` (5) + `MOV EAX, imm32` (5) + `MOV EBX, EAX` (2).
/// The first MOV EAX is dead because EAX is immediately overwritten.
fn dead_eax_block(count: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(count * 12);
    for i in 0..count {
        // MOV EAX, imm32  (will be dead — immediately overwritten)
        bytes.push(0xB8);
        bytes.extend_from_slice(&(i as u32).to_le_bytes());
        // MOV EAX, imm32  (overwrites — keeps this one live)
        bytes.push(0xB8);
        bytes.extend_from_slice(&((i + 1) as u32).to_le_bytes());
        // MOV EBX, EAX   (reads EAX — makes second write live)
        bytes.push(0x89);
        bytes.push(0xC3);
    }
    bytes
}

/// Build a mixed ALU block: MOV EAX/EBX pairs followed by ADD EAX, EBX.
/// Each triplet = MOV EAX (5) + MOV EBX (5) + ADD EAX,EBX (2) = 12 bytes.
fn alu_mix_block(count: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(count * 12);
    for i in 0..count {
        // MOV EAX, imm32
        bytes.push(0xB8);
        bytes.extend_from_slice(&(i as u32).to_le_bytes());
        // MOV EBX, imm32
        bytes.push(0xBB);
        bytes.extend_from_slice(&((i + 1) as u32).to_le_bytes());
        // ADD EAX, EBX (01 D8)
        bytes.push(0x01);
        bytes.push(0xD8);
    }
    bytes
}

/// Build a block with control-flow: CMP + JE (6 bytes each:
/// `3D imm32` + `74 00` — JE to next instruction).
fn cmp_jcc_block(count: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(count * 6);
    for i in 0..count {
        // CMP EAX, imm32 (3D xx xx xx xx)
        bytes.push(0x3D);
        bytes.extend_from_slice(&(i as u32).to_le_bytes());
        // JE rel8 = 0 (jump to next instruction, effectively a NOP-like skip)
        bytes.push(0x74);
        bytes.push(0x00);
    }
    bytes
}

/// Build a block of simple SSE SIMD instructions:
/// MOVUPS XMM0, XMM1 (3 bytes: 0F 10 C1) + MOVUPS XMM1, XMM0 (3 bytes: 0F 10 C8)
/// (register-form MOVUPS is the SSE path supported by the decoder)
fn simd_block(count: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(count * 6);
    for _ in 0..count {
        bytes.extend_from_slice(&[0x0F, 0x10, 0xC1]); // MOVUPS XMM0, XMM1
        bytes.extend_from_slice(&[0x0F, 0x10, 0xC8]); // MOVUPS XMM1, XMM0
    }
    bytes
}

// ---------------------------------------------------------------------------
// Helpers – synthetic PE construction
// ---------------------------------------------------------------------------

/// Build a minimal but valid Portable Executable in memory.
/// Returns the raw PE bytes suitable for `casa1::pe::parse()`.
fn minimal_pe() -> Vec<u8> {
    // DOS header (64 bytes)
    let mut dos = vec![0u8; 64];
    dos[0..2].copy_from_slice(b"MZ");
    // e_lfanew = offset to PE signature (at offset 0x80)
    let e_lfanew: u32 = 0x80;
    dos[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    // Pad to PE signature offset
    let mut pe = dos;
    pe.resize(0x80, 0);

    // PE signature "PE\0\0"
    pe.extend_from_slice(b"PE\0\0");

    // COFF header (20 bytes)
    let machine: u16 = 0x8664; // IMAGE_FILE_MACHINE_AMD64
    let number_of_sections: u16 = 1;
    let time_date_stamp: u32 = 0;
    let pointer_to_symbol_table: u32 = 0;
    let number_of_symbols: u32 = 0;
    let size_of_optional_header: u16 = 0xF0; // standard + Dirs (16 entries)
    let characteristics: u16 = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    pe.extend_from_slice(&machine.to_le_bytes());
    pe.extend_from_slice(&number_of_sections.to_le_bytes());
    pe.extend_from_slice(&time_date_stamp.to_le_bytes());
    pe.extend_from_slice(&pointer_to_symbol_table.to_le_bytes());
    pe.extend_from_slice(&number_of_symbols.to_le_bytes());
    pe.extend_from_slice(&size_of_optional_header.to_le_bytes());
    pe.extend_from_slice(&characteristics.to_le_bytes());

    // Optional header (0xF0 bytes = 240)
    let magic: u16 = 0x020B; // PE32+
    pe.extend_from_slice(&magic.to_le_bytes());

    // Standard fields (PE32+):
    let major_linker_version: u8 = 14;
    let minor_linker_version: u8 = 0;
    let size_of_code: u32 = 0x200;
    let size_of_initialized_data: u32 = 0;
    let size_of_uninitialized_data: u32 = 0;
    let address_of_entry_point: u32 = 0x1000;
    let base_of_code: u32 = 0x1000;

    pe.push(major_linker_version);
    pe.push(minor_linker_version);
    pe.extend_from_slice(&size_of_code.to_le_bytes());
    pe.extend_from_slice(&size_of_initialized_data.to_le_bytes());
    pe.extend_from_slice(&size_of_uninitialized_data.to_le_bytes());
    pe.extend_from_slice(&address_of_entry_point.to_le_bytes());
    pe.extend_from_slice(&base_of_code.to_le_bytes());

    // Windows fields (PE32+):
    let image_base: u64 = 0x140000000;
    let section_alignment: u32 = 0x1000;
    let file_alignment: u32 = 0x200;
    let major_os_version: u16 = 6;
    let minor_os_version: u16 = 0;
    let major_image_version: u16 = 0;
    let minor_image_version: u16 = 0;
    let major_subsystem_version: u16 = 6;
    let minor_subsystem_version: u16 = 0;
    let win32_version_value: u32 = 0;
    let size_of_image: u32 = 0x2000;
    let size_of_headers: u32 = 0x200;
    let check_sum: u32 = 0;
    let subsystem: u16 = 2; // IMAGE_SUBSYSTEM_WINDOWS_GUI
    let dll_characteristics: u16 = 0;
    let size_of_stack_reserve: u64 = 0x100000;
    let size_of_stack_commit: u64 = 0x1000;
    let size_of_heap_reserve: u64 = 0x100000;
    let size_of_heap_commit: u64 = 0x1000;
    let loader_flags: u32 = 0;
    let number_of_rva_and_sizes: u32 = 16;

    pe.extend_from_slice(&image_base.to_le_bytes());
    pe.extend_from_slice(&section_alignment.to_le_bytes());
    pe.extend_from_slice(&file_alignment.to_le_bytes());
    pe.extend_from_slice(&major_os_version.to_le_bytes());
    pe.extend_from_slice(&minor_os_version.to_le_bytes());
    pe.extend_from_slice(&major_image_version.to_le_bytes());
    pe.extend_from_slice(&minor_image_version.to_le_bytes());
    pe.extend_from_slice(&major_subsystem_version.to_le_bytes());
    pe.extend_from_slice(&minor_subsystem_version.to_le_bytes());
    pe.extend_from_slice(&win32_version_value.to_le_bytes());
    pe.extend_from_slice(&size_of_image.to_le_bytes());
    pe.extend_from_slice(&size_of_headers.to_le_bytes());
    pe.extend_from_slice(&check_sum.to_le_bytes());
    pe.extend_from_slice(&subsystem.to_le_bytes());
    pe.extend_from_slice(&dll_characteristics.to_le_bytes());
    pe.extend_from_slice(&size_of_stack_reserve.to_le_bytes());
    pe.extend_from_slice(&size_of_stack_commit.to_le_bytes());
    pe.extend_from_slice(&size_of_heap_reserve.to_le_bytes());
    pe.extend_from_slice(&size_of_heap_commit.to_le_bytes());
    pe.extend_from_slice(&loader_flags.to_le_bytes());
    pe.extend_from_slice(&number_of_rva_and_sizes.to_le_bytes());

    // Data directory entries (16 × 8 bytes = 128 bytes) — all empty
    for _ in 0..16 {
        pe.extend_from_slice(&0u32.to_le_bytes()); // VirtualAddress
        pe.extend_from_slice(&0u32.to_le_bytes()); // Size
    }

    // Section table: one .text section
    let section_name: &[u8; 8] = b".text\0\0\0";
    pe.extend_from_slice(section_name);
    let virtual_size: u32 = 0x1000;
    let virtual_address: u32 = 0x1000;
    let size_of_raw_data: u32 = 0x200;
    let pointer_to_raw_data: u32 = 0x200;
    let pointer_to_relocations: u32 = 0;
    let pointer_to_linenumbers: u32 = 0;
    let number_of_relocations: u16 = 0;
    let number_of_linenumbers: u16 = 0;
    let section_characteristics: u32 = 0x60000020; // CODE | EXECUTE | READ

    pe.extend_from_slice(&virtual_size.to_le_bytes());
    pe.extend_from_slice(&virtual_address.to_le_bytes());
    pe.extend_from_slice(&size_of_raw_data.to_le_bytes());
    pe.extend_from_slice(&pointer_to_raw_data.to_le_bytes());
    pe.extend_from_slice(&pointer_to_relocations.to_le_bytes());
    pe.extend_from_slice(&pointer_to_linenumbers.to_le_bytes());
    pe.extend_from_slice(&number_of_relocations.to_le_bytes());
    pe.extend_from_slice(&number_of_linenumbers.to_le_bytes());
    pe.extend_from_slice(&section_characteristics.to_le_bytes());

    // Raw section data (pad to 0x200 for file alignment)
    pe.resize(0x200, 0);
    // Add some minimal .text content (NOP sled)
    pe.extend_from_slice(&[0x90u8; 0x200]);
    pe.resize(0x400, 0);

    pe
}

/// Write a complete PE32+ optional header: 112 bytes of standard/windows
/// fields plus 16 data directories (128 bytes) = 240 bytes = 0xF0, exactly
/// matching the declared `size_of_optional_header`.
fn write_pe32p_optional_header(
    pe: &mut Vec<u8>,
    entry_point: u32,
    size_of_image: u32,
    size_of_headers: u32,
    directories: &[(u32, u32)],
) {
    pe.extend_from_slice(&0x020Bu16.to_le_bytes()); // PE32+ magic
    pe.push(14); // major linker version
    pe.push(0); // minor linker version
    pe.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfCode
    pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
    pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
    pe.extend_from_slice(&entry_point.to_le_bytes());
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
    pe.extend_from_slice(&0x0001_4000_0000u64.to_le_bytes()); // ImageBase
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    pe.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    pe.extend_from_slice(&6u16.to_le_bytes()); // MajorOSVersion
    pe.extend_from_slice(&0u16.to_le_bytes()); // MinorOSVersion
    pe.extend_from_slice(&0u16.to_le_bytes()); // MajorImageVersion
    pe.extend_from_slice(&0u16.to_le_bytes()); // MinorImageVersion
    pe.extend_from_slice(&6u16.to_le_bytes()); // MajorSubsystemVersion
    pe.extend_from_slice(&0u16.to_le_bytes()); // MinorSubsystemVersion
    pe.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
    pe.extend_from_slice(&size_of_image.to_le_bytes());
    pe.extend_from_slice(&size_of_headers.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes()); // Checksum
    pe.extend_from_slice(&2u16.to_le_bytes()); // Subsystem: WINDOWS_GUI
    pe.extend_from_slice(&0u16.to_le_bytes()); // DllCharacteristics
    pe.extend_from_slice(&0x100_000u64.to_le_bytes()); // SizeOfStackReserve
    pe.extend_from_slice(&0x1000u64.to_le_bytes()); // SizeOfStackCommit
    pe.extend_from_slice(&0x100_000u64.to_le_bytes()); // SizeOfHeapReserve
    pe.extend_from_slice(&0x1000u64.to_le_bytes()); // SizeOfHeapCommit
    pe.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
    pe.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
    for index in 0..16 {
        let (rva, size) = directories.get(index).copied().unwrap_or((0, 0));
        pe.extend_from_slice(&rva.to_le_bytes());
        pe.extend_from_slice(&size.to_le_bytes());
    }
}

/// Append a 40-byte IMAGE_SECTION_HEADER.
fn write_pe_section(
    pe: &mut Vec<u8>,
    name: &[u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    raw_data_size: u32,
    raw_data_ptr: u32,
) {
    pe.extend_from_slice(name);
    pe.extend_from_slice(&virtual_size.to_le_bytes());
    pe.extend_from_slice(&virtual_address.to_le_bytes());
    pe.extend_from_slice(&raw_data_size.to_le_bytes());
    pe.extend_from_slice(&raw_data_ptr.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes()); // relocs ptr
    pe.extend_from_slice(&0u32.to_le_bytes()); // linenumbers ptr
    pe.extend_from_slice(&0u16.to_le_bytes()); // num relocs
    pe.extend_from_slice(&0u16.to_le_bytes()); // num linenumbers
    pe.extend_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE | EXECUTE | READ
}

/// Build a PE with many (empty) sections to stress section-table parsing.
/// Writes the full PE32+ optional header (0xF0) so the section table sits
/// exactly where the parser expects it (optional header + declared size).
fn many_sections_pe(count: usize) -> Vec<u8> {
    let count = count.min(100); // reasonable upper bound
    // DOS header (64 bytes) + e_lfanew
    let mut dos = vec![0u8; 64];
    dos[0..2].copy_from_slice(b"MZ");
    let e_lfanew: u32 = 0x80;
    dos[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    let mut pe = dos;
    pe.resize(0x80, 0);
    pe.extend_from_slice(b"PE\0\0");

    let machine: u16 = 0x8664;
    let number_of_sections: u16 = count as u16;
    pe.extend_from_slice(&machine.to_le_bytes());
    pe.extend_from_slice(&number_of_sections.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes()); // timedatestamp
    pe.extend_from_slice(&0u32.to_le_bytes()); // ptr to symbols
    pe.extend_from_slice(&0u32.to_le_bytes()); // num symbols
    let size_of_optional_header: u16 = 0xF0;
    pe.extend_from_slice(&size_of_optional_header.to_le_bytes());
    pe.extend_from_slice(&0x0022u16.to_le_bytes()); // characteristics

    // Section table starts at 0x80 + 4 + 20 + 0xF0 = 0x188
    let section_table_start = 0x80 + 4 + 20 + 0xF0;
    let headers_size = (section_table_start + count * 40 + 0x1FF) & !0x1FF;
    let size_of_image = 0x1000 * (count as u32 + 2);
    write_pe32p_optional_header(&mut pe, 0x1000, size_of_image, headers_size as u32, &[]);
    debug_assert_eq!(
        pe.len(),
        section_table_start,
        "optional header must be exactly 0xF0 bytes"
    );

    // Section table entries
    for i in 0..count {
        let name = format!(".sec{i:03}\0");
        let name_bytes = name.as_bytes();
        let mut section_name = [0u8; 8];
        section_name[..name_bytes.len().min(8)]
            .copy_from_slice(&name_bytes[..name_bytes.len().min(8)]);
        write_pe_section(
            &mut pe,
            &section_name,
            0x1000,                       // virtual size
            0x1000 + (i as u32 * 0x1000), // VA
            0x200,                        // raw data size
            0x200,                        // raw data ptr
        );
    }
    pe.resize(headers_size, 0);
    // Raw data for the sections (all point at 0x200)
    pe.extend_from_slice(&[0x90u8; 0x200]);
    pe
}

// ===========================================================================
// 1.  CPU ENGINE THROUGHPUT BENCHMARKS
// ===========================================================================

fn bench_cpu_decode_nop(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("cpu/decode/nop");
    for size in [64usize, 256, 1024] {
        let code = nop_sled(size);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode nop sled");
        assert_eq!(
            decoded.len(),
            size,
            "NOP decode must yield one instruction per byte"
        );
        group.bench_function(format!("{size}_bytes"), |b| {
            b.iter(|| {
                let decoded = casa1::cpu::decode_block(bb(&code), bb(0x1000), bb(arch))
                    .expect("decode nop sled");
                bb(decoded)
            })
        });
    }
    group.finish();
}

fn bench_cpu_decode_alu(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("cpu/decode/alu");
    for count in [10usize, 50, 200] {
        let code = alu_mix_block(count);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode alu block");
        assert_eq!(
            decoded.len(),
            count * 3,
            "ALU block is 3 instructions per triplet"
        );
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter(|| {
                let decoded = casa1::cpu::decode_block(bb(&code), bb(0x1000), bb(arch))
                    .expect("decode alu block");
                bb(decoded)
            })
        });
    }
    group.finish();
}

fn bench_cpu_decode_simd(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("cpu/decode/simd");
    for count in [10usize, 50, 200] {
        let code = simd_block(count);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode simd block");
        assert_eq!(
            decoded.len(),
            count * 2,
            "SIMD block is 2 instructions per pair"
        );
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter(|| {
                let decoded = casa1::cpu::decode_block(bb(&code), bb(0x1000), bb(arch))
                    .expect("decode simd block");
                bb(decoded)
            })
        });
    }
    group.finish();
}

fn bench_cpu_decode_control_flow(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("cpu/decode/control_flow");
    for count in [10usize, 50, 200] {
        let code = cmp_jcc_block(count);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode cmp/jcc block");
        assert_eq!(
            decoded.len(),
            count * 2,
            "cmp/jcc block is 2 instructions per pair"
        );
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter(|| {
                let decoded = casa1::cpu::decode_block(bb(&code), bb(0x1000), bb(arch))
                    .expect("decode cmp/jcc block");
                bb(decoded)
            })
        });
    }
    group.finish();
}

fn bench_cpu_lower_to_ir(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("cpu/lower_to_ir");
    for count in [10usize, 50, 200] {
        let code = alu_mix_block(count);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode");
        let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower");
        assert_eq!(
            ir.len(),
            decoded.len(),
            "lowering must preserve instruction count"
        );
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter(|| {
                let ir = casa1::cpu::lower_to_ir(bb(&decoded)).expect("lower");
                bb(ir)
            })
        });
    }
    group.finish();
}

fn bench_cpu_full_pipeline(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let engine = casa1::cpu::CpuExecutionEngine::new(casa1::cpu::CpuEngineConfig {
        arch,
        os_build: "bench".into(),
        macwin_version: "0.0.0".into(),
        virtualization: casa1::cpu::CpuVirtualization::from_profile(arch, None).unwrap(),
    });
    let mut group = c.benchmark_group("cpu/full_pipeline");
    for count in [10usize, 50, 200] {
        let code = alu_mix_block(count);
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter_with_setup(
                || {
                    // Fresh state + memory for each iteration
                    let state = casa1::cpu::CpuState::new(arch);
                    let memory = casa1::cpu::MemoryImage::default();
                    // Decode + lower once, reuse IR across iterations
                    let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode");
                    let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower");
                    (state, memory, ir)
                },
                |(mut state, mut memory, ir)| {
                    let result = engine
                        .execute_ir(bb(&mut state), bb(&mut memory), bb(&ir))
                        .expect("execute");
                    bb(result)
                },
            )
        });
    }
    group.finish();
}

// ===========================================================================
// 2.  JIT CACHE OPTIMISATION BENCHMARKS
// ===========================================================================

fn bench_jit_compile_tier0(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("jit/compile/tier0");
    for count in [10usize, 50, 200] {
        let code = alu_mix_block(count);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode");
        let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower");
        let mut probe = casa1::jit::JitCompiler::new();
        let compiled = probe
            .compile_tier0(&ir, 0x1000, arch, None)
            .expect("compile tier0");
        assert!(compiled.code_size > 0, "tier0 must emit code");
        assert_eq!(compiled.instruction_count, ir.len());
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter_with_setup(casa1::jit::JitCompiler::new, |mut compiler| {
                let result = compiler
                    .compile_tier0(bb(&ir), bb(0x1000), bb(arch), bb(None))
                    .expect("compile tier0");
                bb(result)
            })
        });
    }
    group.finish();
}

fn bench_jit_compile_tier1(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("jit/compile/tier1");
    for count in [10usize, 50, 200] {
        let code = alu_mix_block(count);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode");
        let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower");
        let mut probe = casa1::jit::JitCompiler::new();
        let compiled = probe
            .compile_tier1(&ir, 0x1000, arch, None)
            .expect("compile tier1");
        assert!(compiled.code_size > 0, "tier1 must emit code");
        assert_eq!(compiled.instruction_count, ir.len());
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter_with_setup(casa1::jit::JitCompiler::new, |mut compiler| {
                let result = compiler
                    .compile_tier1(bb(&ir), bb(0x1000), bb(arch), bb(None))
                    .expect("compile tier1");
                bb(result)
            })
        });
    }
    group.finish();
}

fn bench_jit_compile_tier2(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("jit/compile/tier2");
    for count in [10usize, 50, 200] {
        let code = alu_mix_block(count);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode");
        let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower");
        let mut probe = casa1::jit::JitCompiler::new();
        let compiled = probe
            .compile_tier2(&ir, 0x1000, arch, None)
            .expect("compile tier2");
        assert!(compiled.code_size > 0, "tier2 must emit code");
        assert_eq!(compiled.instruction_count, ir.len());
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter_with_setup(casa1::jit::JitCompiler::new, |mut compiler| {
                let result = compiler
                    .compile_tier2(bb(&ir), bb(0x1000), bb(arch), bb(None))
                    .expect("compile tier2");
                bb(result)
            })
        });
    }
    group.finish();
}

fn bench_jit_constant_folding(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("jit/optimiser/constant_fold");
    for count in [10usize, 100, 500] {
        // MOV EAX, imm32 chains — each successive MOV EAX overwrites the
        // previous one; constant folding collapses the chain to the final
        // write (dead-assignment elimination would not shrink it further).
        let code = mov_eax_block(count);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode");
        let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower");
        // Prove the tier1 optimizer actually ran: compiled output must be
        // strictly smaller than the unoptimised tier0 output for the same IR.
        let mut tier0_probe = casa1::jit::JitCompiler::new();
        let mut tier1_probe = casa1::jit::JitCompiler::new();
        let t0 = tier0_probe
            .compile_tier0(&ir, 0x1000, arch, None)
            .expect("compile tier0");
        let t1 = tier1_probe
            .compile_tier1(&ir, 0x1000, arch, None)
            .expect("compile tier1");
        assert!(
            t1.code_size < t0.code_size,
            "constant folding did not reduce code size (tier0={}, tier1={})",
            t0.code_size,
            t1.code_size
        );
        group.bench_function(format!("tier1_{count}_insns"), |b| {
            b.iter_with_setup(casa1::jit::JitCompiler::new, |mut compiler| {
                let result = compiler
                    .compile_tier1(bb(&ir), bb(0x1000), bb(arch), bb(None))
                    .expect("compile tier1");
                bb(result)
            })
        });
    }
    group.finish();
}

fn bench_jit_dead_code_elimination(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("jit/optimiser/dce");
    for count in [10usize, 100, 500] {
        // Each triplet has a dead MOV EAX that is immediately overwritten —
        // DCE eliminates the first assignment (dead-assignment elimination).
        let code = dead_eax_block(count);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode");
        let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower");
        // Prove the DCE pass actually ran: tier1 output must be strictly
        // smaller than tier0 output for the same IR.
        let mut tier0_probe = casa1::jit::JitCompiler::new();
        let mut tier1_probe = casa1::jit::JitCompiler::new();
        let t0 = tier0_probe
            .compile_tier0(&ir, 0x1000, arch, None)
            .expect("compile tier0");
        let t1 = tier1_probe
            .compile_tier1(&ir, 0x1000, arch, None)
            .expect("compile tier1");
        assert!(
            t1.code_size < t0.code_size,
            "DCE did not reduce code size (tier0={}, tier1={})",
            t0.code_size,
            t1.code_size
        );
        group.bench_function(format!("tier1_{count}_insns"), |b| {
            b.iter_with_setup(casa1::jit::JitCompiler::new, |mut compiler| {
                let result = compiler
                    .compile_tier1(bb(&ir), bb(0x1000), bb(arch), bb(None))
                    .expect("compile tier1");
                bb(result)
            })
        });
    }
    group.finish();
}

fn bench_jit_tier_promotion(c: &mut Criterion) {
    let mut group = c.benchmark_group("jit/tier_promotion");
    let mut compiler = casa1::jit::TieredCompiler::with_thresholds(10, 50);

    // Prove the promotion policy: the 10th execution promotes to Tier1 and
    // the 50th to Tier2.
    let mut probe = casa1::jit::TieredCompiler::with_thresholds(10, 50);
    let mut tier1_at = None;
    let mut tier2_at = None;
    for exec in 1..=60 {
        let tier = probe.record_execution(0x1000);
        if tier == Some(casa1::jit::CompilationTier::Tier1) && tier1_at.is_none() {
            tier1_at = Some(exec);
        }
        if tier == Some(casa1::jit::CompilationTier::Tier2) && tier2_at.is_none() {
            tier2_at = Some(exec);
        }
    }
    assert_eq!(
        tier1_at,
        Some(10),
        "Tier1 promotion must occur at 10 executions"
    );
    assert_eq!(
        tier2_at,
        Some(50),
        "Tier2 promotion must occur at 50 executions"
    );

    group.bench_function("100_blocks_x_100_execs", |b| {
        b.iter(|| {
            for i in 0..100 {
                let addr = 0x1000 + (i as u64 * 0x100);
                for _ in 0..100 {
                    let _tier = compiler.record_execution(bb(addr));
                }
                assert_eq!(
                    compiler.get_tier(addr),
                    casa1::jit::CompilationTier::Tier2,
                    "block {addr:#x} must reach Tier2 after 100 executions"
                );
            }
            bb(())
        })
    });
    group.finish();
}

fn bench_jit_inline_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("jit/inline_cache");
    for max_entries in [16usize, 64, 256] {
        group.bench_function(format!("{max_entries}_entries"), |b| {
            let mut ic = casa1::jit::InlineCache::new(max_entries);
            let mut iter_count: u64 = 0;
            b.iter(|| {
                // Phase 1: a distinct stream of call sites (misses that insert).
                // Phase 2: re-lookup the same sites — every lookup must hit.
                // With one insert and one hit per site per iteration the hit
                // rate is exactly 0.5, well above the asserted floor.
                let base = (iter_count % 4) * max_entries as u64;
                iter_count += 1;
                for i in 0..max_entries {
                    let call_site = 0x10_0000 + (base + i as u64) * 0x40;
                    let target = 0x9000_0000 + i as u64;
                    let hit = ic.lookup(bb(call_site), bb(target));
                    bb(hit);
                }
                for i in 0..max_entries {
                    let call_site = 0x10_0000 + (base + i as u64) * 0x40;
                    let target = 0x9000_0000 + i as u64;
                    assert!(
                        ic.lookup(bb(call_site), bb(target)),
                        "repeated call site lookup must hit"
                    );
                }
                let rate = ic.hit_rate();
                assert!(rate >= 0.5, "hit rate {rate} below 0.5");
                bb(rate)
            })
        });
    }
    group.finish();
}

// ===========================================================================
// 3.  PE LOADING BENCHMARKS
// ===========================================================================

fn bench_pe_parse_minimal(c: &mut Criterion) {
    let mut group = c.benchmark_group("pe/parse/minimal");
    let pe_data = minimal_pe();
    let parsed = casa1::pe::parse(&pe_data).expect("minimal PE must parse");
    assert_eq!(parsed.sections.len(), 1);

    group.bench_function("parse", |b| {
        b.iter(|| {
            let parsed = casa1::pe::parse(bb(&pe_data)).expect("parse");
            bb(parsed)
        })
    });
    group.finish();
}

fn bench_pe_parse_many_sections(c: &mut Criterion) {
    let mut group = c.benchmark_group("pe/parse/many_sections");
    for count in [5usize, 20, 100] {
        let pe_data = many_sections_pe(count);
        let parsed = casa1::pe::parse(&pe_data).expect("many-sections PE must parse");
        assert_eq!(
            parsed.sections.len(),
            count,
            "parsed section count mismatch"
        );
        group.bench_function(format!("{count}_sections"), |b| {
            b.iter(|| {
                let parsed = casa1::pe::parse(bb(&pe_data)).expect("parse");
                bb(parsed)
            })
        });
    }
    group.finish();
}

fn bench_pe_parse_and_map(c: &mut Criterion) {
    let mut group = c.benchmark_group("pe/parse_and_map");
    let pe_data = minimal_pe();
    let parsed = casa1::pe::parse(&pe_data).expect("parse");
    let mapped = casa1::pe::map_image(&pe_data, &parsed, "bench", false).expect("map");
    assert!(!mapped.sections.is_empty());

    group.bench_function("parse_then_map", |b| {
        b.iter_with_setup(
            || casa1::pe::parse(&pe_data).expect("parse"),
            |parsed| {
                let mapped = casa1::pe::map_image(bb(&pe_data), bb(&parsed), "bench", bb(false))
                    .expect("map");
                bb(mapped)
            },
        )
    });
    group.finish();
}

// ===========================================================================
// 4.  GRAPHICS PIPELINE BENCHMARKS
// ===========================================================================

fn bench_gfx_command_batching(c: &mut Criterion) {
    use casa1::perf::MetalCommandBatcher;

    let mut group = c.benchmark_group("gfx/command_batcher");
    for max_batch in [32usize, 128, 512] {
        group.bench_function(format!("max_batch_{max_batch}"), |b| {
            b.iter_with_setup(
                || MetalCommandBatcher::new(max_batch),
                |mut batcher| {
                    for i in 0..max_batch * 3 {
                        let pipeline = if i % 3 == 0 { 1 } else { i as u64 % 10 };
                        batcher.record_draw(
                            bb(pipeline),
                            bb(3), // vertex_count
                            bb(0), // index_count
                            bb(1), // instance_count
                            bb(0), // start_vertex
                            bb(0), // base_index
                        );
                    }
                    let batches = batcher.drain_batches();
                    bb(batches.len())
                },
            )
        });
    }
    group.finish();
}

fn bench_gfx_shader_compiler_submit(c: &mut Criterion) {
    use casa1::perf::ParallelShaderCompiler;

    // Measures job-queue bookkeeping only (no shader is compiled).
    let mut group = c.benchmark_group("gfx/shader_compiler/submit_bookkeeping");
    for concurrent in [4usize, 16, 64] {
        // Pre-build the owned job arguments outside the measured closure so
        // no string formatting/allocation happens inside the timed region.
        let jobs: Vec<(String, String, String)> = (0..concurrent * 2)
            .map(|i| (format!("sha256:{i}"), "vs".to_string(), "main".to_string()))
            .collect();
        group.bench_function(format!("{concurrent}_concurrent"), |b| {
            b.iter_with_setup(
                || ParallelShaderCompiler::new(concurrent),
                |mut compiler| {
                    for (hash, stage, entry) in &jobs {
                        let id = compiler.submit_job(
                            bb(hash.clone()),
                            bb(stage.clone()),
                            bb(entry.clone()),
                        );
                        compiler.mark_compiling(bb(id)).expect("mark compiling");
                    }
                    let pending = compiler.pending_jobs().len();
                    bb(pending)
                },
            )
        });
    }
    group.finish();
}

fn bench_gfx_upload_streaming(c: &mut Criterion) {
    use casa1::perf::GpuUploadStreamer;

    // Measures the O(1) allocate() bookkeeping only (no bytes are uploaded).
    let mut group = c.benchmark_group("gfx/upload_streaming/allocate_bookkeeping");
    for alloc_size in [4096usize, 65536, 524288] {
        group.bench_function(format!("{}_bytes", alloc_size), |b| {
            b.iter_with_setup(
                || {
                    let ring = alloc_size * 100;
                    let mut streamer = GpuUploadStreamer::new(ring);
                    let buf_id = streamer.create_streaming_buffer(ring);
                    (streamer, buf_id)
                },
                |(mut streamer, buf_id)| {
                    let offset = streamer
                        .allocate(bb(buf_id), bb(alloc_size))
                        .expect("allocate");
                    bb(offset)
                },
            )
        });
    }
    group.finish();
}

fn bench_gfx_upload_streaming_wrap(c: &mut Criterion) {
    use casa1::perf::GpuUploadStreamer;

    // Exercises the ring-wrap path: allocating past the ring capacity resets
    // the write offset, which is the actual "streaming" semantics.
    let mut group = c.benchmark_group("gfx/upload_streaming/wrap");
    group.bench_function("wrap_ring", |b| {
        b.iter_with_setup(
            || {
                let ring = 65536;
                let mut streamer = GpuUploadStreamer::new(ring);
                let buf_id = streamer.create_streaming_buffer(ring);
                (streamer, buf_id)
            },
            |(mut streamer, buf_id)| {
                let mut saw_wrap = false;
                let mut last_offset = 0usize;
                for _ in 0..64 {
                    let offset = streamer.allocate(bb(buf_id), bb(4096)).expect("allocate");
                    saw_wrap |= offset < last_offset;
                    last_offset = offset;
                }
                assert!(saw_wrap, "streaming ring never wrapped");
                bb(last_offset)
            },
        )
    });
    group.finish();
}

// ===========================================================================
// 5.  STARTUP-TO-FIRST-FRAME BENCHMARK
// ===========================================================================

/// Composite benchmark exercising the full decode→lower→compile→execute
/// pipeline that represents a "first frame" of emulated execution.
fn bench_startup_full_pipeline(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let engine = casa1::cpu::CpuExecutionEngine::new(casa1::cpu::CpuEngineConfig {
        arch,
        os_build: "bench".into(),
        macwin_version: "0.0.0".into(),
        virtualization: casa1::cpu::CpuVirtualization::from_profile(arch, None).unwrap(),
    });

    let mut group = c.benchmark_group("startup/full_pipeline");

    // Build a "boot block" of mixed instructions
    let code = {
        let mut c = Vec::new();
        // 10 NOPs
        c.extend_from_slice(&nop_sled(10));
        // 10 MOV EAX + MOV EBX + ADD EAX,EBX
        c.extend_from_slice(&alu_mix_block(10));
        // 10 CMP/JE
        c.extend_from_slice(&cmp_jcc_block(10));
        c
    };
    // Prove the boot block decodes and lowers before benchmarking it
    let probe_decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode boot block");
    assert!(!probe_decoded.is_empty());
    let probe_ir = casa1::cpu::lower_to_ir(&probe_decoded).expect("lower boot block");
    assert!(!probe_ir.is_empty());

    group.bench_function("decode_lower_execute", |b| {
        b.iter_with_setup(
            || {
                let state = casa1::cpu::CpuState::new(arch);
                let memory = casa1::cpu::MemoryImage::default();
                (state, memory)
            },
            |(mut state, mut memory)| {
                // Phase 1: Decode
                let decoded =
                    casa1::cpu::decode_block(bb(&code), bb(0x1000), bb(arch)).expect("decode");
                // Phase 2: Lower to IR
                let ir = casa1::cpu::lower_to_ir(bb(&decoded)).expect("lower");
                // Phase 3: Execute (interpretation)
                let result = engine
                    .execute_ir(bb(&mut state), bb(&mut memory), bb(&ir))
                    .expect("execute");
                bb(result)
            },
        )
    });

    group.finish();
}

/// Benchmark the JIT compilation pipeline: decode → lower → compile at
/// progressively higher tiers, simulating adaptive optimisation startup.
fn bench_startup_adaptive_jit(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("startup/adaptive_jit");

    let code = alu_mix_block(50);
    let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode");
    let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower");

    group.bench_function("tier0_then_tier1_then_tier2", |b| {
        b.iter_with_setup(casa1::jit::JitCompiler::new, |mut compiler| {
            // Simulate adaptive tier progression
            let t0 = compiler
                .compile_tier0(bb(&ir), bb(0x1000), bb(arch), bb(None))
                .expect("compile tier0");
            let t1 = compiler
                .compile_tier1(bb(&ir), bb(0x1000), bb(arch), bb(None))
                .expect("compile tier1");
            let t2 = compiler
                .compile_tier2(bb(&ir), bb(0x1000), bb(arch), bb(None))
                .expect("compile tier2");
            assert!(t0.code_size > 0 && t1.code_size > 0 && t2.code_size > 0);
            bb((t0, t1, t2))
        })
    });

    group.finish();
}

/// Benchmark the PE loading → JIT compilation → execution pipeline,
/// representing a "load-and-run" startup sequence.
fn bench_startup_pe_load_and_prepare(c: &mut Criterion) {
    let mut group = c.benchmark_group("startup/pe_load_and_prepare");

    let pe_data = minimal_pe();

    group.bench_function("parse_and_map", |b| {
        b.iter_with_setup(
            || casa1::pe::parse(&pe_data).expect("parse"),
            |parsed| {
                // Parse again (cold path)
                let parsed2 = casa1::pe::parse(bb(&pe_data)).expect("parse");
                let mapped = casa1::pe::map_image(bb(&pe_data), bb(&parsed2), "bench", bb(false))
                    .expect("map");
                assert!(!mapped.sections.is_empty());
                bb((parsed, mapped))
            },
        )
    });

    group.finish();
}

/// Benchmark the cumulative overhead of multiple perf subsystem
/// initialisations that happen before the first frame.
fn bench_startup_perf_subsystems(c: &mut Criterion) {
    use casa1::perf::{
        AddressTranslationCache, BlockChainingCache, FileCache, FramePacer, FramePacingConfig,
        LazyJitProfiler, MetalCommandBatcher, ParallelShaderCompiler,
    };

    let mut group = c.benchmark_group("startup/perf_subsystems");

    group.bench_function("init_all", |b| {
        b.iter(|| {
            let _bc = bb(BlockChainingCache::new());
            let _atc = bb(AddressTranslationCache::new(256));
            let _prof = bb(LazyJitProfiler::new(50, 500));
            let _sc = bb(ParallelShaderCompiler::new(4));
            let _batcher = bb(MetalCommandBatcher::new(64));
            let _pacer = bb(FramePacer::new(FramePacingConfig {
                target_fps: 60,
                vsync_enabled: true,
                max_frame_latency: 2,
            }));
            let _fc = bb(FileCache::new(1_000_000));
        })
    });

    group.finish();
}

/// Build a synthetic PE with a real import table.
/// Generates `count` import thunks (hint/name entries) into kernel32.dll.
/// The import directory is populated so `pe::parse` resolves all thunks.
fn many_imports_pe(count: usize) -> Vec<u8> {
    let count = count.min(4096);
    let mut pe = vec![0u8; 64]; // DOS header
    pe[0..2].copy_from_slice(b"MZ");
    let e_lfanew: u32 = 0x80;
    pe[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    pe.resize(0x80, 0);
    pe.extend_from_slice(b"PE\0\0");

    pe.extend_from_slice(&0x8664u16.to_le_bytes()); // machine
    pe.extend_from_slice(&2u16.to_le_bytes()); // number of sections (.text + .idata)
    pe.extend_from_slice(&0u32.to_le_bytes()); // timedatestamp
    pe.extend_from_slice(&0u32.to_le_bytes()); // ptr to symbols
    pe.extend_from_slice(&0u32.to_le_bytes()); // num symbols
    pe.extend_from_slice(&0xF0u16.to_le_bytes()); // size of optional header
    pe.extend_from_slice(&0x0022u16.to_le_bytes()); // characteristics

    // .idata layout (RVA 0x2000, file offset 0x400):
    //   1. Import descriptor table: kernel32 entry + terminator (2 × 20 = 40)
    //   2. ILT: `count` name-RVA thunks + zero terminator
    //   3. IAT: `count` name-RVA thunks + zero terminator
    //   4. Hint/name table: `count` (hint u16 + "FuncN\0" + even padding)
    //   5. DLL name: "kernel32.dll\0"
    let desc_rva: u32 = 0x2000;
    let desc_bytes: u32 = 40;
    let ilt_rva = desc_rva + desc_bytes;
    let ilt_bytes = (count as u32 + 1) * 8;
    let iat_rva = ilt_rva + ilt_bytes;
    let iat_bytes = (count as u32 + 1) * 8;
    let hnt_rva = iat_rva + iat_bytes;
    let mut hnt_bytes: u32 = 0;
    for i in 0..count {
        let entry = 2 + format!("Func{i}\0").len() as u32;
        hnt_bytes += entry + (entry & 1);
    }
    let dll_name_rva = hnt_rva + hnt_bytes;
    let idata_size = (dll_name_rva + "kernel32.dll\0".len() as u32) - desc_rva;

    let mut directories = [(0u32, 0u32); 16];
    directories[casa1::pe::IMAGE_DIRECTORY_ENTRY_IMPORT] = (desc_rva, desc_bytes);
    let size_of_image = (0x2000 + idata_size + 0xFFF) & !0xFFF;
    write_pe32p_optional_header(&mut pe, 0x1000, size_of_image, 0x200, &directories);

    write_pe_section(&mut pe, b".text\0\0\0", 0x1000, 0x1000, 0x200, 0x200);
    write_pe_section(
        &mut pe,
        b".idata\0\0",
        idata_size,
        0x2000,
        idata_size,
        0x400,
    );
    pe.resize(0x400, 0); // headers + .text raw data

    // Helper: file offset of an .idata RVA
    let idata_file = |rva: u32| 0x400 + (rva - desc_rva) as usize;
    let hint_name_offset = |index: usize| -> u32 {
        let mut bytes = 0u32;
        for j in 0..index {
            let entry = 2 + format!("Func{j}\0").len() as u32;
            bytes += entry + (entry & 1);
        }
        bytes
    };

    // Import descriptor for kernel32.dll
    pe.resize(idata_file(desc_rva), 0);
    pe.extend_from_slice(&ilt_rva.to_le_bytes()); // OriginalFirstThunk
    pe.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    pe.extend_from_slice(&0u32.to_le_bytes()); // ForwarderChain
    pe.extend_from_slice(&dll_name_rva.to_le_bytes()); // Name
    pe.extend_from_slice(&iat_rva.to_le_bytes()); // FirstThunk
    // Terminator descriptor
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());

    // ILT: hint/name entries with the zero terminator at the END
    pe.resize(idata_file(ilt_rva), 0);
    for i in 0..count {
        let name_rva = hnt_rva + hint_name_offset(i);
        pe.extend_from_slice(&(name_rva as u64).to_le_bytes());
    }
    pe.extend_from_slice(&0u64.to_le_bytes());

    // IAT: same entries
    pe.resize(idata_file(iat_rva), 0);
    for i in 0..count {
        let name_rva = hnt_rva + hint_name_offset(i);
        pe.extend_from_slice(&(name_rva as u64).to_le_bytes());
    }
    pe.extend_from_slice(&0u64.to_le_bytes());

    // Hint/name table
    pe.resize(idata_file(hnt_rva), 0);
    for i in 0..count {
        pe.extend_from_slice(&0u16.to_le_bytes()); // Hint
        pe.extend_from_slice(format!("Func{i}\0").as_bytes());
        if !pe.len().is_multiple_of(2) {
            pe.push(0);
        }
    }

    // DLL name
    pe.resize(idata_file(dll_name_rva), 0);
    pe.extend_from_slice(b"kernel32.dll\0");
    pe
}

/// Build a synthetic DXIL container for benchmark use.
/// Based on the test helper from tests/section20.rs.
fn make_bench_dxil(instruction_count: u32, entry_name: &str) -> Vec<u8> {
    const LLVM_BC_MAGIC: u32 = 0x0B1E_0BC0u32.to_be();
    let mut data = Vec::new();
    // DXIL header
    data.extend_from_slice(b"DXIL");
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&3u32.to_le_bytes()); // part count (PROG, SIGN, META)
    let descriptors_end = 12 + 3 * 12; // = 48
    let prog_offset: u32 = descriptors_end;
    // PROG part descriptor
    data.extend_from_slice(b"PROG");
    data.extend_from_slice(&prog_offset.to_le_bytes());
    let bitcode_payload_size = 4u32;
    let prog_size = 24 + bitcode_payload_size;
    data.extend_from_slice(&prog_size.to_le_bytes());
    // SIGN part descriptor
    let sign_offset = prog_offset + prog_size;
    data.extend_from_slice(b"SIGN");
    data.extend_from_slice(&sign_offset.to_le_bytes());
    data.extend_from_slice(&4u32.to_le_bytes());
    // META part descriptor
    let meta_offset = sign_offset + 4;
    let name_bytes = entry_name.as_bytes();
    let meta_size = 1 + name_bytes.len() as u32;
    data.extend_from_slice(b"META");
    data.extend_from_slice(&meta_offset.to_le_bytes());
    data.extend_from_slice(&meta_size.to_le_bytes());
    // Pad to prog_offset
    while data.len() < prog_offset as usize {
        data.push(0);
    }
    // PROG part payload (24-byte header)
    data.extend_from_slice(&instruction_count.to_le_bytes());
    data.extend_from_slice(&64u32.to_le_bytes()); // IR size
    data.extend_from_slice(&1u32.to_le_bytes()); // threadgroup x
    data.extend_from_slice(&1u32.to_le_bytes()); // threadgroup y
    data.extend_from_slice(&1u32.to_le_bytes()); // threadgroup z
    data.extend_from_slice(&0u32.to_le_bytes()); // resource use count = 0
    // LLVM bitcode magic
    data.extend_from_slice(&LLVM_BC_MAGIC.to_be_bytes());
    // SIGN part payload
    while data.len() < sign_offset as usize {
        data.push(0);
    }
    data.extend_from_slice(b"SIG1");
    // META part payload
    while data.len() < meta_offset as usize {
        data.push(0);
    }
    data.push(name_bytes.len() as u8);
    data.extend_from_slice(name_bytes);
    data
}

fn bench_shader_input(
    dxil: Vec<u8>,
    stage: casa1::shader::ShaderStage,
) -> casa1::shader::ShaderTranslationInput {
    casa1::shader::ShaderTranslationInput {
        dxil,
        stage,
        root_signature: Vec::new(),
        compile_flags: casa1::shader::CompileFlags {
            fast_math: true,
            denorm_mode: "ieee".to_string(),
            debug: false,
            optimization_level: 0,
        },
        gpu_family: "apple_gpu".to_string(),
        os_build: "macos_14".to_string(),
        macwin_version: "0.1.0".to_string(),
    }
}

// ===========================================================================
// 6.  AUDIO MIXING BENCHMARKS  (Item 287/290)
// ===========================================================================

fn bench_audio_mix_direct_sound(c: &mut Criterion) {
    use casa1::audio::{AudioSubsystem, SampleFormat, WaveFormat};
    // The configured sample rate does not change the per-iteration work
    // (fixed frame counts), so a single representative rate is used.
    let mut group = c.benchmark_group("audio/mix");
    let mut audio = AudioSubsystem::new();
    let ds_id = audio.create_direct_sound8(1).expect("create DS8");
    let fmt = WaveFormat {
        channels: 2,
        sample_rate: 44100,
        sample_format: SampleFormat::Pcm16,
    };
    let buf_id = audio
        .create_direct_sound_buffer_simple(ds_id, fmt.clone())
        .expect("create buffer");
    // Fill buffer with test samples
    let test_samples: Vec<f32> = (0..(44100 * 2))
        .map(|i| ((i as f32) * 0.001).sin())
        .collect();
    audio
        .write_direct_sound_buffer(buf_id, &test_samples)
        .expect("write buffer");
    audio.play_direct_sound_buffer(buf_id).expect("play buffer");

    for frames in [256usize, 512, 1024] {
        // The mixer must always produce exactly frames × channels samples
        let probe = audio
            .mix_direct_sound_buffer(buf_id, frames)
            .expect("mix probe");
        assert_eq!(probe.samples.len(), frames * 2, "mix output sample count");
        group.bench_function(format!("{frames}_frames"), |b| {
            b.iter(|| {
                let out = audio
                    .mix_direct_sound_buffer(bb(buf_id), bb(frames))
                    .expect("mix");
                bb(out)
            })
        });
    }
    group.finish();
}

// ===========================================================================
// 7.  NETWORK SOCKET / WEBSOCKET BENCHMARKS  (Item 291)
// ===========================================================================

fn bench_network_socket_send_recv(c: &mut Criterion) {
    use casa1::network::{AddressFamily, NetworkStack, SockAddr};
    let mut group = c.benchmark_group("network/socket/send_recv");
    let mut net = NetworkStack::new();
    net.wsa_startup();
    let sock_a = net.socket(AddressFamily::Ipv4).expect("create socket A");
    let sock_b = net.socket(AddressFamily::Ipv4).expect("create socket B");
    let addr_a = SockAddr {
        family: AddressFamily::Ipv4,
        host: "127.0.0.1".into(),
        port: 9001,
    };
    let addr_b = SockAddr {
        family: AddressFamily::Ipv4,
        host: "127.0.0.1".into(),
        port: 9002,
    };
    net.bind(sock_a, addr_a.clone()).expect("bind A");
    net.bind(sock_b, addr_b.clone()).expect("bind B");
    net.listen(sock_a, 1).expect("listen A");
    net.connect(sock_b, addr_a).expect("connect B->A");
    let accepted = net.accept(sock_a).expect("accept");

    for size in [64usize, 1024, 65536] {
        let payload = vec![0xABu8; size];
        group.bench_function(format!("send_{size}_bytes"), |b| {
            b.iter(|| {
                let written = net.send(bb(sock_b), bb(&payload)).expect("send");
                let buf = net.recv(bb(accepted), bb(size)).expect("recv");
                bb((written, buf.len()))
            })
        });
    }
    group.finish();
}

fn bench_network_websocket_buffer(c: &mut Criterion) {
    use casa1::network::NetworkStack;
    let mut group = c.benchmark_group("network/websocket/buffer");
    let mut net = NetworkStack::new();
    net.wsa_startup();
    // Set up a routed HTTP request so the WebSocket upgrade machinery
    // (URL building, request-state validation, buffer records) is reached.
    // This is pure bookkeeping — no real network I/O.
    let session = net.win_http_open("bench");
    let conn = net
        .win_http_connect(session, "bench.test", 80, false)
        .expect("connect");
    let req = net
        .win_http_open_request(conn, "GET", "/ws")
        .expect("open request");
    net.add_route(
        "http",
        "bench.test",
        "/ws",
        101,
        BTreeMap::new(),
        b"",
        vec![],
        vec![],
    );
    net.win_http_send_request(req, BTreeMap::new(), b"")
        .expect("send request");
    net.win_http_receive_response(req)
        .expect("receive response");

    for size in [256usize, 4096, 65536] {
        let payload = vec![0xABu8; size];
        let mut rx_buf = vec![0u8; size];
        group.bench_function(format!("send_{size}_bytes"), |b| {
            b.iter(|| {
                // Full buffer-based WebSocket data path: upgrade (creates the
                // WebSocket record), send (open-state check + buffer append),
                // receive (drain), close, then release the handle so no state
                // accumulates across iterations.
                let ws = net
                    .websocket_complete_upgrade(bb(req))
                    .expect("websocket upgrade");
                net.websocket_send(bb(ws), bb(&payload))
                    .expect("websocket send");
                let received = net
                    .websocket_receive(bb(ws), &mut rx_buf)
                    .expect("websocket receive");
                // Nothing feeds the receive buffer in this bench, so a drain
                // must return zero bytes.
                assert_eq!(received, 0, "unexpected buffered WebSocket data");
                net.websocket_close(bb(ws), 1000, Some("bench"))
                    .expect("websocket close");
                let (status, _) = net
                    .websocket_query_close_status(bb(ws))
                    .expect("query close status");
                assert_eq!(status, 1000, "close status round-trip failed");
                net.close_handle(ws);
                bb(received)
            })
        });
    }
    group.finish();
}

// ===========================================================================
// 8.  SHADER TRANSLATION BENCHMARKS  (Item 289)
// ===========================================================================

fn bench_shader_translate_vs(c: &mut Criterion) {
    use casa1::shader::ShaderStage;
    let mut group = c.benchmark_group("shader/translate/vs");
    for insn_count in [0u32, 5, 20] {
        let dxil = make_bench_dxil(insn_count, "vs_main");
        let input = bench_shader_input(dxil, ShaderStage::Vs);
        group.bench_function(format!("{insn_count}_insns"), |b| {
            b.iter(|| {
                let result = casa1::shader::translate_shader(bb(&input));
                bb(result)
            })
        });
    }
    group.finish();
}

fn bench_shader_translate_ps(c: &mut Criterion) {
    use casa1::shader::ShaderStage;
    let mut group = c.benchmark_group("shader/translate/ps");
    let dxil = make_bench_dxil(0, "ps_main");
    let input = bench_shader_input(dxil, ShaderStage::Ps);
    group.bench_function("empty", |b| {
        b.iter(|| {
            let result = casa1::shader::translate_shader(bb(&input));
            bb(result)
        })
    });
    group.finish();
}

fn bench_shader_translate_cs(c: &mut Criterion) {
    use casa1::shader::ShaderStage;
    let mut group = c.benchmark_group("shader/translate/cs");
    let dxil = make_bench_dxil(1, "cs_main");
    let input = bench_shader_input(dxil, ShaderStage::Cs);
    group.bench_function("1_insn", |b| {
        b.iter(|| {
            let result = casa1::shader::translate_shader(bb(&input));
            bb(result)
        })
    });
    group.finish();
}

// ===========================================================================
// 9.  LARGE PE / HIGH IMPORT COUNT BENCHMARKS  (Item 288)
// ===========================================================================

fn bench_pe_parse_large_image(c: &mut Criterion) {
    let mut group = c.benchmark_group("pe/parse/large_image");
    for count in [64usize, 200, 500] {
        let pe_data = many_imports_pe(count);
        let parsed = casa1::pe::parse(&pe_data).expect("import-rich PE must parse");
        assert_eq!(
            parsed.imports.len(),
            1,
            "expected exactly one import descriptor"
        );
        assert_eq!(
            parsed.imports[0].imports.len(),
            count,
            "parsed import thunk count mismatch"
        );
        group.bench_function(format!("{count}_imports"), |b| {
            b.iter(|| {
                let parsed = casa1::pe::parse(bb(&pe_data)).expect("parse");
                bb(parsed)
            })
        });
    }
    group.finish();
}

fn bench_pe_map_large_image(c: &mut Criterion) {
    let mut group = c.benchmark_group("pe/map/large_image");
    for count in [64usize, 200, 500] {
        let pe_data = many_imports_pe(count);
        let parsed = casa1::pe::parse(&pe_data).expect("import-rich PE must parse");
        assert_eq!(parsed.imports[0].imports.len(), count);
        let mapped = casa1::pe::map_image(&pe_data, &parsed, "bench", false).expect("map");
        assert!(!mapped.sections.is_empty());
        group.bench_with_input(
            criterion::BenchmarkId::new("parse_and_map", count),
            &pe_data,
            |b, data| {
                b.iter_with_setup(
                    || casa1::pe::parse(data).expect("parse"),
                    |parsed| {
                        let mapped =
                            casa1::pe::map_image(bb(data), bb(&parsed), "bench", bb(false))
                                .expect("map");
                        bb(mapped)
                    },
                )
            },
        );
    }
    group.finish();
}

fn bench_pe_parse_many_sections_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("pe/parse/many_sections_large");
    for count in [50usize, 100] {
        let pe_data = many_sections_pe(count);
        let parsed = casa1::pe::parse(&pe_data).expect("many-sections PE must parse");
        assert_eq!(
            parsed.sections.len(),
            count,
            "parsed section count mismatch"
        );
        group.bench_function(format!("{count}_sections"), |b| {
            b.iter(|| {
                let parsed = casa1::pe::parse(bb(&pe_data)).expect("parse");
                bb(parsed)
            })
        });
    }
    group.finish();
}

// ===========================================================================
// 10. FAST-THUNK DISPATCH BENCHMARKS  (Item 292)
// ===========================================================================

fn bench_fast_thunk_dispatch_lookup(c: &mut Criterion) {
    // Exercises the real fast-thunk machinery: executable trampolines are
    // emitted per registration and looked up by index afterwards.
    let mut table = casa1::jit::FastThunkTable::new();
    let mut thunk_indices = Vec::new();
    for i in 0..256 {
        thunk_indices.push(table.register(0x1000 + i).expect("register thunk"));
    }
    assert_eq!(table.len(), 256);

    let mut group = c.benchmark_group("fast_thunk/dispatch_lookup");
    group.bench_function("256_thunks", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for index in &thunk_indices {
                acc = acc.wrapping_add(table.thunk_address(bb(*index)).unwrap_or(0));
            }
            bb(acc)
        })
    });
    group.finish();
}

fn bench_fast_thunk_guest_pointer_checks(c: &mut Criterion) {
    use casa1::host_thunks::{
        read_guest_u16_checked, read_guest_u32_checked, read_guest_u64_checked,
    };
    let mut group = c.benchmark_group("fast_thunk/guest_pointer_checks");
    let mut memory = casa1::cpu::MemoryImage::default();
    // Write some test values
    memory.write_u32(0x1000, 42);
    memory.write_u64(0x2000, 0xDEAD_BEEF);

    group.bench_function("read_u32_checked", |b| {
        b.iter(|| {
            let val = read_guest_u32_checked(bb(&memory), bb(0x1000));
            bb(val)
        })
    });
    group.bench_function("read_u64_checked", |b| {
        b.iter(|| {
            let val = read_guest_u64_checked(bb(&memory), bb(0x2000));
            bb(val)
        })
    });
    group.bench_function("read_u16_checked", |b| {
        b.iter(|| {
            let val = read_guest_u16_checked(bb(&memory), bb(0x1000));
            bb(val)
        })
    });
    group.finish();
}

// ===========================================================================
// 11. INTERPRETER THROUGHPUT BENCHMARKS  (Item 287)
// ===========================================================================

fn bench_cpu_decode_throughput(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("cpu/decode/throughput");
    for size in [1024usize, 4096, 16384] {
        let code = nop_sled(size);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode nop sled");
        assert_eq!(decoded.len(), size);
        group.bench_function(format!("{size}_bytes"), |b| {
            b.iter(|| {
                let decoded = casa1::cpu::decode_block(bb(&code), bb(0x1000), bb(arch))
                    .expect("decode nop sled");
                bb(decoded)
            })
        });
    }
    group.finish();
}

// ===========================================================================
// 12. MEMORY USAGE TRACKING UTILITY  (Item 293)
// ===========================================================================

/// A lightweight utility to measure guest memory usage across the major
/// memory regions: code pages, data pages, stack, heap, and JIT cache.
/// This utility can be used in long-running profiling scenarios to detect
/// memory growth patterns in large guest processes.
pub struct MemoryUsageTracker {
    label: String,
    baseline_code: usize,
    baseline_data: usize,
    baseline_stack: usize,
    baseline_heap: usize,
    baseline_jit_cache: usize,
}

impl MemoryUsageTracker {
    pub fn new(label: &str, memory: &casa1::cpu::MemoryImage) -> Self {
        let (code, data, stack, heap, jit) = Self::measure_regions(memory);
        Self {
            label: label.to_string(),
            baseline_code: code,
            baseline_data: data,
            baseline_stack: stack,
            baseline_heap: heap,
            baseline_jit_cache: jit,
        }
    }

    /// Measure sizes of guest memory regions from a MemoryImage.
    /// Each committed page is MEMORY_PAGE_SIZE (4096) bytes.
    fn measure_regions(memory: &casa1::cpu::MemoryImage) -> (usize, usize, usize, usize, usize) {
        // We approximate regions by their virtual address ranges:
        //   Code:   0x0000_0000_0000_1000 – 0x0000_0000_0100_0000 (a few MB)
        //   Data:   0x0000_0000_0100_0000 – 0x0000_0000_4000_0000
        //   Stack:  0x0000_0000_4000_0000 – 0x0000_0000_8000_0000
        //   Heap:   0x0000_0000_8000_0000 – 0x0000_0001_0000_0000
        //   JIT:    0x0000_0001_0000_0000 – 0x0000_0002_0000_0000
        const PAGE_SIZE: usize = 4096;
        let code_end = 0x0100_0000u64;
        let data_end = 0x4000_0000u64;
        let stack_end = 0x8000_0000u64;
        let heap_end = 0x1_0000_0000u64;
        let jit_end = 0x2_0000_0000u64;
        let mut code = 0usize;
        let mut data = 0usize;
        let mut stack = 0usize;
        let mut heap = 0usize;
        let mut jit = 0usize;
        for &addr in memory.committed_page_addresses().iter() {
            if addr < code_end {
                code += PAGE_SIZE;
            } else if addr < data_end {
                data += PAGE_SIZE;
            } else if addr < stack_end {
                stack += PAGE_SIZE;
            } else if addr < heap_end {
                heap += PAGE_SIZE;
            } else if addr < jit_end {
                jit += PAGE_SIZE;
            }
        }
        (code, data, stack, heap, jit)
    }

    pub fn snapshot(&self, memory: &casa1::cpu::MemoryImage) -> MemoryUsageSnapshot {
        let (code, data, stack, heap, jit) = Self::measure_regions(memory);
        MemoryUsageSnapshot {
            label: self.label.clone(),
            code_pages: code,
            data_pages: data,
            stack_pages: stack,
            heap_pages: heap,
            jit_cache: jit,
            delta_code: code.saturating_sub(self.baseline_code),
            delta_data: data.saturating_sub(self.baseline_data),
            delta_stack: stack.saturating_sub(self.baseline_stack),
            delta_heap: heap.saturating_sub(self.baseline_heap),
            delta_jit: jit.saturating_sub(self.baseline_jit_cache),
        }
    }
}

pub struct MemoryUsageSnapshot {
    pub label: String,
    pub code_pages: usize,
    pub data_pages: usize,
    pub stack_pages: usize,
    pub heap_pages: usize,
    pub jit_cache: usize,
    pub delta_code: usize,
    pub delta_data: usize,
    pub delta_stack: usize,
    pub delta_heap: usize,
    pub delta_jit: usize,
}

impl std::fmt::Display for MemoryUsageSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] code={} data={} stack={} heap={} jit={}  delta: code={} data={} stack={} heap={} jit={}",
            self.label,
            self.code_pages,
            self.data_pages,
            self.stack_pages,
            self.heap_pages,
            self.jit_cache,
            self.delta_code,
            self.delta_data,
            self.delta_stack,
            self.delta_heap,
            self.delta_jit,
        )
    }
}

fn bench_memory_usage_tracking(c: &mut Criterion) {
    use casa1::cpu::MemoryImage;
    let mut memory = MemoryImage::default();
    // Allocate some pages to measure
    for i in 0..10 {
        let addr = 0x1000 + (i as u64 * 0x1000);
        memory.write_u32(addr, i as u32);
    }
    for i in 0..5 {
        let addr = 0x100_0000 + (i as u64 * 0x1000);
        memory.write_u32(addr, i as u32);
    }

    let mut group = c.benchmark_group("memory/usage_tracker");
    group.bench_function("measure_regions", |b| {
        b.iter(|| {
            let tracker = MemoryUsageTracker::new("bench", bb(&memory));
            let snap = tracker.snapshot(bb(&memory));
            bb(snap)
        })
    });
    group.finish();
}

// ===========================================================================
// 13. STRESS / LEAK TESTS  (Item 294)
// ===========================================================================

/// Stress test: create and destroy many audio resources in a loop.
fn bench_stress_audio_create_destroy(c: &mut Criterion) {
    use casa1::audio::{AudioSubsystem, SampleFormat, WaveFormat};
    let mut group = c.benchmark_group("stress/audio/create_destroy");
    group.bench_function("100_cycles", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let mut audio = AudioSubsystem::new();
                let ds_id = audio.create_direct_sound8(1).expect("create DS8");
                let fmt = WaveFormat {
                    channels: 2,
                    sample_rate: 48000,
                    sample_format: SampleFormat::Pcm16,
                };
                for _ in 0..10 {
                    let _buf = audio
                        .create_direct_sound_buffer_simple(ds_id, fmt.clone())
                        .expect("create buffer");
                }
                // Drop audio — verifies no leaks via Drop impl
            }
            bb(())
        })
    });
    group.finish();
}

/// Stress test: create and destroy many network sockets in a loop.
fn bench_stress_network_create_destroy(c: &mut Criterion) {
    use casa1::network::{AddressFamily, NetworkStack};
    let mut group = c.benchmark_group("stress/network/create_destroy");
    group.bench_function("100_cycles", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let mut net = NetworkStack::new();
                net.wsa_startup();
                let _sock = net.socket(AddressFamily::Ipv4).expect("create socket");
                // closesocket is called on drop
                bb(())
            }
            bb(())
        })
    });
    group.finish();
}

/// Stress test: create and destroy many PE parse results in a loop.
fn bench_stress_pe_parse_loop(c: &mut Criterion) {
    let mut group = c.benchmark_group("stress/pe/parse_loop");
    let pe_data = minimal_pe();
    casa1::pe::parse(&pe_data).expect("minimal PE must parse");
    group.bench_function("1000_parses", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                let parsed = casa1::pe::parse(bb(&pe_data)).expect("parse");
                let _ = bb(parsed);
            }
            bb(())
        })
    });
    group.finish();
}

/// Stress test: exercise the host-thunk guest pointer validation in a loop.
fn bench_stress_host_thunk_validations(c: &mut Criterion) {
    use casa1::cpu::MemoryImage;
    use casa1::host_thunks::read_guest_u32_checked;
    let mut memory = MemoryImage::default();
    memory.write_u32(0x4000, 0xCAFE);
    let mut group = c.benchmark_group("stress/host_thunk/validations");
    group.bench_function("10000_reads", |b| {
        b.iter(|| {
            for _ in 0..10000 {
                let val = read_guest_u32_checked(bb(&memory), bb(0x4000));
                let _ = bb(val);
            }
            bb(())
        })
    });
    group.finish();
}

// ===========================================================================
// Criterion groups
// ===========================================================================

criterion_group!(
    benches,
    // 1. CPU Engine Throughput
    bench_cpu_decode_nop,
    bench_cpu_decode_alu,
    bench_cpu_decode_simd,
    bench_cpu_decode_control_flow,
    bench_cpu_lower_to_ir,
    bench_cpu_full_pipeline,
    // 2. JIT Cache Optimisation
    bench_jit_compile_tier0,
    bench_jit_compile_tier1,
    bench_jit_compile_tier2,
    bench_jit_constant_folding,
    bench_jit_dead_code_elimination,
    bench_jit_tier_promotion,
    bench_jit_inline_cache,
    // 3. PE Loading
    bench_pe_parse_minimal,
    bench_pe_parse_many_sections,
    bench_pe_parse_and_map,
    // 4. Graphics Pipeline
    bench_gfx_command_batching,
    bench_gfx_shader_compiler_submit,
    bench_gfx_upload_streaming,
    bench_gfx_upload_streaming_wrap,
    // 5. Startup-to-First-Frame
    bench_startup_full_pipeline,
    bench_startup_adaptive_jit,
    bench_startup_pe_load_and_prepare,
    bench_startup_perf_subsystems,
    // 6. Audio Mixing
    bench_audio_mix_direct_sound,
    // 7. Network Socket/WebSocket
    bench_network_socket_send_recv,
    bench_network_websocket_buffer,
    // 8. Shader Translation
    bench_shader_translate_vs,
    bench_shader_translate_ps,
    bench_shader_translate_cs,
    // 9. Large PE / High Import Count
    bench_pe_parse_large_image,
    bench_pe_map_large_image,
    bench_pe_parse_many_sections_large,
    // 10. Fast-Thunk Dispatch
    bench_fast_thunk_dispatch_lookup,
    bench_fast_thunk_guest_pointer_checks,
    // 11. Decode Throughput
    bench_cpu_decode_throughput,
    // 12. Memory Usage Tracking
    bench_memory_usage_tracking,
    // 13. Stress / Leak Tests
    bench_stress_audio_create_destroy,
    bench_stress_network_create_destroy,
    bench_stress_pe_parse_loop,
    bench_stress_host_thunk_validations,
);

criterion_main!(benches);
