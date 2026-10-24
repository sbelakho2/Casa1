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

/// Production worker slice: call/return-heavy native chain.
///
/// The same total number of compiled blocks (4096) runs with three dispatch
/// chunk sizes.  `chunk_1` reproduces the old "one slice per round" barrier
/// behaviour; `chunk_512` keeps the worker in one job for 512 blocks.  The
/// delta is the barrier cost removed by native call/ret chaining.
fn bench_jit_worker_call_return(c: &mut Criterion) {
    use casa1::cpu::{GuestArch, IrInstruction, MemoryImage, Register};
    use casa1::jit::WorkerSliceBenchmark;

    const TOTAL_BLOCKS: u64 = 4096;
    let arch = GuestArch::X64;
    let stack = 0x11_000_u64;
    let mut memory = MemoryImage::default();
    memory.map_bytes(stack & !0xfff, &[0_u8; 0x1000]);
    let blocks = vec![
        (
            0x1000_u64,
            vec![IrInstruction::Call {
                target: 0x2000,
                return_address: 0x1010,
            }],
        ),
        (0x1010, vec![IrInstruction::Jump { target: 0x1000 }]),
        (
            0x2000,
            vec![
                IrInstruction::AddImm {
                    dst: Register::Rcx,
                    value: 1,
                    width: 8,
                },
                IrInstruction::Return { stack_adjust: 0 },
            ],
        ),
    ];
    let mut group = c.benchmark_group("jit/worker_call_return");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(3));
    for chunk in [1_u64, 16, 512] {
        group.bench_function(format!("chunk_{chunk}"), |b| {
            let mut harness =
                WorkerSliceBenchmark::new(arch, &memory, &blocks, 0x1000, stack + 0x800);
            b.iter(|| {
                harness.reset();
                let mut done = 0_u64;
                while done < TOTAL_BLOCKS {
                    let (blocks, _instructions, _metrics) =
                        harness.run(bb(chunk.min(TOTAL_BLOCKS - done)));
                    done += blocks;
                    bb(done);
                }
                bb(done)
            })
        });
    }
    group.finish();
}

/// Production worker slice: indirect-call-heavy chain with a monomorphic site.
fn bench_jit_worker_indirect(c: &mut Criterion) {
    use casa1::cpu::{GuestArch, IrInstruction, MemoryImage, Register};
    use casa1::jit::WorkerSliceBenchmark;

    const TOTAL_BLOCKS: u64 = 4096;
    let arch = GuestArch::X64;
    let stack = 0x12_000_u64;
    let mut memory = MemoryImage::default();
    memory.map_bytes(stack & !0xfff, &[0_u8; 0x1000]);
    let blocks = vec![
        (
            0x1000_u64,
            vec![IrInstruction::CallRegister {
                src: Register::Rax,
                return_address: 0x1010,
            }],
        ),
        (0x1010, vec![IrInstruction::Jump { target: 0x1000 }]),
        (
            0x2000,
            vec![
                IrInstruction::AddImm {
                    dst: Register::Rcx,
                    value: 1,
                    width: 8,
                },
                IrInstruction::Return { stack_adjust: 0 },
            ],
        ),
    ];
    let mut group = c.benchmark_group("jit/worker_indirect");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(3));
    for chunk in [1_u64, 16, 512] {
        group.bench_function(format!("chunk_{chunk}"), |b| {
            let mut harness =
                WorkerSliceBenchmark::new(arch, &memory, &blocks, 0x1000, stack + 0x800);
            harness.reset();
            harness.set_rax(0x2000);
            b.iter(|| {
                let mut done = 0_u64;
                while done < TOTAL_BLOCKS {
                    let (blocks, _instructions, _metrics) =
                        harness.run(bb(chunk.min(TOTAL_BLOCKS - done)));
                    done += blocks;
                    bb(done);
                }
                bb(done)
            });
            harness.reset();
        });
    }
    group.finish();
}

/// Return predictor and 2/4-way/megamorphic indirect-cache hot loops.
fn bench_jit_worker_control_caches(c: &mut Criterion) {
    use casa1::jit::{bench_indirect_cache, bench_return_predictor};

    let mut group = c.benchmark_group("jit/worker_caches");
    group.bench_function("return_predictor_4096", |b| {
        b.iter(|| bb(bench_return_predictor(bb(4096))))
    });
    group.bench_function("indirect_megamorphic_4096", |b| {
        // The helper cycles six targets; the first five populate/promote the
        // site, so the steady state is the megamorphic hash fallback.
        b.iter(|| bb(bench_indirect_cache(bb(4096))))
    });
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

/// Re-sync a large *sparse* guest memory image into the flat JIT mirror.
///
/// The guest image commits only 16 pages spread across a 2 GiB address range;
/// every other guest page is untouched.  Before the on-demand materialisation
/// work this call synchronises (and eagerly pre-faults) the whole 4 GiB flat
/// region on every block execution — over a million page touches per call.
/// After it, only the 16 committed pages are materialised, so the benchmark
/// measures exactly the eager work that was eliminated.
fn bench_cpu_memory_sync_sparse(c: &mut Criterion) {
    use casa1::cpu::MemoryImage;
    use casa1::jit::JitRuntime;

    let arch = casa1::cpu::GuestArch::X64;
    let mut memory = MemoryImage::default();
    let mut committed_pages = 0u64;
    for i in 0..16u64 {
        let addr = i * 0x0800_0000;
        memory.map_bytes(addr, &[0xABu8; 0x1000]);
        committed_pages += 1;
    }
    assert_eq!(memory.committed_page_addresses().len(), 16);
    let mut runtime = JitRuntime::new(arch);
    // Warm one sync so the first call's mmap/page-population cost is not
    // attributed to the measured steady state.
    runtime.sync_all_pages_to_flat(&memory);

    // On-demand proof: one more sync must materialise exactly the 16
    // committed pages, not the whole 1,048,576-page flat region.
    let before = casa1::jit::guest_memory_telemetry();
    runtime.sync_all_pages_to_flat(&memory);
    let after = casa1::jit::guest_memory_telemetry();
    assert_eq!(
        after.pages_materialised - before.pages_materialised,
        16,
        "a sparse 16-page guest image must materialise only 16 pages"
    );
    assert_eq!(
        after.bytes_copied - before.bytes_copied,
        16 * 4096,
        "only the committed bytes may be copied"
    );

    let mut group = c.benchmark_group("cpu/memory");
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(2));
    group.bench_function("sync_sparse_guest", |b| {
        b.iter(|| {
            runtime.sync_all_pages_to_flat(bb(&memory));
            bb(runtime.synced_page_count())
        })
    });
    let _ = committed_pages;
    group.finish();
}

/// Allocation and compiled access for a guest page above 4 GiB.
///
/// `alloc_8g_direct_window_page`/`jit_access_8g_direct_window_page` exercise
/// the new direct window (8 GiB is inside it), while the `_owned_frame_page`
/// pair uses an address beyond the 256 GiB window, i.e. exactly the owned-frame
/// fallback the pre-change implementation used for every address at or above
/// 4 GiB.  The two pairs measure the same work through the old and new paths.
fn bench_cpu_memory_above_four_gib(c: &mut Criterion) {
    use casa1::cpu::{CpuState, GuestArch, IrInstruction, MemoryImage, MemoryOperand, Register};
    use casa1::jit::JitRuntime;

    let direct_address = 0x2_0000_0000_u64;
    // Beyond the 256 GiB direct window: exercises the owned-frame fallback.
    let owned_address = 0x41_0000_0000_u64;
    let operand = |address: u64| MemoryOperand {
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
    let ir = |address: u64| {
        vec![IrInstruction::LoadMemory {
            dst: Register::Rax,
            address: operand(address),
            width: 8,
        }]
    };

    let mut group = c.benchmark_group("cpu/memory");
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(2));

    for (label, address) in [
        ("alloc_8g_direct_window_page", direct_address),
        ("alloc_beyond_window_owned_frame_page", owned_address),
    ] {
        let mut memory = MemoryImage::default();
        memory.map_bytes(address, &[0u8; 4096]);
        group.bench_function(label, |b| {
            b.iter(|| {
                memory.unmap_range(address, 4096);
                memory
                    .commit_zeroed_pages(address, 4096)
                    .expect("commit bench page");
                bb(())
            })
        });
    }

    if casa1::jit::jit_execution_available() {
        for (label, address) in [
            ("jit_access_8g_direct_window_page", direct_address),
            ("jit_access_beyond_window_owned_frame_page", owned_address),
        ] {
            let mut runtime = JitRuntime::new(GuestArch::X64);
            let site = 0x2_0000_5000_u64;
            runtime
                .get_or_compile(&ir(address), site, GuestArch::X64, None)
                .expect("compile bench block");
            let block = runtime
                .block_cache
                .get(&site)
                .cloned()
                .expect("cached bench block");
            let mut state = CpuState::new(GuestArch::X64);
            let mut memory = MemoryImage::default();
            memory.map_bytes(address, &[0x11u8; 4096]);
            group.bench_function(label, |b| {
                b.iter(|| {
                    state.set(Register::Rax, 0);
                    let reason = unsafe { runtime.execute_block(&block, &mut state, &mut memory) };
                    bb(reason)
                })
            });
        }
    }

    group.finish();
}

/// Repeated resolution of a guest thunk address to its host trampoline.
/// A resolved-target cache should make repeat lookups O(1) and bypass the
/// linear entry scan + global-map lock.
fn bench_jit_thunk_resolve(c: &mut Criterion) {
    use casa1::jit::FastThunkTable;

    extern "C" fn bench_thunk_target() -> u64 {
        0x42
    }

    let mut table = FastThunkTable::new();
    let mut guest_addrs = Vec::new();
    let host_fn = bench_thunk_target as *const () as usize;
    for i in 0..256u64 {
        let guest = 0x100_0000 + i * 0x10;
        table
            .register_with_guest_addr(host_fn, guest)
            .expect("register thunk");
        guest_addrs.push(guest);
    }

    let mut group = c.benchmark_group("jit/thunk_resolve");
    group.bench_function("256_repeat_lookups", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for guest in &guest_addrs {
                acc = acc.wrapping_add(table.find_thunk_by_guest(bb(*guest)).unwrap_or(0));
            }
            bb(acc)
        })
    });
    group.finish();
}

/// Lazy x86 flag materialisation: a chain of 200 ADD instructions whose flags
/// are never read until the block ends.  The eager implementation computed a
/// full flag set after every ADD; the lazy path parks each result and
/// materialises only the last one.
fn bench_cpu_lazy_flags_alu_chain(c: &mut Criterion) {
    use casa1::cpu::{
        CpuEngineConfig, CpuExecutionEngine, CpuState, CpuVirtualization, GuestArch, IrInstruction,
        MemoryImage, Register,
    };

    let arch = GuestArch::X64;
    let engine = CpuExecutionEngine::new(CpuEngineConfig {
        arch,
        os_build: "bench".into(),
        macwin_version: "0.0.0".into(),
        virtualization: CpuVirtualization::from_profile(arch, None).unwrap(),
    });
    let ir: Vec<IrInstruction> = (0..200u64)
        .map(|i| IrInstruction::AddImm {
            dst: Register::Rax,
            value: i + 1,
            width: 8,
        })
        .collect();

    // Prove the laziness engages before measuring: at most the final flag set
    // can be computed eagerly; the other 199 must be skipped.  (Other tests
    // run concurrently, so assert the guaranteed lower bound.)
    let mut probe_state = CpuState::new(arch);
    let mut probe_memory = MemoryImage::default();
    let before = casa1::cpu::lazy_flag_telemetry();
    engine
        .execute_ir(&mut probe_state, &mut probe_memory, &ir)
        .expect("probe execution");
    let after = casa1::cpu::lazy_flag_telemetry();
    assert!(
        after.skipped - before.skipped >= 199,
        "lazy flags did not skip dead materialisations: {before:?} -> {after:?}"
    );

    let mut group = c.benchmark_group("cpu/lazy_flags");
    group.bench_function("200_dead_add_flags", |b| {
        b.iter_with_setup(
            || (CpuState::new(arch), MemoryImage::default()),
            |(mut state, mut memory)| {
                let result = engine
                    .execute_ir(bb(&mut state), bb(&mut memory), bb(&ir))
                    .expect("execute");
                bb(result)
            },
        )
    });
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

/// Native block linking: same guest loop with links enabled vs cleared.
fn bench_jit_native_linking(c: &mut Criterion) {
    use casa1::cpu::{ConditionCode, GuestArch, IrInstruction, MemoryImage, Register};
    use casa1::jit::WorkerSliceBenchmark;

    const TOTAL_BLOCKS: u64 = 4096;
    let arch = GuestArch::X64;
    let memory = MemoryImage::default();
    let blocks = vec![
        (
            0x1000_u64,
            vec![
                IrInstruction::SubImm {
                    dst: Register::Rcx,
                    value: 1,
                    width: 4,
                },
                IrInstruction::Compare {
                    lhs: casa1::cpu::CompareOperand::Register(Register::Rcx),
                    rhs: casa1::cpu::CompareOperand::ImmediateU64(0),
                    width: 4,
                },
                IrInstruction::JumpIf {
                    condition: ConditionCode::NotEqual,
                    target: 0x1000,
                    fallthrough: 0x1010,
                },
            ],
        ),
        (0x1010, vec![IrInstruction::Nop]),
    ];
    let mut group = c.benchmark_group("jit/native_linking");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_millis(300));
    group.measurement_time(std::time::Duration::from_secs(2));
    for (name, linked) in [("linked", true), ("unlinked", false)] {
        group.bench_function(name, |b| {
            let mut harness = WorkerSliceBenchmark::new(arch, &memory, &blocks, 0x1000, 0);
            harness.set_linking(linked);
            b.iter(|| {
                harness.reset();
                let mut done = 0_u64;
                while done < TOTAL_BLOCKS {
                    let (blocks, _instructions, _metrics) = harness.run(bb(TOTAL_BLOCKS - done));
                    assert_eq!(blocks, TOTAL_BLOCKS - done);
                    done += blocks;
                }
                bb(done)
            });
        });
    }
    group.finish();
}

/// Conditional-branch-heavy guest code: one native Jcc per iteration.
fn bench_jit_conditional_branch_heavy(c: &mut Criterion) {
    use casa1::cpu::{ConditionCode, GuestArch, IrInstruction, MemoryImage, Register};
    use casa1::jit::WorkerSliceBenchmark;

    const TOTAL_BLOCKS: u64 = 4096;
    let arch = GuestArch::X64;
    let memory = MemoryImage::default();
    let blocks = vec![
        (
            0x1000_u64,
            vec![
                IrInstruction::Compare {
                    lhs: casa1::cpu::CompareOperand::Register(Register::Rcx),
                    rhs: casa1::cpu::CompareOperand::ImmediateU64(0),
                    width: 8,
                },
                IrInstruction::JumpIf {
                    condition: ConditionCode::NotEqual,
                    target: 0x1020,
                    fallthrough: 0x1010,
                },
            ],
        ),
        (0x1010, vec![IrInstruction::Jump { target: 0x1030 }]),
        (
            0x1020,
            vec![
                IrInstruction::SubImm {
                    dst: Register::Rcx,
                    value: 1,
                    width: 8,
                },
                IrInstruction::Jump { target: 0x1000 },
            ],
        ),
        (0x1030, vec![IrInstruction::Nop]),
    ];
    let mut group = c.benchmark_group("jit/conditional_branch_heavy");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_millis(300));
    group.measurement_time(std::time::Duration::from_secs(2));
    for (name, linked) in [("linked", true), ("unlinked", false)] {
        group.bench_function(name, |b| {
            let mut harness = WorkerSliceBenchmark::new(arch, &memory, &blocks, 0x1000, 0);
            harness.set_linking(linked);
            b.iter(|| {
                harness.reset();
                harness.set_rcx(TOTAL_BLOCKS);
                let expected = TOTAL_BLOCKS * 2 + 3;
                let mut done = 0_u64;
                while done < expected {
                    let (blocks, _instructions, _metrics) = harness.run(64);
                    if blocks == 0 {
                        break;
                    }
                    done += blocks;
                }
                assert_eq!(done, expected);
                bb(done)
            });
        });
    }
    group.finish();
}

/// Persistent AOT cache: hit rate over fresh runtime instances.
fn bench_jit_aot_cache(c: &mut Criterion) {
    use casa1::jit::bench_aot_hits;
    let mut group = c.benchmark_group("jit/aot_cache");
    group.sample_size(10);
    group.warm_up_time(std::time::Duration::from_millis(200));
    group.measurement_time(std::time::Duration::from_secs(2));
    group.bench_function("load_hit_rate_8_instances", |b| {
        b.iter(|| {
            let metrics = bench_aot_hits(8);
            assert_eq!(metrics, (8, 1, 0));
            bb(metrics)
        })
    });
    group.finish();
}

// ===========================================================================
// Criterion groups
// ===========================================================================

// ---------------------------------------------------------------------------
// Tier-2 SSA, direct IAT patching and inline API benchmarks
// ---------------------------------------------------------------------------

fn tier2_loop_blocks(iterations: u64) -> Vec<casa1::jit_ssa::FunctionBlock> {
    use casa1::cpu::{CompareOperand, ConditionCode, IrInstruction, Register};
    vec![
        casa1::jit_ssa::FunctionBlock::new(
            0x1000,
            vec![
                IrInstruction::MovImm {
                    dst: Register::Rax,
                    value: 0,
                },
                IrInstruction::MovImm {
                    dst: Register::Rcx,
                    value: iterations,
                },
                IrInstruction::Jump { target: 0x1010 },
            ],
        ),
        casa1::jit_ssa::FunctionBlock::new(
            0x1010,
            vec![
                IrInstruction::AddOperand {
                    dst: Register::Rax,
                    src: CompareOperand::Register(Register::Rcx),
                    width: 8,
                },
                IrInstruction::SubImm {
                    dst: Register::Rcx,
                    value: 1,
                    width: 8,
                },
                IrInstruction::Compare {
                    lhs: CompareOperand::Register(Register::Rcx),
                    rhs: CompareOperand::ImmediateU64(0),
                    width: 8,
                },
                IrInstruction::JumpIf {
                    condition: ConditionCode::NotEqual,
                    target: 0x1010,
                    fallthrough: 0x1020,
                },
            ],
        ),
        casa1::jit_ssa::FunctionBlock::new(0x1020, vec![IrInstruction::Jump { target: 0x9999 }]),
    ]
}

fn run_tier0_loop(
    blocks: &[casa1::jit_ssa::FunctionBlock],
    state: &mut casa1::cpu::CpuState,
    memory: &mut casa1::cpu::MemoryImage,
) {
    use std::collections::HashMap;
    let map: HashMap<u64, &Vec<casa1::cpu::IrInstruction>> = blocks
        .iter()
        .map(|block| (block.guest_address, &block.instructions))
        .collect();
    state.rip = 0x1000;
    for _ in 0..10_000_000 {
        let Some(ir) = map.get(&state.rip) else {
            return;
        };
        casa1::cpu::execute_ir(state, memory, ir).expect("tier0 interp");
    }
    panic!("tier0 loop did not terminate");
}

fn bench_jit_tier2_hot_loop(c: &mut Criterion) {
    use casa1::cpu::{CpuState, GuestArch, MemoryImage};
    use casa1::jit::JitRuntime;
    const ITERS: u64 = 1_000_000;
    let blocks = tier2_loop_blocks(ITERS);
    let mut group = c.benchmark_group("jit_tier2_hot_loop");
    group.sample_size(20);

    group.bench_function("tier0_interpreted_1m", |b| {
        b.iter(|| {
            let mut state = CpuState::new(GuestArch::X64);
            let mut memory = MemoryImage::default();
            run_tier0_loop(&blocks, &mut state, &mut memory);
            bb(state.get(casa1::cpu::Register::Rax))
        })
    });

    let mut runtime = JitRuntime::new(GuestArch::X64);
    let compiled = runtime
        .get_or_compile_function_tier2(&blocks, GuestArch::X64)
        .expect("tier2 compile")
        .expect("tier2 promotion")
        .clone();
    group.bench_function("tier2_native_1m", |b| {
        b.iter(|| {
            let mut state = CpuState::new(GuestArch::X64);
            let mut memory = MemoryImage::default();
            state.rip = 0x1000;
            // SAFETY: the compiled block and state/memory outlive the call.
            let _ = unsafe { runtime.execute_block(&compiled, &mut state, &mut memory) };
            bb(state.get(casa1::cpu::Register::Rax))
        })
    });
    group.finish();

    let metrics = casa1::jit_ssa::tier2_metrics();
    eprintln!(
        "TIER2_HOT_LOOP hit_rate={:.3} compiled={} fallbacks={} blocks={} sccp={} gvn={} dce={} licm={} load_fwd={} store_elim={} spills={}",
        if metrics.functions_compiled + metrics.functions_fallback == 0 {
            0.0
        } else {
            metrics.functions_compiled as f64
                / (metrics.functions_compiled + metrics.functions_fallback) as f64
        },
        metrics.functions_compiled,
        metrics.functions_fallback,
        metrics.blocks,
        metrics.sccp_eliminated,
        metrics.gvn_eliminated,
        metrics.dce_eliminated,
        metrics.licm_hoisted,
        metrics.load_forwarded,
        metrics.store_eliminated,
        metrics.register_spills,
    );
}

fn bench_jit_iat_dispatch(c: &mut Criterion) {
    use casa1::pe::ImportSymbol;
    use casa1::runtime::{IatPatchEntry, IatPatchTable};
    let mut table = IatPatchTable::default();
    table.patch(IatPatchEntry {
        slot_va: 0x4000_1000,
        selected_base: 0x4000_0000,
        iat_rva: 0x1000,
        module: "kernel32.dll".to_string(),
        symbol: ImportSymbol::ByName {
            hint: 0,
            name: "GetTickCount64".to_string(),
        },
        bound_value: 0xABC0,
        patched_value: 0xABC0,
        module_handle: 1,
    });
    let names: BTreeMap<String, u64> = [
        ("GetTickCount64".to_string(), 0xABC0),
        ("GetLastError".to_string(), 0xABC1),
        ("Sleep".to_string(), 0xABC2),
    ]
    .into_iter()
    .collect();

    let mut group = c.benchmark_group("jit_iat_dispatch");
    group.bench_function("patched_direct_bypass", |b| {
        b.iter(|| bb(table.record_dispatch(0xABC0)))
    });
    group.bench_function("generic_name_lookup", |b| {
        b.iter(|| bb(names.get("GetTickCount64").copied()))
    });
    group.finish();
    let metrics = table.metrics();
    eprintln!(
        "IAT_METRICS patched={} bypasses={} repatched={} invalidated={}",
        metrics.patched, metrics.dispatch_bypasses, metrics.repatched, metrics.invalidated
    );
}

fn bench_jit_inlined_api_dispatch(c: &mut Criterion) {
    use casa1::jit::{InlineApi, inline_api_for_target, register_inline_api_target};
    register_inline_api_target(0x9000, InlineApi::GetTickCount64);
    let names: BTreeMap<String, InlineApi> = [
        ("GetLastError".to_string(), InlineApi::GetLastError),
        ("GetTickCount64".to_string(), InlineApi::GetTickCount64),
        (
            "QueryPerformanceCounter".to_string(),
            InlineApi::QueryPerformanceCounter,
        ),
    ]
    .into_iter()
    .collect();

    let mut group = c.benchmark_group("jit_inlined_api_dispatch");
    group.bench_function("registered_target_lookup", |b| {
        b.iter(|| bb(inline_api_for_target(0x9000)))
    });
    group.bench_function("generic_name_lookup", |b| {
        b.iter(|| bb(names.get("GetTickCount64").copied()))
    });
    group.finish();
    eprintln!(
        "INLINE_API_STATS registered_targets=1 inline_metric_total={}",
        casa1::jit::inline_api_metrics().total
    );
}

// ---------------------------------------------------------------------------
// Performance gate: KPI collection and the defined Criterion subset
// ---------------------------------------------------------------------------

#[derive(Default)]
struct GateSliceTotals {
    blocks: u64,
    instructions: u64,
    dispatcher_exits: u64,
    native_chains: u64,
    indirect_ic_hits: u64,
    indirect_ic_misses: u64,
}

impl GateSliceTotals {
    fn add(&mut self, metrics: casa1::jit::SliceMetrics) {
        self.blocks += metrics.blocks_executed;
        self.instructions += metrics.instructions_executed;
        self.dispatcher_exits += metrics.dispatcher_exits;
        self.native_chains += metrics.native_chains;
        self.indirect_ic_hits += metrics.indirect_ic_hits;
        self.indirect_ic_misses += metrics.indirect_ic_misses;
    }

    fn dispatcher_exits_per_1000(&self) -> f64 {
        if self.instructions == 0 {
            0.0
        } else {
            self.dispatcher_exits as f64 * 1000.0 / self.instructions as f64
        }
    }

    fn native_chaining_rate(&self) -> f64 {
        if self.blocks == 0 {
            0.0
        } else {
            self.native_chains as f64 / self.blocks as f64
        }
    }

    fn indirect_ic_hit_rate(&self) -> f64 {
        let total = self.indirect_ic_hits + self.indirect_ic_misses;
        if total == 0 {
            0.0
        } else {
            self.indirect_ic_hits as f64 / total as f64
        }
    }
}

fn gate_kpi_ok(value: f64, unit: &str, direction: &str, source: &str) -> serde_json::Value {
    serde_json::json!({
        "available": true,
        "value": value,
        "unit": unit,
        "direction": direction,
        "source": source,
    })
}

fn gate_kpi_missing(reason: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "available": false, "reason": reason.into() })
}

fn gate_slice_workload(
    blocks: &[(u64, Vec<casa1::cpu::IrInstruction>)],
    entry: u64,
    stack: u64,
    register_value: Option<u64>,
    total_blocks: u64,
    budget: u64,
) -> Result<GateSliceTotals, String> {
    use casa1::cpu::{GuestArch, MemoryImage};
    use casa1::jit::WorkerSliceBenchmark;

    let mut memory = MemoryImage::default();
    memory.map_bytes(stack & !0xfff, &[0_u8; 0x1000]);
    let mut harness =
        WorkerSliceBenchmark::new(GuestArch::X64, &memory, blocks, entry, stack + 0x800);
    harness.reset();
    if let Some(value) = register_value {
        harness.set_rax(value);
    }
    let mut totals = GateSliceTotals::default();
    let mut done = 0_u64;
    while done < total_blocks {
        let (ran, _instructions, metrics) = harness.run(budget.min(total_blocks - done));
        totals.add(metrics);
        if ran == 0 {
            break;
        }
        done += ran;
    }
    Ok(totals)
}

fn gate_worker_kpis() -> Result<(GateSliceTotals, GateSliceTotals), String> {
    use casa1::cpu::{IrInstruction, Register};

    let call_return_blocks = vec![
        (
            0x1000_u64,
            vec![IrInstruction::Call {
                target: 0x2000,
                return_address: 0x1010,
            }],
        ),
        (0x1010, vec![IrInstruction::Jump { target: 0x1000 }]),
        (
            0x2000,
            vec![
                IrInstruction::AddImm {
                    dst: Register::Rcx,
                    value: 1,
                    width: 8,
                },
                IrInstruction::Return { stack_adjust: 0 },
            ],
        ),
    ];
    let indirect_blocks = vec![
        (
            0x1000_u64,
            vec![IrInstruction::CallRegister {
                src: Register::Rax,
                return_address: 0x1010,
            }],
        ),
        (0x1010, vec![IrInstruction::Jump { target: 0x1000 }]),
        (
            0x2000,
            vec![
                IrInstruction::AddImm {
                    dst: Register::Rcx,
                    value: 1,
                    width: 8,
                },
                IrInstruction::Return { stack_adjust: 0 },
            ],
        ),
    ];
    let call_return = gate_slice_workload(&call_return_blocks, 0x1000, 0x11_000, None, 4096, 512)?;
    let indirect =
        gate_slice_workload(&indirect_blocks, 0x1000, 0x12_000, Some(0x2000), 4096, 512)?;
    Ok((call_return, indirect))
}

fn gate_generic_helper_rate() -> Result<f64, String> {
    use casa1::cpu::{GuestArch, IrInstruction};
    use casa1::jit::{JitRuntime, jit_lowering_telemetry};

    let (native_before, fallback_before) = jit_lowering_telemetry();
    let mut runtime = JitRuntime::new(GuestArch::X64);
    let mut ir = vec![IrInstruction::Nop; 64];
    ir.push(IrInstruction::Hlt);
    runtime
        .get_or_compile(&ir, 0x2_0000_6000, GuestArch::X64, None)
        .map_err(|error| error.message.clone())?;
    let (native_after, fallback_after) = jit_lowering_telemetry();
    let native = native_after.saturating_sub(native_before);
    let fallback = fallback_after.saturating_sub(fallback_before);
    if native == 0 {
        return Err("JIT lowering telemetry recorded no instructions".to_string());
    }
    Ok(fallback as f64 / native as f64)
}

fn gate_high_address_metrics() -> Result<(f64, f64), String> {
    use casa1::cpu::{GuestArch, IrInstruction, MemoryImage, MemoryOperand, Register};
    use casa1::jit::{
        WorkerSliceBenchmark, guest_memory_telemetry, jit_execution_available,
        reset_guest_memory_telemetry,
    };

    if !jit_execution_available() {
        return Err("JIT execution capability is unavailable on this host".to_string());
    }
    let address = 0x2_0000_0000_u64;
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
    let blocks = vec![(
        0x1000_u64,
        vec![IrInstruction::LoadMemory {
            dst: Register::Rax,
            address: operand,
            width: 8,
        }],
    )];
    let mut memory = MemoryImage::default();
    memory.map_bytes(address, &[0_u8; 4096]);
    reset_guest_memory_telemetry();
    let mut harness = WorkerSliceBenchmark::new(GuestArch::X64, &memory, &blocks, 0x1000, 0);
    const ACCESSES: u64 = 4096;
    let mut executed = 0_u64;
    let mut instructions = 0_u64;
    for _ in 0..ACCESSES {
        harness.reset();
        let (ran, insns, _) = harness.run(1);
        if ran == 0 {
            break;
        }
        executed += ran;
        instructions += insns;
    }
    if executed == 0 || instructions == 0 {
        return Err("high-address worker slice did not execute the JIT block".to_string());
    }
    let after = guest_memory_telemetry();
    Ok((
        after.sync_operations as f64 * 1000.0 / instructions as f64,
        after.pages_materialised as f64 / executed as f64,
    ))
}

fn gate_thunk_generic_rate() -> Result<f64, String> {
    use casa1::jit::{FastThunkTable, reset_thunk_resolve_telemetry, thunk_resolve_telemetry};

    extern "C" fn gate_thunk_target() -> u64 {
        0x42
    }
    let mut table = FastThunkTable::new();
    let host_fn = gate_thunk_target as *const () as usize;
    let mut addresses = Vec::new();
    for index in 0..256u64 {
        let guest = 0x100_0000 + index * 0x10;
        table
            .register_with_guest_addr(host_fn, guest)
            .map_err(|error| error.message.clone())?;
        addresses.push(guest);
    }
    reset_thunk_resolve_telemetry();
    for _ in 0..64 {
        for guest in &addresses {
            let _ = table.find_thunk_by_guest(*guest);
        }
    }
    let (hits, misses) = thunk_resolve_telemetry();
    let total = hits + misses;
    if total == 0 {
        return Err("thunk-resolution telemetry recorded no lookups".to_string());
    }
    Ok(misses as f64 / total as f64)
}

fn gate_aot_hit_rate() -> Result<f64, String> {
    let (hits, misses, rejected) = casa1::jit::bench_aot_hits(8);
    if rejected != 0 {
        return Err(format!(
            "persistent AOT cache rejected {rejected} record(s)"
        ));
    }
    let total = hits + misses;
    if total == 0 {
        return Err("persistent AOT cache recorded no loads".to_string());
    }
    Ok(hits as f64 / total as f64)
}

fn gate_percentile(sorted: &[u64], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let index = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[index.min(sorted.len() - 1)] as f64
}

fn gate_low_fps(samples_ns: &[u64], fraction: f64) -> f64 {
    if samples_ns.is_empty() {
        return 0.0;
    }
    let mut sorted = samples_ns.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    let count = ((sorted.len() as f64 * fraction).ceil() as usize).max(1);
    let worst: u64 = sorted[..count].iter().sum();
    let average_ns = worst as f64 / count as f64;
    if average_ns == 0.0 {
        0.0
    } else {
        1_000_000_000.0 / average_ns
    }
}

struct GateFrameMetrics {
    present_latency_ns: Vec<u64>,
    interval_ns: Vec<u64>,
}

fn gate_frame_metrics() -> Result<GateFrameMetrics, String> {
    use casa1::gfx::{DxgiFormat, GraphicsBackend, SwapchainDesc};

    let mut backend = GraphicsBackend::new();
    let swapchain = backend
        .create_swapchain(SwapchainDesc {
            width: 320,
            height: 240,
            format: DxgiFormat::R8G8B8A8Unorm,
            buffer_count: 2,
        })
        .map_err(|error| error.message.clone())?;
    for _ in 0..128 {
        backend
            .present(swapchain, 1, false)
            .map_err(|error| error.message.clone())?;
    }
    let mut present_latency_ns = Vec::with_capacity(5_000);
    let mut interval_ns = Vec::with_capacity(5_000);
    for _ in 0..5_000 {
        let started = std::time::Instant::now();
        let result = backend
            .present(swapchain, 1, false)
            .map_err(|error| error.message.clone())?;
        present_latency_ns.push(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
        if result.frame_time_ns > 0 {
            interval_ns.push(result.frame_time_ns);
        }
    }
    Ok(GateFrameMetrics {
        present_latency_ns,
        interval_ns,
    })
}

fn gate_pso_metrics() -> Result<(f64, f64), String> {
    use casa1::metal_backend::MetalGpuBackend;

    let mut gpu = MetalGpuBackend::new().map_err(|error| error.message.clone())?;
    let source = r#"
#include <metal_stdlib>
using namespace metal;
kernel void casa1_perf_gate_kernel(device uint *out [[buffer(0)]], uint id [[thread_position_in_grid]]) {
    out[id] = id;
}
"#;
    let library = gpu
        .compile_shader(source)
        .map_err(|error| error.message.clone())?;
    let started = std::time::Instant::now();
    gpu.create_compute_pipeline("casa1_perf_gate_kernel", library)
        .map_err(|error| error.message.clone())?;
    let compile_us = started.elapsed().as_secs_f64() * 1_000_000.0;
    let started = std::time::Instant::now();
    gpu.create_compute_pipeline("casa1_perf_gate_kernel", library)
        .map_err(|error| error.message.clone())?;
    let hit_us = started.elapsed().as_secs_f64() * 1_000_000.0;
    Ok((compile_us, hit_us))
}

fn gate_encoder_switch_rate() -> Result<f64, String> {
    use casa1::perf::MetalCommandBatcher;

    let mut batcher = MetalCommandBatcher::new(128);
    const DRAWS: u64 = 4096;
    for index in 0..DRAWS {
        batcher.record_draw(index % 2, 3, 0, 1, 0, 0);
    }
    let stats = batcher.stats().clone();
    if stats.total_draw_calls == 0 {
        return Err("command batcher recorded no draws".to_string());
    }
    Ok(stats.pipeline_changes as f64 * 1000.0 / stats.total_draw_calls as f64)
}

fn gate_shader_stall_rates() -> Result<(f64, f64), String> {
    use casa1::shader::{
        CacheHeader, CachePayload, ShaderCache, ShaderCacheEntry, ShaderStage, compile_with_cache,
        shader_cache_key,
    };

    let input = bench_shader_input(make_bench_dxil(5, "cs_main"), ShaderStage::Cs);
    let requests = [input.clone(), input.clone()];
    let mut cache = ShaderCache::new(4 * 1024 * 1024);
    let cold = compile_with_cache(&requests, &mut cache);
    let cold_rate = cold.compile_stalls as f64 / requests.len() as f64;

    let key = shader_cache_key(&input).map_err(|error| error.message.clone())?;
    cache.insert(ShaderCacheEntry {
        header: CacheHeader {
            magic: "casa1-perf-gate".to_string(),
            version: 1,
            key,
            created_ts: 0,
            last_used_ts: 0,
        },
        payload: CachePayload {
            mtl_library_bytes: Vec::new(),
            reflection_json: "{}".to_string(),
            metal_pipeline_archive: None,
        },
        checksum: String::new(),
    });
    let warm = compile_with_cache(&requests, &mut cache);
    if warm.misses != 0 {
        return Err(format!(
            "warm shader-cache probe still missed {} of {} requests",
            warm.misses,
            requests.len()
        ));
    }
    let warm_rate = warm.compile_stalls as f64 / requests.len() as f64;
    Ok((cold_rate, warm_rate))
}

fn gate_upload_copy_rate() -> Result<f64, String> {
    use casa1::gfx::{
        BufferRole, DxgiFormat, GraphicsBackend, HeapType, ResourceDesc, ResourceState,
        ResourceUsageHint,
    };

    let mut backend = GraphicsBackend::new();
    let resource = backend
        .create_resource(ResourceDesc {
            name: "perf-gate-upload".to_string(),
            format: DxgiFormat::Unknown,
            heap: HeapType::Default,
            size: 4096,
            subresources: 1,
            initial_state: ResourceState::Common,
            usage_hint: ResourceUsageHint::Buffer {
                role: BufferRole::Constant,
                cpu_write_frequent: true,
            },
        })
        .map_err(|error| error.message.clone())?;
    for _ in 0..1000 {
        backend
            .update_resource_region(resource, 0, &[0x5A_u8; 64])
            .map_err(|error| error.message.clone())?;
    }
    let stats = backend.translation_stats();
    let total = stats.zero_copy_updates + stats.staged_copies;
    if total == 0 {
        return Err("resource updates recorded no copy path".to_string());
    }
    Ok(stats.staged_copies as f64 / total as f64)
}

fn gate_barrier_rate() -> Result<f64, String> {
    use casa1::gfx::{
        BufferRole, DxgiFormat, GraphicsBackend, HeapType, PipelineStateDesc, ResourceDesc,
        ResourceState, ResourceUsageHint, RootSignatureDesc,
    };

    let mut backend = GraphicsBackend::new();
    let make_resource = |backend: &mut GraphicsBackend, name: &str| {
        backend
            .create_resource(ResourceDesc {
                name: name.to_string(),
                format: DxgiFormat::Unknown,
                heap: HeapType::Default,
                size: 4096,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: BufferRole::Constant,
                    cpu_write_frequent: false,
                },
            })
            .map_err(|error| error.message.clone())
    };
    let resource_a = make_resource(&mut backend, "perf-gate-barrier-a")?;
    let resource_b = make_resource(&mut backend, "perf-gate-barrier-b")?;
    let allocator = backend.create_command_allocator();
    let root_signature = backend.create_root_signature(RootSignatureDesc::default());
    let pipeline = backend.create_pipeline_state(
        root_signature,
        PipelineStateDesc {
            label: "perf-gate-barriers".to_string(),
            compute: true,
            render_target_formats: Vec::new(),
            depth_format: None,
        },
    );
    let list = backend.create_graphics_command_list(allocator, pipeline, false);
    backend
        .record_uav_barrier(list, resource_a)
        .map_err(|error| error.message.clone())?;
    backend
        .record_copy_buffer_region(list, resource_a, 0, resource_b, 0, 8)
        .map_err(|error| error.message.clone())?;
    backend
        .record_uav_barrier(list, resource_a)
        .map_err(|error| error.message.clone())?;
    backend
        .record_aliasing_barrier(list, Some(resource_a), Some(resource_b))
        .map_err(|error| error.message.clone())?;
    backend
        .record_dispatch(list, 1, 1, 1)
        .map_err(|error| error.message.clone())?;
    backend
        .record_aliasing_barrier(list, Some(resource_a), Some(resource_b))
        .map_err(|error| error.message.clone())?;
    let stream = backend
        .close_command_list(list)
        .map_err(|error| error.message.clone())?;
    let analysis = backend
        .analyze_barriers(&[stream])
        .map_err(|error| error.message.clone())?;
    let required = analysis.barriers_required
        + analysis.uav_barriers_required
        + analysis.aliasing_barriers_required;
    let considered = analysis.barriers_considered
        + analysis.uav_barriers_considered
        + analysis.aliasing_barriers_considered;
    if considered == 0 {
        return Err("barrier analysis considered no barriers".to_string());
    }
    Ok(required as f64 * 1000.0 / considered as f64)
}

fn bench_gate_kpis(c: &mut Criterion) {
    use std::collections::BTreeMap;

    let mut metrics: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let jit_ready = casa1::jit::jit_execution_available();

    if jit_ready {
        match gate_worker_kpis() {
            Ok((call_return, indirect)) => {
                metrics.insert(
                    "dispatcher_exits_per_1000_instructions".to_string(),
                    gate_kpi_ok(
                        call_return.dispatcher_exits_per_1000(),
                        "exits/1000 IR instructions",
                        "lower",
                        "WorkerSliceBenchmark call/return chain (4096 blocks, budget 512)",
                    ),
                );
                metrics.insert(
                    "native_chaining_rate".to_string(),
                    gate_kpi_ok(
                        call_return.native_chaining_rate(),
                        "fraction of blocks",
                        "higher",
                        "WorkerSliceBenchmark call/return chain (4096 blocks, budget 512)",
                    ),
                );
                metrics.insert(
                    "indirect_ic_hit_rate".to_string(),
                    gate_kpi_ok(
                        indirect.indirect_ic_hit_rate(),
                        "fraction of indirect lookups",
                        "higher",
                        "WorkerSliceBenchmark monomorphic indirect call chain (4096 blocks, budget 512)",
                    ),
                );
            }
            Err(reason) => {
                for key in [
                    "dispatcher_exits_per_1000_instructions",
                    "native_chaining_rate",
                    "indirect_ic_hit_rate",
                ] {
                    metrics.insert(key.to_string(), gate_kpi_missing(reason.clone()));
                }
            }
        }
    } else {
        for key in [
            "dispatcher_exits_per_1000_instructions",
            "native_chaining_rate",
            "indirect_ic_hit_rate",
        ] {
            metrics.insert(
                key.to_string(),
                gate_kpi_missing("JIT execution capability is unavailable on this host"),
            );
        }
    }

    match gate_generic_helper_rate() {
        Ok(value) => {
            metrics.insert(
                "generic_helper_rate".to_string(),
                gate_kpi_ok(
                    value,
                    "fallback/native lowered IR instruction",
                    "lower",
                    "jit_lowering_telemetry over the gate translation corpus",
                ),
            );
        }
        Err(reason) => {
            metrics.insert("generic_helper_rate".to_string(), gate_kpi_missing(reason));
        }
    }

    match gate_high_address_metrics() {
        Ok((syncs, pages)) => {
            metrics.insert(
                "high_address_software_syncs_per_1000_instructions".to_string(),
                gate_kpi_ok(
                    syncs,
                    "sync operations/1000 instructions",
                    "lower",
                    "guest_memory_telemetry after 4096 JIT loads at guest 0x2_0000_0000",
                ),
            );
            metrics.insert(
                "high_address_guest_page_faults_per_access".to_string(),
                gate_kpi_ok(
                    pages,
                    "materialised pages/access after warm-up",
                    "lower",
                    "guest_memory_telemetry after 4096 JIT loads at guest 0x2_0000_0000",
                ),
            );
        }
        Err(reason) => {
            for key in [
                "high_address_software_syncs_per_1000_instructions",
                "high_address_guest_page_faults_per_access",
            ] {
                metrics.insert(key.to_string(), gate_kpi_missing(reason.clone()));
            }
        }
    }

    match gate_thunk_generic_rate() {
        Ok(value) => {
            metrics.insert(
                "thunk_generic_dispatch_rate".to_string(),
                gate_kpi_ok(
                    value,
                    "generic fallbacks/lookup",
                    "lower",
                    "thunk_resolve_telemetry over 256 registered guest thunk addresses",
                ),
            );
        }
        Err(reason) => {
            metrics.insert(
                "thunk_generic_dispatch_rate".to_string(),
                gate_kpi_missing(reason),
            );
        }
    }

    match gate_aot_hit_rate() {
        Ok(value) => {
            metrics.insert(
                "persistent_aot_hit_rate".to_string(),
                gate_kpi_ok(
                    value,
                    "hits/(hits+misses)",
                    "higher",
                    "JitRuntime::aot_metrics over 8 fresh runtime instances",
                ),
            );
        }
        Err(reason) => {
            metrics.insert(
                "persistent_aot_hit_rate".to_string(),
                gate_kpi_missing(reason),
            );
        }
    }

    match gate_frame_metrics() {
        Ok(frame) => {
            let mut sorted = frame.present_latency_ns.clone();
            sorted.sort_unstable();
            for (key, fraction, unit) in [
                ("frame_latency_p50_us", 0.50, "us"),
                ("frame_latency_p95_us", 0.95, "us"),
                ("frame_latency_p99_us", 0.99, "us"),
                ("frame_latency_p999_us", 0.999, "us"),
            ] {
                metrics.insert(
                    key.to_string(),
                    gate_kpi_ok(
                        gate_percentile(&sorted, fraction) / 1000.0,
                        unit,
                        "lower",
                        "GraphicsBackend::present wall-clock latency over 5000 presents (320x240)",
                    ),
                );
            }
            metrics.insert(
                "frame_latency_1pct_low_fps".to_string(),
                gate_kpi_ok(
                    gate_low_fps(&frame.present_latency_ns, 0.01),
                    "fps",
                    "higher",
                    "1% worst GraphicsBackend::present latencies over 5000 presents (320x240)",
                ),
            );
            metrics.insert(
                "frame_latency_0p1pct_low_fps".to_string(),
                gate_kpi_ok(
                    gate_low_fps(&frame.present_latency_ns, 0.001),
                    "fps",
                    "higher",
                    "0.1% worst GraphicsBackend::present latencies over 5000 presents (320x240)",
                ),
            );
            let mut intervals = frame.interval_ns.clone();
            intervals.sort_unstable();
            for (key, fraction, unit) in [
                ("frame_interval_p50_us", 0.50, "us"),
                ("frame_interval_p95_us", 0.95, "us"),
                ("frame_interval_p99_us", 0.99, "us"),
                ("frame_interval_p999_us", 0.999, "us"),
            ] {
                metrics.insert(
                    key.to_string(),
                    gate_kpi_ok(
                        gate_percentile(&intervals, fraction) / 1000.0,
                        unit,
                        "lower",
                        "PresentResult::frame_time_ns between consecutive presents (64x64)",
                    ),
                );
            }
        }
        Err(reason) => {
            for key in [
                "frame_latency_p50_us",
                "frame_latency_p95_us",
                "frame_latency_p99_us",
                "frame_latency_p999_us",
                "frame_latency_1pct_low_fps",
                "frame_latency_0p1pct_low_fps",
                "frame_interval_p50_us",
                "frame_interval_p95_us",
                "frame_interval_p99_us",
                "frame_interval_p999_us",
            ] {
                metrics.insert(key.to_string(), gate_kpi_missing(reason.clone()));
            }
        }
    }

    match gate_pso_metrics() {
        Ok((compile_us, hit_us)) => {
            metrics.insert(
                "pso_compile_us".to_string(),
                gate_kpi_ok(
                    compile_us,
                    "us",
                    "lower",
                    "MetalGpuBackend::create_compute_pipeline (first creation, cache miss)",
                ),
            );
            metrics.insert(
                "pso_cache_hit_us".to_string(),
                gate_kpi_ok(
                    hit_us,
                    "us",
                    "lower",
                    "MetalGpuBackend::create_compute_pipeline (identical key, cache hit)",
                ),
            );
        }
        Err(reason) => {
            for key in ["pso_compile_us", "pso_cache_hit_us"] {
                metrics.insert(key.to_string(), gate_kpi_missing(reason.clone()));
            }
        }
    }

    match gate_encoder_switch_rate() {
        Ok(value) => {
            metrics.insert(
                "encoder_switches_per_1000_draws".to_string(),
                gate_kpi_ok(
                    value,
                    "pipeline-state switches/1000 draws",
                    "lower",
                    "MetalCommandBatcher over 4096 alternating-pipeline draws",
                ),
            );
        }
        Err(reason) => {
            metrics.insert(
                "encoder_switches_per_1000_draws".to_string(),
                gate_kpi_missing(reason),
            );
        }
    }

    match gate_shader_stall_rates() {
        Ok((cold, hot)) => {
            metrics.insert(
                "shader_compile_stall_rate_cold".to_string(),
                gate_kpi_ok(
                    cold,
                    "stalls/request",
                    "lower",
                    "shader::compile_with_cache over two cache-cold requests",
                ),
            );
            metrics.insert(
                "shader_compile_stall_rate_warm".to_string(),
                gate_kpi_ok(
                    hot,
                    "stalls/request",
                    "lower",
                    "shader::compile_with_cache over two cache-warm requests",
                ),
            );
        }
        Err(reason) => {
            for key in [
                "shader_compile_stall_rate_cold",
                "shader_compile_stall_rate_warm",
            ] {
                metrics.insert(key.to_string(), gate_kpi_missing(reason.clone()));
            }
        }
    }

    match gate_upload_copy_rate() {
        Ok(value) => {
            metrics.insert(
                "gfx_staged_upload_copy_rate".to_string(),
                gate_kpi_ok(
                    value,
                    "staged copies/(zero-copy+staged)",
                    "lower",
                    "GraphicsBackend::translation_stats over 1000 dynamic-buffer updates",
                ),
            );
        }
        Err(reason) => {
            metrics.insert(
                "gfx_staged_upload_copy_rate".to_string(),
                gate_kpi_missing(reason),
            );
        }
    }

    match gate_barrier_rate() {
        Ok(value) => {
            metrics.insert(
                "gfx_barriers_required_per_1000_considered".to_string(),
                gate_kpi_ok(
                    value,
                    "required barriers/1000 considered",
                    "lower",
                    "GraphicsBackend::analyze_barriers over a mixed UAV/aliasing/copy stream",
                ),
            );
        }
        Err(reason) => {
            metrics.insert(
                "gfx_barriers_required_per_1000_considered".to_string(),
                gate_kpi_missing(reason),
            );
        }
    }

    {
        use casa1::cpu::{CpuState, GuestArch, IrInstruction, MemoryImage, execute_ir};
        let instructions = vec![IrInstruction::Nop; 1024];
        let mut state = CpuState::new(GuestArch::X64);
        let mut memory = MemoryImage::default();
        for _ in 0..8 {
            let _ = execute_ir(&mut state, &mut memory, &instructions);
        }
        const ITERATIONS: u64 = 1000;
        let started = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            let _ = execute_ir(&mut state, &mut memory, &instructions);
        }
        let seconds = started.elapsed().as_secs_f64();
        if seconds > 0.0 {
            let mips = (ITERATIONS as f64 * instructions.len() as f64) / seconds / 1_000_000.0;
            metrics.insert(
                "legacy_dispatch_mips".to_string(),
                gate_kpi_ok(
                    mips,
                    "M guest instructions/s",
                    "higher",
                    "execute_ir NOP dispatch, 1024-instruction block, 1000 iterations",
                ),
            );
        } else {
            metrics.insert(
                "legacy_dispatch_mips".to_string(),
                gate_kpi_missing("legacy dispatch measurement elapsed in zero time"),
            );
        }
    }

    for (key, reason) in [
        (
            "gpu_idle_gap_us",
            "no GPU completion-timestamp history is retained; the queue exposes drain callbacks only, so inter-frame GPU idle gaps cannot be measured without a new timestamp query path",
        ),
        (
            "residency_churn_per_1000_frames",
            "MTLResidencySet exposes membership and allocated size but no add/remove event counter, and the backend does not record commit churn",
        ),
        (
            "gpu_heap_faults_per_1000_frames",
            "Metal does not expose MTLHeap page-fault counts; the backend tracks staging fallbacks, not GPU page faults",
        ),
    ] {
        metrics.insert(key.to_string(), gate_kpi_missing(reason));
    }

    {
        use casa1::cpu::GuestArch;
        use casa1::jit::JitRuntime;
        let blocks = tier2_loop_blocks(1000);
        let mut runtime = JitRuntime::new(GuestArch::X64);
        let _ = runtime.get_or_compile_function_tier2(&blocks, GuestArch::X64);
        let metrics = casa1::jit_ssa::tier2_metrics();
        let hit_rate = if metrics.functions_compiled + metrics.functions_fallback == 0 {
            0.0
        } else {
            metrics.functions_compiled as f64
                / (metrics.functions_compiled + metrics.functions_fallback) as f64
        };
        eprintln!(
            "TIER2_HOT_LOOP hit_rate={:.3} compiled={} fallbacks={} blocks={} sccp={} gvn={} dce={} licm={} load_fwd={} store_elim={} spills={}",
            hit_rate,
            metrics.functions_compiled,
            metrics.functions_fallback,
            metrics.blocks,
            metrics.sccp_eliminated,
            metrics.gvn_eliminated,
            metrics.dce_eliminated,
            metrics.licm_hoisted,
            metrics.load_forwarded,
            metrics.store_eliminated,
            metrics.register_spills,
        );
    }
    {
        use casa1::pe::ImportSymbol;
        use casa1::runtime::{IatPatchEntry, IatPatchTable};
        let mut table = IatPatchTable::default();
        table.patch(IatPatchEntry {
            slot_va: 0x5000_1000,
            selected_base: 0x5000_0000,
            iat_rva: 0x1000,
            module: "kernel32.dll".to_string(),
            symbol: ImportSymbol::ByName {
                hint: 0,
                name: "GetTickCount64".to_string(),
            },
            bound_value: 0xABC0,
            patched_value: 0xABC0,
            module_handle: 1,
        });
        let _ = table.record_dispatch(0xABC0);
        let metrics = table.metrics();
        eprintln!(
            "IAT_METRICS patched={} bypasses={} repatched={} invalidated={}",
            metrics.patched, metrics.dispatch_bypasses, metrics.repatched, metrics.invalidated
        );
    }
    {
        use casa1::jit::{
            InlineApi, inline_api_for_target, inline_api_metrics, register_inline_api_target,
        };
        register_inline_api_target(0x9100, InlineApi::GetTickCount64);
        eprintln!(
            "INLINE_API_STATS registered_targets={} inline_metric_total={}",
            u64::from(inline_api_for_target(0x9100).is_some()),
            inline_api_metrics().total
        );
    }

    let document = serde_json::json!({
        "schema": 1,
        "generated_at": format!("{:?}", std::time::SystemTime::now()),
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "metrics": metrics,
    });
    let text = serde_json::to_string(&document).unwrap_or_else(|_| "{}".to_string());
    if let Ok(path) = std::env::var("CASA1_PERF_KPI_OUT") {
        let _ = std::fs::write(path, &text);
    }
    eprintln!("CASA1_PERF_KPI {text}");

    let mut group = c.benchmark_group("gate/kpi");
    group.sample_size(20);
    group.warm_up_time(std::time::Duration::from_millis(100));
    group.measurement_time(std::time::Duration::from_millis(500));

    {
        use casa1::cpu::{CpuState, GuestArch, IrInstruction, MemoryImage, execute_ir};
        let instructions = vec![IrInstruction::Nop; 1024];
        group.bench_function("cpu_dispatch_nop_1024", |b| {
            let mut state = CpuState::new(GuestArch::X64);
            let mut memory = MemoryImage::default();
            b.iter(|| bb(execute_ir(&mut state, &mut memory, &instructions).is_ok()))
        });
    }

    {
        use casa1::perf::{GpuUploadStreamer, MetalCommandBatcher};
        group.bench_function("gfx_upload_allocate_64k", |b| {
            let mut streamer = GpuUploadStreamer::new(64 * 1024 * 128);
            let buffer = streamer.create_streaming_buffer(64 * 1024 * 128);
            b.iter(|| {
                streamer.advance_frame();
                bb(streamer.allocate(buffer, 64 * 1024).is_ok())
            })
        });
        group.bench_function("gfx_command_batch_128", |b| {
            b.iter_with_setup(
                || MetalCommandBatcher::new(128),
                |mut batcher| {
                    for index in 0..384 {
                        batcher.record_draw(index % 3, 3, 0, 1, 0, 0);
                    }
                    bb(batcher.drain_batches().len())
                },
            )
        });
    }

    {
        use casa1::pe::parse;
        let pe = minimal_pe();
        group.bench_function("pe_parse_minimal", |b| b.iter(|| bb(parse(&pe).is_ok())));
    }

    {
        use casa1::gfx::{DxgiFormat, GraphicsBackend, SwapchainDesc};
        let mut backend = GraphicsBackend::new();
        let swapchain = backend
            .create_swapchain(SwapchainDesc {
                width: 64,
                height: 64,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("perf gate swapchain");
        group.bench_function("frame_present_64x64", |b| {
            b.iter(|| bb(backend.present(swapchain, 1, false).is_ok()))
        });
    }

    {
        use casa1::jit::FastThunkTable;
        extern "C" fn gate_bench_thunk_target() -> u64 {
            0x42
        }
        let mut table = FastThunkTable::new();
        let host_fn = gate_bench_thunk_target as *const () as usize;
        let mut addresses = Vec::new();
        for index in 0..256u64 {
            let guest = 0x200_0000 + index * 0x10;
            table
                .register_with_guest_addr(host_fn, guest)
                .expect("register perf gate thunk");
            addresses.push(guest);
        }
        group.bench_function("thunk_resolve_256", |b| {
            b.iter(|| {
                let mut acc = 0usize;
                for guest in &addresses {
                    acc = acc.wrapping_add(table.find_thunk_by_guest(bb(*guest)).unwrap_or(0));
                }
                bb(acc)
            })
        });
    }

    {
        use casa1::shader::{ShaderCache, ShaderStage, compile_with_cache};
        let input = bench_shader_input(make_bench_dxil(5, "cs_main"), ShaderStage::Cs);
        let requests = [input];
        let mut cache = ShaderCache::new(4 * 1024 * 1024);
        let _ = compile_with_cache(&requests, &mut cache);
        group.bench_function("shader_cache_hit", |b| {
            b.iter(|| bb(compile_with_cache(&requests, &mut cache)))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_gate_kpis,
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
    bench_jit_worker_call_return,
    bench_jit_worker_indirect,
    bench_jit_worker_control_caches,
    bench_jit_native_linking,
    bench_jit_conditional_branch_heavy,
    bench_jit_aot_cache,
    bench_jit_tier2_hot_loop,
    bench_jit_iat_dispatch,
    bench_jit_inlined_api_dispatch,
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
    // Interpreter memory model (on-demand page materialisation)
    bench_cpu_memory_sync_sparse,
    bench_cpu_memory_above_four_gib,
    bench_jit_thunk_resolve,
    // Interpreter lazy flag materialisation
    bench_cpu_lazy_flags_alu_chain,
    // 12. Memory Usage Tracking
    bench_memory_usage_tracking,
    // 13. Stress / Leak Tests
    bench_stress_audio_create_destroy,
    bench_stress_network_create_destroy,
    bench_stress_pe_parse_loop,
    bench_stress_host_thunk_validations,
);

criterion_main!(benches);
