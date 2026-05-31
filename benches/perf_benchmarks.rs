//! Extended Criterion benchmarks for the Casa1 performance infrastructure.
//!
//! Covers 5 categories:
//! 1. CPU Engine Throughput — decode, lower-to-IR, and execute pipelines
//! 2. JIT Cache Optimization — compile tiers, constant folding, inline cache
//! 3. PE Loading — parse, section enumeration, import resolution
//! 4. Graphics Pipeline — command batching, shader compiler, upload streaming
//! 5. Startup-to-First-Frame — composite pipeline benchmark

use criterion::{criterion_group, criterion_main, Criterion};
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
/// MOVUPS XMM0, XMM1 (3 bytes: 0F 10 C1) + ADDPS XMM0, XMM1 (3 bytes: 0F 58 C1)
fn simd_block(count: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(count * 6);
    for _ in 0..count {
        bytes.extend_from_slice(&[0x0F, 0x10, 0xC1]); // MOVUPS XMM0, XMM1
        bytes.extend_from_slice(&[0x0F, 0x58, 0xC1]); // ADDPS XMM0, XMM1
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

/// Build a PE with many (empty) sections to stress section-table parsing.
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

    // Optional header (minimal)
    pe.extend_from_slice(&0x020Bu16.to_le_bytes()); // PE32+ magic
    pe.extend_from_slice(&[0; 86]); // minimal optional header padding
    // Data directory entries (16 × 8 = 128 bytes)
    for _ in 0..16 {
        pe.extend_from_slice(&0u32.to_le_bytes());
        pe.extend_from_slice(&0u32.to_le_bytes());
    }

    // Section table entries
    for i in 0..count {
        let name = format!(".sec{i:03}\0");
        let name_bytes = name.as_bytes();
        let mut section_name = [0u8; 8];
        section_name[..name_bytes.len().min(8)].copy_from_slice(&name_bytes[..name_bytes.len().min(8)]);
        pe.extend_from_slice(&section_name);
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // virtual size
        pe.extend_from_slice(&(0x1000 + (i as u32 * 0x1000)).to_le_bytes()); // VA
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // raw data size
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // raw data ptr
        pe.extend_from_slice(&0u32.to_le_bytes()); // relocs ptr
        pe.extend_from_slice(&0u32.to_le_bytes()); // linenumbers ptr
        pe.extend_from_slice(&0u16.to_le_bytes()); // num relocs
        pe.extend_from_slice(&0u16.to_le_bytes()); // num linenumbers
        pe.extend_from_slice(&0x60000020u32.to_le_bytes()); // characteristics
    }

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
        group.bench_function(format!("{size}_bytes"), |b| {
            b.iter(|| {
                let decoded = casa1::cpu::decode_block(bb(&code), bb(0x1000), bb(arch));
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
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter(|| {
                let decoded = casa1::cpu::decode_block(bb(&code), bb(0x1000), bb(arch));
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
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter(|| {
                let decoded = casa1::cpu::decode_block(bb(&code), bb(0x1000), bb(arch));
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
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter(|| {
                let decoded = casa1::cpu::decode_block(bb(&code), bb(0x1000), bb(arch));
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
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter(|| {
                let ir = casa1::cpu::lower_to_ir(bb(&decoded));
                bb(ir)
            })
        });
    }
    group.finish();
}

fn bench_cpu_full_pipeline(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let engine = casa1::cpu::CpuExecutionEngine::new(
        casa1::cpu::CpuEngineConfig {
            arch,
            os_build: "bench".into(),
            macwin_version: "0.0.0".into(),
            virtualization: casa1::cpu::CpuVirtualization::from_profile(arch, None).unwrap(),
        },
    );
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
                    let result = engine.execute_ir(bb(&mut state), bb(&mut memory), bb(&ir));
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
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter_with_setup(
                || casa1::jit::JitCompiler::new(),
                |mut compiler| {
                    let result = compiler.compile_tier0(bb(&ir), bb(0x1000), bb(arch), bb(None));
                    bb(result)
                },
            )
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
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter_with_setup(
                || casa1::jit::JitCompiler::new(),
                |mut compiler| {
                    let result = compiler.compile_tier1(bb(&ir), bb(0x1000), bb(arch), bb(None));
                    bb(result)
                },
            )
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
        group.bench_function(format!("{count}_insns"), |b| {
            b.iter_with_setup(
                || casa1::jit::JitCompiler::new(),
                |mut compiler| {
                    let result = compiler.compile_tier2(bb(&ir), bb(0x1000), bb(arch), bb(None));
                    bb(result)
                },
            )
        });
    }
    group.finish();
}

fn bench_jit_constant_folding(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("jit/optimiser/constant_fold");
    for count in [10usize, 100, 500] {
        // Build MOV EAX, imm32 chains — each successive MOV EAX overwrites the
        // previous, producing dead assignments that constant folding resolves.
        let code = mov_eax_block(count);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode");
        let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower");
        // Compile with tier1 (includes constant folding pass internally)
        group.bench_function(format!("tier1_{count}_insns"), |b| {
            b.iter_with_setup(
                || casa1::jit::JitCompiler::new(),
                |mut compiler| {
                    let result = compiler.compile_tier1(bb(&ir), bb(0x1000), bb(arch), bb(None));
                    bb(result)
                },
            )
        });
    }
    group.finish();
}

fn bench_jit_dead_code_elimination(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let mut group = c.benchmark_group("jit/optimiser/dce");
    for count in [10usize, 100, 500] {
        // Build dead_eax_block: each triplet has a dead MOV EAX that is
        // immediately overwritten — DCE eliminates the first assignment.
        let code = dead_eax_block(count);
        let decoded = casa1::cpu::decode_block(&code, 0x1000, arch).expect("decode");
        let ir = casa1::cpu::lower_to_ir(&decoded).expect("lower");
        // Compile with tier1 (includes constant folding + DCE passes internally)
        group.bench_function(format!("tier1_{count}_insns"), |b| {
            b.iter_with_setup(
                || casa1::jit::JitCompiler::new(),
                |mut compiler| {
                    let result = compiler.compile_tier1(bb(&ir), bb(0x1000), bb(arch), bb(None));
                    bb(result)
                },
            )
        });
    }
    group.finish();
}

fn bench_jit_tier_promotion(c: &mut Criterion) {
    let mut group = c.benchmark_group("jit/tier_promotion");
    let mut compiler = casa1::jit::TieredCompiler::with_thresholds(10, 50);

    group.bench_function("100_blocks_x_100_execs", |b| {
        b.iter(|| {
            for i in 0..100 {
                let addr = 0x1000 + (i as u64 * 0x100);
                for _ in 0..100 {
                    let _tier = compiler.record_execution(bb(addr));
                }
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
            b.iter(|| {
                // Mix of hits (repeated call sites) and misses
                for i in 0..max_entries * 4 {
                    let call_site = 0x1000 + (i as u64 * 0x40);
                    let target = 0x8000_0000 + ((i as u64 % max_entries as u64) * 0x100);
                    let hit = ic.lookup(bb(call_site), bb(target));
                    bb(hit);
                }
                bb(ic.hit_rate())
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

    group.bench_function("parse", |b| {
        b.iter(|| {
            let parsed = casa1::pe::parse(bb(&pe_data));
            bb(parsed)
        })
    });
    group.finish();
}

fn bench_pe_parse_many_sections(c: &mut Criterion) {
    let mut group = c.benchmark_group("pe/parse/many_sections");
    for count in [5usize, 20, 100] {
        let pe_data = many_sections_pe(count);
        group.bench_function(format!("{count}_sections"), |b| {
            b.iter(|| {
                let parsed = casa1::pe::parse(bb(&pe_data));
                bb(parsed)
            })
        });
    }
    group.finish();
}

fn bench_pe_parse_and_map(c: &mut Criterion) {
    let mut group = c.benchmark_group("pe/parse_and_map");
    let pe_data = minimal_pe();

    group.bench_function("parse_then_map", |b| {
        b.iter_with_setup(
            || {
                let parsed = casa1::pe::parse(&pe_data).expect("parse");
                parsed
            },
            |parsed| {
                let mapped = casa1::pe::map_image(bb(&pe_data), bb(&parsed), "bench", bb(false));
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
                            bb(3),           // vertex_count
                            bb(0),           // index_count
                            bb(1),           // instance_count
                            bb(0),           // start_vertex
                            bb(0),           // base_index
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

    let mut group = c.benchmark_group("gfx/shader_compiler/submit");
    for concurrent in [4usize, 16, 64] {
        group.bench_function(format!("{concurrent}_concurrent"), |b| {
            b.iter_with_setup(
                || ParallelShaderCompiler::new(concurrent),
                |mut compiler| {
                    for i in 0..concurrent * 2 {
                        let id = compiler.submit_job(
                            bb(format!("sha256:{i}")),
                            bb("vs".into()),
                            bb("main".into()),
                        );
                        let _ = compiler.mark_compiling(bb(id));
                    }
                    bb(compiler.pending_jobs().len())
                },
            )
        });
    }
    group.finish();
}

fn bench_gfx_upload_streaming(c: &mut Criterion) {
    use casa1::perf::GpuUploadStreamer;

    let mut group = c.benchmark_group("gfx/upload_streaming");
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
                    let offset = streamer.allocate(bb(buf_id), bb(alloc_size));
                    bb(offset)
                },
            )
        });
    }
    group.finish();
}

// ===========================================================================
// 5.  STARTUP-TO-FIRST-FRAME BENCHMARK
// ===========================================================================

/// Composite benchmark exercising the full decode→lower→compile→execute
/// pipeline that represents a "first frame" of emulated execution.
fn bench_startup_full_pipeline(c: &mut Criterion) {
    let arch = casa1::cpu::GuestArch::X64;
    let engine = casa1::cpu::CpuExecutionEngine::new(
        casa1::cpu::CpuEngineConfig {
            arch,
            os_build: "bench".into(),
            macwin_version: "0.0.0".into(),
            virtualization: casa1::cpu::CpuVirtualization::from_profile(arch, None).unwrap(),
        },
    );

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

    group.bench_function("decode_lower_execute", |b| {
        b.iter_with_setup(
            || {
                let state = casa1::cpu::CpuState::new(arch);
                let memory = casa1::cpu::MemoryImage::default();
                (state, memory)
            },
            |(mut state, mut memory)| {
                // Phase 1: Decode
                let decoded = casa1::cpu::decode_block(bb(&code), bb(0x1000), bb(arch))
                    .expect("decode");
                // Phase 2: Lower to IR
                let ir = casa1::cpu::lower_to_ir(bb(&decoded)).expect("lower");
                // Phase 3: Execute (interpretation)
                let result = engine.execute_ir(bb(&mut state), bb(&mut memory), bb(&ir));
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
        b.iter_with_setup(
            || casa1::jit::JitCompiler::new(),
            |mut compiler| {
                // Simulate adaptive tier progression
                let _t0 = compiler.compile_tier0(bb(&ir), bb(0x1000), bb(arch), bb(None));
                let _t1 = compiler.compile_tier1(bb(&ir), bb(0x1000), bb(arch), bb(None));
                let _t2 = compiler.compile_tier2(bb(&ir), bb(0x1000), bb(arch), bb(None));
                bb(())
            },
        )
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
            || {
                let parsed = casa1::pe::parse(&pe_data).expect("parse");
                parsed
            },
            |parsed| {
                // Parse again (cold path)
                let parsed2 = casa1::pe::parse(bb(&pe_data)).expect("parse");
                let mapped = casa1::pe::map_image(bb(&pe_data), bb(&parsed2), "bench", bb(false));
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
    // 5. Startup-to-First-Frame
    bench_startup_full_pipeline,
    bench_startup_adaptive_jit,
    bench_startup_pe_load_and_prepare,
    bench_startup_perf_subsystems,
);

criterion_main!(benches);
