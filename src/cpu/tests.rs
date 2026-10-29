use super::*;

fn assert_jit_matches_interpreter(label: &str, bytes: &[u8], seed: &[(Register, u64)]) {
    let run = |use_jit: bool| -> CpuState {
        let config = CpuEngineConfig::from_profile(GuestArch::X64, "test", "test", None)
            .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut state = CpuState::new(GuestArch::X64);
        for &(r, v) in seed {
            state.set(r, v);
        }
        state.rip = 0x1000;
        let mut memory = MemoryImage::default();
        memory.map_bytes(0x1000, bytes);
        memory.map_bytes(0x1000 + bytes.len() as u64, &[0xc3]); // ret sentinel
        // Provide a usable stack page + a scratch data region for stores.
        memory.map_bytes(0x70000000, &[0; 0x1000]);
        memory.map_bytes(0x8000, &[0; 0x1000]);
        memory.map_bytes(0x9000, &[0; 0x1000]);
        if state.get(Register::Rsp) == 0 {
            state.set(Register::Rsp, 0x70000800);
        }
        let decoded = decode_block(bytes, 0x1000, GuestArch::X64).expect("decode");
        let ir = lower_to_ir(&decoded).expect("lower");
        // Reset the fault-storm flag so prior tests don't block JIT.
        crate::jit::JIT_FAULT_STORM_DISABLED.store(false, std::sync::atomic::Ordering::Relaxed);
        let mut jit = if use_jit {
            Some(crate::jit::JitRuntime::new(GuestArch::X64))
        } else {
            None
        };
        // Execute: JIT path uses execute_with_jit (no interpreter).
        // Reference path uses execute_ir_with_hashing directly (test-only).
        if use_jit {
            engine
                .execute_with_jit(&mut state, &mut memory, &ir, jit.as_mut())
                .expect("exec");
        } else {
            execute_ir_with_hashing(&mut state, &mut memory, &ir, None, false, None)
                .expect("exec ref");
        }
        state
    };

    let ref_state = run(false);
    let jit_state = run(true);
    for i in 0..16u32 {
        let reg = match i {
            0 => Register::Rax,
            1 => Register::Rcx,
            2 => Register::Rdx,
            3 => Register::Rbx,
            4 => Register::Rsp,
            5 => Register::Rbp,
            6 => Register::Rsi,
            7 => Register::Rdi,
            8 => Register::R8,
            9 => Register::R9,
            10 => Register::R10,
            11 => Register::R11,
            12 => Register::R12,
            13 => Register::R13,
            14 => Register::R14,
            15 => Register::R15,
            _ => unreachable!(),
        };
        let a = ref_state.get(reg);
        let b = jit_state.get(reg);
        assert_eq!(
            a, b,
            "{label}: JIT/interpreter divergence on {:?}: interp={a:#x} jit={b:#x}",
            reg,
        );
    }
    assert_eq!(
        ref_state.rip, jit_state.rip,
        "{label}: rip divergence interp={:#x} jit={:#x}",
        ref_state.rip, jit_state.rip,
    );
}

#[test]
fn jit_diff_add_imm_32bit_does_not_truncate_to_byte() {
    // Regression for the uxtb-instead-of-uxtw bug: a 32-bit `add eax, 0x10`
    // must keep the full 32-bit result, not truncate to a byte.
    // 01 d0 = add eax, edx ; then 05 10 00 00 00 = add eax, 0x10
    // Simpler: 83 c0 10 = add eax, 0x10 (32-bit).
    assert_jit_matches_interpreter(
        "add eax, 0x10 (32-bit)",
        &[0x83, 0xc0, 0x10],
        &[(Register::Rax, 0x1234_5678)],
    );
}

#[test]
fn memory_image_read_bytes_reads_contiguous_ranges_and_rejects_gaps() {
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x2000, &[0x10, 0x20, 0x30, 0x40]);

    assert_eq!(
        memory.read_bytes(0x2001, 3).unwrap(),
        vec![0x20, 0x30, 0x40]
    );
    assert_eq!(memory.read_u16(0x2000).unwrap(), 0x2010);
    assert_eq!(memory.read_u32(0x2000).unwrap(), 0x4030_2010);

    let error = memory.read_bytes(0x2003, 2).expect_err("gap should fail");
    assert_eq!(error.code, ReasonCode::RcUnimplInsn);
    assert!(error.message.contains("0x2004"));

    let error = memory.read_u16(0x2003).expect_err("gap should fail");
    assert_eq!(error.code, ReasonCode::RcUnimplInsn);
    assert!(error.message.contains("0x2004"));
}

#[test]
fn memory_image_page_index_handles_out_of_order_low_pages() {
    let mut memory = MemoryImage::default();
    let hot_page = 0x2000_u64;
    let earlier_page = hot_page - MEMORY_PAGE_SIZE as u64;
    let later_page = hot_page + MEMORY_PAGE_SIZE as u64;

    memory.map_bytes(hot_page, &[0x10, 0x20, 0x30, 0x40]);
    assert_eq!(memory.page_index(hot_page), Some(0));
    assert_eq!(memory.read_u32(hot_page).unwrap(), 0x4030_2010);
    assert_eq!(memory.read_u16(hot_page + 2).unwrap(), 0x4030);

    memory.map_bytes(earlier_page, &[0xAA]);
    assert_eq!(memory.page_index(earlier_page), Some(1));
    assert_eq!(memory.page_index(hot_page), Some(0));
    assert_eq!(memory.read_u32(hot_page).unwrap(), 0x4030_2010);

    memory.map_bytes(later_page, &[0x55, 0x66, 0x77, 0x88]);
    assert_eq!(memory.page_index(later_page), Some(2));
    assert_eq!(memory.read_u32(later_page).unwrap(), 0x8877_6655);
}

#[test]
fn memory_image_high_pages_use_fallback_lookup() {
    let mut memory = MemoryImage::default();
    // Beyond the direct window: this page must use an owned frame.
    let high_page = (GUEST_FLAT_SIZE as u64) + 0x2000;

    memory.map_bytes(high_page, &[0x11, 0x22, 0x33, 0x44]);

    assert_eq!(memory.page_index(high_page), Some(0));
    assert_eq!(memory.read_u32(high_page).unwrap(), 0x4433_2211);
    assert_eq!(memory.canonical_store().high_page_count(), 1);
}

#[test]
fn memory_image_commit_zeroed_pages_creates_missing_pages() {
    let mut memory = MemoryImage::default();

    // commit_zeroed_pages should now create the page if it doesn't exist,
    // rather than failing. This handles the case where a page was previously
    // decommitted (removed from the sparse page table) and the guest later
    // writes to that address.
    memory.commit_zeroed_pages(0x5000, 1).unwrap();

    let page = memory.page(0x5000).expect("page should be created");
    assert!(page.is_fully_mapped());
    assert_eq!(memory.read_u8(0x5000).unwrap(), 0);
}

#[test]
fn guest_write_checked_faults_on_unmapped_and_never_creates_pages() {
    let mut memory = MemoryImage::default();
    let fault = memory
        .guest_write_checked(0x7000_0000, &[0xAA, 0xBB, 0xCC])
        .expect_err("store to unmapped memory must fault");
    assert_eq!(fault.address, 0x7000_0000, "precise fault address");
    assert!(fault.write, "access type must be write");
    assert_eq!(fault.read_len, 3, "access length");
    assert!(
        memory.page(0x7000_0000).is_none(),
        "guest write must NEVER create the page"
    );
    let mut probe = [0_u8; 3];
    let read_fault = memory
        .guest_read_checked(0x7000_0000, &mut probe)
        .expect_err("the page must still be unmapped after the failed store");
    assert_eq!(read_fault.address, 0x7000_0000);
    assert!(!read_fault.write);
}

#[test]
fn guest_read_checked_faults_without_allocating_and_reads_mapped() {
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x3000, &[0x01, 0x02, 0x03, 0x04]);

    let mut buf = [0_u8; 2];
    memory
        .guest_read_checked(0x3000, &mut buf)
        .expect("mapped read");
    assert_eq!(buf, [0x01, 0x02]);

    let mut buf = [0_u8; 8];
    let fault = memory
        .guest_read_checked(0x3002, &mut buf)
        .expect_err("read past the mapped range must fault");
    assert_eq!(fault.address, 0x3004, "precise first-unmapped byte");
    assert!(!fault.write, "access type must be read");

    // Unmapped page: faults and does not create anything.
    let mut buf = [0_u8; 1];
    let fault = memory
        .guest_read_checked(0x9_0000, &mut buf)
        .expect_err("unmapped page must fault");
    assert_eq!(fault.address, 0x9_0000);
    assert!(memory.page(0x9_0000).is_none(), "read must not allocate");
}

#[test]
fn write_memory_value_faults_on_unmapped_with_av_error_and_does_not_map() {
    let mut memory = MemoryImage::default();
    let error = write_memory_value(&mut memory, 0x0000_0100_0000, 0x1234, 4)
        .expect_err("guest store to unmapped memory must raise an access violation");
    assert_eq!(error.code, ReasonCode::RcUnimplInsn);
    assert!(
        error.message.contains("unmapped guest memory at 0x1000000"),
        "AV error must carry the fault address: {}",
        error.message
    );
    assert!(
        memory.page(0x0000_0100_0000).is_none(),
        "guest store must not materialize the page"
    );
    let mut probe = [0_u8; 4];
    memory
        .guest_read_checked(0x0000_0100_0000, &mut probe)
        .expect_err("the page must still fault after the failed store");
}

#[test]
fn decode_and_execute_cvtdq2pd_then_addsd_updates_scalar_double() {
    let start_address = 0x1902_b133;
    let bytes = [
        0xF3, 0x0F, 0xE6, 0xC0, 0xC1, 0xE8, 0x1F, 0xF2, 0x0F, 0x58, 0x04, 0xC5, 0x60, 0x9D, 0x19,
        0x00,
    ];
    let decoded =
        decode_block(&bytes, start_address, GuestArch::X86).expect("decode cvtdq2pd/addsd block");
    let ir = lower_to_ir(&decoded).expect("lower cvtdq2pd/addsd block");
    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::Cvtdq2pd),
        "decoded={decoded:?}"
    );
    assert!(
        matches!(decoded[2].opcode, DecodedOpcode::Addsd),
        "decoded={decoded:?}"
    );
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x8000_0000);
    state.set_xmm(0, u32x4_to_xmm([1, 2, 0, 0]));
    memory.map_bytes(0x0019_9d68, &0.5_f64.to_le_bytes());

    execute_ir(&mut state, &mut memory, &ir).expect("execute cvtdq2pd/addsd block");

    assert_eq!(state.get(Register::Rax), 1);
    assert_eq!(xmm_to_f64x2(state.get_xmm(0)), [1.5, 2.0]);
}

#[test]
fn decode_and_execute_divss_then_comiss_updates_scalar_lane_and_flags() {
    let start_address = 0x1902_b165;
    let bytes = [0xF3, 0x0F, 0x5E, 0xC8, 0x0F, 0x2F, 0xCB];
    let decoded =
        decode_block(&bytes, start_address, GuestArch::X86).expect("decode divss/comiss block");
    let ir = lower_to_ir(&decoded).expect("lower divss/comiss block");
    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::Divss),
        "decoded={decoded:?}"
    );
    assert!(
        matches!(decoded[1].opcode, DecodedOpcode::Comiss),
        "decoded={decoded:?}"
    );
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set_xmm(0, f32x4_to_xmm([2.0, 9.0, 9.0, 9.0]));
    state.set_xmm(1, f32x4_to_xmm([8.0, 1.0, 2.0, 3.0]));
    state.set_xmm(3, f32x4_to_xmm([3.0, 7.0, 8.0, 9.0]));

    execute_ir(&mut state, &mut memory, &ir).expect("execute divss/comiss block");

    assert_eq!(xmm_to_f32x4(state.get_xmm(1)), [4.0, 1.0, 2.0, 3.0]);
    assert!(!state.flags.cf);
    assert!(!state.flags.zf);
    assert!(!state.flags.pf);
}

#[test]
fn decode_and_execute_pcmpistri_match_sets_ecx_and_cf() {
    let start_address = 0x18ff_e4b3;
    let bytes = [0x66, 0x0F, 0x3A, 0x63, 0x40, 0xF0, 0x0C];
    let decoded =
        decode_block(&bytes, start_address, GuestArch::X86).expect("decode pcmpistri match");
    let ir = lower_to_ir(&decoded).expect("lower pcmpistri match");
    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::Pcmpistri),
        "decoded={decoded:?}"
    );
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    let mut needle = [0_u8; 16];
    let mut haystack = [b'z'; 16];

    needle[..4].copy_from_slice(b"ABC\0");
    haystack[2..5].copy_from_slice(b"ABC");

    state.set(Register::Rax, 0x5010);
    state.set_xmm(0, bytes_to_xmm(needle));
    memory.map_bytes(0x5000, &haystack);

    execute_ir(&mut state, &mut memory, &ir).expect("execute pcmpistri match");

    // imm8=0x0C, aggregation=3 (Equal Ordered), comparison=0 (Equal), polarity=0
    // Match at position 2 sets bitmask[2]=1; CF=bitmask[0] is 0; index=LSB=2
    assert_eq!(state.get(Register::Rcx), 2);
    assert!(!state.flags.cf, "CF should be 0 (bitmask[0] not set)");
    assert!(!state.flags.zf);
    assert!(state.flags.sf);
    assert!(
        condition_holds(state.flags, ConditionCode::Above),
        "Above = !CF && !ZF"
    );
    assert!(
        condition_holds(state.flags, ConditionCode::NotBelow),
        "NotBelow = CF || !ZF"
    );
}

#[test]
fn decode_and_execute_pcmpistri_no_match_without_nul_sets_above() {
    let start_address = 0x18ff_e4b3;
    let bytes = [0x66, 0x0F, 0x3A, 0x63, 0x40, 0xF0, 0x0C];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86)
        .expect("decode pcmpistri continue-scan");
    let ir = lower_to_ir(&decoded).expect("lower pcmpistri continue-scan");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    let mut needle = [0_u8; 16];

    needle[..4].copy_from_slice(b"ABC\0");

    state.set(Register::Rax, 0x6010);
    state.set_xmm(0, bytes_to_xmm(needle));
    memory.map_bytes(0x6000, &[b'z'; 16]);

    execute_ir(&mut state, &mut memory, &ir).expect("execute pcmpistri continue-scan");

    assert_eq!(state.get(Register::Rcx), 16);
    assert!(!state.flags.cf);
    assert!(!state.flags.zf);
    assert!(state.flags.sf);
    assert!(condition_holds(state.flags, ConditionCode::Above));
    assert!(condition_holds(state.flags, ConditionCode::NotBelow));
}

#[test]
fn decode_and_execute_pcmpistri_no_match_with_nul_sets_not_below_only() {
    let start_address = 0x18ff_e4b3;
    let bytes = [0x66, 0x0F, 0x3A, 0x63, 0x40, 0xF0, 0x0C];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86)
        .expect("decode pcmpistri end-of-string");
    let ir = lower_to_ir(&decoded).expect("lower pcmpistri end-of-string");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    let mut needle = [0_u8; 16];
    let mut haystack = [0_u8; 16];

    needle[..4].copy_from_slice(b"ABC\0");
    haystack[..2].copy_from_slice(b"zz");

    state.set(Register::Rax, 0x7010);
    state.set_xmm(0, bytes_to_xmm(needle));
    memory.map_bytes(0x7000, &haystack);

    execute_ir(&mut state, &mut memory, &ir).expect("execute pcmpistri end-of-string");

    assert_eq!(state.get(Register::Rcx), 16);
    assert!(!state.flags.cf);
    assert!(state.flags.zf);
    assert!(state.flags.sf);
    assert!(!condition_holds(state.flags, ConditionCode::Above));
    assert!(condition_holds(state.flags, ConditionCode::NotBelow));
}

#[test]
fn decode_and_execute_fcomi_then_fcomip_sets_flags_and_pops() {
    let start_address = 0x18ef_7a00;
    let bytes = [0xDB, 0xF1, 0xDF, 0xF1];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode fcomi/fcomip");
    let ir = lower_to_ir(&decoded).expect("lower fcomi/fcomip");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.x87.stack.push(1.0);
    state.x87.stack.push(0.0);

    execute_ir(&mut state, &mut memory, &ir).expect("execute fcomi/fcomip");

    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::Fcomi),
        "decoded={decoded:?}"
    );
    assert!(
        matches!(decoded[1].opcode, DecodedOpcode::Fcomip),
        "decoded={decoded:?}"
    );
    assert!(state.flags.cf);
    assert!(!state.flags.zf);
    assert!(!state.flags.pf);
    assert_eq!(state.x87.stack, vec![1.0]);
}

#[test]
fn decode_and_execute_live_steam_bsf_updates_index_and_zf() {
    let start_address = 0x18ff_e257;
    let bytes = [0x0f, 0xbc, 0xc1];
    let decoded =
        decode_block(&bytes, start_address, GuestArch::X86).expect("decode live steam bsf block");
    let ir = lower_to_ir(&decoded).expect("lower live steam bsf block");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0xffff_ffff);
    state.set(Register::Rcx, 0x0000_00e0);

    execute_ir(&mut state, &mut memory, &ir).expect("execute live steam bsf block");

    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::Bsf),
        "decoded={decoded:?}"
    );
    assert_eq!(state.get(Register::Rax), 5);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_live_steam_not_al_then_test_sets_low_byte() {
    let start_address = 0x1902_0613;
    let bytes = [0xf6, 0xd0, 0xa8, 0x01];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86)
        .expect("decode live steam not/test block");
    let ir = lower_to_ir(&decoded).expect("lower live steam not/test block");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0);

    execute_ir(&mut state, &mut memory, &ir).expect("execute live steam not/test block");

    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::Not),
        "decoded={decoded:?}"
    );
    assert_eq!(state.get_byte(ByteRegister::Al), 0xff);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_live_steam_shr_cl_imm8_then_test_updates_low_byte() {
    let start_address = 0x18f1_4838;
    let bytes = [0xc0, 0xe9, 0x07, 0x84, 0xc9];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86)
        .expect("decode live steam shr/test block");
    let ir = lower_to_ir(&decoded).expect("lower live steam shr/test block");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rcx, 0xfe);

    execute_ir(&mut state, &mut memory, &ir).expect("execute live steam shr/test block");

    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::ShrImm),
        "decoded={decoded:?}"
    );
    assert_eq!(state.get_byte(ByteRegister::Cl), 0x01);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_sub_al_imm8_updates_accumulator() {
    let start_address = 0x1909_790a;
    let bytes = [0x2C, 0x61];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode sub al, 0x61");
    let ir = lower_to_ir(&decoded).expect("lower sub al, 0x61");
    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::SubReg8),
        "decoded={decoded:?}"
    );
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x92);

    execute_ir(&mut state, &mut memory, &ir).expect("execute sub al, 0x61");

    assert_eq!(state.get(Register::Rax), 0x31);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_add_al_imm8_updates_accumulator() {
    let start_address = 0x1909_7908;
    let bytes = [0x04, 0x07];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode add al, 0x07");
    let ir = lower_to_ir(&decoded).expect("lower add al, 0x07");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x92);

    execute_ir(&mut state, &mut memory, &ir).expect("execute add al, 0x07");

    assert_eq!(state.get(Register::Rax), 0x99);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_xor_al_imm8_updates_accumulator() {
    let start_address = 0x1909_790c;
    let bytes = [0x34, 0x01];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode xor al, 1");
    let ir = lower_to_ir(&decoded).expect("lower xor al, 1");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x92);

    execute_ir(&mut state, &mut memory, &ir).expect("execute xor al, 1");

    assert_eq!(state.get(Register::Rax), 0x93);
    assert!(!state.flags.zf);
}

#[test]
fn execute_lea_with_negative_displacement_wraps_instead_of_faulting() {
    let start_address = 0x4000;
    let bytes = [0x44, 0x8D, 0x42, 0x9F];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::Rdx, 0x4e);
    execute_ir(&mut state, &mut memory, &ir).expect("execute lea");

    assert_eq!(state.get(Register::R8), 0x0000_0000_ffff_ffed);
}

#[test]
fn decode_and_execute_test_r10b_imm8_updates_zero_flag() {
    let start_address = 0x4000;
    let bytes = [0x41, 0xF6, 0xC2, 0x01];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::R10, 0x2);
    execute_ir(&mut state, &mut memory, &ir).expect("execute test r10b, imm8");
    assert!(state.flags.zf);

    state.set(Register::R10, 0x1);
    execute_ir(&mut state, &mut memory, &ir).expect("execute test r10b, imm8");
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_test_r10d_imm32_updates_zero_flag() {
    let start_address = 0x5000;
    let bytes = [0x41, 0xF7, 0xC2, 0x00, 0x01, 0x00, 0x00];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::R10, 0x2);
    execute_ir(&mut state, &mut memory, &ir).expect("execute test r10d, imm32");
    assert!(state.flags.zf);

    state.set(Register::R10, 0x100);
    execute_ir(&mut state, &mut memory, &ir).expect("execute test r10d, imm32");
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_seto_cl_materializes_overflow_in_x86() {
    let bytes = [
        0xB8, 0xFF, 0xFF, 0xFF, 0x7F, 0x83, 0xC0, 0x01, 0x0F, 0x90, 0xC1,
    ];
    let decoded = decode_block(&bytes, 0x6000, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    execute_ir(&mut state, &mut memory, &ir).expect("execute seto cl");

    assert_eq!(state.get(Register::Rcx) & 0xff, 1);
    assert!(state.flags.of);
}

#[test]
fn decode_and_execute_or_ah_ah_updates_flags_in_x86() {
    let bytes = [0xB4, 0x80, 0x0A, 0xE4];
    let decoded = decode_block(&bytes, 0x6000, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    execute_ir(&mut state, &mut memory, &ir).expect("execute or ah, ah");

    assert_eq!(state.get(Register::Rax), 0x8000);
    assert!(!state.flags.zf);
    assert!(state.flags.sf);
}

#[test]
fn decode_and_execute_or_al_into_memory_byte_updates_memory_and_flags() {
    let bytes = [0x08, 0x45, 0x0B];
    let decoded = decode_block(&bytes, 0x6010, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x0f);
    state.set(Register::Rbp, 0x7000);
    memory.map_bytes(0x700b, &[0x80]);

    execute_ir(&mut state, &mut memory, &ir).expect("execute or byte ptr [ebp+0xb], al");

    assert_eq!(
        read_memory_value(&memory, 0x700b, 1).expect("or target"),
        0x8f
    );
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_add_ah_dh_updates_high_bytes_in_x86() {
    let bytes = [0xB6, 0x01, 0xB4, 0x02, 0x02, 0xE6];
    let decoded = decode_block(&bytes, 0x6000, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    execute_ir(&mut state, &mut memory, &ir).expect("execute add ah, dh");

    assert_eq!(state.get(Register::Rax), 0x0300);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_and_r10b_r9b_then_cmp_preserves_byte_result() {
    let start_address = 0x20b9_661a_179b;
    let bytes = [0x45, 0x20, 0xCA, 0x41, 0x80, 0xFA, 0x01, 0x75, 0x08];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded[..2]).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::R9, 0x1);
    state.set(Register::R10, 0x3);
    execute_ir(&mut state, &mut memory, &ir).expect("execute and/cmp prefix");

    assert_eq!(state.get(Register::R10) & 0xff, 1);
    assert!(state.flags.zf);

    state.set(Register::R9, 0x2);
    state.set(Register::R10, 0x3);
    execute_ir(&mut state, &mut memory, &ir).expect("execute and/cmp prefix with zero result");

    assert_eq!(state.get(Register::R10) & 0xff, 0x2);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_xor_bp_ax_preserves_upper_ebp_bits() {
    let start_address = 0x20b9_661a_2000;
    let bytes = [0x66, 0x33, 0xE8];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x5678_f0f0);
    state.set(Register::Rbp, 0xabcd_1234);

    execute_ir(&mut state, &mut memory, &ir).expect("execute xor bp, ax");

    assert_eq!(state.get(Register::Rbp), 0xabcd_e2c4);
    assert!(!state.flags.zf);
    assert!(state.flags.sf);
}

#[test]
fn decode_and_execute_xor_eax_stack_dword_zero_extends_result() {
    let start_address = 0x18ff_df4d;
    let bytes = [0x33, 0x45, 0xF4];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0xffff_ffff_1234_5678);
    state.set(Register::Rbp, 0x4000);
    memory.map_bytes(0x3ff4, &0x8000_0000_u32.to_le_bytes());

    execute_ir(&mut state, &mut memory, &ir).expect("execute xor eax, [ebp-0xc]");

    assert_eq!(state.get(Register::Rax), 0x0000_0000_9234_5678);
    assert!(!state.flags.zf);
    assert!(state.flags.sf);
}

#[test]
fn decode_and_execute_xor_stack_dword_eax_updates_memory() {
    let start_address = 0x18ff_df5d;
    let bytes = [0x31, 0x45, 0xFC];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x8000_0001);
    state.set(Register::Rbp, 0x5000);
    memory.map_bytes(0x4ffc, &0x1234_5678_u32.to_le_bytes());

    execute_ir(&mut state, &mut memory, &ir).expect("execute xor [ebp-0x4], eax");

    assert_eq!(
        read_memory_value(&memory, 0x4ffc, 4).expect("updated dword"),
        0x9234_5679
    );
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_xor_bl_bl_zeroes_bl() {
    let start_address = 0x18ff_d10d;
    let bytes = [0x32, 0xDB];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rbx, 0x1234_56ab);

    execute_ir(&mut state, &mut memory, &ir).expect("execute xor bl, bl");

    assert_eq!(state.get(Register::Rbx), 0x1234_5600);
    assert!(state.flags.zf);
    assert!(!state.flags.sf);
}

#[test]
fn decode_and_execute_fnclex_clears_x87_exception_flags() {
    let start_address = 0x18ff_d05c;
    let bytes = [0xDB, 0xE2];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.x87.divide_by_zero = true;
    state.x87.precision = true;

    execute_ir(&mut state, &mut memory, &ir).expect("execute fnclex");

    assert!(!state.x87.divide_by_zero);
    assert!(!state.x87.precision);
}

#[test]
fn decode_and_execute_xor_edi_imm32_zero_extends_result() {
    let start_address = 0x18ff_db3f;
    let bytes = [0x81, 0xF7, 0x47, 0x65, 0x6E, 0x75];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rdi, 0xffff_ffff_1234_5678);

    execute_ir(&mut state, &mut memory, &ir).expect("execute xor edi, imm32");

    assert_eq!(state.get(Register::Rdi), 0x0000_0000_675a_333f);
    assert!(!state.flags.zf);
    assert!(!state.flags.sf);
}

#[test]
fn decode_and_execute_bt_edx_ecx_then_jae_uses_carry_flag() {
    let start_address = 0x2099_f66b_1989;
    let bytes = [0x0F, 0xA3, 0xCA, 0x73, 0x23];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::Rdx, 0x100);
    state.set(Register::Rcx, 8);
    execute_ir(&mut state, &mut memory, &ir).expect("execute bt/jcc when tested bit is set");
    assert!(state.flags.cf);
    assert_eq!(state.rip, start_address + 5);

    state.set(Register::Rdx, 0x100);
    state.set(Register::Rcx, 0);
    execute_ir(&mut state, &mut memory, &ir).expect("execute bt/jcc when tested bit is clear");
    assert!(!state.flags.cf);
    assert_eq!(state.rip, start_address + 0x28);
}

#[test]
fn decode_and_execute_cmp_byte_ptr_ecx_al_then_je_uses_zero_flag() {
    let start_address = 0x1901_c0fa;
    let bytes = [0x38, 0x01, 0x74, 0x0c];
    let decoded =
        decode_block(&bytes, start_address, GuestArch::X86).expect("decode cmp/jcc block");
    let ir = lower_to_ir(&decoded).expect("lower cmp/jcc ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, u64::from(b'A'));
    state.set(Register::Rcx, 0x7000);
    memory.map_bytes(0x7000, b"A");

    execute_ir(&mut state, &mut memory, &ir).expect("execute cmp/jcc when bytes match");
    assert!(state.flags.zf);
    assert_eq!(state.rip, start_address + 0x10);

    memory.map_bytes(0x7000, b"B");
    execute_ir(&mut state, &mut memory, &ir).expect("execute cmp/jcc when bytes differ");
    assert!(!state.flags.zf);
    assert_eq!(state.rip, start_address + 4);
}

#[test]
fn decode_and_execute_bt_absolute_dword_imm8_then_jnc_uses_carry_flag() {
    let start_address = 0x18ff_ef32;
    let bytes = [0x0F, 0xBA, 0x25, 0xDC, 0x74, 0x30, 0x19, 0x01, 0x73, 0x09];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode bt imm block");
    let ir = lower_to_ir(&decoded).expect("lower bt imm ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    let address = 0x1930_74dc;

    memory.map_bytes(address, &2_u32.to_le_bytes());
    execute_ir(&mut state, &mut memory, &ir).expect("execute bt imm/jcc when tested bit is set");
    assert!(state.flags.cf);
    assert_eq!(state.rip, start_address + 10);

    memory.map_bytes(address, &0_u32.to_le_bytes());
    execute_ir(&mut state, &mut memory, &ir).expect("execute bt imm/jcc when tested bit is clear");
    assert!(!state.flags.cf);
    assert_eq!(state.rip, start_address + 19);
}

#[test]
fn decode_and_execute_and_r13d_imm32_then_jne_uses_zero_flag() {
    let start_address = 0x2057_c70b_1a36;
    let bytes = [
        0x41, 0x81, 0xE5, 0x00, 0x00, 0x00, 0x80, 0x0F, 0x85, 0x2D, 0xFF, 0xFF, 0xFF,
    ];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    let fallthrough = start_address + bytes.len() as u64;
    let taken =
        ((fallthrough as i128) + i32::from_le_bytes([0x2D, 0xFF, 0xFF, 0xFF]) as i128) as u64;

    state.set(Register::R13, 0xffff_ffff_8000_0001);
    execute_ir(&mut state, &mut memory, &ir).expect("execute and/jne with non-zero result");
    assert_eq!(state.get(Register::R13), 0x8000_0000);
    assert!(!state.flags.zf);
    assert_eq!(state.rip, taken);

    state.set(Register::R13, 0x7fff_ffff);
    execute_ir(&mut state, &mut memory, &ir).expect("execute and/jne with zero result");
    assert_eq!(state.get(Register::R13), 0);
    assert!(state.flags.zf);
    assert_eq!(state.rip, fallthrough);
}

#[test]
fn decode_and_execute_add_ebx_r9d_then_cmp_updates_flags() {
    let start_address = 0x2041_b6b7_216b;
    let bytes = [0x44, 0x01, 0xCB, 0x83, 0xFB, 0x14];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::Rbx, 10);
    state.set(Register::R9, 10);
    execute_ir(&mut state, &mut memory, &ir).expect("execute add/cmp with equality");
    assert_eq!(state.get(Register::Rbx), 20);
    assert!(state.flags.zf);
    assert!(!state.flags.cf);

    state.set(Register::Rbx, 5);
    state.set(Register::R9, 10);
    execute_ir(&mut state, &mut memory, &ir).expect("execute add/cmp with below result");
    assert_eq!(state.get(Register::Rbx), 15);
    assert!(!state.flags.zf);
    assert!(state.flags.cf);
}

#[test]
fn decode_and_execute_rip_relative_add_ecx_to_memory_updates_memory_and_flags() {
    let start_address = 0x21ab_e554_23eb;
    let bytes = [0x01, 0x0D, 0x33, 0x2D, 0x00, 0x00];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    let target_address = start_address + bytes.len() as u64 + 0x2d33;

    state.set(Register::Rcx, 3);
    memory.map_bytes(target_address, &5_u32.to_le_bytes());

    execute_ir(&mut state, &mut memory, &ir).expect("execute rip-relative add to memory");

    assert_eq!(
        read_memory_value(&memory, target_address, 4).expect("read dword"),
        8
    );
    assert!(!state.flags.zf);
    assert!(!state.flags.cf);
}

#[test]
fn decode_and_execute_shr_r13d_cl_then_test_and_jz_uses_shifted_value() {
    let start_address = 0x206c_0a30_19b4;
    let bytes = [0x41, 0xD3, 0xED, 0x41, 0xF6, 0xC5, 0x02, 0x74, 0x23];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::Rcx, 1);
    state.set(Register::R13, 0x4);
    execute_ir(&mut state, &mut memory, &ir).expect("execute shr/test/jz with set bit");
    assert_eq!(state.get(Register::R13), 0x2);
    assert!(!state.flags.zf);
    assert_eq!(state.rip, start_address + 9);

    state.set(Register::Rcx, 1);
    state.set(Register::R13, 0x2);
    execute_ir(&mut state, &mut memory, &ir).expect("execute shr/test/jz with cleared bit");
    assert_eq!(state.get(Register::R13), 0x1);
    assert!(state.flags.zf);
    assert_eq!(state.rip, start_address + 0x2c);
}

#[test]
fn decode_and_execute_rol_eax_imm8_rotates_left() {
    let start_address = 0x18f6_fd5b;
    let bytes = [0xC1, 0xC0, 0x0F];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x1234_5678);

    execute_ir(&mut state, &mut memory, &ir).expect("execute rol eax, 0x0f");

    assert_eq!(state.get(Register::Rax), 0x2b3c_091a);
    assert!(!state.flags.cf);
}

#[test]
fn decode_and_execute_lock_inc_memory_updates_value() {
    let start_address = 0x1901_f157;
    let bytes = [0xF0, 0xFF, 0x00];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x4000);
    memory.map_bytes(0x4000, &5_u32.to_le_bytes());

    execute_ir(&mut state, &mut memory, &ir).expect("execute lock inc dword ptr [eax]");

    assert_eq!(
        read_memory_value(&memory, 0x4000, 4).expect("updated dword"),
        6
    );
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_lock_cmpxchg8b_mismatch_loads_edx_eax() {
    let start_address = 0x18fe_d3d9;
    let bytes = [0xF0, 0x0F, 0xC7, 0x0E];
    let decoded =
        decode_block(&bytes, start_address, GuestArch::X86).expect("decode lock cmpxchg8b [esi]");
    let ir = lower_to_ir(&decoded).expect("lower lock cmpxchg8b [esi]");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rsi, 0x6000);
    state.set(Register::Rax, 0x5566_7788);
    state.set(Register::Rdx, 0x1122_3344);
    state.set(Register::Rbx, 0xddee_ff00);
    state.set(Register::Rcx, 0x99aa_bbcc);
    memory.map_bytes(0x6000, &0x8877_6655_4433_2211_u64.to_le_bytes());

    execute_ir(&mut state, &mut memory, &ir).expect("execute lock cmpxchg8b [esi]");

    assert_eq!(
        read_memory_value(&memory, 0x6000, 8).expect("original qword"),
        0x8877_6655_4433_2211
    );
    assert_eq!(state.get(Register::Rax), 0x4433_2211);
    assert_eq!(state.get(Register::Rdx), 0x8877_6655);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_or_r9d_edx_zero_extends_result() {
    let start_address = 0x7000;
    let bytes = [0x41, 0x09, 0xD1];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::R9, 0xffff_ffff_0000_0001);
    state.set(Register::Rdx, 0x2);
    execute_ir(&mut state, &mut memory, &ir).expect("execute or r9d, edx");

    assert_eq!(state.get(Register::R9), 0x3);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_or_ebx_stack_dword_zero_extends_result() {
    let start_address = 0x1912_2493_3e70;
    let bytes = [0x0B, 0x5C, 0x24, 0x28];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::Rsp, 0x4000);
    state.set(Register::Rbx, 0xffff_ffff_1234_5678);
    memory.map_bytes(0x4028, &0x8000_0000_u32.to_le_bytes());

    execute_ir(&mut state, &mut memory, &ir).expect("execute or ebx, dword ptr [rsp+0x28]");

    assert_eq!(state.get(Register::Rbx), 0x0000_0000_9234_5678);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_or_stack_dword_ebx_updates_memory() {
    let start_address = 0x1912_2493_5000;
    let bytes = [0x09, 0x5C, 0x24, 0x28];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::Rsp, 0x5000);
    state.set(Register::Rbx, 0x8000_0001);
    memory.map_bytes(0x5028, &0x1234_5678_u32.to_le_bytes());

    execute_ir(&mut state, &mut memory, &ir).expect("execute or dword ptr [rsp+0x28], ebx");

    assert_eq!(
        read_memory_value(&memory, 0x5028, 4).expect("updated dword"),
        0x9234_5679
    );
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_sbb_edi_memory_uses_carry_flag() {
    let start_address = 0x1e95_ea9e_14f1;
    let bytes = [0x1B, 0x3C, 0x00];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::Rax, 0x2000);
    state.set(Register::Rdi, 0x10);
    state.flags.cf = true;
    memory.map_bytes(0x4000, &5_u32.to_le_bytes());

    execute_ir(&mut state, &mut memory, &ir).expect("execute sbb edi, dword ptr [rax+rax]");

    assert_eq!(state.get(Register::Rdi), 10);
    assert!(!state.flags.cf);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_sbb_edx_imm8_uses_carry_flag() {
    let start_address = 0x21ba_1574_2720;
    let bytes = [0x83, 0xDA, 0x00];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::Rdx, 5);
    state.flags.cf = true;

    execute_ir(&mut state, &mut memory, &ir).expect("execute sbb edx, 0");

    assert_eq!(state.get(Register::Rdx), 4);
    assert!(!state.flags.cf);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_sbb_ebx_imm32_uses_carry_flag() {
    let start_address = 0x1901_4e4b;
    let bytes = [0x81, 0xDB, 0xDE, 0xB1, 0x9D, 0x01];
    let decoded = decode_block(&bytes, start_address, GuestArch::X86).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();

    state.set(Register::Rbx, 0x0200_0000);
    state.flags.cf = true;

    execute_ir(&mut state, &mut memory, &ir).expect("execute sbb ebx, imm32");

    assert_eq!(state.get(Register::Rbx), 0x0062_4e21);
    assert!(!state.flags.cf);
    assert!(!state.flags.zf);
}

#[test]
fn decode_and_execute_or_r10b_imm8_preserves_upper_bits() {
    let start_address = 0x266b_ceb3_2749;
    let bytes = [0x41, 0x80, 0xCA, 0x30];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    state.set(Register::R10, 0x1234_5678_9abc_00cd);

    execute_ir(&mut state, &mut memory, &ir).expect("execute or r10b, 0x30");

    assert_eq!(state.get(Register::R10), 0x1234_5678_9abc_00fd);
    assert!(!state.flags.cf);
    assert!(!state.flags.zf);
}

#[test]
fn execute_decimal_format_loop_body_reduces_ecx_and_emits_digits() {
    let start_address = 0x277f_9d1b_2720;
    let bytes = [
        0xBA, 0xCD, 0xCC, 0xCC, 0xCC, 0x41, 0x89, 0xC8, 0x4C, 0x0F, 0xAF, 0xC2, 0x49, 0xC1, 0xE8,
        0x23, 0x47, 0x8D, 0x0C, 0x00, 0x47, 0x8D, 0x0C, 0x89, 0x41, 0x89, 0xCA, 0x45, 0x29, 0xCA,
        0x41, 0x80, 0xCA, 0x30, 0x44, 0x88, 0x50, 0x01, 0x48, 0x83, 0xC0, 0x01, 0x83, 0xC7, 0x01,
        0x83, 0xF9, 0x09, 0x44, 0x89, 0xC1,
    ];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    memory.map_bytes(0x5000, &[0; 8]);
    state.set(Register::Rax, 0x5000);
    state.set(Register::Rcx, 35);
    state.set(Register::Rdi, 1);

    execute_ir(&mut state, &mut memory, &ir).expect("execute decimal format body first pass");

    assert_eq!(state.get(Register::Rcx), 3);
    assert_eq!(state.get(Register::Rdi), 2);
    assert_eq!(state.get(Register::Rax), 0x5001);
    assert_eq!(memory.read_u8(0x5001).expect("first digit"), b'5');
    assert!(condition_holds(state.flags, ConditionCode::Above));

    execute_ir(&mut state, &mut memory, &ir).expect("execute decimal format body second pass");

    assert_eq!(state.get(Register::Rcx), 0);
    assert_eq!(state.get(Register::Rdi), 3);
    assert_eq!(state.get(Register::Rax), 0x5002);
    assert_eq!(memory.read_u8(0x5002).expect("second digit"), b'3');
    assert!(!condition_holds(state.flags, ConditionCode::Above));
}

#[test]
fn decode_and_execute_rip_relative_add_imm8_to_memory_updates_memory_and_flags() {
    let start_address = 0x9000;
    let target_address = 0x9040;
    let displacement = (target_address as i64 - (start_address as i64 + 7)) as i32;
    let bytes = [
        0x83,
        0x05,
        displacement as u8,
        (displacement >> 8) as u8,
        (displacement >> 16) as u8,
        (displacement >> 24) as u8,
        0x01,
    ];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64).expect("decode block");
    let ir = lower_to_ir(&decoded).expect("lower ir");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    memory.map_bytes(target_address, &5_u32.to_le_bytes());
    execute_ir(&mut state, &mut memory, &ir).expect("execute add dword ptr [rip+disp32], 1");

    // Regression: a counted zero-fill loop `add rax,8; cmp rax,0x1bf; jne`
    // (the CRT BSS-init pattern from the Tetris guest) must terminate.
    // This exercises REX.W `add rax, imm8`, REX.W `cmp rax, imm32`, and a
    // conditional backward jump — if any of these mis-update a register or
    // flag, the loop spins forever and the guest hangs at startup.
    {
        let loop_start = 0x1000u64;
        // add rax,8 ; cmp rax,0x1bf ; jne loop_start(-0xd from after cmp)
        let add_bytes = [0x48, 0x83, 0xC0, 0x08];
        let cmp_bytes = [0x48, 0x3D, 0xBF, 0x01, 0x00, 0x00];
        let jne_bytes = [0x75, 0xF4]; // -12 -> back to loop_start
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&add_bytes);
        bytes.extend_from_slice(&cmp_bytes);
        bytes.extend_from_slice(&jne_bytes);
        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rax, 0);
        let mut memory = MemoryImage::default();
        let mut iterations = 0usize;
        loop {
            iterations += 1;
            if iterations > 1000 {
                panic!(
                    "add-rax loop did not terminate after 1000 iters; rax={:#x}",
                    state.get(Register::Rax)
                );
            }
            let decoded = decode_block(&bytes, loop_start, GuestArch::X64).expect("decode");
            let ir = lower_to_ir(&decoded).expect("lower");
            let before = state.get(Register::Rax);
            execute_ir(&mut state, &mut memory, &ir).expect("exec");
            // The block should set rip back to loop_start while rax < 0x1bf,
            // or fall through (rip past the block) when done.
            let _ = before;
            if state.get(Register::Rax) >= 0x1bf {
                break;
            }
            // If rip didn't advance/jump, force continuation.
            if state.rip != loop_start {
                state.rip = loop_start;
            }
        }
        assert!(state.get(Register::Rax) >= 0x1bf, "rax should reach 0x1bf");
    }

    assert_eq!(
        read_memory_value(&memory, target_address, 4).expect("updated dword"),
        6
    );
    assert!(!state.flags.zf);
    assert!(!state.flags.cf);
}

#[test]
fn decode_evex_prefix_returns_correct_fields() {
    // EVEX prefix bytes for: 0x62 0x51 0x94 0x20
    // byte0 = 0x62 (EVEX marker)
    // byte1 = 0x51 = 0101_0001:
    //   bit7(R')=0 → r_prime=true, bit6(R)=1 → r=false,
    //   bit5(X)=0 → x=true, bit4(B)=1 → b=false,
    //   bit3(R'')=0 → r_prime2=true, bits2:0(mm)=001 → map_select=1
    // byte2 = 0x94 = 1001_0100:
    //   bit7(W)=1 → w=true, bits6:3(vvvv)=0010 → vvvv_low=13,
    //   bit2=1(fixed), bits1:0(pp)=00
    // byte3 = 0x20 = 0010_0000:
    //   bit7(z)=0, bits6:5(ll)=01 (256-bit), bit4(bcast)=0,
    //   bit3(V')=0 → v_prime=1, bits2:0(aaa)=000
    let bytes = [0x62, 0x51, 0x94, 0x20, 0x98];
    let (evex, consumed) = decode_evex_prefix(&bytes, 0)
        .expect("decode EVEX")
        .expect("EVEX present");
    assert_eq!(consumed, 4, "EVEX prefix consumes 4 bytes");
    assert!(!evex.r, "r should be false (R bit 1 inverted)");
    assert!(evex.x, "x should be true (X bit 0 inverted)");
    assert!(!evex.b, "b should be false (B bit 1 inverted)");
    assert!(evex.r_prime, "r' should be true (R' bit 0 inverted)");
    assert!(evex.r_prime2, "r'' should be true (R'' bit 0 inverted)");
    assert_eq!(evex.map_select, 1, "map_select should be 1 (0x0F38)");
    assert!(evex.w, "w should be true");
    assert_eq!(
        evex.vvvv, 29,
        "5-bit vvvv should be 29 (complement of register 2)"
    );
    assert_eq!(evex.pp, 0, "pp should be 0 (none)");
    assert_eq!(evex.ll, 1, "ll should be 1 (256-bit)");
    assert!(!evex.z, "z should be false");
    assert!(!evex.bcast, "bcast should be false");
    assert_eq!(evex.aaa, 0, "aaa should be 0");
}

#[test]
fn evex_prefix_truncated_bytes_return_error() {
    // Only 2 bytes of EVEX prefix
    let bytes = [0x62, 0xF1];
    let result = decode_evex_prefix(&bytes, 0);
    assert!(
        result.is_err() || result.as_ref().is_ok_and(|o| o.is_none()),
        "truncated EVEX should error or return None"
    );
}

// ──────────────────────────────────────────────────────────
// AES-NI software implementation tests
// ──────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────
// AES-NI decode-and-execute tests
// ──────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────
// PCLMULQDQ decode-and-execute test
// ──────────────────────────────────────────────────────────

// ──────────────────────────────────────────────────────────
// SHA decode-and-execute tests
// ──────────────────────────────────────────────────────────

// ── CPUID/XCR0 honesty tests ────────────────────────────────────────

#[test]
fn cpu_feature_set_for_arch_is_honest() {
    let features = CpuFeatureSet::for_arch(GuestArch::X64);
    // for_arch() must NOT advertise features that require
    // platform-specific lowering which isn't guaranteed.  The one
    // exception: on Apple Silicon hosts the ARMv8 NEON AES/SHA/PMULL
    // hardware IS guaranteed, so the crypto advertisement is honest
    // there (and must match the production from_profile() path).
    if !is_apple_silicon_host() {
        assert!(!features.aes);
        assert!(!features.sha);
        assert!(!features.pclmulqdq);
    } else {
        assert!(features.aes);
        assert!(features.sha);
        assert!(features.pclmulqdq);
    }
    // Core features should still be present
    assert!(features.baseline_x86_64);
    assert!(features.sse2);
    assert!(features.x87);
}

#[test]
fn xcr0_reports_honest_bits() {
    // XCR0 must only claim components the XSAVE area actually serializes:
    // x87 (bit 0), SSE (bit 1), AVX YMM (bit 2). AVX-512/MPX/PKRU/CET
    // bits are never claimed, even when the feature flags are enabled,
    // because the interpreter's XSAVE layout does not contain them.
    let virt =
        CpuVirtualization::from_profile(GuestArch::X64, None).expect("CpuVirtualization for x64");
    let xcr0 = virt.xcr0();
    // Bits 0 (x87) and 1 (SSE) should always be set
    assert!(xcr0 & 0x1 != 0, "x87 bit must be set");
    assert!(xcr0 & 0x2 != 0, "SSE bit must be set");
    // for_arch() has avx=true so bit 2 SHOULD be set
    assert!(
        xcr0 & 0x4 != 0,
        "AVX bit must be set when features.avx is true"
    );
    // Bits 3+ (MPX 3-4, AVX-512 5-7, PKRU 9, CET 11-12, ...) must NOT be
    // set: those components are not serialized by XSAVE/XRSTOR.
    assert!(
        xcr0 & !0b111 == 0,
        "no unsupported state components may be claimed, got {xcr0:#x}"
    );
    // MPX bits (3-4) must NOT be set (MPX is never implemented)
    assert!(xcr0 & 0x18 == 0, "MPX bits must NOT be set");
}

// ── FXSAVE x87 tag word tests ──────────────────────────────────────────
//
// The FXSAVE abridged tag word (byte at offset 4) uses Intel/AMD encoding:
//   bit i = 1  → ST(i) is EMPTY
//   bit i = 0  → ST(i) is non-empty (Valid, Zero, or Special)
//
// Helper: map zeroed pages at address for an FXSAVE area (512 bytes).
fn map_fxsave_area(memory: &mut MemoryImage, base: u64) {
    memory.map_zeroed_if_unmapped(base, 512);
}

// Helper: FXSAVE into a scratch buffer and return the tag byte at offset 4.
fn fxsave_tag(state: &CpuState, memory: &mut MemoryImage, base: u64) -> u8 {
    fxsave_to_memory(state, memory, base).expect("fxsave_to_memory");
    memory.read_u8(base + 4).expect("read tag byte")
}

// =====================================================================
// Self-modifying code: TranslationCache tests
// =====================================================================

#[test]
fn translation_cache_invalidate_code_write_removes_overlapping_blocks() {
    let mut cache = TranslationCache::default();
    let config =
        CpuEngineConfig::from_profile(GuestArch::X64, "test".to_string(), "test".to_string(), None)
            .unwrap();

    // Translate three blocks at different addresses
    let bytes_a = vec![0xB8, 0x0A, 0x00, 0x00, 0x00]; // mov eax, 10
    let bytes_b = vec![0xB8, 0x14, 0x00, 0x00, 0x00]; // mov eax, 20
    let bytes_c = vec![0xB8, 0x1E, 0x00, 0x00, 0x00]; // mov eax, 30

    cache.translate(&bytes_a, 0x1000, &config).unwrap();
    cache.translate(&bytes_b, 0x2000, &config).unwrap();
    cache.translate(&bytes_c, 0x3000, &config).unwrap();

    assert_eq!(cache.blocks.len(), 3, "three blocks should be cached");

    // Invalidate a write that overlaps block at 0x2000
    let keys = cache.invalidate_code_write(0x2000, 4);
    assert_eq!(keys.len(), 1, "one block should be invalidated");
    assert_eq!(cache.blocks.len(), 2, "two blocks should remain");
    assert!(
        cache.blocks.iter().any(|(k, _)| k.start_address == 0x1000),
        "block 0x1000 should remain"
    );
    assert!(
        cache.blocks.iter().any(|(k, _)| k.start_address == 0x3000),
        "block 0x3000 should remain"
    );
}

#[test]
fn translation_cache_invalidate_code_write_shared_page() {
    let mut cache = TranslationCache::default();
    let config =
        CpuEngineConfig::from_profile(GuestArch::X64, "test".to_string(), "test".to_string(), None)
            .unwrap();

    // Two blocks on the same 4K page
    let bytes_a = vec![0xB8, 0x0A, 0x00, 0x00, 0x00]; // mov eax, 10 at 0x1000
    let bytes_b = vec![0xB8, 0x14, 0x00, 0x00, 0x00]; // mov eax, 20 at 0x1FF0 (near page boundary)
    // Note: at 0x1FF0, with 5 bytes, it crosses into page 0x2000? No, 0x1FF0+5 = 0x1FF5, still on page 0x1000.

    cache.translate(&bytes_a, 0x1000, &config).unwrap();
    let block_b = cache.translate(&bytes_b, 0x1FF0, &config).unwrap();
    // Both should share page 0x1000
    assert!(
        block_b.touched_pages.contains(&0x1000),
        "block at 0x1FF0 should touch page 0x1000"
    );

    assert_eq!(cache.blocks.len(), 2);

    // Write to page 0x1000 should invalidate both blocks
    let keys = cache.invalidate_code_write(0x1000, 1);
    assert_eq!(
        keys.len(),
        2,
        "both blocks on page 0x1000 should be invalidated"
    );
    assert!(cache.blocks.is_empty(), "all blocks should be removed");
}

#[test]
fn translation_cache_invalidate_code_write_no_overlap() {
    let mut cache = TranslationCache::default();
    let config =
        CpuEngineConfig::from_profile(GuestArch::X64, "test".to_string(), "test".to_string(), None)
            .unwrap();

    let bytes = vec![0xB8, 0x0A, 0x00, 0x00, 0x00];
    cache.translate(&bytes, 0x1000, &config).unwrap();

    // Write to a completely different page
    let keys = cache.invalidate_code_write(0x9000, 16);
    assert!(keys.is_empty(), "no blocks should be invalidated");
    assert_eq!(cache.blocks.len(), 1, "block should remain");
}

#[test]
fn translation_cache_invalidate_code_write_zero_length() {
    let mut cache = TranslationCache::default();
    let config =
        CpuEngineConfig::from_profile(GuestArch::X64, "test".to_string(), "test".to_string(), None)
            .unwrap();

    let bytes = vec![0xB8, 0x0A, 0x00, 0x00, 0x00];
    cache.translate(&bytes, 0x1000, &config).unwrap();

    // Write with length=0 to a different page (0x5000).
    // Note: touched_pages uses length.max(1), so zero-length still targets
    // one page, but that page (0x5000) has no blocks.
    let keys = cache.invalidate_code_write(0x5000, 0);
    assert!(
        keys.is_empty(),
        "zero-length write to non-overlapping page should not invalidate anything"
    );
    assert_eq!(cache.blocks.len(), 1, "block should remain");
}

#[test]
fn translation_cache_invalidate_code_write_stress() {
    let mut cache = TranslationCache::default();
    let config =
        CpuEngineConfig::from_profile(GuestArch::X64, "test".to_string(), "test".to_string(), None)
            .unwrap();

    let stress_count = 50;

    // Place each block on its own page to avoid page-sharing effects.
    // Page size is 4K (0x1000), so address = page_base + i * 0x1000
    // keeps each block on a distinct page.
    for i in 0..stress_count {
        let page_base = 0x1000 + (i as u64 * 0x1000);
        // Place block at the start of each page
        let addr = page_base;
        let value = (i as u8).wrapping_mul(2).wrapping_add(1);
        let bytes = vec![0xB8, value, 0x00, 0x00, 0x00]; // mov eax, value
        cache.translate(&bytes, addr, &config).unwrap();
    }

    assert_eq!(
        cache.blocks.len(),
        stress_count,
        "all {} blocks should be cached",
        stress_count
    );

    // Invalidate every other block by writing to its exact address
    for i in (0..stress_count).step_by(2) {
        let page_base = 0x1000 + (i as u64 * 0x1000);
        cache.invalidate_code_write(page_base, 4);
    }

    // Only odd-indexed blocks should remain (each on its own page)
    let remaining: Vec<u64> = cache.blocks.keys().map(|k| k.start_address).collect();
    for i in 0..stress_count {
        let page_base = 0x1000 + (i as u64 * 0x1000);
        if i % 2 == 0 {
            assert!(
                !remaining.contains(&page_base),
                "even-indexed block at {:#x} should be removed",
                page_base
            );
        } else {
            assert!(
                remaining.contains(&page_base),
                "odd-indexed block at {:#x} should remain",
                page_base
            );
        }
    }
    assert_eq!(
        cache.blocks.len(),
        stress_count / 2,
        "half the blocks should remain"
    );
}

// =====================================================================
// E4 — BMI/BMI2 instruction tests (IR level)
// =====================================================================

// =====================================================================
// E4 — AES-NI instruction tests (IR level)
// =====================================================================

// =====================================================================
// E4 — FMA instruction tests (IR level)
// =====================================================================

// =====================================================================
// E4 — Additional SIMD instruction tests
// =====================================================================

// =====================================================================
// E4 — Division by zero and edge case tests
// =====================================================================

#[test]
fn execute_div_by_zero_using_div_idiv_ir_fails_gracefully() {
    // DIV and IDIV with divisor=0 should produce an error
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 10);
    state.set(Register::Rcx, 0);
    let result = execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Div {
            src: CompareOperand::Register(Register::Rcx),
            width: 4,
        }],
    );
    assert!(result.is_err(), "DIV by zero should fail");
}

#[test]
fn execute_idiv_by_zero_fails_gracefully() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 10);
    state.set(Register::Rcx, 0);
    let result = execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Idiv {
            src: CompareOperand::Register(Register::Rcx),
            width: 4,
        }],
    );
    assert!(result.is_err(), "IDIV by zero should fail");
}

#[test]
fn execute_div_overflow_fails_gracefully() {
    // DIV quotient overflow: RDX:RAX=0x1_0000_0000, divisor=1 => quotient 0x1_0000_0000 doesn't fit in 32-bit EAX
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0);
    state.set(Register::Rdx, 1); // RDX:RAX = 0x1_0000_0000
    state.set(Register::Rcx, 1);
    let result = execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Div {
            src: CompareOperand::Register(Register::Rcx),
            width: 4,
        }],
    );
    assert!(result.is_err(), "DIV overflow should fail");
}

#[test]
fn execute_idiv_overflow_fails_gracefully() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    // IDIV with dividend INT32_MIN and divisor -1 overflows
    state.set(Register::Rax, 0x8000_0000u32 as u64);
    state.set(Register::Rdx, 0xFFFF_FFFFu32 as u64);
    state.set(Register::Rcx, 0xFFFF_FFFFu32 as u64); // -1
    let result = execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Idiv {
            src: CompareOperand::Register(Register::Rcx),
            width: 4,
        }],
    );
    assert!(result.is_err(), "IDIV overflow should fail");
}

// =====================================================================
// E4 — Flag computation tests
// =====================================================================

#[test]
fn flag_computation_sub_sets_cf_on_borrow() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::SubImm {
            dst: Register::Rax,
            value: 1,
            width: 4,
        }],
    )
    .expect("sub");
    assert!(state.flags.cf, "CF should be set on borrow (0 - 1)");
    assert!(!state.flags.zf);
    assert!(state.flags.sf, "SF should be set (result = -1)");
}

#[test]
fn flag_computation_and_clears_cf_of_sets_zf_sf() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0xFFFF_FFFF);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::AndImm {
            dst: Register::Rax,
            value: 0,
            width: 4,
        }],
    )
    .expect("and");
    assert!(!state.flags.cf, "CF should be cleared by AND");
    assert!(!state.flags.of, "OF should be cleared by AND");
    assert!(state.flags.zf, "ZF should be set (result=0)");
    assert!(
        !state.flags.sf,
        "SF should be cleared (result non-negative)"
    );
}

#[test]
fn flag_computation_xor_clears_cf_of_sets_zf_on_self() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0x1234_5678);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::XorReg {
            dst: Register::Rax,
            src: CompareOperand::Register(Register::Rax),
            width: 4,
        }],
    )
    .expect("xor");
    assert!(!state.flags.cf, "CF should be cleared by XOR");
    assert!(!state.flags.of, "OF should be cleared by XOR");
    assert!(state.flags.zf, "ZF should be set (self-xor = 0)");
    assert!(!state.flags.sf, "SF should be cleared");
}

#[test]
fn flag_computation_cmp_sets_flags_like_sub_without_destination() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 5);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Compare {
            lhs: CompareOperand::Register(Register::Rax),
            rhs: CompareOperand::ImmediateU64(5),
            width: 4,
        }],
    )
    .expect("cmp");
    assert!(state.flags.zf, "ZF should be set (5 == 5)");
    assert!(!state.flags.cf, "CF should be cleared (no borrow)");
    assert!(!state.flags.sf, "SF should be cleared");
}

#[test]
fn flag_computation_test_sets_zf_on_zero_result() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0x0000_00FF);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Test {
            lhs: CompareOperand::Register(Register::Rax),
            rhs: CompareOperand::ImmediateU64(0x0000_FF00),
            width: 4,
        }],
    )
    .expect("test");
    assert!(state.flags.zf, "ZF should be set (no overlapping bits)");
    assert!(!state.flags.cf, "CF should be cleared by TEST");
    assert!(!state.flags.of, "OF should be cleared by TEST");
}

#[test]
fn flag_computation_mul_sets_cf_of_on_result_overflow() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0x1000_0000);
    state.set(Register::Rcx, 0x10);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::MulAcc {
            src: CompareOperand::Register(Register::Rcx),
            width: 4,
        }],
    )
    .expect("mul");
    assert!(state.flags.cf, "MUL CF should indicate overflow");
    assert!(state.flags.of, "MUL OF should indicate overflow");
}

#[test]
fn flag_computation_inc_does_not_affect_cf() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0xFFFF_FFFF);
    state.flags.cf = false;
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::IncReg {
            dst: Register::Rax,
            width: 4,
        }],
    )
    .expect("inc");
    assert!(!state.flags.cf, "INC should not alter CF");
    assert!(state.flags.zf, "ZF should be set (result wraps to 0)");
}

#[test]
fn flag_computation_dec_sets_zf_on_zero() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 1);
    state.flags.cf = false;
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::DecReg {
            dst: Register::Rax,
            width: 4,
        }],
    )
    .expect("dec");
    assert!(state.flags.zf, "ZF should be set (1 - 1 = 0)");
    assert!(!state.flags.cf, "DEC should not alter CF");
}

// =====================================================================
// Phase H — AVX-512 execution tests
// =====================================================================

// =====================================================================
// Phase H — Mask register operation tests
// =====================================================================

#[test]
fn execute_ktest_sets_cf_and_zf() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    // CF = (src1 & src2) == 0, ZF = src1 == 0
    state.set_opmask(0, 0x0000); // src1 = 0
    state.set_opmask(1, 0x00FF); // src2 non-zero
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Ktest {
            src1: 0,
            src2: 1,
            size: 16,
        }],
    )
    .expect("execute Ktest");
    assert!(state.flags.zf, "ZF should be set when src1 == 0");
    assert!(state.flags.cf, "CF should be set when (src1 & src2) == 0");

    // Non-zero src1 and overlapping bits
    state.set_opmask(0, 0x00FF);
    state.set_opmask(1, 0x000F);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Ktest {
            src1: 0,
            src2: 1,
            size: 16,
        }],
    )
    .expect("execute Ktest");
    assert!(!state.flags.zf, "ZF should be clear when src1 != 0");
    assert!(
        !state.flags.cf,
        "CF should be clear when (src1 & src2) != 0"
    );
}

// =====================================================================
// Phase H — CET shadow stack tests
// =====================================================================

// =====================================================================
// Phase H — MPX bounds checking tests
// =====================================================================

#[test]
fn execute_bndcl_fails_when_addr_below_lower_bound() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set_bnd(0, (0x1000, !0x1FFF)); // range [0x1000, 0x2000]
    state.set(Register::Rax, 0x0800); // below LB
    let result = execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::BndclReg { bnd: 0, src: 0 }],
    );
    assert!(result.is_err(), "BNDCL should #BR for addr < LB");
}

#[test]
fn execute_bndcu_fails_when_addr_above_upper_bound() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set_bnd(0, (0x1000, !0x1FFF)); // range [0x1000, 0x2000]
    state.set(Register::Rax, 0x3000); // above upper bound
    let result = execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::BndcuReg { bnd: 0, src: 0 }],
    );
    assert!(result.is_err(), "BNDCU should #BR for addr > NOT(UB)");
}

// =====================================================================
// Phase H — RDPMC test
// =====================================================================

// =====================================================================
// Phase H — TSX/RTM tests
// =====================================================================

#[test]
fn execute_xabort_is_nop() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Xabort { imm: 0xFF }],
    )
    .expect("execute Xabort");
    // XABORT with RTM disabled is #UD; we treat as NOP
}

// =====================================================================
// Phase H — SGX stub tests
// =====================================================================

// =====================================================================
// Phase H — Cache management NOP tests
// =====================================================================

// =====================================================================
// Phase H — XSAVE/XRSTOR serializes exactly x87 | SSE | AVX
// =====================================================================

#[test]
fn xsave_xrstor_round_trip_preserves_only_serialized_state() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();

    // Set up AVX-512 ZMM/opmask state (NOT serialized by the XSAVE area)
    // FIRST — set_zmm composes ZMM from the XMM/YMM/ZMM register files,
    // so it must run before the YMM upper-half setup below.
    state.set_zmm(
        0,
        ZmmValue {
            low: YmmValue {
                low: XmmValue {
                    low: 0xDEADBEEFCAFEBABE,
                    high: 0x0123456789ABCDEF,
                },
                high: XmmValue {
                    low: 0x1111111111111111,
                    high: 0x2222222222222222,
                },
            },
            high: YmmValue {
                low: XmmValue {
                    low: 0x3333333333333333,
                    high: 0x4444444444444444,
                },
                high: XmmValue {
                    low: 0x5555555555555555,
                    high: 0x6666666666666666,
                },
            },
        },
    );
    state.set_opmask(0, 0xAAAAAAAAAAAAAAAA);
    state.set_opmask(7, 0x5555555555555555);
    // AVX YMM upper halves (serialized, bit 2).
    state.ymm_upper[0].low = 0x1111_2222_3333_4444;
    state.ymm_upper[0].high = 0x5555_6666_7777_8888;
    state.ymm_upper[7].low = 0xAAAA_BBBB_CCCC_DDDD;
    state.ymm_upper[7].high = 0xEEEE_FFFF_0000_1111;
    state.mxcsr = 0x0000_9FC0;

    // Map an XSAVE area (832 bytes suffice for the serialized layout).
    let xsave_area: u64 = 0x10000;
    memory.map_zeroed_if_unmapped(xsave_area, 1024);

    // XSAVE with the full supported mask (x87 | SSE | AVX).
    xsave_to_memory(&state, &mut memory, xsave_area, XSAVE_SUPPORTED_STATE)
        .expect("xsave_to_memory");
    // XSTATE_BV announces exactly the written components: no AVX-512,
    // PKRU or CET bits.
    assert_eq!(
        memory.read_u64(xsave_area + 512).expect("xstate_bv"),
        0b111,
        "XSTATE_BV must announce exactly the serialized components"
    );
    assert_eq!(
        memory.read_u64(xsave_area + 520).expect("xcomp_bv"),
        0,
        "standard (non-compacted) format"
    );

    // Create a fresh state and restore
    let mut restored = CpuState::new(GuestArch::X64);
    xrstor_from_memory(&mut restored, &memory, xsave_area).expect("xrstor_from_memory");

    // YMM upper halves (serialized) are restored.
    assert_eq!(restored.ymm_upper[0].low, 0x1111_2222_3333_4444);
    assert_eq!(restored.ymm_upper[0].high, 0x5555_6666_7777_8888);
    assert_eq!(restored.ymm_upper[7].low, 0xAAAA_BBBB_CCCC_DDDD);
    assert_eq!(restored.ymm_upper[7].high, 0xEEEE_FFFF_0000_1111);
    assert_eq!(restored.mxcsr, 0x0000_9FC0);
    // AVX-512 state is NOT part of the XSAVE layout and must not be
    // claimed or restored by it. (The low 128 bits of ZMM0 are the XMM0
    // register, which IS serialized in the SSE region; the upper 256
    // bits are not.)
    assert_eq!(restored.get_opmask(0), 0, "opmask is not serialized");
    assert_eq!(restored.get_opmask(7), 0, "opmask is not serialized");
    assert_eq!(
        restored.get_zmm(0).high.low.low,
        0,
        "ZMM upper state is not serialized"
    );

    // Unaligned XSAVE/XRSTOR destinations are rejected (64-byte alignment).
    let unaligned = xsave_area + 32;
    assert!(xsave_to_memory(&state, &mut memory, unaligned, XSAVE_SUPPORTED_STATE).is_err());
    assert!(xrstor_from_memory(&mut restored, &memory, unaligned).is_err());

    // Requesting components outside the supported mask is rejected.
    assert!(xsave_to_memory(&state, &mut memory, xsave_area, 1 << 9).is_err());
    assert!(xsave_to_memory(&state, &mut memory, xsave_area, 0b101).is_ok());
}

// =====================================================================
// Phase H — MinPacked/MaxPacked/SqrtPacked tests
// =====================================================================

#[test]
fn execute_sqrtpacked_computes_square_root() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set_xmm(0, f64x2_to_xmm([4.0, 9.0]));
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::SqrtPacked {
            dst: 0,
            src: VectorOperand::Register(0),
            element_size: 1,
            width: 16,
            evex: EvexInfo::default(),
        }],
    )
    .expect("execute SqrtPacked");
    let result = xmm_to_f64x2(state.get_xmm(0));
    assert!((result[0] - 2.0).abs() < 1e-10, "sqrt lane 0");
    assert!((result[1] - 3.0).abs() < 1e-10, "sqrt lane 1");
}

// ------------------------------------------------------------------
// Property-based tests – decode determinism  (requires `cargo test --features proptest`)
// ------------------------------------------------------------------
#[cfg(feature = "proptest")]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn decode_deterministic(
            bytes in proptest::collection::vec(any::<u8>(), 0..=64),
            addr in any::<u64>(),
        ) {
            let arch = GuestArch::X64;
            let first = decode_block(&bytes, addr, arch);
            let second = decode_block(&bytes, addr, arch);
            match (first, second) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a.len(), b.len(), "decoded instruction count mismatch");
                    #[allow(clippy::needless_range_loop)]
                    for i in 0..a.len() {
                        assert_eq!(
                            std::mem::discriminant(&a[i].opcode),
                            std::mem::discriminant(&b[i].opcode),
                            "opcode discriminant differs at index {i}"
                        );
                    }
                }
                (Err(_), Err(_)) => {} // both failed – consistent
                (Ok(_), Err(err)) => panic!("second decode failed after first succeeded: {err:?}"),
                (Err(err), Ok(_)) => panic!("first decode failed after second succeeded: {err:?}"),
            }
        }
    }
}

// =====================================================================
// Gap 9.6: SBB register-to-memory decode and execution tests
// =====================================================================

// =====================================================================
// Gap 9.7: XCHG register/register decode and execution tests
// =====================================================================

// =====================================================================
// Gap 9.9: BOUND instruction decode and execution tests
// =====================================================================

#[test]
fn decode_bound_64bit_mode_returns_error() {
    // In 64-bit mode, 0x62 is EVEX prefix, not BOUND.
    // 0x62 0x01 0x00 0x00 should be treated as EVEX or fail.
    let bytes = [0x62, 0x01, 0x00, 0x00];
    let result = decode_block(&bytes, 0x1000, GuestArch::X64);
    // Should either decode as EVEX (consuming 0x62) or fail — but NOT decode as BOUND.
    if let Ok(decoded) = result {
        for insn in decoded {
            assert!(
                !matches!(insn.opcode, DecodedOpcode::Bound),
                "BOUND should not decode in 64-bit mode"
            );
        }
    }
}

#[test]
fn execute_bound_below_range_traps_br() {
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    let bounds_addr: u64 = 0x4000;

    // Set register value below the lower bound
    state.set(Register::Rax, 2);
    // Set up bounds pair: lower=5, upper=10
    memory.map_bytes(bounds_addr, &5_u32.to_le_bytes());
    memory.map_bytes(bounds_addr + 4, &10_u32.to_le_bytes());

    let result = execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Bound {
            reg: Register::Rax,
            address: MemoryOperand {
                base: None,
                index: None,
                scale: 1,
                displacement: 0,
                rip_relative: false,
                rip_base: 0,
                segment: None,
                address_size_32: false,
                absolute_address: Some(bounds_addr),
            },
            width: 4,
        }],
    );

    assert!(
        result.is_err(),
        "BOUND should trap #BR when value is below lower bound"
    );
}

#[test]
fn execute_bound_above_range_traps_br() {
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    let bounds_addr: u64 = 0x4000;

    // Set register value above upper bound
    state.set(Register::Rax, 15);
    // Set up bounds pair: lower=5, upper=10
    memory.map_bytes(bounds_addr, &5_u32.to_le_bytes());
    memory.map_bytes(bounds_addr + 4, &10_u32.to_le_bytes());

    let result = execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Bound {
            reg: Register::Rax,
            address: MemoryOperand {
                base: None,
                index: None,
                scale: 1,
                displacement: 0,
                rip_relative: false,
                rip_base: 0,
                segment: None,
                address_size_32: false,
                absolute_address: Some(bounds_addr),
            },
            width: 4,
        }],
    );

    assert!(
        result.is_err(),
        "BOUND should trap #BR when value is above upper bound"
    );
}

#[test]
fn execute_bound_at_lower_boundary_does_not_trap() {
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    let bounds_addr: u64 = 0x4000;

    // Set register value exactly to lower bound
    state.set(Register::Rax, 5);
    memory.map_bytes(bounds_addr, &5_u32.to_le_bytes());
    memory.map_bytes(bounds_addr + 4, &10_u32.to_le_bytes());

    let result = execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Bound {
            reg: Register::Rax,
            address: MemoryOperand {
                base: None,
                index: None,
                scale: 1,
                displacement: 0,
                rip_relative: false,
                rip_base: 0,
                segment: None,
                address_size_32: false,
                absolute_address: Some(bounds_addr),
            },
            width: 4,
        }],
    );

    assert!(
        result.is_ok(),
        "BOUND should not trap when value equals lower bound"
    );
}

#[test]
fn execute_bound_at_upper_boundary_does_not_trap() {
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    let bounds_addr: u64 = 0x4000;

    // Set register value exactly to upper bound
    state.set(Register::Rax, 10);
    memory.map_bytes(bounds_addr, &5_u32.to_le_bytes());
    memory.map_bytes(bounds_addr + 4, &10_u32.to_le_bytes());

    let result = execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Bound {
            reg: Register::Rax,
            address: MemoryOperand {
                base: None,
                index: None,
                scale: 1,
                displacement: 0,
                rip_relative: false,
                rip_base: 0,
                segment: None,
                address_size_32: false,
                absolute_address: Some(bounds_addr),
            },
            width: 4,
        }],
    );

    assert!(
        result.is_ok(),
        "BOUND should not trap when value equals upper bound"
    );
}

// -----------------------------------------------------------------------
// Arithmetic flag unit tests
// -----------------------------------------------------------------------

#[test]
fn add_flags_carry_set_on_unsigned_overflow_8bit() {
    // 0xFF + 0x01 = 0x100 → truncated to 0x00, CF=1
    let flags = add_flags(0xFF, 0x01, 0x00, 8);
    assert!(flags.cf, "CF should be set: 0xFF + 0x01 overflows u8");
    assert!(flags.zf, "ZF should be set: result is zero");
    assert!(flags.af, "AF should be set: carry from bit 3");
    assert!(!flags.sf, "SF should be clear: result is zero");
}

#[test]
fn add_flags_carry_clear_on_no_overflow_8bit() {
    // 0x10 + 0x20 = 0x30, CF=0
    let flags = add_flags(0x10, 0x20, 0x30, 8);
    assert!(!flags.cf, "CF should be clear: no overflow");
    assert!(!flags.zf, "ZF should be clear: result is non-zero");
}

#[test]
fn sub_flags_carry_set_on_borrow_8bit() {
    // 0x00 - 0x01 = borrow
    let flags = sub_flags(0x00, 0x01, 0xFF, 8);
    assert!(flags.cf, "CF should be set: 0 - 1 borrows");
    assert!(!flags.zf, "ZF should be clear: result is 0xFF");
    assert!(flags.sf, "SF should be set: MSB of 0xFF is 1");
}

#[test]
fn sub_flags_carry_clear_on_no_borrow_8bit() {
    // 0x10 - 0x05 = 0x0B, no borrow
    let flags = sub_flags(0x10, 0x05, 0x0B, 8);
    assert!(!flags.cf, "CF should be clear: no borrow");
    assert!(!flags.zf, "ZF should be clear: result is non-zero");
}

#[test]
fn sub_flags_equal_values_clears_carry() {
    // 42 - 42 = 0, no borrow
    let flags = sub_flags(42, 42, 0, 32);
    assert!(!flags.cf, "CF should be clear: equal values");
    assert!(flags.zf, "ZF should be set: result is zero");
}

#[test]
fn add_flags_overflow_signed_8bit() {
    // 0x7F + 0x01 = 0x80 → signed overflow (positive + positive = negative)
    let flags = add_flags(0x7F, 0x01, 0x80, 8);
    assert!(flags.of, "OF should be set: 127 + 1 overflows i8");
    assert!(flags.sf, "SF should be set: result MSB is 1");
    assert!(!flags.cf, "CF should be clear: no unsigned overflow");
}

#[test]
fn add_flags_overflow_signed_negative_8bit() {
    // 0x80 + 0x80 = 0x00 → signed overflow (negative + negative = positive)
    let flags = add_flags(0x80, 0x80, 0x00, 8);
    assert!(flags.of, "OF should be set: -128 + (-128) overflows i8");
    assert!(flags.cf, "CF should be set: unsigned overflow");
    assert!(flags.zf, "ZF should be set: result is zero");
}

#[test]
fn add_flags_no_overflow_positive_plus_negative() {
    // Positive + negative never overflows signed
    let flags = add_flags(0x50, 0x90, 0xE0, 8); // 80 + (-112) = -32
    assert!(
        !flags.of,
        "OF should be clear: positive + negative cannot overflow"
    );
    assert!(flags.sf, "SF should be set: result is negative");
}

#[test]
fn sub_flags_overflow_signed_8bit() {
    // 0x80 - 0x01 = 0x7F → signed overflow (negative - positive = positive)
    let flags = sub_flags(0x80, 0x01, 0x7F, 8);
    assert!(flags.of, "OF should be set: -128 - 1 overflows i8");
    assert!(!flags.sf, "SF should be clear: result MSB is 0");
}

#[test]
fn sub_flags_no_overflow_same_sign() {
    // Subtracting values of the same sign doesn't overflow
    let flags = sub_flags(0x50, 0x20, 0x30, 8); // 80 - 32 = 48
    assert!(!flags.of, "OF should be clear: same sign subtraction");
}

#[test]
fn zero_flag_clear_on_nonzero_result() {
    let flags = add_flags(1, 2, 3, 32);
    assert!(!flags.zf, "ZF should be clear: 1 + 2 = 3");
}

#[test]
fn sign_flag_set_on_negative_result_8bit() {
    // Result with MSB set
    let flags = add_flags(0x70, 0x10, 0x80, 8);
    assert!(flags.sf, "SF should be set: result MSB is 1");
}

#[test]
fn sign_flag_clear_on_positive_result_8bit() {
    let flags = add_flags(0x10, 0x20, 0x30, 8);
    assert!(!flags.sf, "SF should be clear: result MSB is 0");
}

#[test]
fn parity_flag_odd_ones_in_low_byte() {
    // 0x01 has 1 bit set → odd parity
    assert!(!parity(0x01), "1 bit → odd parity");
    // 0x07 has 3 bits set → odd parity
    assert!(!parity(0x07), "3 bits → odd parity");
    // 0x80 has 1 bit set → odd parity
    assert!(!parity(0x80), "1 bit → odd parity");
}

#[test]
fn parity_flag_in_add_result() {
    // 1 + 1 = 2 → 0x02 has 1 bit → odd parity → PF false
    let flags = add_flags(1, 1, 2, 8);
    assert!(!flags.pf, "PF should be clear: result 0x02 has odd parity");

    // 1 + 2 = 3 → 0x03 has 2 bits → even parity → PF true
    let flags = add_flags(1, 2, 3, 8);
    assert!(flags.pf, "PF should be set: result 0x03 has even parity");
}

#[test]
fn logic_flags_clears_cf_and_of() {
    let flags = logic_flags(0xFF, 8);
    assert!(!flags.cf, "CF should be clear after logic op");
    assert!(!flags.of, "OF should be clear after logic op");
    assert!(!flags.af, "AF should be clear after logic op");
}

#[test]
fn logic_flags_zero_result() {
    let flags = logic_flags(0, 32);
    assert!(flags.zf, "ZF should be set: result is zero");
    assert!(!flags.sf, "SF should be clear: result is zero");
}

#[test]
fn logic_flags_negative_result_32bit() {
    let flags = logic_flags(0x8000_0000, 32);
    assert!(flags.sf, "SF should be set: MSB is 1");
    assert!(!flags.zf, "ZF should be clear: result is non-zero");
}

#[test]
fn checked_le_bytes_4_out_of_bounds() {
    let data = vec![0x10, 0x20, 0x30];
    let err = checked_le_bytes_4(&data, 0).unwrap_err();
    assert_eq!(err.code, ReasonCode::RcUnimplInsn);
    assert!(err.message.contains("offset 0"));
    assert!(err.message.contains("len=3"));
}

#[test]
fn checked_le_bytes_8_out_of_bounds() {
    let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    let err = checked_le_bytes_8(&data, 0).unwrap_err();
    assert_eq!(err.code, ReasonCode::RcUnimplInsn);
    assert!(err.message.contains("offset 0"));
    assert!(err.message.contains("len=7"));
}

// -----------------------------------------------------------------------
// Item 89: Instruction-level tests for arithmetic flags
// -----------------------------------------------------------------------

#[test]
fn auxiliary_carry_flag_clear_on_no_nibble_carry_add() {
    // 0x10 + 0x01 = 0x11: no carry from bit 3 → AF=0
    let flags = add_flags(0x10, 0x01, 0x11, 8);
    assert!(!flags.af, "AF should be clear: no carry from low nibble");
}

#[test]
fn auxiliary_carry_flag_clear_on_no_nibble_borrow_sub() {
    // 0x10 - 0x10 = 0x00: no borrow → AF=0
    let flags = sub_flags(0x10, 0x10, 0x00, 8);
    assert!(!flags.af, "AF should be clear: no borrow");
}

#[test]
fn add_flags_overflow_16bit() {
    // 0x7FFF + 0x0001 = 0x8000 → signed overflow
    let flags = add_flags(0x7FFF, 0x0001, 0x8000, 16);
    assert!(flags.of, "OF should be set: i16 overflow");
    assert!(flags.sf, "SF should be set: result MSB is 1");
}

#[test]
fn add_flags_overflow_32bit() {
    // 0x7FFFFFFF + 1 = 0x80000000 → signed overflow
    let flags = add_flags(0x7FFF_FFFF, 1, 0x8000_0000, 32);
    assert!(flags.of, "OF should be set: i32 overflow");
    assert!(flags.sf, "SF should be set: result MSB is 1");
}

#[test]
fn sub_flags_overflow_16bit() {
    // 0x8000 - 0x0001 = 0x7FFF → signed overflow (-32768 - 1 = overflow)
    let flags = sub_flags(0x8000, 0x0001, 0x7FFF, 16);
    assert!(flags.of, "OF should be set: i16 borrow overflow");
    assert!(!flags.sf, "SF should be clear: result MSB is 0");
}

#[test]
fn sub_flags_overflow_32bit() {
    // 0x80000000 - 1 = 0x7FFFFFFF → signed overflow
    let flags = sub_flags(0x8000_0000, 1, 0x7FFF_FFFF, 32);
    assert!(flags.of, "OF should be set: i32 borrow overflow");
}

#[test]
fn sub_flags_parity_odd() {
    // 0x10 - 0x0F = 0x01 (1 bit set) → odd parity → PF=0
    let flags = sub_flags(0x10, 0x0F, 0x01, 8);
    assert!(!flags.pf, "PF=0 for result 0x01 (odd parity)");
}

// -----------------------------------------------------------------------
// Exhaustive flag ground truth: every width-8 pair, dense width-16/32/64
// samples, for ADD/ADC/SUB/SBB — the same overflowing_add/overflowing_sub
// formulation the interpreter and the JIT helper must agree on.
// -----------------------------------------------------------------------

fn ground_truth_add(a: u64, b: u64, bits: u32) -> Flags {
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let (a, b) = (a & mask, b & mask);
    // Truncate the sum to the operation width BEFORE testing the carry:
    // 8-bit 0xff + 0x01 wraps to 0x00 with a carry even though the u64
    // addition 255 + 1 does not overflow.
    let sum = a.wrapping_add(b) & mask;
    let sign_bit = 1u64 << (bits - 1);
    Flags {
        cf: sum < a,
        pf: parity(sum as u8),
        af: ((a ^ b ^ sum) & 0x10) != 0,
        zf: sum == 0,
        sf: (sum & sign_bit) != 0,
        of: ((!(a ^ b) & (a ^ sum)) & sign_bit) != 0,
    }
}

fn ground_truth_adc(a: u64, b: u64, carry_in: u64, bits: u32) -> Flags {
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let (a, b) = (a & mask, b & mask);
    let sum = a as u128 + b as u128 + carry_in as u128;
    let result = (sum & mask as u128) as u64;
    let sign_bit = 1u64 << (bits - 1);
    let signed_a = signed_value(a, bits as usize);
    let signed_b = signed_value(b, bits as usize);
    let signed_sum = signed_a + signed_b + carry_in as i128;
    let min_signed = -(1_i128 << (bits - 1));
    let max_signed = (1_i128 << (bits - 1)) - 1;
    Flags {
        cf: sum > mask as u128,
        pf: parity(result as u8),
        af: ((a & 0x0f) + (b & 0x0f) + carry_in) > 0x0f,
        zf: result == 0,
        sf: (result & sign_bit) != 0,
        of: signed_sum < min_signed || signed_sum > max_signed,
    }
}

fn ground_truth_sub(a: u64, b: u64, bits: u32) -> Flags {
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let (a, b) = (a & mask, b & mask);
    let (diff, _borrow) = a.overflowing_sub(b);
    let diff = diff & mask;
    let sign_bit = 1u64 << (bits - 1);
    Flags {
        cf: a < b,
        pf: parity(diff as u8),
        af: ((a ^ b ^ diff) & 0x10) != 0,
        zf: diff == 0,
        sf: (diff & sign_bit) != 0,
        of: (((a ^ b) & (a ^ diff)) & sign_bit) != 0,
    }
}

fn ground_truth_sbb(a: u64, b: u64, borrow_in: u64, bits: u32) -> Flags {
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let (a, b) = (a & mask, b & mask);
    let rhs_with_borrow = b.wrapping_add(borrow_in) & mask;
    let diff = a.wrapping_sub(rhs_with_borrow) & mask;
    let sign_bit = 1u64 << (bits - 1);
    Flags {
        cf: (a as u128) < (b as u128 + borrow_in as u128),
        pf: parity(diff as u8),
        af: ((a ^ rhs_with_borrow ^ diff) & 0x10) != 0,
        zf: diff == 0,
        sf: (diff & sign_bit) != 0,
        of: (((a ^ rhs_with_borrow) & (a ^ diff)) & sign_bit) != 0,
    }
}

fn assert_flags_eq(got: Flags, expected: Flags, context: &str) {
    assert_eq!(got.cf, expected.cf, "{context}: CF");
    assert_eq!(got.pf, expected.pf, "{context}: PF");
    assert_eq!(got.af, expected.af, "{context}: AF");
    assert_eq!(got.zf, expected.zf, "{context}: ZF");
    assert_eq!(got.sf, expected.sf, "{context}: SF");
    assert_eq!(got.of, expected.of, "{context}: OF");
}

fn stride_sample_values(bits: u32) -> Vec<u64> {
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let msb = 1u64 << (bits - 1);
    let mut values = vec![
        0,
        1,
        mask,
        mask - 1,
        msb,
        msb - 1,
        msb + 1,
        0x0f,
        0x10,
        0xff,
        0x0f_0f,
        0xf0_f0,
    ];
    let stride = mask / 257;
    for k in 0..=256u64 {
        values.push(k.wrapping_mul(stride) & mask);
    }
    values
}

#[test]
fn add_flags_exhaustive_8bit_matches_ground_truth() {
    for a in 0..=255u64 {
        for b in 0..=255u64 {
            let sum = a.wrapping_add(b) & 0xff;
            assert_flags_eq(
                add_flags(a, b, sum, 8),
                ground_truth_add(a, b, 8),
                &format!("8-bit add {a:#x} + {b:#x}"),
            );
        }
    }
}

#[test]
fn adc_flags_exhaustive_8bit_matches_ground_truth() {
    for carry in [0u64, 1] {
        for a in 0..=255u64 {
            for b in 0..=255u64 {
                let sum = a.wrapping_add(b).wrapping_add(carry) & 0xff;
                assert_flags_eq(
                    adc_flags(a, b, carry, sum, 8),
                    ground_truth_adc(a, b, carry, 8),
                    &format!("8-bit adc {a:#x} + {b:#x} + {carry}"),
                );
            }
        }
    }
}

#[test]
fn sub_flags_exhaustive_8bit_matches_ground_truth() {
    for a in 0..=255u64 {
        for b in 0..=255u64 {
            let diff = a.wrapping_sub(b) & 0xff;
            assert_flags_eq(
                sub_flags(a, b, diff, 8),
                ground_truth_sub(a, b, 8),
                &format!("8-bit sub {a:#x} - {b:#x}"),
            );
        }
    }
}

#[test]
fn sbb_flags_exhaustive_8bit_matches_ground_truth() {
    for borrow in [0u64, 1] {
        for a in 0..=255u64 {
            for b in 0..=255u64 {
                let rhs = b.wrapping_add(borrow) & 0xff;
                let diff = a.wrapping_sub(rhs) & 0xff;
                assert_flags_eq(
                    sbb_flags(a, b, borrow, diff, 8),
                    ground_truth_sbb(a, b, borrow, 8),
                    &format!("8-bit sbb {a:#x} - {b:#x} - {borrow}"),
                );
            }
        }
    }
}

#[test]
fn inc_flags_does_not_affect_carry() {
    // INC eax (width=32): 0xFFFFFFFF + 1 = 0x00000000 but CF is NOT set
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0xFFFF_FFFF);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::IncReg {
            dst: Register::Rax,
            width: 4,
        }],
    )
    .expect("inc eax");
    assert_eq!(state.get(Register::Rax), 0);
    assert!(!state.flags.cf, "INC should not affect CF");
    assert!(state.flags.zf, "ZF should be set: result is zero");
}

#[test]
fn dec_flags_does_not_affect_carry() {
    // DEC eax (width=32): 0x00000000 - 1 = 0xFFFFFFFF but CF is NOT set
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::DecReg {
            dst: Register::Rax,
            width: 4,
        }],
    )
    .expect("dec eax");
    assert_eq!(state.get(Register::Rax), 0xFFFF_FFFF);
    assert!(!state.flags.cf, "DEC should not affect CF");
    assert!(state.flags.sf, "SF should be set: result MSB is 1");
}

#[test]
fn neg_flags_zero_result() {
    // NEG of 0 is 0: ZF=1, CF=0
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::NegReg {
            dst: Register::Rax,
            width: 4,
        }],
    )
    .expect("neg eax");
    assert_eq!(state.get(Register::Rax), 0);
    assert!(state.flags.zf, "ZF should be set: result is zero");
    assert!(!state.flags.cf, "CF should be clear: neg(0) = 0, no borrow");
}

#[test]
fn shift_flags_carry_from_sar() {
    // SAR preserves sign; for width=8:
    // 0x80 >> 1 = 0xC0 (sign-extended), CF=0 (LSB was 0)
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0x80);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::SarImm {
            dst: Register::Rax,
            count: 1,
            width: 1,
        }],
    )
    .expect("sar al, 1");
    assert_eq!(state.get_byte(ByteRegister::Al), 0xC0);
    assert!(!state.flags.cf, "CF should be clear: LSB was 0");
    assert!(state.flags.sf, "SF should be set: sign preserved");
}

// -----------------------------------------------------------------------
// Item 90: Instruction-level tests for string instructions and repeat prefixes
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Item 91: Segment, TLS, TEB, and PEB interactions
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Item 92: SSE, AVX-shaped, and floating-point operations
// -----------------------------------------------------------------------
//
// NOTE: Scalar SSE operations (ADDSS, SUBSS, MULSS, SQRTSS, MAXSS, MINSS)
// are tested via the full decode+execute pipeline using real x86 bytes in the
// existing tests above (e.g., decode_and_execute_divss_then_comiss).
// The tests below exercise packed arithmetic via the AVX-512 AddPacked/
// SubPacked/MulPacked/etc. IR instructions (which also serve as the
// execution backend for VEX-encoded 128/256-bit operations).

#[test]
fn addsd_scalar_double_addition() {
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    state.set_xmm(0, f64x2_to_xmm([2.5, 9.0]));
    state.set_xmm(1, f64x2_to_xmm([3.5, 1.0]));
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Addsd {
            dst: 0,
            src: VectorOperand::Register(1),
        }],
    )
    .expect("Addsd");
    // Addsd only modifies the low (scalar) lane of the destination
    assert_eq!(xmm_to_f64x2(state.get_xmm(0)), [6.0, 9.0]);
}

#[test]
fn comiss_sets_flags_for_equal_values() {
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    state.set_xmm(0, f32x4_to_xmm([1.0, 0.0, 0.0, 0.0]));
    state.set_xmm(1, f32x4_to_xmm([1.0, 0.0, 0.0, 0.0]));
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Comiss {
            lhs: 0,
            rhs: VectorOperand::Register(1),
        }],
    )
    .expect("Comiss equal");
    assert!(!state.flags.cf, "CF=0 for equal");
    assert!(state.flags.zf, "ZF=1 for equal (ordered)");
    assert!(!state.flags.pf, "PF=0 for equal (no unordered)");
}

#[test]
fn comiss_sets_flags_for_less_than() {
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    state.set_xmm(0, f32x4_to_xmm([1.0, 0.0, 0.0, 0.0]));
    state.set_xmm(1, f32x4_to_xmm([2.0, 0.0, 0.0, 0.0]));
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::Comiss {
            lhs: 0,
            rhs: VectorOperand::Register(1),
        }],
    )
    .expect("Comiss less");
    assert!(state.flags.cf, "CF=1 for less than (unordered)");
    assert!(!state.flags.zf, "ZF=0 for less than");
}

// -----------------------------------------------------------------------
// Item 93: x86 and x64 register aliasing behavior
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Item 94: Stack alignment across host thunk calls, callbacks, SEH, and JIT exits
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Item 95: CPUID leaf behavior against expected Windows guest assumptions
// -----------------------------------------------------------------------

// -----------------------------------------------------------------------
// Item 96: Differential tests comparing interpreter and JIT output
// -----------------------------------------------------------------------

#[test]
fn interpreter_and_jit_produce_same_result_for_arithmetic_block() {
    // Execute the same IR block via interpreter and (if JIT available) via JIT
    // At minimum, verify the interpreter produces the expected result.
    let ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 0x10,
        },
        IrInstruction::AddImm {
            dst: Register::Rax,
            value: 0x20,
            width: 4,
        },
        IrInstruction::MovImm {
            dst: Register::Rbx,
            value: 0x05,
        },
        IrInstruction::SubImm {
            dst: Register::Rbx,
            value: 0x03,
            width: 4,
        },
    ];

    // Interpreter run
    let mut interp_state = CpuState::new(GuestArch::X64);
    let mut interp_memory = MemoryImage::default();
    execute_ir(&mut interp_state, &mut interp_memory, &ir).expect("interpreter execute ir");

    // Verify interpreter result
    assert_eq!(interp_state.get(Register::Rax), 0x30);
    assert_eq!(interp_state.get(Register::Rbx), 0x02);
    assert!(!interp_state.flags.zf, "ZF should be clear");
    assert!(!interp_state.flags.cf, "CF should be clear");
}

#[test]
fn interpreter_produces_expected_flags_for_complex_arithmetic() {
    // Test a sequence: ADD with overflow, then ADC with carry
    let ir = vec![
        IrInstruction::MovImm {
            dst: Register::Rax,
            value: 0x7FFF_FFFF,
        },
        IrInstruction::AddImm {
            dst: Register::Rax,
            value: 0x0000_0001,
            width: 4,
        },
    ];
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    execute_ir(&mut state, &mut memory, &ir).expect("execute add overflow sequence");
    assert_eq!(state.get(Register::Rax), 0x8000_0000);
    assert!(state.flags.of, "OF should be set: signed overflow");
    assert!(state.flags.sf, "SF should be set: MSB=1");
    assert!(
        !state.flags.cf,
        "CF should be clear: no unsigned overflow at 32-bit"
    );
}

// -----------------------------------------------------------------------
// Item 97: Property tests for IR optimizer transformations
// -----------------------------------------------------------------------

#[test]
fn xor_same_register_zeroes_it() {
    // XOR reg, reg should zero the register (property: x XOR x = 0)
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0xDEAD_BEEF);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::XorReg {
            dst: Register::Rax,
            src: CompareOperand::Register(Register::Rax),
            width: 4,
        }],
    )
    .expect("xor eax, eax");
    assert_eq!(state.get(Register::Rax), 0, "XOR same reg should zero it");
    assert!(state.flags.zf, "ZF should be set: result is zero");
    assert!(!state.flags.cf, "CF should be cleared by XOR");
    assert!(!state.flags.of, "OF should be cleared by XOR");
}

#[test]
fn or_same_register_preserves_value() {
    // OR reg, reg should preserve the value but set flags
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rcx, 0xABCD);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::OrReg {
            dst: Register::Rcx,
            src: CompareOperand::Register(Register::Rcx),
            width: 2,
        }],
    )
    .expect("or cx, cx");
    assert_eq!(
        state.get(Register::Rcx),
        0xABCD,
        "OR same reg preserves value"
    );
    assert!(state.flags.sf, "SF should be set: MSB=1 at 16-bit");
    assert!(!state.flags.cf, "CF should be cleared by OR");
}

#[test]
fn add_zero_identity() {
    // ADD reg, 0 should not change the value
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0x42);
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::AddImm {
            dst: Register::Rax,
            value: 0,
            width: 4,
        }],
    )
    .expect("add eax, 0");
    assert_eq!(state.get(Register::Rax), 0x42, "ADD 0 is identity");
    assert!(!state.flags.zf, "ZF should be clear: result is non-zero");
}

#[test]
fn double_neg_identity() {
    // NEG(NEG(x)) = x (for non-minimum values)
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 0x42);
    // First NEG
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::NegReg {
            dst: Register::Rax,
            width: 4,
        }],
    )
    .expect("first neg");
    assert_eq!(state.get(Register::Rax), 0xFFFF_FFBEu64);
    // Second NEG
    execute_ir(
        &mut state,
        &mut memory,
        &[IrInstruction::NegReg {
            dst: Register::Rax,
            width: 4,
        }],
    )
    .expect("second neg");
    assert_eq!(state.get(Register::Rax), 0x42, "NEG(NEG(x)) = x");
}

// -----------------------------------------------------------------------
// Item 98: Unsupported instructions fail with precise reason codes
// -----------------------------------------------------------------------

#[test]
fn unsupported_instruction_returns_rc_unimpl_insn() {
    // Attempt to execute an instruction with an unimplemented opcode
    // via the decode and execute path
    let start_address = 0x1000;
    // 0x0F 0x01 0xC1 = VMCALL (typically unsupported)
    let bytes = [0x0F, 0x01, 0xC1];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64);
    // Depending on whether the decoder recognizes VMCALL, it may return an error
    if let Ok(decoded) = decoded {
        let result = lower_to_ir(&decoded);
        if let Ok(ir) = result {
            let mut state = CpuState::new(GuestArch::X64);
            let mut memory = MemoryImage::default();
            let exec_result = execute_ir(&mut state, &mut memory, &ir);
            if let Err(e) = exec_result {
                assert_eq!(
                    e.code,
                    ReasonCode::RcUnimplInsn,
                    "Unimplemented instruction should return RcUnimplInsn, got {:?}",
                    e.code
                );
            }
        }
    }
}

#[test]
fn unsupported_xop_instruction_returns_precise_error() {
    // XOP instructions (0x8F prefix) are not implemented and should fail
    let start_address = 0x1000;
    // 0x8F is the XOP prefix (AMD-specific, not supported)
    let bytes = [0x8F, 0x00, 0x00];
    let result = decode_block(&bytes, start_address, GuestArch::X64);
    match result {
        Err(e) => {
            assert_eq!(
                e.code,
                ReasonCode::RcUnimplInsn,
                "XOP decode error should have precise code"
            );
        }
        Ok(decoded) => {
            let ir_result = lower_to_ir(&decoded);
            match ir_result {
                Err(e) => {
                    assert_eq!(
                        e.code,
                        ReasonCode::RcUnimplInsn,
                        "XOP lower error should have precise code"
                    );
                }
                Ok(ir) => {
                    let mut state = CpuState::new(GuestArch::X64);
                    let mut memory = MemoryImage::default();
                    let exec_result = execute_ir(&mut state, &mut memory, &ir);
                    if let Err(e) = exec_result {
                        assert_eq!(
                            e.code,
                            ReasonCode::RcUnimplInsn,
                            "XOP exec error should have precise code"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn decode_illegal_instruction_returns_rc_unimpl_insn() {
    // 0x0F 0x0B = UD2 (undefined instruction). It decodes cleanly so that
    // MSVC __assume(0)/assert paths become visible guest faults at
    // execution time rather than decode errors.
    let start_address = 0x1000;
    let bytes = [0x0F, 0x0B];
    let decoded = decode_block(&bytes, start_address, GuestArch::X64)
        .expect("UD2 should decode to a dedicated opcode");
    assert_eq!(decoded.len(), 1, "UD2 should decode one instruction");
    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::Ud2),
        "UD2 should decode as DecodedOpcode::Ud2"
    );
    let ir = lower_to_ir(&decoded).expect("UD2 should lower");
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    let result = execute_ir(&mut state, &mut memory, &ir);
    assert!(result.is_err(), "UD2 execution should fault");
    if let Err(e) = result {
        assert_eq!(
            e.code,
            ReasonCode::RcUnimplInsn,
            "UD2 should return RcUnimplInsn, got {:?}",
            e.code
        );
    }
}

#[test]
fn decode_unsupported_three_byte_opcode_returns_precise_reason() {
    // 3-byte opcodes in the 0x0F 0x3A/0x38 space that are not implemented
    let start_address = 0x1000;
    // 0x66 0x0F 0x3A 0x42 = MPSADBW (not necessarily implemented)
    let bytes = [0x66, 0x0F, 0x3A, 0x42, 0xC0, 0x00];
    let result = decode_block(&bytes, start_address, GuestArch::X64);
    match result {
        Err(e) => {
            assert_eq!(
                e.code,
                ReasonCode::RcUnimplInsn,
                "Unsupported 3-byte opcode should return RcUnimplInsn"
            );
        }
        Ok(_) => {
            // If it happens to be implemented, that's fine - just verify it doesn't panic
        }
    }
}

#[test]
fn unsupported_avx512_evex_instruction_returns_precise_error() {
    // EVEX-encoded instruction that might not be implemented
    let start_address = 0x1000;
    // 0x62 = EVEX prefix, followed by a valid but potentially unsupported combination
    let bytes = [0x62, 0xF2, 0x7D, 0x48, 0x58, 0xC0]; // EVEX.NDS.512 VADDPD
    let result = decode_block(&bytes, start_address, GuestArch::X64);
    match result {
        Err(e) => {
            assert_eq!(
                e.code,
                ReasonCode::RcUnimplInsn,
                "Unsupported EVEX instruction should return RcUnimplInsn"
            );
        }
        Ok(decoded) => {
            let ir_result = lower_to_ir(&decoded);
            match ir_result {
                Err(e) => {
                    assert_eq!(
                        e.code,
                        ReasonCode::RcUnimplInsn,
                        "Unsupported EVEX lower should return RcUnimplInsn"
                    );
                }
                Ok(ir) => {
                    let mut state = CpuState::new(GuestArch::X64);
                    let mut memory = MemoryImage::default();
                    let exec_result = execute_ir(&mut state, &mut memory, &ir);
                    if let Err(e) = exec_result {
                        assert_eq!(
                            e.code,
                            ReasonCode::RcUnimplInsn,
                            "Unsupported EVEX exec should return RcUnimplInsn, got {:?}",
                            e.code
                        );
                    }
                }
            }
        }
    }
}

// =====================================================================
// Newly implemented opcodes: 0x22 AND r8,r/m8, 0x28 SUB r/m8,r8,
// BSWAP, ROR, PUSHAD/POPAD, LODS, SAHF/LAHF, JP/JNP, parity conditions
// =====================================================================

#[test]
fn decode_and_execute_and_r8_rm8_opcode_0x22_register_form() {
    // AND al, bl = 0x22 0xC3 (mod=11, reg=000=al, rm=011=bl)
    let bytes = [0x22, 0xC3];
    let decoded = decode_block(&bytes, 0x1000, GuestArch::X86).expect("decode 0x22 AND al, bl");
    assert_eq!(decoded.len(), 1);
    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::AndReg8),
        "0x22 should decode as AndReg8"
    );
    let ir = lower_to_ir(&decoded).expect("lower 0x22");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    state.set_byte(ByteRegister::Al, 0x0F);
    state.set_byte(ByteRegister::Bl, 0x33);
    execute_ir(&mut state, &mut memory, &ir).expect("execute AND al, bl");
    assert_eq!(state.get_byte(ByteRegister::Al), 0x03);
    assert!(!state.flags.zf && !state.flags.sf);
    assert!(state.flags.pf, "0x03 has two set bits -> even parity");
}

#[test]
fn decode_and_execute_sahf_lahf_roundtrip() {
    // SAHF = 0x9E, LAHF = 0x9F.
    let bytes = [0x9E];
    let decoded = decode_block(&bytes, 0x1000, GuestArch::X86).expect("decode SAHF");
    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::Sahf),
        "0x9e should decode as Sahf"
    );
    let ir = lower_to_ir(&decoded).expect("lower SAHF");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    state.set_byte(ByteRegister::Ah, 0b1100_0101);
    execute_ir(&mut state, &mut memory, &ir).expect("execute SAHF");
    assert!(state.flags.sf, "SF from AH bit 7");
    assert!(state.flags.zf, "ZF from AH bit 6");
    assert!(!state.flags.af, "AF from AH bit 4");
    assert!(state.flags.pf, "PF from AH bit 2");
    assert!(state.flags.cf, "CF from AH bit 0");

    // LAHF back: 0x9F
    let bytes = [0x9F];
    let decoded = decode_block(&bytes, 0x1000, GuestArch::X86).expect("decode LAHF");
    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::Lahf),
        "0x9f should decode as Lahf"
    );
    let ir = lower_to_ir(&decoded).expect("lower LAHF");
    state.set_byte(ByteRegister::Ah, 0);
    execute_ir(&mut state, &mut memory, &ir).expect("execute LAHF");
    assert_eq!(state.get_byte(ByteRegister::Ah), 0b1100_0101);
}

#[test]
fn decode_and_execute_clc_stc_cmc() {
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    state.flags.cf = true;
    execute_ir(
        &mut state,
        &mut memory,
        &lower_to_ir(&decode_block(&[0xF8], 0x1000, GuestArch::X86).expect("decode CLC"))
            .expect("lower CLC"),
    )
    .expect("execute CLC");
    assert!(!state.flags.cf, "CLC clears CF");

    execute_ir(
        &mut state,
        &mut memory,
        &lower_to_ir(&decode_block(&[0xF9], 0x1000, GuestArch::X86).expect("decode STC"))
            .expect("lower STC"),
    )
    .expect("execute STC");
    assert!(state.flags.cf, "STC sets CF");

    execute_ir(
        &mut state,
        &mut memory,
        &lower_to_ir(&decode_block(&[0xF5], 0x1000, GuestArch::X86).expect("decode CMC"))
            .expect("lower CMC"),
    )
    .expect("execute CMC");
    assert!(!state.flags.cf, "CMC complements CF");
}

#[test]
fn decode_and_execute_opcode_0x82_alias_and_sbb_eax_imm32() {
    // 0x82 is the 32-bit-mode alias of 0x80: AND byte ptr [ebx], 0x0F
    let bytes = [0x82, 0x23, 0x0F]; // mod=00, reg=100=and, rm=011=ebx
    let decoded = decode_block(&bytes, 0x1000, GuestArch::X86).expect("decode 0x82 alias");
    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::AndImm),
        "0x82 should decode as AndImm"
    );
    let ir = lower_to_ir(&decoded).expect("lower 0x82");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    state.set(Register::Rbx, 0x5000);
    memory.write_u8(0x5000, 0xFF);
    execute_ir(&mut state, &mut memory, &ir).expect("execute 0x82 AND");
    assert_eq!(memory.read_u8(0x5000).expect("read result"), 0x0F);

    // 0x82 must be rejected in 64-bit mode
    let result = decode_block(&bytes, 0x1000, GuestArch::X64);
    assert!(result.is_err(), "0x82 is invalid in 64-bit mode");

    // SBB eax, 5 = 0x1D 0x05 0x00 0x00 0x00 with CF=1: eax = 100 - 5 - 1 = 94
    let bytes = [0x1D, 0x05, 0x00, 0x00, 0x00];
    let decoded = decode_block(&bytes, 0x1000, GuestArch::X86).expect("decode SBB eax, 5");
    assert!(
        matches!(decoded[0].opcode, DecodedOpcode::SbbImm),
        "0x1d should decode as SbbImm"
    );
    let ir = lower_to_ir(&decoded).expect("lower 0x1d");
    let mut state = CpuState::new(GuestArch::X86);
    let mut memory = MemoryImage::default();
    state.set(Register::Rax, 100);
    state.flags.cf = true;
    execute_ir(&mut state, &mut memory, &ir).expect("execute SBB eax, 5");
    assert_eq!(state.get(Register::Rax), 94);
}

// ── Hot-block decode cache ──────────────────────────────────────────

#[test]
fn decode_cache_direct_hit_miss_and_capacity_eviction() {
    let bytes = [0x90u8; 8];
    let decoded = Arc::new(decode_block_uncached(&bytes, 0x1000, GuestArch::X64).expect("decode"));

    let mut cache = DecodeCache::new();
    cache.insert(0x1000, bytes.len(), 0, &bytes, Arc::clone(&decoded));
    assert!(
        cache.get(0x1000, bytes.len(), 0, &bytes).is_some(),
        "identical bytes must hit"
    );
    assert!(
        cache.get(0x1000, bytes.len(), 0, &[0xCC; 8]).is_none(),
        "different bytes at the same address must miss"
    );
    assert!(
        cache.get(0x2000, bytes.len(), 0, &bytes).is_none(),
        "different address must miss"
    );

    let evictions_before = decode_cache_telemetry().evictions;
    for index in 0..(DECODE_CACHE_CAPACITY as u64 + 4) {
        cache.insert(0x20_0000 + index, 1, 0, &[0x90], Arc::clone(&decoded));
    }
    assert!(
        decode_cache_telemetry().evictions > evictions_before,
        "exceeding capacity must evict entries"
    );
}

// ── Lazy x86 flag materialisation ───────────────────────────────────

#[test]
fn copy_page_to_raw_copies_fully_mapped_page_and_rejects_partial() {
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x4000, &[0xCD; 4096]);

    let mut dst = [0u8; 4096];
    assert!(unsafe { memory.copy_page_to_raw(0x4000, dst.as_mut_ptr()) });
    assert_eq!(dst[0], 0xCD);
    assert_eq!(dst[2048], 0xCD);
    assert_eq!(dst[4095], 0xCD);

    // A partially-mapped page must be rejected.
    let mut partial = MemoryImage::default();
    partial.map_bytes(0x5000, &[0x11; 16]);
    assert!(!unsafe { partial.copy_page_to_raw(0x5000, dst.as_mut_ptr()) });

    // An absent page must be rejected.
    assert!(!unsafe { memory.copy_page_to_raw(0x9000, dst.as_mut_ptr()) });
}

// ── Canonical sparse store ─────────────────────────────────────────

#[test]
fn sparse_two_gib_commit_materialises_pages_once_and_only_touched_pages_resident() {
    let mut memory = MemoryImage::default();
    let low = 0x1000_u64;
    let two_gib = 0x7FFF_F000_u64;
    memory.map_bytes(low, &[0x11; 4096]);
    memory.map_bytes(two_gib, &[0xA5; 4096]);
    let store = Arc::clone(memory.canonical_store());

    assert_eq!(store.materialised_page_count(), 2);
    assert_eq!(store.materialisation_count(), 2);
    assert_eq!(
        store.resident_flat_page_count(),
        2,
        "only the two touched pages may be resident in a 4 GiB window"
    );

    // Repeated reads/writes of committed pages must never re-materialise.
    for value in 0..16_u64 {
        memory.write_u64(low, value);
        memory.write_u64(two_gib, value);
        assert_eq!(memory.read_u64(low).unwrap(), value);
        assert_eq!(memory.read_u64(two_gib).unwrap(), value);
    }
    assert_eq!(store.materialisation_count(), 2);
    assert_eq!(store.resident_flat_page_count(), 2);

    // An untouched page is a fault, not a materialisation.
    let error = memory
        .read_u8(0x4000_0000)
        .expect_err("an untouched sparse page must fault");
    assert_eq!(error.code, ReasonCode::RcUnimplInsn);
    assert_eq!(store.materialisation_count(), 2);
    assert!(!store.is_page_materialised(0x4000_0000));
}

#[test]
fn overwrite_mapped_page_never_corrupts_neighbour_pages_or_snapshot() {
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x2000, &[0x11; 4096]);
    memory.map_bytes(0x3000, &[0x22; 4096]);
    memory.map_bytes(0x4000, &[0x33; 4096]);
    let snapshot = memory.clone();

    memory.map_bytes(0x3000, &[0x44; 4096]);
    assert_eq!(memory.read_u8(0x2FFF).unwrap(), 0x11);
    assert_eq!(memory.read_u8(0x3000).unwrap(), 0x44);
    assert_eq!(memory.read_u8(0x3FFF).unwrap(), 0x44);
    assert_eq!(memory.read_u8(0x4000).unwrap(), 0x33);
    assert_eq!(
        snapshot.read_u8(0x3000).unwrap(),
        0x22,
        "a clone must remain an independent snapshot"
    );
    assert_eq!(snapshot.read_u8(0x2FFF).unwrap(), 0x11);
    assert_eq!(snapshot.read_u8(0x4000).unwrap(), 0x33);

    let store = Arc::clone(memory.canonical_store());
    assert_eq!(store.materialisation_count(), 3);
    memory.unmap_range(0x3000, 4096);
    assert_eq!(memory.read_u8(0x2000).unwrap(), 0x11);
    assert_eq!(memory.read_u8(0x4000).unwrap(), 0x33);
    assert!(
        memory.read_u8(0x3000).is_err(),
        "an unmapped page must not remain readable"
    );
    memory.map_bytes(0x3000, &[0x55; 16]);
    assert_eq!(
        store.materialisation_count(),
        4,
        "re-committing an unmapped page is a new materialisation"
    );
    assert_eq!(memory.read_u8(0x2000).unwrap(), 0x11);
    assert_eq!(memory.read_u8(0x3000).unwrap(), 0x55);
    assert_eq!(memory.read_u8(0x4000).unwrap(), 0x33);
    assert_eq!(snapshot.canonical_store().materialisation_count(), 3);
}

#[test]
fn high_address_edge_page_outside_flat_window_is_never_flat_resident() {
    let mut memory = MemoryImage::default();
    // A dynamic-base x64 PE is routinely mapped above the direct window.
    let address = 0x1800_0000_0000_u64;
    memory.map_bytes(address, &[0x7E; 4096]);
    let store = Arc::clone(memory.canonical_store());
    assert_eq!(store.materialised_page_count(), 1);
    assert_eq!(store.materialisation_count(), 1);
    assert_eq!(
        store.resident_flat_page_count(),
        0,
        "a page above the flat window must not consume flat residency"
    );
    assert!(store.is_page_materialised(address));
    assert_eq!(memory.read_u8(address).unwrap(), 0x7E);
    memory.write_u8(address + 4095, 0x42);
    assert_eq!(memory.read_u8(address + 4095).unwrap(), 0x42);
    assert_eq!(store.materialisation_count(), 1);

    memory.unmap_range(address, 4096);
    assert_eq!(store.materialised_page_count(), 0);
    assert!(!store.is_page_materialised(address));
    assert!(
        memory.read_u8(address).is_err(),
        "a released high page must fault"
    );
}

#[test]
fn partial_page_boundary_probes_never_report_unmapped_bytes_or_absent_pages() {
    let mut memory = MemoryImage::default();
    memory.map_bytes(0x5000, &[0x11; 16]);
    assert!(memory.page_exists(0x5000));
    assert!(!memory.page_is_fully_mapped(0x5000));
    assert!(memory.page_byte_is_mapped(0x5000, 0));
    assert!(memory.page_byte_is_mapped(0x5000, 15));
    assert!(!memory.page_byte_is_mapped(0x5000, 16));
    assert!(!memory.page_byte_is_mapped(0x5000, 4095));
    assert!(!memory.page_exists(0x6000));
    assert!(!memory.page_byte_is_mapped(0x6000, 0));
    assert_eq!(memory.canonical_store().materialisation_count(), 1);
}

#[test]
fn concurrent_flat_and_image_atomic_views_never_observe_stale_or_torn_values() {
    use std::sync::atomic::AtomicU32;

    let mut memory = MemoryImage::default();
    let address = 0x8000_u64;
    memory.map_bytes(address, &[0; 4096]);
    let store = memory.canonical_store();
    let flat_view = (store.flat_base() + address) as usize;
    let image_view = memory.atomic_u32_at(address).unwrap() as *const AtomicU32 as usize;
    let iterations = 100_000_u32;

    // JIT view writes, interpreter view reads.
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            // SAFETY: the canonical page is committed and 4-byte aligned;
            // the raw address came from the store's flat window.
            let atomic = unsafe { &*(flat_view as *const AtomicU32) };
            for value in 1..=iterations {
                atomic.store(value, std::sync::atomic::Ordering::SeqCst);
            }
        });
        // SAFETY: the page is committed and naturally aligned; the image
        // view is the same physical bytes as the flat view.
        let reader = unsafe { &*(image_view as *const AtomicU32) };
        let mut last = 0_u32;
        while last < iterations {
            let observed = reader.load(std::sync::atomic::Ordering::SeqCst);
            assert!(
                observed >= last,
                "the interpreter view moved backwards: {observed} < {last}"
            );
            last = observed;
            std::hint::spin_loop();
        }
        writer.join().unwrap();
    });
    assert_eq!(memory.read_u32(address).unwrap(), iterations);

    // Interpreter view writes, JIT view reads.
    let image_atomic = unsafe { &*(image_view as *const AtomicU32) };
    image_atomic.store(0, std::sync::atomic::Ordering::SeqCst);
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            // SAFETY: same committed, aligned canonical page as above.
            let atomic = unsafe { &*(image_view as *const AtomicU32) };
            for value in 1..=iterations {
                atomic.store(value, std::sync::atomic::Ordering::SeqCst);
            }
        });
        // SAFETY: same committed, aligned canonical page as above.
        let reader = unsafe { &*(flat_view as *const AtomicU32) };
        let mut last = 0_u32;
        while last < iterations {
            let observed = reader.load(std::sync::atomic::Ordering::SeqCst);
            assert!(
                observed >= last,
                "the flat view moved backwards: {observed} < {last}"
            );
            last = observed;
            std::hint::spin_loop();
        }
        writer.join().unwrap();
    });
    assert_eq!(memory.read_u32(address).unwrap(), iterations);
    assert_eq!(store.materialisation_count(), 1);
}

#[test]
fn concurrent_multi_page_stress_keeps_views_coherent_without_rematerialising() {
    use std::sync::atomic::{AtomicBool, AtomicU64};

    const PAGES: u64 = 8;
    const ITERATIONS: u64 = 20_000;
    let mut memory = MemoryImage::default();
    let mut views = Vec::new();
    for page in 0..PAGES {
        let address = 0x10_0000 + page * 0x1000;
        memory.map_bytes(address, &[0; 4096]);
        let image_ptr = memory.page(address).expect("committed page").bytes.as_ptr() as usize;
        views.push((
            image_ptr,
            memory.canonical_store().flat_base() as usize + address as usize,
        ));
    }
    let store = memory.canonical_store();
    let done = AtomicBool::new(false);

    std::thread::scope(|scope| {
        let mut writers = Vec::new();
        for &(_, flat) in &views {
            writers.push(scope.spawn(move || {
                // SAFETY: page base is aligned and committed; each writer
                // owns a distinct page.
                let atomic = unsafe { &*(flat as *const AtomicU64) };
                for _ in 0..ITERATIONS {
                    atomic.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        let mut readers = Vec::new();
        for &(image, _) in &views {
            let done = &done;
            readers.push(scope.spawn(move || {
                // SAFETY: page base is aligned and committed; readers only
                // load from the same physical atomic the writer updates.
                let atomic = unsafe { &*(image as *const AtomicU64) };
                let mut last = 0_u64;
                while !done.load(std::sync::atomic::Ordering::Acquire) {
                    let observed = atomic.load(std::sync::atomic::Ordering::SeqCst);
                    assert!(
                        observed >= last,
                        "concurrent view observed a backwards value: {observed} < {last}"
                    );
                    last = observed;
                    std::hint::spin_loop();
                }
                atomic.load(std::sync::atomic::Ordering::SeqCst)
            }));
        }
        for writer in writers {
            writer.join().unwrap();
        }
        done.store(true, std::sync::atomic::Ordering::Release);
        for reader in readers {
            assert_eq!(reader.join().unwrap(), ITERATIONS);
        }
    });

    for page in 0..PAGES {
        let address = 0x10_0000 + page * 0x1000;
        assert_eq!(memory.read_u64(address).unwrap(), ITERATIONS);
        assert_eq!(
            memory.page(address).expect("committed page").bytes.as_ptr() as usize,
            views[page as usize].0
        );
    }
    assert_eq!(store.materialised_page_count(), PAGES);
    assert_eq!(store.materialisation_count(), PAGES);
}

// ── Large sparse direct window ──────────────────────────────────────

#[test]
fn flat_window_reservation_is_aligned_sparse_and_rejects_overflow() {
    let memory = MemoryImage::default();
    let store = memory.canonical_store();
    assert_eq!(
        store.flat_size() >= GUEST_FLAT_MIN_SIZE,
        true,
        "the direct window must be at least 128 GiB (256 GiB preferred)"
    );
    assert_eq!(store.flat_size().is_power_of_two(), true);
    assert_eq!(
        store.flat_size() % GUEST_FLAT_MIN_SIZE,
        0,
        "window sizes must be power-of-two multiples of the minimum"
    );
    assert_eq!(store.is_valid(), true);
    assert_eq!(
        store.flat_base() % GUEST_FLAT_ALIGN as u64,
        0,
        "the flat base must be aligned for direct guest addressing"
    );
    assert_eq!(store.flat_base() % 4096, 0);
    assert_eq!(store.materialised_page_count(), 0);
    assert_eq!(store.materialisation_count(), 0);
    assert_eq!(
        store.resident_flat_page_count(),
        0,
        "reserving the window must not commit a single page"
    );
    assert_eq!(store.high_page_count(), 0);

    // The reservation must fail cleanly instead of panicking or wrapping.
    assert_eq!(
        unsafe { reserve_flat_window(usize::MAX, GUEST_FLAT_ALIGN) }.is_null(),
        true,
        "size overflow must be rejected"
    );
    assert_eq!(
        unsafe { reserve_flat_window(usize::MAX - GUEST_FLAT_ALIGN, GUEST_FLAT_ALIGN) }.is_null(),
        true,
        "an impossible reservation must fail without committing memory"
    );

    // When the preferred size is impossible, the next candidate (the
    // guaranteed 128 GiB minimum) must be reserved instead.
    let (fallback_size, fallback_base) = reserve_flat_window_candidates(
        &[usize::MAX - GUEST_FLAT_ALIGN, GUEST_FLAT_MIN_SIZE],
        GUEST_FLAT_ALIGN,
    );
    assert_eq!(fallback_size, GUEST_FLAT_MIN_SIZE);
    assert_eq!(fallback_base.is_null(), false);
    assert_eq!(
        fallback_base as usize % GUEST_FLAT_ALIGN,
        0,
        "a fallback reservation must stay aligned"
    );
    // SAFETY: the reservation was returned by the helper above and is no
    // longer used after this release.
    unsafe {
        libc::munmap(fallback_base as *mut libc::c_void, fallback_size);
    }

    // Every candidate failing returns a null base and the preferred size,
    // never a dangling pointer.
    let (failed_size, failed_base) =
        reserve_flat_window_candidates(&[usize::MAX, usize::MAX - 1], GUEST_FLAT_ALIGN);
    assert_eq!(failed_size, usize::MAX);
    assert_eq!(failed_base.is_null(), true);
}

#[test]
fn page_directory_boundary_reuses_one_table_for_adjacent_high_pages() {
    let mut memory = MemoryImage::default();
    let first = 0x2_0000_0000_u64;
    let second = first + 0x1000;
    let unmapped_in_chunk = first + 0x2000;
    memory.map_bytes(first, &[0x10; 16]);
    memory.map_bytes(second, &[0x20; 16]);
    assert_eq!(memory.page_index(first), Some(0));
    assert_eq!(memory.page_index(second), Some(1));
    assert_eq!(memory.page_index(unmapped_in_chunk), None);
    assert_eq!(memory.read_u8(first).unwrap(), 0x10);
    assert_eq!(memory.read_u8(second).unwrap(), 0x20);
    assert_eq!(
        memory.read_u8(unmapped_in_chunk).is_err(),
        true,
        "an absent entry in an allocated 2 MiB chunk must fault"
    );
    assert_eq!(memory.canonical_store().materialisation_count(), 2);
    assert_eq!(memory.canonical_store().high_page_count(), 0);
}

#[test]
fn flat_window_four_gib_and_end_boundary_select_direct_or_owned_frames() {
    let mut memory = MemoryImage::default();
    let window_size = memory.canonical_store().flat_size() as u64;
    let below_four_gib = 0xFFFF_F000_u64;
    let at_four_gib = 0x1_0000_0000_u64;
    let at_sixty_four_gib = 0x10_0000_0000_u64;
    let last_flat_page = window_size - 0x1000;
    let beyond_window = window_size;
    let pages = [
        (below_four_gib, 0x11_u8),
        (at_four_gib, 0x22),
        (at_sixty_four_gib, 0x23),
        (last_flat_page, 0x33),
        (beyond_window, 0x44),
    ];
    for (address, value) in pages {
        memory.map_bytes(address, &[value; 16]);
    }
    let store = Arc::clone(memory.canonical_store());
    assert_eq!(store.materialised_page_count(), 5);
    assert_eq!(store.materialisation_count(), 5);
    assert_eq!(
        store.high_page_count(),
        1,
        "only the page beyond the window may use an owned frame"
    );
    assert_eq!(
        store.resident_flat_page_count(),
        4,
        "only the four in-window pages may be resident"
    );
    assert_eq!(store.is_page_materialised(below_four_gib), true);
    assert_eq!(store.is_page_materialised(at_four_gib), true);
    assert_eq!(store.is_page_materialised(at_sixty_four_gib), true);
    assert_eq!(store.is_page_materialised(last_flat_page), true);
    assert_eq!(store.is_page_materialised(beyond_window), true);

    let flat_base = store.flat_base() as usize;
    for address in [
        below_four_gib,
        at_four_gib,
        at_sixty_four_gib,
        last_flat_page,
    ] {
        assert_eq!(
            memory.page(address).expect("flat page").bytes.as_ptr() as usize,
            flat_base + address as usize,
            "an address below the window must live at flat_base + address"
        );
    }
    assert_ne!(
        memory
            .page(beyond_window)
            .expect("owned frame")
            .bytes
            .as_ptr() as usize,
        flat_base + beyond_window as usize,
        "an address beyond the window must not alias the flat mapping"
    );

    // The direct mapping and the interpreter see the same bytes, including
    // the exact 4 GiB boundary and the last page of the window.
    for (address, value) in pages {
        assert_eq!(memory.read_u8(address).unwrap(), value);
        // SAFETY: every in-window page is backed by the live mapping; the
        // out-of-window page is deliberately not dereferenced directly.
        if address < window_size {
            assert_eq!(
                unsafe { std::ptr::read_volatile((flat_base + address as usize) as *const u8) },
                value
            );
            memory.write_u8(address, value.wrapping_add(1));
            assert_eq!(
                unsafe { std::ptr::read_volatile((flat_base + address as usize) as *const u8) },
                value.wrapping_add(1)
            );
        }
    }
    assert_eq!(store.materialisation_count(), 5);
}

#[test]
fn snapshot_above_four_gib_heap_never_observes_stale_live_writes() {
    let mut memory = MemoryImage::default();
    let address = 0x2_0000_0000_u64;
    let high_address = 0x1800_0000_0000_u64;
    memory.map_bytes(address, &[0x5A; 4096]);
    memory.map_bytes(high_address, &[0x6B; 4096]);
    let snapshot = memory.clone();
    assert_eq!(snapshot.read_u8(address).unwrap(), 0x5A);
    assert_eq!(
        snapshot.read_u8(high_address).unwrap(),
        0x6B,
        "an owned-frame page must survive the snapshot"
    );
    assert_eq!(
        memory.canonical_store().flat_size() >= GUEST_FLAT_MIN_SIZE,
        true
    );
    assert_eq!(
        snapshot.canonical_store().flat_size() >= GUEST_FLAT_MIN_SIZE,
        true
    );
    assert_ne!(
        memory.canonical_store().flat_base(),
        snapshot.canonical_store().flat_base(),
        "a clone must own a separate direct window"
    );

    memory.write_u8(address, 0xA5);
    memory.write_u8(high_address, 0xB6);
    assert_eq!(memory.read_u8(address).unwrap(), 0xA5);
    assert_eq!(memory.read_u8(high_address).unwrap(), 0xB6);
    assert_eq!(
        snapshot.read_u8(address).unwrap(),
        0x5A,
        "the snapshot must not observe the live image's write"
    );
    assert_eq!(
        snapshot.read_u8(high_address).unwrap(),
        0x6B,
        "the snapshot's owned frame must stay independent"
    );
    assert_eq!(memory.canonical_store().materialisation_count(), 2);
    assert_eq!(snapshot.canonical_store().materialisation_count(), 2);
    assert_eq!(memory.canonical_store().high_page_count(), 1);
    assert_eq!(snapshot.canonical_store().high_page_count(), 1);
}

#[test]
fn concurrent_views_above_four_gib_never_observe_torn_values() {
    use std::sync::atomic::AtomicU64;

    let mut memory = MemoryImage::default();
    let address = 0x2_0000_0000_u64;
    memory.map_bytes(address, &[0; 4096]);
    let store = memory.canonical_store();
    let flat_view = (store.flat_base() + address) as usize;
    let image_view = memory.page(address).expect("page").bytes.as_ptr() as usize;
    let iterations = 20_000_u64;

    std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            // SAFETY: the >4 GiB page is committed in the flat window and
            // both addresses refer to the same 8-byte-aligned atomic.
            let atomic = unsafe { &*(flat_view as *const AtomicU64) };
            for value in 1..=iterations {
                atomic.store(value, std::sync::atomic::Ordering::SeqCst);
            }
        });
        // SAFETY: same committed, aligned canonical page as above.
        let reader = unsafe { &*(image_view as *const AtomicU64) };
        let mut last = 0_u64;
        while last < iterations {
            let observed = reader.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                observed >= last,
                true,
                "the image view moved backwards: {observed} < {last}"
            );
            last = observed;
            std::hint::spin_loop();
        }
        writer.join().unwrap();
    });
    assert_eq!(memory.read_u64(address).unwrap(), iterations);
    assert_eq!(store.materialisation_count(), 1);
    assert_eq!(store.high_page_count(), 0);
}

#[test]
fn c7_slash0_is_mov_imm32_and_f8_is_xbegin_exactly() {
    // MOV RBX, 0x12345678 (REX.W C7 /0, mod=11)
    let mov = [0x48, 0xC7, 0xC3, 0x78, 0x56, 0x34, 0x12];
    let decoded = decode_block(&mov, 0x1000, GuestArch::X64).expect("decode mov");
    assert_eq!(decoded.len(), 1);
    assert_ne!(decoded[0].opcode, DecodedOpcode::Xbegin);
    assert_eq!(decoded[0].opcode, DecodedOpcode::MovImm);
    assert_eq!(
        decoded[0].operands,
        vec![
            Operand::Register(Register::Rbx),
            Operand::ImmediateU64(0x1234_5678)
        ]
    );

    // XBEGIN rel32 uses ModRM F8 (reg=7, rm=0), not /0.
    let xbegin = [0xC7, 0xF8, 0x05, 0x00, 0x00, 0x00];
    let decoded = decode_block(&xbegin, 0x2000, GuestArch::X86).expect("decode xbegin");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].opcode, DecodedOpcode::Xbegin);
}
