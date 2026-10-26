// ── JIT helper semantic tests ───────────────────────────────────────────────
//
// Native execution is capability-gated (see `jit_execution_capability`); the
// host-side helpers are plain `extern "C"` functions — these tests call
// `jit_helper_set_flags` / `jit_helper_load` directly and check their
// semantics against the x86 truth table.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpectedFlags {
    zf: bool,
    sf: bool,
    pf: bool,
    cf: bool,
    of: bool,
    af: bool,
}

fn width_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn even_low_byte_parity(value: u64) -> bool {
    let low = value as u8;
    (0..8).filter(|&i| low & (1 << i) != 0).count() % 2 == 0
}

fn truth_add(lhs: u64, rhs: u64, bits: u32) -> ExpectedFlags {
    let m = width_mask(bits);
    let (a, b) = (lhs & m, rhs & m);
    let sum = a.wrapping_add(b) & m;
    let msb = 1u64 << (bits - 1);
    ExpectedFlags {
        zf: sum == 0,
        sf: sum & msb != 0,
        pf: even_low_byte_parity(sum),
        cf: sum < a,
        of: (a & msb != 0) == (b & msb != 0) && (sum & msb != 0) != (a & msb != 0),
        af: (a ^ b ^ sum) & 0x10 != 0,
    }
}

fn truth_sub(lhs: u64, rhs: u64, bits: u32) -> ExpectedFlags {
    let m = width_mask(bits);
    let (a, b) = (lhs & m, rhs & m);
    let (diff, _borrow) = a.overflowing_sub(b);
    let diff = diff & m;
    let msb = 1u64 << (bits - 1);
    ExpectedFlags {
        zf: diff == 0,
        sf: diff & msb != 0,
        pf: even_low_byte_parity(diff),
        cf: a < b,
        of: (a & msb != 0) != (b & msb != 0) && (diff & msb != 0) != (a & msb != 0),
        af: (a ^ b ^ diff) & 0x10 != 0,
    }
}

fn truth_logic(result: u64, bits: u32) -> ExpectedFlags {
    let r = result & width_mask(bits);
    let msb = 1u64 << (bits - 1);
    ExpectedFlags {
        zf: r == 0,
        sf: r & msb != 0,
        pf: even_low_byte_parity(r),
        cf: false,
        of: false,
        af: false,
    }
}

fn read_flags(state: &CpuState) -> ExpectedFlags {
    ExpectedFlags {
        zf: state.flags.zf,
        sf: state.flags.sf,
        pf: state.flags.pf,
        cf: state.flags.cf,
        of: state.flags.of,
        af: state.flags.af,
    }
}

fn call_set_flags(result: u64, lhs: u64, rhs: u64, op: u64, width: u64) -> ExpectedFlags {
    let mut state = CpuState::new(GuestArch::X64);
    unsafe { jit_helper_set_flags(&mut state, result, lhs, rhs, op, width) };
    read_flags(&state)
}

fn check_vector(name: &str, lhs: u64, rhs: u64, width: u64) {
    let bits = (width * 8) as u32;
    let m = width_mask(bits);
    let (a, b) = (lhs & m, rhs & m);

    // add
    let sum = a.wrapping_add(b);
    let got = call_set_flags(sum, a, b, 0, width);
    assert_eq!(
        got,
        truth_add(a, b, bits),
        "{name} (w={width}): add flags mismatch for {a:#x} + {b:#x}"
    );

    // sub
    let diff = a.wrapping_sub(b);
    let got_sub = call_set_flags(diff, a, b, 1, width);
    assert_eq!(
        got_sub,
        truth_sub(a, b, bits),
        "{name} (w={width}): sub flags mismatch for {a:#x} - {b:#x}"
    );

    // cmp — flags of a subtraction without storing the result
    let got_cmp = call_set_flags(diff, a, b, 3, width);
    assert_eq!(
        got_cmp, got_sub,
        "{name} (w={width}): cmp({a:#x}, {b:#x}) must produce identical flags to sub"
    );

    // logic
    let logic = a & b;
    let got_logic = call_set_flags(logic, a, b, 2, width);
    assert_eq!(
        got_logic,
        truth_logic(logic, bits),
        "{name} (w={width}): logic flags mismatch for {a:#x} & {b:#x}"
    );
}

#[test]
fn jit_helper_load_unmapped_read_marks_fault_and_returns_zero() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    let address = 0x0000_0001_0000_0000u64;
    for width in [1u64, 2, 4, 8] {
        state.jit_pending_fault = None;
        state.jit_pending_fault_write = true;
        let value = unsafe { jit_helper_load(&mut state, &mut memory, address, width) };
        assert_eq!(value, 0, "failed read returns 0 to JIT code (w={width})");
        assert_eq!(
            state.jit_pending_fault,
            Some(address),
            "fault address must be recorded for the dispatcher (w={width})"
        );
        assert!(
            !state.jit_pending_fault_write,
            "a faulting READ must record access type write=false (w={width})"
        );
    }
}

#[test]
fn jit_helper_load_mapped_read_returns_value_without_fault() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    let address = 0x4000;
    memory.write_u64(address, 0x1122_3344_5566_7788);
    let value = unsafe { jit_helper_load(&mut state, &mut memory, address, 8) };
    assert_eq!(value, 0x1122_3344_5566_7788);
    assert_eq!(
        state.jit_pending_fault, None,
        "a successful read must not fabricate a fault"
    );
    assert!(!state.jit_pending_fault_write);
}

#[test]
fn jit_helper_store_unmapped_write_marks_fault_and_never_creates_page() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    // Cross-page guard probe: map only byte 0x4000, so a store at 0x4001
    // faults at the first guarded byte.
    memory.map_bytes(0x4000, &[0x11]);
    for width in [1u64, 2, 4, 8] {
        state.jit_pending_fault = None;
        state.jit_pending_fault_write = false;
        unsafe {
            jit_helper_store(
                &mut state,
                &mut memory,
                0x0000_0100_0000,
                0xDEAD_BEEF,
                width,
            )
        };
        assert_eq!(
            state.jit_pending_fault,
            Some(0x0000_0100_0000),
            "fault address must be recorded for the dispatcher (w={width})"
        );
        assert!(
            state.jit_pending_fault_write,
            "a faulting WRITE must record access type write=true (w={width})"
        );
        assert!(
            memory
                .guest_read_checked(0x0000_0100_0000, &mut [0_u8; 1])
                .is_err(),
            "a failed guest store must NEVER materialize the page (w={width})"
        );
    }

    // Precise fault address: store past the single mapped byte.
    state.jit_pending_fault = None;
    unsafe { jit_helper_store(&mut state, &mut memory, 0x4001, 0xFFFF, 2) };
    assert_eq!(
        state.jit_pending_fault,
        Some(0x4001),
        "fault address must be the first guarded byte"
    );
    assert!(state.jit_pending_fault_write);
    assert_eq!(
        memory.read_u8(0x4000).unwrap(),
        0x11,
        "no partial write before the faulting byte"
    );
}

#[test]
fn jit_helper_store_mapped_write_succeeds_without_fault() {
    let mut state = CpuState::new(GuestArch::X64);
    let mut memory = MemoryImage::default();
    memory.map_zeroed_if_unmapped(0x4000, 0x100);
    for width in [1u64, 2, 4, 8] {
        state.jit_pending_fault = None;
        unsafe {
            jit_helper_store(
                &mut state,
                &mut memory,
                0x4008,
                0x1122_3344_5566_7788,
                width,
            )
        };
        assert_eq!(
            state.jit_pending_fault, None,
            "a successful store must not fabricate a fault (w={width})"
        );
        assert!(!state.jit_pending_fault_write);
    }
    assert_eq!(memory.read_u64(0x4008).unwrap(), 0x1122_3344_5566_7788);
    assert_eq!(memory.read_u8(0x4008).unwrap(), 0x88);
}

fn stride_sample_values(bits: u32) -> Vec<u64> {
    let mask = width_mask(bits);
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
        0x55_55,
        0xaa_aa,
    ];
    let stride = mask / 257;
    for k in 0..=256u64 {
        values.push(k.wrapping_mul(stride) & mask);
    }
    values
}

#[test]
fn jit_helper_set_flags_add_exhaustive_8bit() {
    // EXHAUSTIVE: every pair (a, b) in 0..=255 × 0..=255 — this is the
    // exact vector family where the unmasked-sum carry bug lived (e.g.
    // 0xff + 0x01 must set CF; the old code computed sum = 0x100 and
    // 0x100 < 0xff = false).
    let mut state = CpuState::new(GuestArch::X64);
    for a in 0..=255u64 {
        for b in 0..=255u64 {
            let sum = a.wrapping_add(b) & 0xff;
            unsafe { jit_helper_set_flags(&mut state, sum, a, b, 0, 1) };
            let got = read_flags(&state);
            assert_eq!(
                got,
                truth_add(a, b, 8),
                "8-bit ADD flags mismatch for {a:#x} + {b:#x}"
            );
        }
    }
}

#[test]
fn jit_helper_set_flags_sub_exhaustive_8bit() {
    let mut state = CpuState::new(GuestArch::X64);
    for a in 0..=255u64 {
        for b in 0..=255u64 {
            let diff = a.wrapping_sub(b) & 0xff;
            unsafe { jit_helper_set_flags(&mut state, diff, a, b, 1, 1) };
            let got = read_flags(&state);
            assert_eq!(
                got,
                truth_sub(a, b, 8),
                "8-bit SUB flags mismatch for {a:#x} - {b:#x}"
            );
        }
    }
}

#[test]
fn jit_helper_set_flags_add_sub_dense_samples_16_32_64() {
    // Dense samples at 16/32/64: every width edge (0, 1, msb±1, mask-1,
    // mask, carry/borrow boundaries, AF nibble edges) plus a stride
    // sample covering the full width.
    let mut state = CpuState::new(GuestArch::X64);
    for (width, bits) in [(2u64, 16u32), (4, 32), (8, 64)] {
        let values = stride_sample_values(bits);
        for &a in &values {
            for &b in &values {
                let sum = a.wrapping_add(b) & width_mask(bits);
                unsafe { jit_helper_set_flags(&mut state, sum, a, b, 0, width) };
                assert_eq!(
                    read_flags(&state),
                    truth_add(a, b, bits),
                    "ADD flags mismatch at {bits} bits for {a:#x} + {b:#x}"
                );
                let diff = a.wrapping_sub(b) & width_mask(bits);
                unsafe { jit_helper_set_flags(&mut state, diff, a, b, 1, width) };
                assert_eq!(
                    read_flags(&state),
                    truth_sub(a, b, bits),
                    "SUB flags mismatch at {bits} bits for {a:#x} - {b:#x}"
                );
                unsafe { jit_helper_set_flags(&mut state, diff, a, b, 3, width) };
                assert_eq!(
                    read_flags(&state),
                    truth_sub(a, b, bits),
                    "CMP flags mismatch at {bits} bits for {a:#x} cmp {b:#x}"
                );
            }
        }
    }
}
