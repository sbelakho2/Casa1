#![allow(unused_imports)]

use super::*;
use crate::cpu::{
    ConditionCode, CpuState, GuestArch, GuestMemoryFault, GuestMemoryStore, IrInstruction,
    MemoryImage, Register,
};
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

// ---------------------------------------------------------------------------
// ARM64 register mapping for guest GPRs
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(super) mod regmap {
    /// Map guest x86/x64 register index to ARM64 register.
    /// Guest: RAX(0), RCX(1), RDX(2), RBX(3), RSP(4), RBP(5), RSI(6), RDI(7),
    ///        R8(8), R9(9), R10(10), R11(11), R12(12), R13(13), R14(14), R15(15)
    /// ARM64: x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x19, x20
    pub const fn guest_to_arm(guest_index: usize) -> u32 {
        match guest_index {
            0 => 4,   // RAX -> x4
            1 => 5,   // RCX -> x5
            2 => 6,   // RDX -> x6
            3 => 7,   // RBX -> x7
            4 => 8,   // RSP -> x8
            5 => 9,   // RBP -> x9
            6 => 10,  // RSI -> x10
            7 => 11,  // RDI -> x11
            8 => 12,  // R8  -> x12
            9 => 13,  // R9  -> x13
            10 => 14, // R10 -> x14
            11 => 15, // R11 -> x15
            12 => 16, // R12 -> x16
            13 => 17, // R13 -> x17
            14 => 19, // R14 -> x19
            15 => 20, // R15 -> x20
            _ => 4,
        }
    }

    pub const X0: u32 = 0;
    pub const X1: u32 = 1;
    pub const X2: u32 = 2;
    pub const X3: u32 = 3;
    pub const X9: u32 = 9;
    pub const X21: u32 = 21;
    pub const X22: u32 = 22;
    pub const X23: u32 = 23;
    pub const X24: u32 = 24;
    pub const X25: u32 = 25;
    pub const X26: u32 = 26;
    pub const X27: u32 = 27;
    pub const X28: u32 = 28;
    pub const FP: u32 = 29;
    pub const LR: u32 = 30;
    pub const SP: u32 = 31;
    pub const XZR: u32 = 31;
}
