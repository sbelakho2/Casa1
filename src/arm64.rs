//! Native ARM64 execution, the Windows AArch64 ABI bridge, TEB/PEB state,
//! import callbacks and the in-process ARM64 image runner.

use crate::arm64x::{
    self, Arm64ImageMetadata, ChpeCodeKind, HybridView, IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_ARM64EC, IMAGE_FILE_MACHINE_ARM64X,
};
use crate::error::{AppError, AppResult};
use crate::pe::{self, ImportSymbol, MappedImage, ParsedPe, SectionMapping};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::ffi::c_void;
use std::ptr;

pub const ARM64_REGISTER_COUNT: usize = 31;
pub const ARM64_STACK_ALIGNMENT: u64 = 16;
pub const TEB_CTX_SLOT: usize = 0x100;
pub const TEB_HOST_SP_SLOT: usize = 0x108;
pub const TEB_GUEST_X17_SLOT: usize = 0x110;
pub const TEB_HOST_X18_SLOT: usize = 0x118;
pub const DEFAULT_STACK_SIZE: usize = 0x10000;
pub const DEFAULT_TEB_SIZE: usize = 0x1000;

pub const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xc000_0005;

pub const MISSING_CROSS_ISA_PIECE: &str =
    "x64 guest instruction execution under the ARM64EC ABI (the x64<->ARM64EC thunk bridge)";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arm64Register {
    X(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arm64Isa {
    Arm64,
    X64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossIsaError {
    pub from: Arm64Isa,
    pub to: Arm64Isa,
    pub status: u32,
    pub missing_piece: &'static str,
}

impl CrossIsaError {
    pub const fn new(from: Arm64Isa, to: Arm64Isa) -> Self {
        Self {
            from,
            to,
            status: STATUS_NOT_SUPPORTED,
            missing_piece: MISSING_CROSS_ISA_PIECE,
        }
    }

    pub fn message(&self) -> String {
        format!(
            "ARM64EC cross-ISA transition {:?}->{:?} is fail-closed: missing {} (status 0x{:08x})",
            self.from, self.to, self.missing_piece, self.status
        )
    }

    pub fn to_app_error(&self) -> AppError {
        AppError::new(ReasonCode::RcUnimplInsn, self.message())
            .with_hint(format!("ntstatus=0x{:08x}", self.status))
            .with_hint(format!("missing_piece={}", self.missing_piece))
    }
}

impl std::fmt::Display for CrossIsaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for CrossIsaError {}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64Context {
    pub x: [u64; ARM64_REGISTER_COUNT],
    pub sp: u64,
    pub pc: u64,
    pub nzcv: u64,
    pub fpcr: u32,
    pub fpsr: u32,
    pub d: [u128; 32],
}

impl Default for Arm64Context {
    fn default() -> Self {
        Self {
            x: [0; ARM64_REGISTER_COUNT],
            sp: 0,
            pc: 0,
            nzcv: 0,
            fpcr: 0,
            fpsr: 0,
            d: [0; 32],
        }
    }
}

impl Arm64Context {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, register: usize) -> u64 {
        self.x.get(register).copied().unwrap_or(0)
    }

    pub fn set(&mut self, register: usize, value: u64) {
        if let Some(slot) = self.x.get_mut(register) {
            *slot = value;
        }
    }

    pub fn x0(&self) -> u64 {
        self.x[0]
    }

    pub fn set_x0(&mut self, value: u64) {
        self.x[0] = value;
    }

    pub fn arg(&self, index: usize) -> u64 {
        self.get(index)
    }

    pub fn set_arg(&mut self, index: usize, value: u64) {
        self.set(index, value);
    }

    pub fn teb(&self) -> u64 {
        self.x[18]
    }

    pub fn set_teb(&mut self, address: u64) {
        self.x[18] = address;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arm64RuntimeFunction {
    pub begin_address: u32,
    pub unwind_data: u32,
}

pub struct Arm64Teb {
    memory: Box<[u8]>,
    peb: Box<Arm64Peb>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Arm64Peb {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub bit_field: u8,
    pub mutant: u64,
    pub image_base_address: u64,
    pub ldr: u64,
    pub process_parameters: u64,
    pub sub_system_data: u64,
    pub process_heap: u64,
    pub fast_peb_lock: u64,
    pub atl_thunk_slist_ptr: u64,
    pub ifeo_key: u64,
    pub cross_process_flags: u32,
    pub nt_global_flag: u32,
    pub os_major_version: u32,
    pub os_minor_version: u32,
    pub os_build_number: u16,
    pub os_platform_id: u16,
    pub image_sub_system: u16,
    pub image_sub_system_major_version: u16,
    pub image_sub_system_minor_version: u16,
    pub process_affinity_mask: u64,
    pub gdi_shared_handle_table: u32,
    pub using_immutable_file: u32,
    pub process_id: u64,
    pub thread_id: u64,
}

impl Default for Arm64Teb {
    fn default() -> Self {
        Self::new(DEFAULT_STACK_SIZE as u64)
    }
}

impl Arm64Teb {
    pub fn new(stack_size: u64) -> Self {
        let mut memory = vec![0u8; DEFAULT_TEB_SIZE].into_boxed_slice();
        let peb = Box::new(Arm64Peb {
            os_major_version: 10,
            os_minor_version: 0,
            os_build_number: 22631,
            os_platform_id: 2,
            image_sub_system: 3,
            ..Arm64Peb::default()
        });
        let peb_address = (&*peb as *const Arm64Peb) as u64;
        let teb_address = memory.as_ptr() as u64;
        write_u64_slice(&mut memory, 0x08, teb_address + stack_size);
        write_u64_slice(&mut memory, 0x10, teb_address);
        write_u64_slice(&mut memory, 0x30, teb_address);
        write_u64_slice(&mut memory, 0x40, 1);
        write_u64_slice(&mut memory, 0x48, 1);
        write_u64_slice(&mut memory, 0x60, peb_address);
        Self { memory, peb }
    }

    pub fn address(&self) -> u64 {
        self.memory.as_ptr() as u64
    }

    pub fn peb_address(&self) -> u64 {
        (&*self.peb as *const Arm64Peb) as u64
    }

    pub fn peb(&self) -> &Arm64Peb {
        &self.peb
    }

    pub fn peb_mut(&mut self) -> &mut Arm64Peb {
        &mut self.peb
    }

    pub fn set_image_base(&mut self, image_base: u64) {
        self.peb.image_base_address = image_base;
    }

    pub fn set_last_error(&mut self, value: u32) {
        write_u32_slice(&mut self.memory, 0x68, value);
    }

    pub fn last_error(&self) -> u32 {
        read_u32_slice(&self.memory, 0x68)
    }

    pub fn set_tls_pointer(&mut self, value: u64) {
        write_u64_slice(&mut self.memory, 0x58, value);
    }

    pub fn tls_pointer(&self) -> u64 {
        read_u64_slice(&self.memory, 0x58)
    }

    pub fn set_stack(&mut self, stack_base: u64, stack_limit: u64) {
        write_u64_slice(&mut self.memory, 0x08, stack_base);
        write_u64_slice(&mut self.memory, 0x10, stack_limit);
    }

    pub fn host_context_slot(&self) -> u64 {
        read_u64_slice(&self.memory, TEB_CTX_SLOT)
    }

    pub fn host_stack_slot(&self) -> u64 {
        read_u64_slice(&self.memory, TEB_HOST_SP_SLOT)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arm64Exception {
    StackMisaligned { sp: u64 },
    NullTeb,
    EntryPointOutsideExecutableRegion { pc: u64 },
}

impl Arm64Exception {
    pub const fn nt_status(self) -> u32 {
        STATUS_ACCESS_VIOLATION
    }

    pub fn to_app_error(self) -> AppError {
        match self {
            Self::StackMisaligned { sp } => AppError::new(
                ReasonCode::RcInvalidParameter,
                format!("ARM64 stack pointer 0x{sp:016x} is not 16-byte aligned"),
            )
            .with_hint(format!("ntstatus=0x{:08x}", self.nt_status())),
            Self::NullTeb => {
                AppError::new(ReasonCode::RcInvalidParameter, "ARM64 x18 (TEB) is null")
                    .with_hint(format!("ntstatus=0x{:08x}", self.nt_status()))
            }
            Self::EntryPointOutsideExecutableRegion { pc } => AppError::new(
                ReasonCode::RcInvalidParameter,
                format!("ARM64 entry point 0x{pc:016x} is outside the executable region"),
            )
            .with_hint(format!("ntstatus=0x{:08x}", self.nt_status())),
        }
    }
}

fn write_u32_slice(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_slice(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u32_slice(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64_slice(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

struct ExecutableRegion {
    pointer: *mut u8,
    len: usize,
    jit: bool,
    writable: bool,
}

unsafe impl Send for ExecutableRegion {}

impl ExecutableRegion {
    fn allocate(len: usize) -> AppResult<Self> {
        let page = page_size();
        let len = len.max(page).div_ceil(page) * page;
        #[cfg(target_os = "macos")]
        {
            let pointer = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_JIT,
                    -1,
                    0,
                )
            };
            if pointer != libc::MAP_FAILED {
                unsafe { libc::pthread_jit_write_protect_np(0) };
                return Ok(Self {
                    pointer: pointer as *mut u8,
                    len,
                    jit: true,
                    writable: true,
                });
            }
        }
        let pointer = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                format!("failed to allocate {len} bytes for ARM64 native code"),
            ));
        }
        Ok(Self {
            pointer: pointer as *mut u8,
            len,
            jit: false,
            writable: true,
        })
    }

    fn allocate_data(len: usize) -> AppResult<Self> {
        let page = page_size();
        let len = len.max(page).div_ceil(page) * page;
        let pointer = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                format!("failed to allocate {len} bytes for ARM64 native data"),
            ));
        }
        unsafe { std::ptr::write_bytes(pointer as *mut u8, 0, len) };
        Ok(Self {
            pointer: pointer as *mut u8,
            len,
            jit: false,
            writable: true,
        })
    }

    fn address(&self) -> u64 {
        self.pointer as u64
    }

    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pointer, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.pointer, self.len) }
    }

    fn write(&mut self, offset: usize, bytes: &[u8]) -> AppResult<()> {
        if self.jit || !self.writable {
            self.make_writable()?;
        }
        let end = offset.checked_add(bytes.len()).ok_or_else(|| {
            AppError::new(ReasonCode::RcInvalidParameter, "ARM64 code write overflows")
        })?;
        if end > self.len {
            return Err(AppError::new(
                ReasonCode::RcInvalidParameter,
                "ARM64 code write exceeds the executable region",
            ));
        }
        self.as_mut_slice()[offset..end].copy_from_slice(bytes);
        Ok(())
    }

    fn make_writable(&mut self) -> AppResult<()> {
        #[cfg(target_os = "macos")]
        if self.jit {
            unsafe { libc::pthread_jit_write_protect_np(0) };
            self.writable = true;
            return Ok(());
        }
        let result = unsafe {
            libc::mprotect(
                self.pointer as *mut c_void,
                self.len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        if result != 0 {
            return Err(AppError::new(
                ReasonCode::RcUnsupportedPlatform,
                "failed to make ARM64 executable memory writable",
            ));
        }
        self.writable = true;
        Ok(())
    }

    fn finish_writes(&mut self) -> AppResult<()> {
        #[cfg(target_os = "macos")]
        if self.jit {
            unsafe { libc::pthread_jit_write_protect_np(1) };
            self.writable = false;
            return Ok(());
        }
        let result = unsafe {
            libc::mprotect(
                self.pointer as *mut c_void,
                self.len,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };
        if result != 0 {
            return Err(AppError::new(
                ReasonCode::RcUnsupportedPlatform,
                "failed to make ARM64 native code executable",
            ));
        }
        flush_instruction_cache(self.pointer, self.len);
        self.writable = false;
        Ok(())
    }

    fn protect_image_sections(&mut self, sections: &[SectionMapping]) -> AppResult<()> {
        if self.jit || !self.writable {
            return Ok(());
        }
        let page = page_size();
        let mut protected = vec![false; self.len.div_ceil(page)];
        for section in sections {
            let start = (section.virtual_address as usize) & !(page - 1);
            let end = ((section.virtual_address as usize)
                .saturating_add(section.mapped_size as usize)
                .saturating_add(page - 1))
                & !(page - 1);
            let end = end.min(self.len);
            let mut index = start / page;
            while index < end / page {
                if !protected[index] {
                    let protection = section_protection(section);
                    let page_pointer = unsafe { self.pointer.add(index * page) };
                    let result = apply_page_protection(page_pointer, page, protection);
                    if !result {
                        return Err(AppError::new(
                            ReasonCode::RcUnsupportedPlatform,
                            format!(
                                "failed to apply section protection {:?} at RVA 0x{:x}",
                                section.protection, section.virtual_address
                            ),
                        ));
                    }
                    protected[index] = true;
                }
                index += 1;
            }
        }
        for (index, done) in protected.iter().enumerate() {
            if !done {
                let page_pointer = unsafe { self.pointer.add(index * page) };
                let result = apply_page_protection(page_pointer, page, libc::PROT_READ);
                if !result {
                    return Err(AppError::new(
                        ReasonCode::RcUnsupportedPlatform,
                        "failed to apply image header protection",
                    ));
                }
            }
        }
        flush_instruction_cache(self.pointer, self.len);
        self.writable = false;
        Ok(())
    }
}

impl Drop for ExecutableRegion {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.pointer as *mut c_void, self.len);
        }
    }
}

#[cfg(target_os = "macos")]
fn flush_instruction_cache(pointer: *mut u8, len: usize) {
    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut c_void, len: usize);
    }
    unsafe { sys_icache_invalidate(pointer as *mut c_void, len) };
}

#[cfg(all(target_arch = "aarch64", not(target_os = "macos")))]
fn flush_instruction_cache(pointer: *mut u8, len: usize) {
    unsafe extern "C" {
        fn __clear_cache(start: *mut i8, end: *mut i8);
    }
    unsafe { __clear_cache(pointer as *mut i8, pointer.add(len) as *mut i8) };
}

#[cfg(not(target_arch = "aarch64"))]
fn flush_instruction_cache(_pointer: *mut u8, _len: usize) {}

#[cfg(target_os = "macos")]
fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(not(target_os = "macos"))]
fn page_size() -> usize {
    4096
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_vm_protect(
        target_task: u32,
        address: u64,
        size: u64,
        set_maximum: bool,
        new_protection: i32,
    ) -> i32;
}

#[cfg(target_os = "macos")]
fn apply_page_protection(pointer: *mut u8, len: usize, protection: libc::c_int) -> bool {
    let vm_protection = ((if protection & libc::PROT_READ != 0 {
        1
    } else {
        0
    }) | (if protection & libc::PROT_WRITE != 0 {
        2
    } else {
        0
    }) | (if protection & libc::PROT_EXEC != 0 {
        4
    } else {
        0
    })) as i32;
    #[allow(deprecated)]
    let task = unsafe { libc::mach_task_self() };
    let result = unsafe { mach_vm_protect(task, pointer as u64, len as u64, false, vm_protection) };
    result == 0
}

#[cfg(not(target_os = "macos"))]
fn apply_page_protection(pointer: *mut u8, len: usize, protection: libc::c_int) -> bool {
    unsafe { libc::mprotect(pointer as *mut c_void, len, protection) == 0 }
}

fn section_protection(section: &SectionMapping) -> libc::c_int {
    let mut protection = libc::PROT_READ;
    if section.protection.write {
        protection |= libc::PROT_WRITE;
    }
    if section.protection.execute {
        protection |= libc::PROT_EXEC;
    }
    protection
}

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(
    r#"
    .text
    .global _casa1_arm64_call_bridge
    .p2align 2
_casa1_arm64_call_bridge:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    str x18, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp d8, d9, [sp, #-16]!
    stp d10, d11, [sp, #-16]!
    stp d12, d13, [sp, #-16]!
    stp d14, d15, [sp, #-16]!
    sub sp, sp, #16
    str x0, [sp]

    ldr x9, [x0, #144]
    str x0, [x9, #256]
    mov x10, sp
    str x10, [x9, #264]
    str x18, [x9, #280]

    ldr x9, [x0, #264]
    msr nzcv, x9
    ldr w9, [x0, #272]
    msr fpcr, x9
    ldr w9, [x0, #276]
    msr fpsr, x9

    ldp x1, x2, [x0, #8]
    ldp x3, x4, [x0, #24]
    ldp x5, x6, [x0, #40]
    ldp x7, x8, [x0, #56]
    ldr x9, [x0, #72]
    ldp x10, x11, [x0, #80]
    ldp x12, x13, [x0, #96]
    ldp x14, x15, [x0, #112]
    ldp x16, x17, [x0, #128]
    ldr x18, [x0, #144]
    ldp x19, x20, [x0, #152]
    ldp x21, x22, [x0, #168]
    ldp x23, x24, [x0, #184]
    ldp x25, x26, [x0, #200]
    ldp x27, x28, [x0, #216]
    ldr x29, [x0, #232]
    ldr x30, [x0, #248]
    mov sp, x30
    ldr x30, [x0, #256]
    ldr x0, [x0, #0]
    blr x30

    str x17, [x18, #272]
    ldr x17, [x18, #256]
    str x0, [x17, #0]
    stp x1, x2, [x17, #8]
    stp x3, x4, [x17, #24]
    stp x5, x6, [x17, #40]
    stp x7, x8, [x17, #56]
    str x9, [x17, #72]
    stp x10, x11, [x17, #80]
    stp x12, x13, [x17, #96]
    stp x14, x15, [x17, #112]
    str x16, [x17, #128]
    ldr x9, [x18, #272]
    str x9, [x17, #136]
    str x18, [x17, #144]
    stp x19, x20, [x17, #152]
    stp x21, x22, [x17, #168]
    stp x23, x24, [x17, #184]
    stp x25, x26, [x17, #200]
    stp x27, x28, [x17, #216]
    str x29, [x17, #232]
    str x30, [x17, #240]
    mov x9, sp
    str x9, [x17, #248]
    mrs x9, nzcv
    str x9, [x17, #264]
    mrs x9, fpcr
    str w9, [x17, #272]
    mrs x9, fpsr
    str w9, [x17, #276]

    ldr x9, [x18, #264]
    mov sp, x9
    add sp, sp, #16
    ldp d14, d15, [sp], #16
    ldp d12, d13, [sp], #16
    ldp d10, d11, [sp], #16
    ldp d8, d9, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldr x18, [sp], #16
    ldp x29, x30, [sp], #16
    ret
    "#
);

#[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
core::arch::global_asm!(
    r#"
    .text
    .global casa1_arm64_call_bridge
    .p2align 2
casa1_arm64_call_bridge:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    str x18, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    stp d8, d9, [sp, #-16]!
    stp d10, d11, [sp, #-16]!
    stp d12, d13, [sp, #-16]!
    stp d14, d15, [sp, #-16]!
    sub sp, sp, #16
    str x0, [sp]

    ldr x9, [x0, #144]
    str x0, [x9, #256]
    mov x10, sp
    str x10, [x9, #264]
    str x18, [x9, #280]

    ldr x9, [x0, #264]
    msr nzcv, x9
    ldr w9, [x0, #272]
    msr fpcr, x9
    ldr w9, [x0, #276]
    msr fpsr, x9

    ldp x1, x2, [x0, #8]
    ldp x3, x4, [x0, #24]
    ldp x5, x6, [x0, #40]
    ldp x7, x8, [x0, #56]
    ldr x9, [x0, #72]
    ldp x10, x11, [x0, #80]
    ldp x12, x13, [x0, #96]
    ldp x14, x15, [x0, #112]
    ldp x16, x17, [x0, #128]
    ldr x18, [x0, #144]
    ldp x19, x20, [x0, #152]
    ldp x21, x22, [x0, #168]
    ldp x23, x24, [x0, #184]
    ldp x25, x26, [x0, #200]
    ldp x27, x28, [x0, #216]
    ldr x29, [x0, #232]
    ldr x30, [x0, #248]
    mov sp, x30
    ldr x30, [x0, #256]
    ldr x0, [x0, #0]
    blr x30

    str x17, [x18, #272]
    ldr x17, [x18, #256]
    str x0, [x17, #0]
    stp x1, x2, [x17, #8]
    stp x3, x4, [x17, #24]
    stp x5, x6, [x17, #40]
    stp x7, x8, [x17, #56]
    str x9, [x17, #72]
    stp x10, x11, [x17, #80]
    stp x12, x13, [x17, #96]
    stp x14, x15, [x17, #112]
    str x16, [x17, #128]
    ldr x9, [x18, #272]
    str x9, [x17, #136]
    str x18, [x17, #144]
    stp x19, x20, [x17, #152]
    stp x21, x22, [x17, #168]
    stp x23, x24, [x17, #184]
    stp x25, x26, [x17, #200]
    stp x27, x28, [x17, #216]
    str x29, [x17, #232]
    str x30, [x17, #240]
    mov x9, sp
    str x9, [x17, #248]
    mrs x9, nzcv
    str x9, [x17, #264]
    mrs x9, fpcr
    str w9, [x17, #272]
    mrs x9, fpsr
    str w9, [x17, #276]

    ldr x9, [x18, #264]
    mov sp, x9
    add sp, sp, #16
    ldp d14, d15, [sp], #16
    ldp d12, d13, [sp], #16
    ldp d10, d11, [sp], #16
    ldp d8, d9, [sp], #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldr x18, [sp], #16
    ldp x29, x30, [sp], #16
    ret
    "#
);

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn casa1_arm64_call_bridge(context: *mut Arm64Context);
}

#[cfg(target_arch = "aarch64")]
fn invoke_bridge(context: &mut Arm64Context) -> AppResult<()> {
    if context.sp % ARM64_STACK_ALIGNMENT != 0 {
        return Err(Arm64Exception::StackMisaligned { sp: context.sp }.to_app_error());
    }
    if context.x[18] == 0 {
        return Err(Arm64Exception::NullTeb.to_app_error());
    }
    if context.pc == 0 {
        return Err(Arm64Exception::EntryPointOutsideExecutableRegion { pc: 0 }.to_app_error());
    }
    #[cfg(target_os = "macos")]
    unsafe {
        libc::pthread_jit_write_protect_np(1);
    }
    unsafe { casa1_arm64_call_bridge(context as *mut Arm64Context) };
    Ok(())
}

#[cfg(not(target_arch = "aarch64"))]
fn invoke_bridge(_context: &mut Arm64Context) -> AppResult<()> {
    Err(AppError::new(
        ReasonCode::RcUnsupportedPlatform,
        "native ARM64 execution requires an aarch64 host",
    ))
}

pub fn native_arm64_available() -> bool {
    cfg!(target_arch = "aarch64")
}

pub struct Arm64Executor {
    code: ExecutableRegion,
    _stack: ExecutableRegion,
    teb: Arm64Teb,
    stack_base: u64,
    stack_limit: u64,
}

impl Arm64Executor {
    pub fn new() -> AppResult<Self> {
        Self::with_sizes(DEFAULT_STACK_SIZE, DEFAULT_STACK_SIZE)
    }

    pub fn with_sizes(stack_size: usize, teb_stack_size: usize) -> AppResult<Self> {
        let code = ExecutableRegion::allocate(page_size())?;
        let stack = ExecutableRegion::allocate_data(stack_size)?;
        let mut teb = Arm64Teb::new(teb_stack_size as u64);
        let stack_base = stack.address() + stack.len() as u64;
        let stack_limit = stack.address();
        teb.set_stack(stack_base, stack_limit);
        Ok(Self {
            code,
            _stack: stack,
            teb,
            stack_base,
            stack_limit,
        })
    }

    pub fn teb_address(&self) -> u64 {
        self.teb.address()
    }

    pub fn teb(&self) -> &Arm64Teb {
        &self.teb
    }

    pub fn teb_mut(&mut self) -> &mut Arm64Teb {
        &mut self.teb
    }

    pub fn stack_base(&self) -> u64 {
        self.stack_base
    }

    pub fn stack_limit(&self) -> u64 {
        self.stack_limit
    }

    pub fn map_code(&mut self, bytes: &[u8]) -> AppResult<u64> {
        let address = self.code.address();
        self.code.write(0, bytes)?;
        self.code.finish_writes()?;
        Ok(address)
    }

    pub fn prepare_context(&self, entry: u64, args: &[u64]) -> Arm64Context {
        let mut context = Arm64Context::new();
        context.pc = entry;
        context.sp = self.stack_base - 8;
        context.sp &= !(ARM64_STACK_ALIGNMENT - 1);
        context.x[18] = self.teb.address();
        context.x[30] = entry;
        for (index, value) in args.iter().copied().enumerate() {
            if index < 8 {
                context.x[index] = value;
            }
        }
        context
    }

    pub fn call_code(&mut self, code: &[u8], args: &[u64]) -> AppResult<Arm64CallResult> {
        let entry = self.map_code(code)?;
        self.call_address(entry, args)
    }

    pub fn call_address(&mut self, entry: u64, args: &[u64]) -> AppResult<Arm64CallResult> {
        if entry < self.code.address() || entry >= self.code.address() + self.code.len() as u64 {
            return Err(
                Arm64Exception::EntryPointOutsideExecutableRegion { pc: entry }.to_app_error(),
            );
        }
        let mut context = self.prepare_context(entry, args);
        invoke_bridge(&mut context)?;
        Ok(Arm64CallResult { context })
    }

    pub fn call_with_context(&mut self, context: &mut Arm64Context) -> AppResult<()> {
        if context.x[18] == 0 {
            context.x[18] = self.teb.address();
        }
        if context.sp == 0 {
            context.sp = self.stack_base - 8;
            context.sp &= !(ARM64_STACK_ALIGNMENT - 1);
        }
        invoke_bridge(context)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm64CallResult {
    pub context: Arm64Context,
}

impl Arm64CallResult {
    pub fn return_value(&self) -> u64 {
        self.context.x[0]
    }

    pub fn x(&self, register: usize) -> u64 {
        self.context.get(register)
    }

    pub fn sp(&self) -> u64 {
        self.context.sp
    }

    pub fn nzcv(&self) -> u64 {
        self.context.nzcv
    }
}

pub fn execute_arm64_function(code: &[u8], args: &[u64]) -> AppResult<u64> {
    let mut executor = Arm64Executor::new()?;
    let result = executor.call_code(code, args)?;
    Ok(result.return_value())
}

pub fn execute_arm64_context(code: &[u8], context: &mut Arm64Context) -> AppResult<()> {
    let mut executor = Arm64Executor::new()?;
    let entry = executor.map_code(code)?;
    context.pc = entry;
    if context.sp == 0 {
        context.sp = executor.stack_base() - 8;
        context.sp &= !(ARM64_STACK_ALIGNMENT - 1);
    }
    if context.x[18] == 0 {
        context.x[18] = executor.teb_address();
    }
    executor.call_with_context(context)
}

pub struct Arm64Assembler {
    bytes: Vec<u8>,
}

impl Default for Arm64Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Arm64Assembler {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn word(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn nop(&mut self) -> &mut Self {
        self.word(0xd503_201f)
    }

    pub fn ret(&mut self) -> &mut Self {
        self.word(0xd65f_03c0)
    }

    pub fn movz_x(&mut self, rd: u32, imm16: u16, shift: u32) -> &mut Self {
        self.word(0xd280_0000 | ((shift / 16) << 21) | (u32::from(imm16) << 5) | (rd & 31))
    }

    pub fn movk_x(&mut self, rd: u32, imm16: u16, shift: u32) -> &mut Self {
        self.word(0xf280_0000 | ((shift / 16) << 21) | (u32::from(imm16) << 5) | (rd & 31))
    }

    pub fn mov_abs_x(&mut self, rd: u32, value: u64) -> &mut Self {
        self.movz_x(rd, value as u16, 0);
        if value >> 16 != 0 {
            self.movk_x(rd, (value >> 16) as u16, 16);
        }
        if value >> 32 != 0 {
            self.movk_x(rd, (value >> 32) as u16, 32);
        }
        if value >> 48 != 0 {
            self.movk_x(rd, (value >> 48) as u16, 48);
        }
        self
    }

    pub fn mov_x(&mut self, rd: u32, rm: u32) -> &mut Self {
        self.word(0xaa00_03e0 | ((rm & 31) << 16) | (rd & 31))
    }

    pub fn add_x_imm(&mut self, rd: u32, rn: u32, imm12: u32) -> &mut Self {
        self.word(0x9100_0000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31))
    }

    pub fn sub_x_imm(&mut self, rd: u32, rn: u32, imm12: u32) -> &mut Self {
        self.word(0xd100_0000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | (rd & 31))
    }

    pub fn add_x_reg(&mut self, rd: u32, rn: u32, rm: u32) -> &mut Self {
        self.word(0x8b00_0000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31))
    }

    pub fn sub_x_reg(&mut self, rd: u32, rn: u32, rm: u32) -> &mut Self {
        self.word(0xcb00_0000 | ((rm & 31) << 16) | ((rn & 31) << 5) | (rd & 31))
    }

    pub fn cmp_x_imm(&mut self, rn: u32, imm12: u32) -> &mut Self {
        self.word(0xf100_0000 | ((imm12 & 0xfff) << 10) | ((rn & 31) << 5) | 31)
    }

    pub fn ldr_x_imm(&mut self, rt: u32, rn: u32, offset: u32) -> &mut Self {
        self.word(0xf940_0000 | (((offset / 8) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31))
    }

    pub fn str_x_imm(&mut self, rt: u32, rn: u32, offset: u32) -> &mut Self {
        self.word(0xf900_0000 | (((offset / 8) & 0xfff) << 10) | ((rn & 31) << 5) | (rt & 31))
    }

    pub fn br(&mut self, rn: u32) -> &mut Self {
        self.word(0xd61f_0000 | ((rn & 31) << 5))
    }

    pub fn blr(&mut self, rn: u32) -> &mut Self {
        self.word(0xd63f_0000 | ((rn & 31) << 5))
    }

    pub fn ldr_x_literal(&mut self, rt: u32, byte_offset: i32) -> &mut Self {
        let imm19 = (byte_offset / 4) as u32 & 0x7ffff;
        self.word(0x5800_0000 | (imm19 << 5) | (rt & 31))
    }

    pub fn adrp(&mut self, rd: u32, page_delta: i64) -> &mut Self {
        let imm = (page_delta as u64) & 0x1f_ffff;
        let immlo = (imm & 0x3) as u32;
        let immhi = ((imm >> 2) & 0x7_ffff) as u32;
        self.word(0x9000_0000 | (immlo << 29) | (immhi << 5) | (rd & 31))
    }

    pub fn b_cond(&mut self, cond: u32, byte_offset: i32) -> &mut Self {
        let imm19 = (byte_offset / 4) as u32 & 0x7ffff;
        self.word(0x5400_0000 | (imm19 << 5) | (cond & 0xf))
    }
}

type ImportCallback = Box<dyn FnMut(u64, u64, u64, u64, u64, u64, u64, u64) -> u64>;

thread_local! {
    static IMPORT_CALLBACKS: RefCell<HashMap<u64, ImportCallback>> = RefCell::new(HashMap::new());
    static NEXT_IMPORT_ID: Cell<u64> = const { Cell::new(1) };
}

extern "C" fn arm64_import_dispatch(
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    id: u64,
) -> u64 {
    let callback = IMPORT_CALLBACKS.with(|cell| cell.borrow_mut().remove(&id));
    let Some(mut callback) = callback else {
        return u64::MAX;
    };
    let result = callback(a0, a1, a2, a3, a4, a5, a6, a7);
    IMPORT_CALLBACKS.with(|cell| {
        cell.borrow_mut().insert(id, callback);
    });
    result
}

pub struct Arm64ImportTable {
    region: ExecutableRegion,
    names: BTreeMap<String, u64>,
    next_offset: usize,
}

impl Arm64ImportTable {
    pub fn new() -> AppResult<Self> {
        let region = ExecutableRegion::allocate(page_size())?;
        Ok(Self {
            region,
            names: BTreeMap::new(),
            next_offset: 0,
        })
    }

    pub fn register(
        &mut self,
        name: impl Into<String>,
        callback: impl FnMut(u64, u64, u64, u64, u64, u64, u64, u64) -> u64 + 'static,
    ) -> AppResult<u64> {
        let id = NEXT_IMPORT_ID.with(|next| {
            let id = next.get();
            next.set(id.wrapping_add(1).max(1));
            id
        });
        IMPORT_CALLBACKS.with(|cell| {
            cell.borrow_mut().insert(id, Box::new(callback));
        });
        let thunk = build_import_thunk(id, arm64_import_dispatch as *const () as usize);
        let offset = self.next_offset;
        let next = offset.checked_add(thunk.len()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcInvalidParameter,
                "import thunk table overflow",
            )
        })?;
        if next > self.region.len() {
            return Err(AppError::new(
                ReasonCode::RcJitCodeAllocFailed,
                "ARM64 import thunk table is full",
            ));
        }
        self.region.write(offset, &thunk)?;
        self.region.finish_writes()?;
        self.next_offset = next;
        let address = self.region.address() + offset as u64;
        self.names.insert(name.into(), address);
        Ok(address)
    }

    pub fn resolve(&self, name: &str) -> Option<u64> {
        self.names.get(name).copied()
    }

    pub fn names(&self) -> impl Iterator<Item = (&str, u64)> {
        self.names
            .iter()
            .map(|(name, address)| (name.as_str(), *address))
    }

    pub fn call(&self, name: &str, args: &[u64]) -> AppResult<u64> {
        let address = self.resolve(name).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcImportMissing,
                format!("missing ARM64 import {name}"),
            )
        })?;
        let mut executor = Arm64Executor::new()?;
        let mut context = executor.prepare_context(address, args);
        executor.call_with_context(&mut context)?;
        Ok(context.x[0])
    }
}

fn build_import_thunk(id: u64, dispatch: usize) -> [u8; 72] {
    let mut bytes = [0u8; 72];
    let mut writer = Arm64Assembler::new();
    writer
        .ldr_x_literal(16, 56)
        .sub_x_imm(31, 31, 32)
        .str_x_imm(16, 31, 0)
        .str_x_imm(30, 31, 8)
        .str_x_imm(18, 31, 16)
        .ldr_x_imm(17, 18, 0x118)
        .mov_x(18, 17)
        .ldr_x_literal(16, 36)
        .blr(16)
        .ldr_x_imm(18, 31, 16)
        .ldr_x_imm(30, 31, 8)
        .add_x_imm(31, 31, 32)
        .ret()
        .nop();
    bytes[..writer.bytes().len()].copy_from_slice(writer.bytes());
    bytes[56..64].copy_from_slice(&id.to_le_bytes());
    bytes[64..72].copy_from_slice(&(dispatch as u64).to_le_bytes());
    bytes
}

pub struct Arm64Image {
    region: ExecutableRegion,
    pub base: u64,
    pub size: usize,
    pub mapped: MappedImage,
    protected: bool,
}

impl Arm64Image {
    pub fn load(bytes: &[u8], image: &ParsedPe) -> AppResult<Self> {
        let size = image.size_of_image as usize;
        let mut region = ExecutableRegion::allocate(size)?;
        let base = region.address();
        let mapped = pe::map_image_at(bytes, image, base)?;
        if mapped.memory.len() > region.len() {
            return Err(AppError::new(
                ReasonCode::RcInvalidParameter,
                "mapped ARM64 image exceeds its host allocation",
            ));
        }
        region.write(0, &mapped.memory)?;
        Ok(Self {
            region,
            base,
            size,
            mapped,
            protected: false,
        })
    }

    pub fn entry_point(&self, image: &ParsedPe, view: HybridView) -> AppResult<u64> {
        let rva = arm64x::route_entry_point(image, view)?;
        self.address_for_rva(rva)
    }

    pub fn address_for_rva(&self, rva: u32) -> AppResult<u64> {
        if rva as usize >= self.size {
            return Err(AppError::new(
                ReasonCode::RcInvalidParameter,
                format!("ARM64 image RVA 0x{rva:x} is outside SizeOfImage"),
            ));
        }
        Ok(self.base + u64::from(rva))
    }

    pub fn write_slot(&mut self, rva: u32, value: u64) -> AppResult<()> {
        let offset = rva as usize;
        let end = offset.checked_add(8).ok_or_else(|| {
            AppError::new(ReasonCode::RcInvalidParameter, "ARM64 IAT slot overflows")
        })?;
        if end > self.size {
            return Err(AppError::new(
                ReasonCode::RcInvalidParameter,
                "ARM64 IAT slot exceeds SizeOfImage",
            ));
        }
        self.region.write(offset, &value.to_le_bytes())
    }

    pub fn bind_imports(
        &mut self,
        image: &ParsedPe,
        imports: &mut Arm64ImportTable,
    ) -> AppResult<()> {
        for descriptor in image.imports.iter().chain(image.delay_imports.iter()) {
            for thunk in &descriptor.imports {
                let name = match &thunk.symbol {
                    ImportSymbol::ByName { name, .. } => name.clone(),
                    ImportSymbol::ByOrdinal { ordinal } => {
                        format!("{}.{ordinal}", descriptor.dll_name)
                    }
                };
                let key = format!("{}.{}", descriptor.dll_name, name);
                let target = imports.resolve(&key).ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcImportMissing,
                        format!("missing ARM64 import callback {key}"),
                    )
                })?;
                self.write_slot(thunk.iat_rva, target)?;
            }
        }
        Ok(())
    }

    pub fn protect(&mut self) -> AppResult<()> {
        if !self.protected {
            self.region.protect_image_sections(&self.mapped.sections)?;
            self.protected = true;
        }
        Ok(())
    }

    pub fn sections(&self) -> &[SectionMapping] {
        &self.mapped.sections
    }

    pub fn bytes(&self) -> &[u8] {
        self.region.as_slice()
    }

    pub fn executable_region(&self) -> (u64, usize) {
        (self.region.address(), self.region.len())
    }
}

pub struct Arm64NativeRunner {
    pub image: Arm64Image,
    pub executor: Arm64Executor,
    pub imports: Arm64ImportTable,
}

impl Arm64NativeRunner {
    pub fn load(bytes: &[u8], image: &ParsedPe) -> AppResult<Self> {
        let image = Arm64Image::load(bytes, image)?;
        let mut executor = Arm64Executor::new()?;
        executor.teb_mut().set_image_base(image.base);
        let imports = Arm64ImportTable::new()?;
        Ok(Self {
            image,
            executor,
            imports,
        })
    }

    pub fn prepare(&mut self, image: &ParsedPe) -> AppResult<()> {
        self.image.bind_imports(image, &mut self.imports)?;
        self.image.protect()
    }

    pub fn call_entry(&mut self, image: &ParsedPe, args: &[u64]) -> AppResult<Arm64CallResult> {
        let entry = self.image.entry_point(image, HybridView::Native)?;
        let mut context = self.executor.prepare_context(entry, args);
        self.executor.call_with_context(&mut context)?;
        Ok(Arm64CallResult { context })
    }

    pub fn call_rva(&mut self, rva: u32, args: &[u64]) -> AppResult<Arm64CallResult> {
        let entry = self.image.address_for_rva(rva)?;
        let mut context = self.executor.prepare_context(entry, args);
        self.executor.call_with_context(&mut context)?;
        Ok(Arm64CallResult { context })
    }

    pub fn teb(&self) -> &Arm64Teb {
        self.executor.teb()
    }
}

pub fn code_kind_for(image: &ParsedPe, rva: u32) -> Option<ChpeCodeKind> {
    image
        .chpe_metadata()
        .and_then(|chpe| chpe.code_kind_at(rva))
}

pub fn image_machine_is_native_arm64(image: &ParsedPe) -> bool {
    matches!(
        image.machine,
        IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARM64EC | IMAGE_FILE_MACHINE_ARM64X
    )
}

pub fn hybrid_metadata(image: &ParsedPe) -> Option<&Arm64ImageMetadata> {
    image.arm64.as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{PeSection, SectionMapping};
    use crate::reason::ReasonCode;

    fn leaf_add(a: u16, b: u16) -> Vec<u8> {
        let mut assembler = Arm64Assembler::new();
        assembler
            .movz_x(0, a, 0)
            .movz_x(1, b, 0)
            .add_x_reg(0, 0, 1)
            .ret();
        assembler.into_bytes()
    }

    #[test]
    fn arm64_bridge_abi_offset_boundaries_are_pinned() {
        assert_eq!(std::mem::offset_of!(Arm64Context, x), 0);
        assert_eq!(std::mem::offset_of!(Arm64Context, sp), 248);
        assert_eq!(std::mem::offset_of!(Arm64Context, pc), 256);
        assert_eq!(std::mem::offset_of!(Arm64Context, nzcv), 264);
        assert_eq!(std::mem::offset_of!(Arm64Context, fpcr), 272);
        assert_eq!(std::mem::offset_of!(Arm64Context, fpsr), 276);
    }

    #[test]
    fn arm64_misaligned_stack_is_rejected_exactly() {
        let mut context = Arm64Context::new();
        context.sp = 0x1001;
        let error = invoke_bridge(&mut context).expect_err("misaligned stack must fail");
        assert_eq!(error.code, ReasonCode::RcInvalidParameter);
        assert_eq!(
            error.message,
            "ARM64 stack pointer 0x0000000000001001 is not 16-byte aligned"
        );
    }

    #[test]
    fn arm64_null_teb_is_rejected_exactly() {
        let mut context = Arm64Context::new();
        context.sp = 0x1000;
        let error = invoke_bridge(&mut context).expect_err("null TEB must fail");
        assert_eq!(error.message, "ARM64 x18 (TEB) is null");
    }

    #[test]
    fn arm64_zero_entry_point_is_rejected_exactly() {
        let mut context = Arm64Context::new();
        context.sp = 0x1000;
        context.x[18] = 0x2000;
        let error = invoke_bridge(&mut context).expect_err("null entry must fail");
        assert_eq!(
            error.message,
            "ARM64 entry point 0x0000000000000000 is outside the executable region"
        );
    }

    #[test]
    fn arm64_leaf_execution_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let code = leaf_add(20, 22);
        let result = execute_arm64_function(&code, &[]).expect("execute ARM64 leaf");
        assert_eq!(result, 42);
    }

    #[test]
    fn arm64_register_stack_and_flags_boundary_roundtrip() {
        if !native_arm64_available() {
            return;
        }
        let mut assembler = Arm64Assembler::new();
        assembler
            .sub_x_imm(31, 31, 32)
            .str_x_imm(3, 31, 0)
            .str_x_imm(4, 31, 8)
            .ldr_x_imm(0, 31, 0)
            .ldr_x_imm(1, 31, 8)
            .add_x_reg(0, 0, 1)
            .cmp_x_imm(0, 123)
            .add_x_imm(31, 31, 32)
            .ret();
        let mut context = Arm64Context::new();
        context.x[3] = 100;
        context.x[4] = 23;
        execute_arm64_context(&assembler.into_bytes(), &mut context)
            .expect("execute ARM64 context");
        assert_eq!(context.x[0], 123);
        assert_eq!(context.nzcv & 0x4000_0000, 0x4000_0000);
    }

    #[test]
    fn arm64_teb_peb_access_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut assembler = Arm64Assembler::new();
        assembler.ldr_x_imm(0, 18, 0x60).ldr_x_imm(0, 0, 0x58).ret();
        let mut executor = Arm64Executor::new().unwrap();
        let code = assembler.into_bytes();
        let entry = executor.map_code(&code).unwrap();
        let mut context = executor.prepare_context(entry, &[]);
        executor.call_with_context(&mut context).unwrap();
        assert_eq!(context.x[0], 10);
        assert_eq!(executor.teb().peb().os_major_version, 10);
    }

    #[test]
    fn arm64_import_callback_argument_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut imports = Arm64ImportTable::new().unwrap();
        let address = imports
            .register("Add", |a0, a1, _a2, _a3, _a4, _a5, _a6, _a7| a0 + a1)
            .unwrap();
        assert_eq!(imports.resolve("Add"), Some(address));
        assert_eq!(imports.call("Add", &[19, 23]).unwrap(), 42);
    }

    #[test]
    fn arm64_native_import_thunk_edge_call_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut imports = Arm64ImportTable::new().unwrap();
        let callback = imports
            .register("Add", |a0, a1, _, _, _, _, _, _| a0 + a1)
            .unwrap();
        let mut assembler = Arm64Assembler::new();
        assembler
            .movz_x(0, 20, 0)
            .movz_x(1, 22, 0)
            .mov_abs_x(9, callback)
            .br(9);
        let mut executor = Arm64Executor::new().unwrap();
        let entry = executor.map_code(&assembler.into_bytes()).unwrap();
        let mut context = executor.prepare_context(entry, &[]);
        executor.call_with_context(&mut context).unwrap();
        assert_eq!(context.x[0], 42);
    }

    #[test]
    fn arm64_missing_import_callback_fails_closed() {
        let imports = Arm64ImportTable::new().unwrap();
        let error = imports
            .call("Missing", &[])
            .expect_err("missing import must fail");
        assert_eq!(error.code, ReasonCode::RcImportMissing);
        assert_eq!(error.message, "missing ARM64 import Missing");
    }

    #[test]
    fn cross_isa_transition_fails_closed_with_exact_status() {
        let error = CrossIsaError::new(Arm64Isa::Arm64, Arm64Isa::X64);
        assert_eq!(error.status, 0xc000_00bb);
        assert_eq!(error.missing_piece, MISSING_CROSS_ISA_PIECE);
        let message = error.to_string();
        assert!(message.contains("missing x64 guest instruction execution"));
        let app = error.to_app_error();
        assert_eq!(app.code, ReasonCode::RcUnimplInsn);
        assert_eq!(app.reproduction_hints[0], "ntstatus=0xc00000bb");
    }

    #[test]
    fn arm64_image_section_protection_boundary_is_pinned() {
        let mut bytes = vec![0u8; 0x800];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
        let optional = 0x98usize;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let section = optional + 0xF0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let image = pe::parse(&bytes).expect("parse ARM64 image");
        let mut loaded = Arm64Image::load(&bytes, &image).expect("load ARM64 image");
        assert_eq!(loaded.sections()[0].protection.execute, true);
        loaded.protect().expect("protect ARM64 image");
        assert_eq!(loaded.protected, true);
    }

    fn arm64_pe_with_code(code: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x600];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
        let optional = 0x98usize;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let section = optional + 0xF0;
        bytes[section..section + 5].copy_from_slice(b".text");
        bytes[section + 8..section + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        bytes[0x400..0x400 + code.len()].copy_from_slice(code);
        bytes
    }

    #[test]
    fn arm64_native_pe_entry_execution_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut assembler = Arm64Assembler::new();
        assembler.movz_x(0, 42, 0).ret();
        let bytes = arm64_pe_with_code(&assembler.into_bytes());
        let image = pe::parse(&bytes).expect("parse executable ARM64 PE");
        let mut runner = Arm64NativeRunner::load(&bytes, &image).expect("load ARM64 PE");
        runner.prepare(&image).expect("protect ARM64 PE");
        let result = runner
            .call_entry(&image, &[])
            .expect("execute ARM64 PE entry");
        assert_eq!(result.return_value(), 42);
        assert_eq!(runner.image.sections().len(), 1);
    }

    #[test]
    fn arm64_runtime_executes_native_pe_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut assembler = Arm64Assembler::new();
        assembler.movz_x(0, 7, 0).ret();
        let bytes = arm64_pe_with_code(&assembler.into_bytes());
        let directory = tempfile::tempdir().expect("tempdir");
        let ge = crate::ge::GameEnvironment::create_in(
            directory.path(),
            "arm64-native",
            crate::ge::GeArch::X64,
            "win11-23h2",
        )
        .expect("create game environment");
        let path = directory.path().join("arm64.exe");
        std::fs::write(&path, &bytes).expect("write ARM64 PE");
        let result = crate::runtime::execute(
            &path,
            &[],
            &ge,
            directory.path(),
            &std::collections::BTreeMap::new(),
            true,
            "arm64-native-boundary",
        )
        .expect("execute native ARM64 PE");
        assert_eq!(result.exit_code, 7);
        assert_eq!(
            result.termination,
            crate::runtime::ExecutionTermination::GuestExit { code: 7 }
        );
    }

    fn arm64_pe_with_import(code: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x800];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
        let optional = 0x98usize;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        bytes[optional + 120..optional + 124].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 124..optional + 128].copy_from_slice(&20u32.to_le_bytes());
        bytes[optional + 208..optional + 212].copy_from_slice(&0x2060u32.to_le_bytes());
        bytes[optional + 212..optional + 216].copy_from_slice(&16u32.to_le_bytes());
        let text = optional + 0xF0;
        bytes[text..text + 5].copy_from_slice(b".text");
        bytes[text + 8..text + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[text + 12..text + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[text + 16..text + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[text + 20..text + 24].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[text + 36..text + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        let data = text + 40;
        bytes[data..data + 6].copy_from_slice(b".idata");
        bytes[data + 8..data + 12].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[data + 12..data + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[data + 16..data + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[data + 20..data + 24].copy_from_slice(&0x600u32.to_le_bytes());
        bytes[data + 36..data + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());
        bytes[0x400..0x400 + code.len()].copy_from_slice(code);
        bytes[0x600..0x614].copy_from_slice(&[
            0x40, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x20, 0, 0, 0x60, 0x20, 0, 0,
        ]);
        bytes[0x614..0x618].copy_from_slice(&[0, 0, 0, 0]);
        bytes[0x640..0x648].copy_from_slice(&0x20A0u64.to_le_bytes());
        bytes[0x660..0x668].copy_from_slice(&0x20A0u64.to_le_bytes());
        bytes[0x680..0x68D].copy_from_slice(b"kernel32.dll\0");
        bytes[0x6A0..0x6A2].copy_from_slice(&0u16.to_le_bytes());
        bytes[0x6A2..0x6B6].copy_from_slice(b"GetCurrentProcessId\0");
        bytes
    }

    #[test]
    fn arm64_runtime_import_callback_boundary_is_pinned() {
        if !native_arm64_available() {
            return;
        }
        let mut assembler = Arm64Assembler::new();
        assembler.movz_x(0, 9, 0).ret();
        let bytes = arm64_pe_with_import(&assembler.into_bytes());
        let directory = tempfile::tempdir().expect("tempdir");
        let ge = crate::ge::GameEnvironment::create_in(
            directory.path(),
            "arm64-import",
            crate::ge::GeArch::X64,
            "win11-23h2",
        )
        .expect("create game environment");
        let path = directory.path().join("arm64-import.exe");
        std::fs::write(&path, &bytes).expect("write ARM64 import PE");
        let result = crate::runtime::execute(
            &path,
            &[],
            &ge,
            directory.path(),
            &std::collections::BTreeMap::new(),
            true,
            "arm64-import-boundary",
        )
        .expect("execute native ARM64 import PE");
        assert_eq!(result.exit_code, 9);
    }

    #[test]
    fn arm64_image_rejects_out_of_range_entry() {
        let mut bytes = vec![0u8; 0x400];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&IMAGE_FILE_MACHINE_ARM64.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        let optional = 0x98usize;
        bytes[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_8000_0000u64.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[optional + 60..optional + 64].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let image = pe::parse(&bytes).expect("parse minimal ARM64 image");
        let loaded = Arm64Image::load(&bytes, &image).expect("load minimal ARM64 image");
        let error = loaded
            .entry_point(&image, HybridView::Native)
            .expect_err("entry outside image must fail");
        assert_eq!(
            error.message,
            "ARM64 image RVA 0x2000 is outside SizeOfImage"
        );
    }

    #[test]
    fn arm64_import_slot_outside_image_is_rejected_exactly() {
        let bytes = vec![0u8; 0x400];
        let mut image = pe::pe_stub_for_tests();
        image.machine = IMAGE_FILE_MACHINE_ARM64;
        let mut loaded = Arm64Image::load(&bytes, &image).expect("load empty image");
        let error = loaded
            .write_slot(0x2000, 1)
            .expect_err("bad slot must fail");
        assert_eq!(error.message, "ARM64 IAT slot exceeds SizeOfImage");
    }

    #[test]
    fn arm64_executor_rejects_code_outside_region() {
        let mut executor = Arm64Executor::new().unwrap();
        let error = executor
            .call_address(0, &[])
            .expect_err("outside entry must fail");
        assert_eq!(
            error.message,
            "ARM64 entry point 0x0000000000000000 is outside the executable region"
        );
    }

    #[test]
    fn arm64_import_thunk_encoding_boundary_is_pinned() {
        let thunk = build_import_thunk(7, 0x1234_5678);
        assert_eq!(&thunk[56..64], &7u64.to_le_bytes());
        assert_eq!(&thunk[64..72], &0x1234_5678u64.to_le_bytes());
        assert_eq!(&thunk[0..4], &0x580001D0u32.to_le_bytes());
    }

    #[test]
    fn arm64_assembler_leaf_encoding_boundary_is_pinned() {
        let code = leaf_add(1, 2);
        assert_eq!(&code[0..4], &0xd2800020u32.to_le_bytes());
        assert_eq!(&code[4..8], &0xd2800041u32.to_le_bytes());
        assert_eq!(&code[8..12], &0x8b010000u32.to_le_bytes());
        assert_eq!(&code[12..16], &0xd65f03c0u32.to_le_bytes());
    }

    #[test]
    fn arm64_section_protection_rwx_boundary_is_pinned() {
        let section = SectionMapping {
            name: ".data".to_string(),
            virtual_address: 0x1000,
            mapped_size: 0x1000,
            raw_data_size: 0x1000,
            protection: crate::pe::MemoryProtection {
                read: true,
                write: true,
                execute: false,
            },
        };
        assert_eq!(
            section_protection(&section) & libc::PROT_WRITE,
            libc::PROT_WRITE
        );
        assert_ne!(
            section_protection(&section) & libc::PROT_EXEC,
            libc::PROT_EXEC
        );
    }

    #[test]
    fn arm64_code_kind_missing_chpe_map_route_is_pinned() {
        let mut image = pe::pe_stub_for_tests();
        image.machine = IMAGE_FILE_MACHINE_ARM64EC;
        image.arm64 = Some(Arm64ImageMetadata {
            machine: IMAGE_FILE_MACHINE_ARM64EC,
            chpe: None,
            dynamic_relocations: Vec::new(),
            extra_rfe_table: None,
            exception_tables: Vec::new(),
        });
        assert_eq!(code_kind_for(&image, 0x1000), None);
        assert!(image_machine_is_native_arm64(&image));
        assert!(hybrid_metadata(&image).is_some());
    }
}
