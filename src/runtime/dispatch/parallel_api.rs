//! Worker-side execution of the concurrency-safe host API subset.
//!
//! A production worker that reaches a host thunk normally stops with a host
//! barrier and lets the runtime owner execute it.  This module classifies the
//! thunk surface and implements the small, deliberately conservative subset
//! that is safe to execute *on the worker itself*:
//!
//! * stateless calls read only the calling thread's
//!   [`GuestThreadContext`](super::super::GuestThreadContext) and constant
//!   data (clock/time, thread/process identity, last-error, CPU features,
//!   pure formatting helpers), and
//! * read-mostly calls read process-wide values the owner publishes behind
//!   per-subsystem `RwLock`s (version, system/CPU information, memory
//!   status).
//!
//! Everything else — loader, registry, handles, allocation, GPU, COM, TPM,
//! driver island — remains owner-only and is still executed exactly once on
//! the existing host-barrier path.
//!
//! The worker implementation mirrors the owner's dispatch arms byte for
//! byte, including x86 stdcall argument cleanup and the per-thread
//! last-error slot.  A failure to reproduce an owner path (missing published
//! version, guest memory that the worker view cannot service) returns the
//! barrier verdict rather than guessing.

use super::super::{
    ERROR_INVALID_PARAMETER, GuestThreadContext, HostThunk, ProcessShared,
    WINDOWS_EPOCH_OFFSET_100NS, WorkerVersion, current_host_ticks_100ns,
    is_processor_feature_present, shlwapi_format_time_interval,
};
use crate::cpu::{GuestArch, Register};
use crate::host_thunks::ThunkConcurrency;
use crate::jit::GuestSliceMemory;

/// The concurrency-safe worker implementation of one host thunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerApi {
    GetLastError,
    SetLastError,
    GetCurrentThreadId,
    GetCurrentThread,
    GetCurrentProcessId,
    GetCurrentProcess,
    GetTickCount,
    GetTickCount64,
    QueryPerformanceCounter,
    QueryPerformanceFrequency,
    GetSystemTimeAsFileTime,
    GetSystemTimePreciseAsFileTime,
    GetVersion,
    GetVersionExW,
    GetVersionExA,
    IsWow64Process,
    GetSystemInfo,
    GetNativeSystemInfo,
    GlobalMemoryStatusEx,
    IsProcessorFeaturePresent,
    CharNextW,
    CharPrevW,
    StrFromTimeIntervalW,
}

impl WorkerApi {
    pub(crate) const fn class(self) -> ThunkConcurrency {
        match self {
            Self::GetVersion
            | Self::GetVersionExW
            | Self::GetVersionExA
            | Self::GetSystemInfo
            | Self::GetNativeSystemInfo
            | Self::GlobalMemoryStatusEx
            | Self::IsWow64Process => ThunkConcurrency::ReadMostly,
            _ => ThunkConcurrency::Stateless,
        }
    }
}

/// Map a registered host thunk to its worker implementation, if it has one.
pub(crate) fn worker_api(thunk: &HostThunk) -> Option<WorkerApi> {
    Some(match thunk {
        HostThunk::GetLastError => WorkerApi::GetLastError,
        HostThunk::SetLastError => WorkerApi::SetLastError,
        HostThunk::GetCurrentThreadId => WorkerApi::GetCurrentThreadId,
        HostThunk::GetCurrentThread => WorkerApi::GetCurrentThread,
        HostThunk::GetCurrentProcessId => WorkerApi::GetCurrentProcessId,
        HostThunk::GetCurrentProcess => WorkerApi::GetCurrentProcess,
        HostThunk::GetTickCount => WorkerApi::GetTickCount,
        HostThunk::GetTickCount64 => WorkerApi::GetTickCount64,
        HostThunk::QueryPerformanceCounter => WorkerApi::QueryPerformanceCounter,
        HostThunk::QueryPerformanceFrequency => WorkerApi::QueryPerformanceFrequency,
        HostThunk::GetSystemTimeAsFileTime => WorkerApi::GetSystemTimeAsFileTime,
        HostThunk::GetSystemTimePreciseAsFileTime => WorkerApi::GetSystemTimePreciseAsFileTime,
        HostThunk::GetVersion => WorkerApi::GetVersion,
        HostThunk::GetVersionExW => WorkerApi::GetVersionExW,
        HostThunk::GetVersionExA => WorkerApi::GetVersionExA,
        HostThunk::IsWow64Process => WorkerApi::IsWow64Process,
        HostThunk::GetSystemInfo => WorkerApi::GetSystemInfo,
        HostThunk::GetNativeSystemInfo => WorkerApi::GetNativeSystemInfo,
        HostThunk::GlobalMemoryStatusEx => WorkerApi::GlobalMemoryStatusEx,
        HostThunk::IsProcessorFeaturePresent => WorkerApi::IsProcessorFeaturePresent,
        HostThunk::CharNextW => WorkerApi::CharNextW,
        HostThunk::CharPrevW => WorkerApi::CharPrevW,
        HostThunk::StrFromTimeIntervalW => WorkerApi::StrFromTimeIntervalW,
        _ => return None,
    })
}

/// The canonical concurrency class of a registered thunk.
pub(crate) fn thunk_class(thunk: &HostThunk) -> ThunkConcurrency {
    worker_api(thunk).map_or(ThunkConcurrency::OwnerOnly, WorkerApi::class)
}

/// A worker-safe view of guest memory.
pub(crate) trait WorkerMemoryView {
    fn load(&self, address: u64, len: usize) -> Option<u64>;
    fn store(&self, address: u64, bytes: &[u8]) -> bool;
}

impl WorkerMemoryView for GuestSliceMemory {
    fn load(&self, address: u64, len: usize) -> Option<u64> {
        GuestSliceMemory::load(self, address, len).ok()
    }

    fn store(&self, address: u64, bytes: &[u8]) -> bool {
        GuestSliceMemory::store(self, address, bytes).is_ok()
    }
}

/// Execute `entry` on the calling worker.
///
/// Returns `true` when the thunk ran and the guest state now continues at
/// its return address.  Returns `false` when the caller must fall back to the
/// owner (owner-only thunk, missing published state, or guest memory the
/// worker view cannot service); the caller restores the context snapshot it
/// took before calling.
pub(crate) fn invoke_parallel_api(
    shared: &ProcessShared,
    context: &mut GuestThreadContext,
    memory: &dyn WorkerMemoryView,
    entry: &super::super::ParallelThunk,
) -> bool {
    let Some(api) = entry.api else {
        return false;
    };
    let rsp = context.state.get(Register::Rsp);
    if rsp == 0 {
        return false;
    }
    let pointer_bytes = context.state.arch.pointer_bytes() as u64;
    let Some(return_address) = memory.load(rsp, pointer_bytes as usize) else {
        return false;
    };
    context
        .state
        .set(Register::Rsp, rsp.wrapping_add(pointer_bytes));
    if !execute(api, shared, context, memory) {
        return false;
    }
    if context.state.arch == GuestArch::X86 {
        context.state.set(
            Register::Rsp,
            context
                .state
                .get(Register::Rsp)
                .wrapping_add(entry.x86_arg_bytes),
        );
    }
    context.state.rip = return_address;
    true
}

fn execute(
    api: WorkerApi,
    shared: &ProcessShared,
    context: &mut GuestThreadContext,
    memory: &dyn WorkerMemoryView,
) -> bool {
    match api {
        WorkerApi::GetLastError => {
            context
                .state
                .set(Register::Rax, u64::from(context.last_error));
            true
        }
        WorkerApi::SetLastError => {
            let Some(value) = read_arg(context, memory, 0) else {
                return false;
            };
            context.last_error = value as u32;
            context.state.set(Register::Rax, 0);
            true
        }
        WorkerApi::GetCurrentThreadId => {
            context
                .state
                .set(Register::Rax, u64::from(context.thread_id));
            context.last_error = 0;
            true
        }
        WorkerApi::GetCurrentThread => {
            context.state.set(Register::Rax, u64::from(context.handle));
            context.last_error = 0;
            true
        }
        WorkerApi::GetCurrentProcessId => {
            let identity = shared.identity_snapshot();
            context
                .state
                .set(Register::Rax, u64::from(identity.process_id));
            context.last_error = 0;
            true
        }
        WorkerApi::GetCurrentProcess => {
            let identity = shared.identity_snapshot();
            context
                .state
                .set(Register::Rax, u64::from(identity.process_handle));
            context.last_error = 0;
            true
        }
        WorkerApi::GetTickCount => {
            let clock = shared.clock_snapshot();
            context.state.set(
                Register::Rax,
                clock.clock.tick_count64() & u64::from(u32::MAX),
            );
            context.last_error = 0;
            true
        }
        WorkerApi::GetTickCount64 => {
            let clock = shared.clock_snapshot();
            context.state.set(Register::Rax, clock.clock.tick_count64());
            context.last_error = 0;
            true
        }
        WorkerApi::QueryPerformanceCounter => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
            } else {
                let clock = shared.clock_snapshot();
                if !write_u64(
                    memory,
                    pointer,
                    clock.clock.query_performance_counter() as u64,
                ) {
                    return false;
                }
                context.state.set(Register::Rax, 1);
                context.last_error = 0;
            }
            true
        }
        WorkerApi::QueryPerformanceFrequency => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
            } else {
                let clock = shared.clock_snapshot();
                if !write_u64(
                    memory,
                    pointer,
                    clock.clock.query_performance_frequency() as u64,
                ) {
                    return false;
                }
                context.state.set(Register::Rax, 1);
                context.last_error = 0;
            }
            true
        }
        WorkerApi::GetSystemTimeAsFileTime => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            let clock = shared.clock_snapshot();
            let ticks = if clock.dtm {
                WINDOWS_EPOCH_OFFSET_100NS
                    .saturating_add(clock.deterministic_tick_ms.saturating_mul(10_000))
            } else {
                current_host_ticks_100ns()
            };
            if pointer != 0 && !write_u64(memory, pointer, ticks) {
                return false;
            }
            context.state.set(Register::Rax, 0);
            context.last_error = 0;
            true
        }
        WorkerApi::GetSystemTimePreciseAsFileTime => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            let clock = shared.clock_snapshot();
            let ticks = clock.clock.system_time_precise_file_time();
            if pointer != 0 && !write_u64(memory, pointer, ticks) {
                return false;
            }
            context.state.set(Register::Rax, 0);
            context.last_error = 0;
            true
        }
        WorkerApi::GetVersion => {
            let Some(version) = shared.version_snapshot() else {
                return false;
            };
            let packed = (version.build << 16)
                | ((version.major & 0xff) << 8)
                | (version.minor & 0xff)
                | 0x8000_0000;
            context.state.set(Register::Rax, u64::from(packed));
            context.last_error = 0;
            true
        }
        WorkerApi::GetVersionExW => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(version) = shared.version_snapshot() else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            write_version_info_w(context, memory, pointer, &version)
        }
        WorkerApi::GetVersionExA => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(version) = shared.version_snapshot() else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            write_version_info_a(context, memory, pointer, &version)
        }
        WorkerApi::IsWow64Process => {
            let Some(pointer) = read_arg(context, memory, 1) else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
            } else {
                if !write_u32(memory, pointer, 0) {
                    return false;
                }
                context.state.set(Register::Rax, 1);
                context.last_error = 0;
            }
            true
        }
        WorkerApi::GetSystemInfo | WorkerApi::GetNativeSystemInfo => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            if pointer != 0 && !write_system_info(memory, pointer, context.state.arch) {
                return false;
            }
            context.state.set(Register::Rax, 0);
            context.last_error = 0;
            true
        }
        WorkerApi::GlobalMemoryStatusEx => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            let Some(status) = shared.memory_status_snapshot() else {
                return false;
            };
            let total_virt: u64 = 2 * 1024 * 1024 * 1024;
            let avail_virt: u64 = 1024 * 1024 * 1024;
            let memory_load =
                ((status.total_phys - status.avail_phys) * 100 / status.total_phys) as u32;
            if !write_u32(memory, pointer, 64)
                || !write_u32(memory, pointer + 4, memory_load)
                || !write_u64(memory, pointer + 8, status.total_phys)
                || !write_u64(memory, pointer + 16, status.avail_phys)
                || !write_u64(memory, pointer + 24, status.total_page)
                || !write_u64(memory, pointer + 32, status.avail_page)
                || !write_u64(memory, pointer + 40, total_virt)
                || !write_u64(memory, pointer + 48, avail_virt)
            {
                return false;
            }
            context.state.set(Register::Rax, 1);
            true
        }
        WorkerApi::IsProcessorFeaturePresent => {
            let Some(feature) = read_arg(context, memory, 0) else {
                return false;
            };
            context.state.set(
                Register::Rax,
                u64::from(is_processor_feature_present(feature as u32)),
            );
            context.last_error = 0;
            true
        }
        WorkerApi::CharNextW => {
            let Some(current) = read_arg(context, memory, 0) else {
                return false;
            };
            let next = if current == 0 {
                current
            } else {
                let Some(unit) = read_u16(memory, current) else {
                    return false;
                };
                if unit == 0 { current } else { current + 2 }
            };
            context.state.set(Register::Rax, next);
            context.last_error = 0;
            true
        }
        WorkerApi::CharPrevW => {
            let Some(start) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(current) = read_arg(context, memory, 1) else {
                return false;
            };
            let previous = if current <= start { start } else { current - 2 };
            context.state.set(Register::Rax, previous);
            context.last_error = 0;
            true
        }
        WorkerApi::StrFromTimeIntervalW => {
            let Some(buffer) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(buffer_len) = read_arg(context, memory, 1) else {
                return false;
            };
            let Some(milliseconds) = read_arg(context, memory, 2) else {
                return false;
            };
            let Some(digits) = read_arg(context, memory, 3) else {
                return false;
            };
            let written = if buffer == 0 || buffer_len == 0 {
                0
            } else {
                match shlwapi_format_time_interval(milliseconds as u32, digits as i32) {
                    Some(formatted) => {
                        let units: Vec<u16> = formatted.encode_utf16().collect();
                        let copy_units = units.len().min((buffer_len as usize).saturating_sub(1));
                        let mut bytes = Vec::with_capacity((copy_units + 1) * 2);
                        for unit in units.iter().take(copy_units) {
                            bytes.extend_from_slice(&unit.to_le_bytes());
                        }
                        bytes.extend_from_slice(&0_u16.to_le_bytes());
                        if !write_bytes(memory, buffer, &bytes) {
                            return false;
                        }
                        copy_units as u32
                    }
                    None => {
                        if !write_u16(memory, buffer, 0) {
                            return false;
                        }
                        0
                    }
                }
            };
            context.state.set(Register::Rax, u64::from(written));
            context.last_error = 0;
            true
        }
    }
}

fn read_arg(
    context: &GuestThreadContext,
    memory: &dyn WorkerMemoryView,
    index: usize,
) -> Option<u64> {
    let state = &context.state;
    match state.arch {
        GuestArch::X64 => match index {
            0 => Some(state.get(Register::Rcx)),
            1 => Some(state.get(Register::Rdx)),
            2 => Some(state.get(Register::R8)),
            3 => Some(state.get(Register::R9)),
            _ => memory.load(
                state.get(Register::Rsp) + 0x20 + ((index - 4) as u64 * 8),
                8,
            ),
        },
        GuestArch::X86 => memory.load(state.get(Register::Rsp) + (index as u64 * 4), 4),
    }
}

fn read_u16(memory: &dyn WorkerMemoryView, address: u64) -> Option<u16> {
    memory.load(address, 2).map(|value| value as u16)
}

fn write_bytes(memory: &dyn WorkerMemoryView, address: u64, bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + 8).min(bytes.len());
        if !memory.store(address + offset as u64, &bytes[offset..end]) {
            return false;
        }
        offset = end;
    }
    true
}

fn write_u16(memory: &dyn WorkerMemoryView, address: u64, value: u16) -> bool {
    write_bytes(memory, address, &value.to_le_bytes())
}

fn write_u32(memory: &dyn WorkerMemoryView, address: u64, value: u32) -> bool {
    write_bytes(memory, address, &value.to_le_bytes())
}

fn write_u64(memory: &dyn WorkerMemoryView, address: u64, value: u64) -> bool {
    write_bytes(memory, address, &value.to_le_bytes())
}

fn write_version_info_w(
    context: &mut GuestThreadContext,
    memory: &dyn WorkerMemoryView,
    pointer: u64,
    version: &WorkerVersion,
) -> bool {
    const VER_PLATFORM_WIN32_NT: u32 = 2;
    const OSVERSIONINFOEXW_SIZE: u32 = 0x11C;
    let Some(reported_size) = read_u32(memory, pointer) else {
        return false;
    };
    if !write_u32(memory, pointer + 0x04, version.major)
        || !write_u32(memory, pointer + 0x08, version.minor)
        || !write_u32(memory, pointer + 0x0C, version.build)
        || !write_u32(memory, pointer + 0x10, VER_PLATFORM_WIN32_NT)
        || !write_bytes(memory, pointer + 0x14, &[0_u8; 0x100])
    {
        return false;
    }
    if reported_size >= OSVERSIONINFOEXW_SIZE
        && (!write_u16(memory, pointer + 0x114, version.service_pack_major)
            || !write_u16(memory, pointer + 0x116, version.service_pack_minor)
            || !write_u16(memory, pointer + 0x118, version.suite_mask)
            || !write_bytes(memory, pointer + 0x11A, &[version.product_type, 0]))
    {
        return false;
    }
    if !write_u32(memory, pointer, reported_size) {
        return false;
    }
    context.state.set(Register::Rax, 1);
    context.last_error = 0;
    true
}

fn write_version_info_a(
    context: &mut GuestThreadContext,
    memory: &dyn WorkerMemoryView,
    pointer: u64,
    version: &WorkerVersion,
) -> bool {
    const VER_PLATFORM_WIN32_NT: u32 = 2;
    const OSVERSIONINFOEXA_SIZE: u32 = 0x9C;
    let Some(reported_size) = read_u32(memory, pointer) else {
        return false;
    };
    if !write_u32(memory, pointer + 0x04, version.major)
        || !write_u32(memory, pointer + 0x08, version.minor)
        || !write_u32(memory, pointer + 0x0C, version.build)
        || !write_u32(memory, pointer + 0x10, VER_PLATFORM_WIN32_NT)
        || !write_bytes(memory, pointer + 0x14, &[0_u8; 0x80])
    {
        return false;
    }
    if reported_size >= OSVERSIONINFOEXA_SIZE
        && (!write_u16(memory, pointer + 0x94, version.service_pack_major)
            || !write_u16(memory, pointer + 0x96, version.service_pack_minor)
            || !write_u16(memory, pointer + 0x98, version.suite_mask)
            || !write_bytes(memory, pointer + 0x9A, &[version.product_type, 0]))
    {
        return false;
    }
    if !write_u32(memory, pointer, reported_size) {
        return false;
    }
    context.state.set(Register::Rax, 1);
    context.last_error = 0;
    true
}

fn read_u32(memory: &dyn WorkerMemoryView, address: u64) -> Option<u32> {
    memory.load(address, 4).map(|value| value as u32)
}

fn write_system_info(memory: &dyn WorkerMemoryView, pointer: u64, guest_arch: GuestArch) -> bool {
    const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
    const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
    let (arch, pointer_size) = match guest_arch {
        GuestArch::X86 => (PROCESSOR_ARCHITECTURE_INTEL, 4u64),
        GuestArch::X64 => (PROCESSOR_ARCHITECTURE_AMD64, 8),
    };
    let max_address: u64 = if pointer_size == 8 {
        0x7FFE_FFFF_FFFF
    } else {
        0x7FFF_FFFF
    };
    let processor_level: u16 = if arch == PROCESSOR_ARCHITECTURE_INTEL {
        6
    } else {
        21
    };
    let mut offset = pointer;
    let mut ok = write_u16(memory, offset, arch);
    offset += 2;
    ok &= write_u16(memory, offset, 0);
    offset += 2;
    ok &= write_u32(memory, offset, 4096);
    offset += 4;
    ok &= write_u64(memory, offset, 0x10000);
    offset += pointer_size;
    ok &= write_u64(memory, offset, max_address);
    offset += pointer_size;
    ok &= write_u64(memory, offset, 0xFF);
    offset += pointer_size;
    ok &= write_u32(memory, offset, 8);
    offset += 4;
    ok &= write_u32(memory, offset, 0);
    offset += 4;
    ok &= write_u32(memory, offset, 0x10000);
    offset += 4;
    ok &= write_u16(memory, offset, processor_level);
    offset += 2;
    ok &= write_u16(memory, offset, 0);
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anticheat::MonotonicClock;
    use crate::cpu::CpuState;
    use crate::runtime::{
        GuestThreadContext, ParallelThunk, ProcessShared, WorkerClock, WorkerEnvironment,
        WorkerIdentity, WorkerMemoryStatus, WorkerVersion,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const THUNK: u64 = 0x7000;
    const RETURN_ADDRESS: u64 = 0x9000;
    const STACK: u64 = 0x200;

    struct TestMemory {
        bytes: std::cell::RefCell<Vec<u8>>,
    }

    impl TestMemory {
        fn new() -> Self {
            Self {
                bytes: std::cell::RefCell::new(vec![0_u8; 0x2000]),
            }
        }
    }

    impl WorkerMemoryView for TestMemory {
        fn load(&self, address: u64, len: usize) -> Option<u64> {
            let start = usize::try_from(address).ok()?;
            let bytes = self.bytes.borrow();
            let slice = bytes.get(start..start.checked_add(len)?)?;
            let mut value = 0_u64;
            for (index, byte) in slice.iter().enumerate() {
                value |= u64::from(*byte) << (index * 8);
            }
            Some(value)
        }

        fn store(&self, address: u64, bytes: &[u8]) -> bool {
            let Ok(start) = usize::try_from(address) else {
                return false;
            };
            let mut target = self.bytes.borrow_mut();
            let Some(slot) = target.get_mut(start..) else {
                return false;
            };
            if slot.len() < bytes.len() {
                return false;
            }
            slot[..bytes.len()].copy_from_slice(bytes);
            true
        }
    }

    fn environment(process_id: u32) -> WorkerEnvironment {
        WorkerEnvironment {
            identity: WorkerIdentity {
                process_id,
                process_handle: 0x44,
            },
            clock: WorkerClock {
                clock: Arc::new(MonotonicClock::new()),
                dtm: false,
                deterministic_tick_ms: 0,
            },
            version: Some(WorkerVersion {
                major: 10,
                minor: 0,
                build: 22631,
                service_pack_major: 0,
                service_pack_minor: 0,
                suite_mask: 0,
                product_type: 1,
            }),
            memory_status: Some(WorkerMemoryStatus {
                total_phys: 16 * 1024 * 1024 * 1024,
                avail_phys: 8 * 1024 * 1024 * 1024,
                total_page: 32 * 1024 * 1024 * 1024,
                avail_page: 16 * 1024 * 1024 * 1024,
            }),
        }
    }

    fn x64_context(thread_id: u32) -> GuestThreadContext {
        let mut context = GuestThreadContext::new(thread_id, CpuState::new(GuestArch::X64));
        context.state.set(Register::Rsp, STACK);
        context
    }

    fn x86_context(thread_id: u32) -> GuestThreadContext {
        let mut context = GuestThreadContext::new(thread_id, CpuState::new(GuestArch::X86));
        context.state.set(Register::Rsp, STACK);
        context
    }

    fn thunk_address(context: &GuestThreadContext) -> u64 {
        THUNK + u64::from(context.thread_id) * 0x40
    }

    fn invoke(
        shared: &ProcessShared,
        context: &mut GuestThreadContext,
        memory: &TestMemory,
        thunk: HostThunk,
    ) -> bool {
        let address = thunk_address(context);
        shared.publish_thunk(address, &thunk);
        context.state.rip = address;
        let pointer = context.state.arch.pointer_bytes() as u64;
        let rsp = context.state.get(Register::Rsp);
        if rsp != 0 {
            let pushed = rsp - pointer;
            assert_eq!(
                memory.store(pushed, &RETURN_ADDRESS.to_le_bytes()[..pointer as usize]),
                true
            );
            context.state.set(Register::Rsp, pushed);
        }
        let executed = shared.run_worker_api(context, memory, address);
        if !executed {
            context.state.set(Register::Rsp, rsp);
        }
        executed
    }

    fn set_x86_arg(memory: &TestMemory, index: u64, value: u32) {
        assert_eq!(memory.store(STACK + index * 4, &value.to_le_bytes()), true);
    }

    #[test]
    fn parallel_api_stateless_hammer_has_exact_per_thread_results() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(0x1234));
        const THREADS: u32 = 8;
        const CALLS: u32 = 400;
        let expected_version = (22631_u64 << 16) | (10_u64 << 8) | 0x8000_0000;
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                let mut context = x64_context(0x100 + thread);
                let memory = TestMemory::new();
                for _ in 0..CALLS {
                    assert_eq!(
                        invoke(
                            &shared,
                            &mut context,
                            &memory,
                            HostThunk::GetCurrentThreadId
                        ),
                        true
                    );
                    assert_eq!(context.state.get(Register::Rax), 0x100 + thread as u64);
                    assert_eq!(
                        invoke(
                            &shared,
                            &mut context,
                            &memory,
                            HostThunk::GetCurrentProcessId
                        ),
                        true
                    );
                    assert_eq!(context.state.get(Register::Rax), 0x1234);
                    assert_eq!(
                        invoke(&shared, &mut context, &memory, HostThunk::GetVersion),
                        true
                    );
                    assert_eq!(context.state.get(Register::Rax), expected_version);
                }
            }));
        }
        for worker in workers {
            worker.join().expect("stateless hammer worker");
        }
        let metrics = shared.api_dispatch_metrics();
        assert_eq!(metrics.parallel_dispatched, u64::from(THREADS * CALLS * 3));
        assert_eq!(metrics.barrier_calls, 0);
    }

    #[test]
    fn parallel_api_last_error_isolation_under_concurrency() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(0x1234));
        const THREADS: u32 = 8;
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                let expected = 0x5000 + thread;
                let mut context = x64_context(0x200 + thread);
                let memory = TestMemory::new();
                context.state.set(Register::Rcx, u64::from(expected));
                assert_eq!(
                    invoke(&shared, &mut context, &memory, HostThunk::SetLastError),
                    true
                );
                shared.with_process(|| std::thread::yield_now());
                assert_eq!(
                    invoke(&shared, &mut context, &memory, HostThunk::GetLastError),
                    true
                );
                assert_eq!(context.state.get(Register::Rax), u64::from(expected));
                assert_eq!(context.last_error, expected);
            }));
        }
        for worker in workers {
            worker.join().expect("last-error worker");
        }
        let metrics = shared.api_dispatch_metrics();
        assert_eq!(metrics.parallel_dispatched, u64::from(THREADS * 2));
        assert_eq!(metrics.barrier_calls, 0);
    }

    #[test]
    fn parallel_api_read_mostly_readers_race_writer_consistency() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(100));
        let stop = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicU64::new(0));
        let mut readers = Vec::new();
        for thread in 0..4 {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            let reads = Arc::clone(&reads);
            readers.push(std::thread::spawn(move || {
                let mut context = x64_context(0x300 + thread);
                let memory = TestMemory::new();
                while !stop.load(Ordering::Acquire) {
                    assert_eq!(
                        invoke(
                            &shared,
                            &mut context,
                            &memory,
                            HostThunk::GetCurrentProcessId
                        ),
                        true
                    );
                    let pid = context.state.get(Register::Rax);
                    assert_eq!(pid == 100 || pid == 101, true);
                    reads.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for iteration in 0..2_000 {
            shared.publish_identity(WorkerIdentity {
                process_id: if iteration % 2 == 0 { 101 } else { 100 },
                process_handle: 0x44,
            });
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while reads.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        stop.store(true, Ordering::Release);
        for reader in readers {
            reader.join().expect("read-mostly reader");
        }
        assert_eq!(reads.load(Ordering::Relaxed) > 0, true);
    }

    #[test]
    fn parallel_api_owner_only_thunk_stays_on_barrier() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(7));
        let mut context = x64_context(0x400);
        let memory = TestMemory::new();
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CreateFileW),
            false
        );
        assert_eq!(context.state.get(Register::Rsp), STACK);
        assert_eq!(context.state.rip, thunk_address(&context));
        let metrics = shared.api_dispatch_metrics();
        assert_eq!(metrics.parallel_dispatched, 0);
        assert_eq!(metrics.barrier_calls, 1);
    }

    #[test]
    fn parallel_api_mixed_parallel_and_barrier_calls_no_deadlock() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(9));
        const THREADS: u32 = 6;
        const ROUNDS: u32 = 200;
        let started = std::time::Instant::now();
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                let mut context = x64_context(0x500 + thread);
                let memory = TestMemory::new();
                for _ in 0..ROUNDS {
                    assert_eq!(
                        invoke(
                            &shared,
                            &mut context,
                            &memory,
                            HostThunk::GetCurrentThreadId
                        ),
                        true
                    );
                    shared.with_process(|| std::thread::yield_now());
                    assert_eq!(
                        invoke(&shared, &mut context, &memory, HostThunk::CreateFileW),
                        false
                    );
                }
            }));
        }
        for worker in workers {
            worker.join().expect("mixed worker");
        }
        assert_eq!(started.elapsed() < std::time::Duration::from_secs(5), true);
        let metrics = shared.api_dispatch_metrics();
        assert_eq!(metrics.parallel_dispatched, u64::from(THREADS * ROUNDS));
        assert_eq!(metrics.barrier_calls, u64::from(THREADS * ROUNDS));
        assert_eq!(shared.process_operations(), u64::from(THREADS * ROUNDS));
    }

    #[test]
    fn parallel_api_classification_and_names_are_canonical() {
        assert_eq!(
            thunk_class(&HostThunk::GetTickCount64),
            ThunkConcurrency::Stateless
        );
        assert_eq!(
            thunk_class(&HostThunk::GetVersion),
            ThunkConcurrency::ReadMostly
        );
        assert_eq!(
            thunk_class(&HostThunk::CreateFileW),
            ThunkConcurrency::OwnerOnly
        );
        assert_eq!(
            crate::host_thunks::classify_thunk_concurrency("GetLastError"),
            ThunkConcurrency::Stateless
        );
        assert_eq!(
            crate::host_thunks::classify_thunk_concurrency("GetSystemInfo"),
            ThunkConcurrency::ReadMostly
        );
        assert_eq!(
            crate::host_thunks::classify_thunk_concurrency("CreateFileW"),
            ThunkConcurrency::OwnerOnly
        );
    }

    #[test]
    fn parallel_api_invalid_arguments_boundary_outcomes_are_exact() {
        let shared = ProcessShared::new();
        let mut context = x64_context(0x600);
        let memory = TestMemory::new();
        shared.publish_environment(environment(11));

        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::QueryPerformanceCounter
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::QueryPerformanceFrequency
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::IsWow64Process),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::GlobalMemoryStatusEx
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExA),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn parallel_api_missing_state_and_memory_fall_back_to_barrier() {
        let shared = ProcessShared::new();
        let mut context = x64_context(0x700);
        let memory = TestMemory::new();
        // No environment published: version has no snapshot.
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersion),
            false
        );
        assert_eq!(context.state.rip, thunk_address(&context));

        // VersionEx* also refuse to guess without a published version.
        let mut context_w = x64_context(0x702);
        let memory_w = TestMemory::new();
        assert_eq!(
            invoke(&shared, &mut context_w, &memory_w, HostThunk::GetVersionExW),
            false
        );
        assert_eq!(
            invoke(&shared, &mut context_w, &memory_w, HostThunk::GetVersionExA),
            false
        );

        // A published version but unmapped output pointer.
        shared.publish_environment(environment(3));
        context.state.set(Register::Rcx, 0x1_0000);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExW),
            false
        );

        // No stack at all.
        context.state.set(Register::Rsp, 0);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetTickCount64),
            false
        );

        // Globals without a memory-status snapshot.
        let shared = ProcessShared::new();
        let mut context = x64_context(0x701);
        let memory = TestMemory::new();
        shared.publish_thunk(THUNK, &HostThunk::GlobalMemoryStatusEx);
        context.state.rip = THUNK;
        assert_eq!(memory.store(STACK, &RETURN_ADDRESS.to_le_bytes()), true);
        context.state.set(Register::Rsp, STACK);
        context.state.set(Register::Rcx, 0x300);
        let entry = shared.parallel_thunk(THUNK).expect("published thunk");
        assert_eq!(
            super::invoke_parallel_api(&shared, &mut context, &memory, &entry),
            false
        );

        // x64 stack arguments (index >= 4) are not used by the safe subset
        // but the reader must fail closed rather than fabricate a value.
        context.state.set(Register::Rsp, STACK);
        assert_eq!(super::read_arg(&context, &memory, 4), Some(0));
        context.state.set(Register::Rsp, 0x1_0000);
        assert_eq!(super::read_arg(&context, &memory, 4), None);
    }

    #[test]
    fn parallel_api_worker_success_paths_have_exact_results() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x2222));
        let memory = TestMemory::new();

        let mut context = x64_context(0x800);
        context.state.set(Register::Rax, 0xDEAD);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetCurrentProcess),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x44);

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetCurrentThread),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x800);

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetTickCount),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax) <= u64::from(u32::MAX),
            true
        );

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetTickCount64),
            true
        );
        assert_eq!(context.last_error, 0);

        // QueryPerformanceCounter/Frequency and the two FILETIME APIs.
        for thunk in [
            HostThunk::QueryPerformanceCounter,
            HostThunk::QueryPerformanceFrequency,
        ] {
            context.state.set(Register::Rcx, 0x1000);
            assert_eq!(invoke(&shared, &mut context, &memory, thunk), true);
            assert_eq!(context.state.get(Register::Rax), 1);
            assert_eq!(context.last_error, 0);
        }
        for thunk in [
            HostThunk::GetSystemTimeAsFileTime,
            HostThunk::GetSystemTimePreciseAsFileTime,
        ] {
            context.state.set(Register::Rcx, 0x1000);
            assert_eq!(invoke(&shared, &mut context, &memory, thunk), true);
            assert_eq!(context.state.get(Register::Rax), 0);
        }

        // Null output pointers are valid for the FILETIME APIs.
        for thunk in [
            HostThunk::GetSystemTimeAsFileTime,
            HostThunk::GetSystemTimePreciseAsFileTime,
        ] {
            context.state.set(Register::Rcx, 0);
            assert_eq!(invoke(&shared, &mut context, &memory, thunk), true);
            assert_eq!(context.state.get(Register::Rax), 0);
        }

        context.state.set(Register::Rcx, 0x1200);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(0x1204, 4), Some(10));

        context.state.set(Register::Rcx, 0x1300);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExA),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(0x1304, 4), Some(10));

        // Extended variant writes the service-pack tail.
        assert_eq!(memory.store(0x1200, &0x11C_u32.to_le_bytes()), true);
        assert_eq!(memory.store(0x1300, &0x9C_u32.to_le_bytes()), true);
        context.state.set(Register::Rcx, 0x1200);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExW),
            true
        );
        assert_eq!(memory.load(0x1214, 2), Some(0));
        context.state.set(Register::Rcx, 0x1300);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExA),
            true
        );

        context.state.set(Register::Rcx, 0x1400);
        context.state.set(Register::Rdx, 0x1500);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::IsWow64Process),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(0x1500, 4), Some(0));

        for thunk in [HostThunk::GetSystemInfo, HostThunk::GetNativeSystemInfo] {
            context.state.set(Register::Rcx, 0x1600);
            assert_eq!(invoke(&shared, &mut context, &memory, thunk.clone()), true);
            assert_eq!(context.state.get(Register::Rax), 0);
            assert_eq!(memory.load(0x1600, 2), Some(9));
            // Null pointer is accepted.
            context.state.set(Register::Rcx, 0);
            assert_eq!(invoke(&shared, &mut context, &memory, thunk.clone()), true);
            assert_eq!(context.state.get(Register::Rax), 0);
        }

        context.state.set(Register::Rcx, 0x1700);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::GlobalMemoryStatusEx
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(0x1700, 4), Some(64));

        context.state.set(Register::Rcx, 2);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::IsProcessorFeaturePresent
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        context.state.set(Register::Rcx, 0);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::IsProcessorFeaturePresent
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);

        // CharNextW: null pointer, NUL unit and a real code unit.
        context.state.set(Register::Rcx, 0);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CharNextW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(memory.store(0x1800, &0_u16.to_le_bytes()), true);
        context.state.set(Register::Rcx, 0x1800);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CharNextW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x1800);
        assert_eq!(memory.store(0x1800, &0x41_u16.to_le_bytes()), true);
        context.state.set(Register::Rcx, 0x1800);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CharNextW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x1802);

        context.state.set(Register::Rcx, 0x1800);
        context.state.set(Register::Rdx, 0x1800);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CharPrevW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x1800);
        context.state.set(Register::Rdx, 0x1802);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CharPrevW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x1800);

        // StrFromTimeIntervalW: success, truncation, null buffer and an
        // invalid digit count.
        context.state.set(Register::Rcx, 0x1900);
        context.state.set(Register::Rdx, 8);
        context.state.set(Register::R8, 3_723_000);
        context.state.set(Register::R9, 4);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::StrFromTimeIntervalW
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax) > 0, true);
        context.state.set(Register::Rcx, 0);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::StrFromTimeIntervalW
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        context.state.set(Register::Rcx, 0x1900);
        context.state.set(Register::R9, 0);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::StrFromTimeIntervalW
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
    }

    struct FailingMemory<'a> {
        inner: &'a TestMemory,
        remaining: std::cell::Cell<usize>,
    }

    impl WorkerMemoryView for FailingMemory<'_> {
        fn load(&self, address: u64, len: usize) -> Option<u64> {
            self.inner.load(address, len)
        }

        fn store(&self, address: u64, bytes: &[u8]) -> bool {
            if self.remaining.get() == 0 {
                return false;
            }
            self.remaining.set(self.remaining.get() - 1);
            self.inner.store(address, bytes)
        }
    }

    fn prepare_call(
        shared: &ProcessShared,
        context: &mut GuestThreadContext,
        memory: &TestMemory,
        thunk: HostThunk,
    ) -> u64 {
        let address = thunk_address(context);
        shared.publish_thunk(address, &thunk);
        context.state.rip = address;
        let pointer = context.state.arch.pointer_bytes() as u64;
        let pushed = context.state.get(Register::Rsp) - pointer;
        assert_eq!(
            memory.store(pushed, &RETURN_ADDRESS.to_le_bytes()[..pointer as usize]),
            true
        );
        context.state.set(Register::Rsp, pushed);
        address
    }

    #[test]
    fn parallel_api_out_of_bounds_reads_and_writes_fail_closed() {
        assert_eq!(format!("{:?}", ProcessShared::new()).is_empty(), false);
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x4444));
        let memory = TestMemory::new();
        let mut context = x64_context(0xA00);
        let entry = prepare_call(&shared, &mut context, &memory, HostThunk::CharNextW);
        context.state.set(Register::Rcx, 0x1FFF);
        assert_eq!(shared.run_worker_api(&mut context, &memory, entry), false);

        // Version info headers that cannot be read at all.
        context.state.set(Register::Rsp, STACK);
        let entry = prepare_call(&shared, &mut context, &memory, HostThunk::GetVersionExW);
        context.state.set(Register::Rcx, 0x1FFF);
        assert_eq!(shared.run_worker_api(&mut context, &memory, entry), false);

        // A return-address fetch beyond the view.
        context.state.set(Register::Rsp, 0x1FFF);
        assert_eq!(shared.run_worker_api(&mut context, &memory, entry), false);

        // VersionExA's size header cannot be read.
        context.state.set(Register::Rsp, STACK);
        let entry = prepare_call(&shared, &mut context, &memory, HostThunk::GetVersionExA);
        context.state.set(Register::Rcx, 0x1FFF);
        assert_eq!(shared.run_worker_api(&mut context, &memory, entry), false);

        // A thunk entry with no worker implementation is a barrier.
        let barrier_only = ParallelThunk {
            api: None,
            class: crate::host_thunks::ThunkConcurrency::OwnerOnly,
            x86_arg_bytes: 0,
        };
        assert_eq!(
            super::invoke_parallel_api(&shared, &mut context, &memory, &barrier_only),
            false
        );
    }

    #[test]
    fn parallel_api_unreadable_stack_arguments_fall_back_to_barrier() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x6666));
        let memory = TestMemory::new();
        let first_arg = [
            HostThunk::SetLastError,
            HostThunk::QueryPerformanceCounter,
            HostThunk::QueryPerformanceFrequency,
            HostThunk::GetSystemTimeAsFileTime,
            HostThunk::GetSystemTimePreciseAsFileTime,
            HostThunk::GetVersionExW,
            HostThunk::GetVersionExA,
            HostThunk::GetSystemInfo,
            HostThunk::GetNativeSystemInfo,
            HostThunk::GlobalMemoryStatusEx,
            HostThunk::IsProcessorFeaturePresent,
            HostThunk::CharNextW,
            HostThunk::CharPrevW,
            HostThunk::StrFromTimeIntervalW,
        ];
        for (index, thunk) in first_arg.into_iter().enumerate() {
            let mut context = x86_context(0xC00 + index as u32);
            context.state.set(Register::Rsp, 0x2000);
            let address = prepare_call(&shared, &mut context, &memory, thunk);
            assert_eq!(
                shared.run_worker_api(&mut context, &memory, address),
                false,
                "an unreadable first argument must fall back to the barrier"
            );
        }

        // IsWow64Process reads its output pointer from the second argument.
        let mut context = x86_context(0xC80);
        context.state.set(Register::Rsp, 0x1FFC);
        let address = prepare_call(&shared, &mut context, &memory, HostThunk::IsWow64Process);
        assert_eq!(shared.run_worker_api(&mut context, &memory, address), false);

        // CharPrevW reads a second argument.
        let mut context = x86_context(0xC81);
        context.state.set(Register::Rsp, 0x1FFC);
        let address = prepare_call(&shared, &mut context, &memory, HostThunk::CharPrevW);
        assert_eq!(shared.run_worker_api(&mut context, &memory, address), false);

        // StrFromTimeIntervalW reads arguments 1..3 after a readable buffer.
        for (index, stack) in [(1_u32, 0x1FFC_u64), (2, 0x1FF8), (3, 0x1FF4)] {
            let mut context = x86_context(0xC90 + index);
            context.state.set(Register::Rsp, stack);
            let address = prepare_call(
                &shared,
                &mut context,
                &memory,
                HostThunk::StrFromTimeIntervalW,
            );
            assert_eq!(
                shared.run_worker_api(&mut context, &memory, address),
                false,
                "an unreadable argument {index} must fall back to the barrier"
            );
        }
    }

    #[test]
    fn parallel_api_write_faults_fall_back_to_barrier() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x5555));
        let memory = TestMemory::new();
        // Seed a full-size version header so the writers get past the size read.
        assert_eq!(memory.store(0x1B00, &0x11C_u32.to_le_bytes()), true);
        assert_eq!(memory.store(0x1D00, &0x9C_u32.to_le_bytes()), true);
        let cases: &[(HostThunk, [u64; 4])] = &[
            (HostThunk::QueryPerformanceCounter, [0x1B00, 0, 0, 0]),
            (HostThunk::QueryPerformanceFrequency, [0x1B00, 0, 0, 0]),
            (HostThunk::GetSystemTimeAsFileTime, [0x1B00, 0, 0, 0]),
            (HostThunk::GetSystemTimePreciseAsFileTime, [0x1B00, 0, 0, 0]),
            (HostThunk::GetVersionExW, [0x1B00, 0, 0, 0]),
            (HostThunk::GetVersionExA, [0x1D00, 0, 0, 0]),
            (HostThunk::IsWow64Process, [0, 0x1B00, 0, 0]),
            (HostThunk::GetSystemInfo, [0x1B00, 0, 0, 0]),
            (HostThunk::GetNativeSystemInfo, [0x1B00, 0, 0, 0]),
            (HostThunk::GlobalMemoryStatusEx, [0x1B00, 0, 0, 0]),
            (HostThunk::StrFromTimeIntervalW, [0x1B00, 8, 3_723_000, 4]),
        ];
        for (index, (thunk, args)) in cases.iter().enumerate() {
            let mut context = x64_context(0xB00 + index as u32);
            context.state.rip = THUNK;
            context.state.set(Register::Rcx, args[0]);
            context.state.set(Register::Rdx, args[1]);
            context.state.set(Register::R8, args[2]);
            context.state.set(Register::R9, args[3]);
            context.state.set(Register::Rax, 0xDEAD);
            let entry = prepare_call(&shared, &mut context, &memory, thunk.clone());
            let mut saw_false = false;
            for allowed in 0..=40 {
                let failing = FailingMemory {
                    inner: &memory,
                    remaining: std::cell::Cell::new(allowed),
                };
                context.state.set(Register::Rsp, STACK);
                let entry = prepare_call(&shared, &mut context, &memory, thunk.clone());
                context.state.set(Register::Rcx, args[0]);
                context.state.set(Register::Rdx, args[1]);
                context.state.set(Register::R8, args[2]);
                context.state.set(Register::R9, args[3]);
                if !shared.run_worker_api(&mut context, &failing, entry) {
                    saw_false = true;
                }
            }
            let _ = entry;
            assert_eq!(
                saw_false, true,
                "a write fault must fall back to the barrier (case {index}: {thunk:?})"
            );
        }

        // Invalid digits take the formatting helper's failure branch.
        let mut context = x64_context(0xB80);
        let entry = prepare_call(
            &shared,
            &mut context,
            &memory,
            HostThunk::StrFromTimeIntervalW,
        );
        context.state.set(Register::Rcx, 0x1B00);
        context.state.set(Register::Rdx, 8);
        context.state.set(Register::R8, 1000);
        context.state.set(Register::R9, 0);
        let failing = FailingMemory {
            inner: &memory,
            remaining: std::cell::Cell::new(0),
        };
        assert_eq!(shared.run_worker_api(&mut context, &failing, entry), false);
    }

    #[test]
    fn parallel_api_deterministic_filetime_uses_guest_clock_exactly() {
        let shared = ProcessShared::new();
        let mut environment = environment(0x7777);
        environment.clock.dtm = true;
        environment.clock.deterministic_tick_ms = 1234;
        shared.publish_environment(environment);
        let memory = TestMemory::new();
        let mut context = x64_context(0xD00);
        context.state.set(Register::Rcx, 0x1B00);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetSystemTimeAsFileTime
            ),
            true
        );
        let expected = WINDOWS_EPOCH_OFFSET_100NS + 1234 * 10_000;
        assert_eq!(memory.load(0x1B00, 8), Some(expected));
        assert_eq!(context.last_error, 0);
    }

    #[test]
    fn parallel_api_x86_stdcall_cleanup_and_stack_args_are_exact() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x3333));
        let mut context = x86_context(0x900);
        let memory = TestMemory::new();
        set_x86_arg(&memory, 0, 0xCAFE);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::SetLastError),
            true
        );
        assert_eq!(context.last_error, 0xCAFE);
        assert_eq!(context.state.get(Register::Rsp), STACK + 4);
        assert_eq!(context.state.rip, RETURN_ADDRESS);

        // A 4-byte x86 out pointer is written through the worker view.
        context.state.set(Register::Rsp, STACK);
        set_x86_arg(&memory, 0, 0x1A00);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetSystemInfo),
            true
        );
        assert_eq!(memory.load(0x1A00, 2), Some(0));
        assert_eq!(context.state.get(Register::Rsp), STACK + 4);
    }
}
