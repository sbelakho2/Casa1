//! CasaK kernel introspection: real, internally-consistent Windows kernel
//! state assembled from the live runtime (loader tables, the Win32 handle
//! table, the guest scheduler's thread set, the tagged pool and the guest
//! clock).
//!
//! This module is PURE: it owns no mutable state and performs no guest
//! execution.  [`KernelSnapshot`] is a plain-value view of the live runtime;
//! the runtime dispatch layer fills it from its canonical tables and the
//! serializers below lay it out as the real `ntoskrnl` structures the
//! anti-cheat / native-introspection surface reads.
//!
//! INTERNAL-CONSISTENCY CONTRACT (pinned by the adversarial tests):
//! - module base addresses and sizes are the loader's real mappings, and the
//!   reported `FullPathName` is the exact loaded path;
//! - every process record's `UniqueProcessId` is a real guest pid and its
//!   thread records are the scheduler's real threads;
//! - every handle record's `HandleValue`, granted access and type index come
//!   from the one live Win32 handle table;
//! - pool counters are the tagged pool's real accounting (never estimated);
//! - the debugger / code-integrity flags are the runtime's truthful state.

use crate::casak::exec::PoolTag;
use crate::casak::object::NtStatus;

/// NTSTATUS values the introspection surface reports (canonical ntstatus.h).
pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_INFO_LENGTH_MISMATCH: NtStatus = 0xC000_0004u32 as NtStatus;
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023u32 as NtStatus;
/// `STATUS_INVALID_INFO_CLASS` — an information class this surface does not
/// back with real state.
pub const STATUS_INVALID_INFO_CLASS: NtStatus = 0xC000_0003u32 as NtStatus;
/// `STATUS_NOT_SUPPORTED` — the class is known but a required field cannot be
/// backed by real runtime state (never fabricate it).
pub const STATUS_NOT_SUPPORTED: NtStatus = 0xC000_00BBu32 as NtStatus;

// ── SYSTEM_INFORMATION_CLASS values (the ntoskrnl numbering) ───────────────
/// `SystemBasicInformation`.
pub const SYSTEM_BASIC_INFORMATION_CLASS: u32 = 0;
/// `SystemPerformanceInformation`.
pub const SYSTEM_PERFORMANCE_INFORMATION_CLASS: u32 = 2;
/// `SystemTimeOfDayInformation`.
pub const SYSTEM_TIME_OF_DAY_INFORMATION_CLASS: u32 = 3;
/// `SystemProcessInformation`.
pub const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
/// `SystemExtendedProcessInformation` — the extended process array whose
/// thread records are `SYSTEM_EXTENDED_THREAD_INFORMATION`.
pub const SYSTEM_EXTENDED_PROCESS_INFORMATION_CLASS: u32 = 57;
/// `SystemProcessorPerformanceInformation`.
pub const SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_CLASS: u32 = 8;
/// `SystemModuleInformation`.
pub const SYSTEM_MODULE_INFORMATION_CLASS: u32 = 11;
/// `SystemHandleInformation`.
pub const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;
/// `SystemPageFileInformation`.
pub const SYSTEM_PAGEFILE_INFORMATION_CLASS: u32 = 18;
/// `SystemKernelDebuggerInformation`.
pub const SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS: u32 = 35;
/// `SystemLookasideInformation`.
pub const SYSTEM_LOOKASIDE_INFORMATION_CLASS: u32 = 45;
/// `SystemRangeStartInformation`.
pub const SYSTEM_RANGE_START_INFORMATION_CLASS: u32 = 50;
/// `SystemExtendedHandleInformation`.
pub const SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS: u32 = 64;
/// `SystemBigPoolInformation`.
pub const SYSTEM_BIGPOOL_INFORMATION_CLASS: u32 = 66;
/// `SystemFirmwareTableInformation`.
pub const SYSTEM_FIRMWARE_TABLE_INFORMATION_CLASS: u32 = 76;
/// `SystemCodeIntegrityInformation`.
pub const SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS: u32 = 103;

/// x64 `SYSTEM_MODULE` entry size (Reserved[2] + base + size + flags +
/// 4 ushorts + 256-byte path).
pub const SYSTEM_MODULE_ENTRY_SIZE: usize = 296;
/// x64 `SYSTEM_HANDLE_TABLE_ENTRY_INFO` size: two `USHORT`, two `UCHAR`, a
/// `USHORT`, a `PVOID` and a `ULONG`, 8-aligned.
pub const SYSTEM_HANDLE_TABLE_ENTRY_SIZE: usize = 24;
/// x64 `SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX` size.
pub const SYSTEM_HANDLE_TABLE_ENTRY_EX_SIZE: usize = 40;
/// x64 `SYSTEM_PROCESS_INFORMATION` fixed size (before the thread array).
pub const SYSTEM_PROCESS_INFORMATION_FIXED_SIZE: usize = 0x100;
/// x64 `SYSTEM_THREAD_INFORMATION` size.
pub const SYSTEM_THREAD_INFORMATION_SIZE: usize = 0x50;
/// x64 `SYSTEM_EXTENDED_THREAD_INFORMATION` size: the plain thread record
/// plus `StackBase`, `StackLimit`, `Win32StartAddress`, `TebBase` and three
/// reserved pointer slots.
pub const SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE: usize = 0x88;
/// x86 `SYSTEM_PROCESS_INFORMATION` fixed size (before the thread array):
/// the same fields as x64 with 32-bit pointers and `SIZE_T`s.
pub const SYSTEM_PROCESS_INFORMATION_FIXED_SIZE_X86: usize = 0xB8;
/// x86 `SYSTEM_THREAD_INFORMATION` size (8-aligned: the last field ends at
/// 0x3C and the `LARGE_INTEGER` members force 8-byte alignment).
pub const SYSTEM_THREAD_INFORMATION_SIZE_X86: usize = 0x40;
/// x86 `SYSTEM_EXTENDED_THREAD_INFORMATION` size: the plain thread record
/// plus four pointers (`StackBase`, `StackLimit`, `Win32StartAddress`,
/// `TebBase`) and three reserved pointer slots, 8-aligned.
pub const SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE_X86: usize = 0x60;

/// One loaded image (kernel module or user module) as the loader really
/// mapped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelModule {
    /// Mapped base address.
    pub base: u64,
    /// Mapped image size in bytes.
    pub size: u32,
    /// Full guest path exactly as the loader recorded it.
    pub path: String,
    /// `LoadCount` the module's loader entry reports.
    pub load_count: u16,
    /// The image-entry RVA (0 when the image has no entry point).
    pub entry_rva: u32,
    /// True for kernel-mode images (drivers); false for user images.
    pub kernel_mode: bool,
}

impl KernelModule {
    /// The file-name portion of the module path (the
    /// `SYSTEM_MODULE.OffsetToFileName` target).
    pub fn file_name(&self) -> &str {
        let trimmed = self.path.trim_end_matches(['\0']);
        match trimmed.rsplit_once(['\\', '/']) {
            Some((_, name)) if !name.is_empty() => name,
            _ => trimmed,
        }
    }
}

/// One guest thread record, straight from the scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelThread {
    pub thread_id: u32,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    /// Entry point the thread started at (0 for the main thread).
    pub start_address: u64,
    pub win32_start_address: u64,
    pub priority: i32,
    pub base_priority: i32,
    pub context_switches: u32,
    /// `ThreadState` (`5` = `Waiting`).
    pub state: u32,
    /// `WaitReason` (`6` = `WrSuspended`, `0` = `Executive`).
    pub wait_reason: u32,
    pub wait_time: u32,
    pub teb_base: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
}

/// One guest process record with its real threads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_name: String,
    pub base_priority: i32,
    pub handle_count: u32,
    pub session_id: u32,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    pub virtual_size: u64,
    pub peak_virtual_size: u64,
    pub working_set: u64,
    pub peak_working_set: u64,
    pub page_fault_count: u32,
    pub threads: Vec<KernelThread>,
}

/// One live handle in the single Win32 handle table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelHandle {
    pub handle: u32,
    pub object: u64,
    pub process_id: u32,
    pub access: u32,
    /// The kernel object type index (`ObjectTypeInformation` numbering).
    pub object_type_index: u8,
    pub pointer_count: u32,
    pub handle_count: u32,
}

/// One tagged-pool accounting row, from the real tagged pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelPoolTag {
    pub tag: PoolTag,
    pub used_bytes: u64,
    pub allocations: u64,
    pub frees: u64,
}

/// One lookaside-list row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelLookaside {
    pub tag: PoolTag,
    pub current_depth: u32,
    pub maximum_depth: u32,
    pub total_allocates: u32,
    pub allocate_misses: u32,
    pub total_frees: u32,
    pub free_misses: u32,
    pub size: u32,
}

/// A plain-value snapshot of the live kernel state the serializers consume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelSnapshot {
    pub processor_count: u32,
    /// Active processor mask (`0xFF` for the 8-processor topology).
    pub active_processor_mask: u64,
    /// Current `FILETIME` (100 ns since 1601).
    pub system_time: i64,
    /// Boot `FILETIME` (system time minus uptime).
    pub boot_time: i64,
    /// `MmSystemRangeStart` for the guest architecture.
    pub range_start: u64,
    pub modules: Vec<KernelModule>,
    pub processes: Vec<KernelProcess>,
    pub handles: Vec<KernelHandle>,
    pub pool_tags: Vec<KernelPoolTag>,
    pub pool_used_bytes: u64,
    pub pool_budget_bytes: u64,
    pub lookaside: Vec<KernelLookaside>,
    /// `SystemKernelDebuggerInformation` — truthful runtime state.
    pub debugger_present: bool,
    pub debugger_enabled: bool,
    /// `SystemCodeIntegrityInformation` options word (truthful).
    pub code_integrity_options: u32,
    /// `SystemFirmwareTableInformation` query (provider + table id).
    pub firmware_provider: u32,
    pub firmware_table_id: u32,
    /// Truthful firmware table payload (empty when no table is exposed).
    pub firmware_table: Vec<u8>,
    /// `SystemPageFileInformation` facts.
    pub page_file_path: String,
    pub page_file_total_pages: u32,
    pub page_file_in_use_pages: u32,
    pub page_file_peak_pages: u32,
    /// Installed physical memory (informational).
    pub installed_memory_bytes: u64,
}

/// The result of serializing one information class: the NTSTATUS the runtime
/// must return, the byte count the buffer needs, and the bytes to copy on
/// success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysInfoSerialized {
    pub status: NtStatus,
    pub required: u64,
    pub bytes: Vec<u8>,
}

impl SysInfoSerialized {
    fn success(bytes: Vec<u8>) -> Self {
        let required = bytes.len() as u64;
        Self {
            status: STATUS_SUCCESS,
            required,
            bytes,
        }
    }

    fn mismatch(required: u64) -> Self {
        Self {
            status: STATUS_INFO_LENGTH_MISMATCH,
            required,
            bytes: Vec::new(),
        }
    }

    fn invalid_class() -> Self {
        Self {
            status: STATUS_INVALID_INFO_CLASS,
            required: 0,
            bytes: Vec::new(),
        }
    }
}

/// `MmSystemRangeStart` for a guest architecture: the address above which
/// only the kernel may map.  x64 guests get the canonical `0xFFFF8000_00000000`
/// split; x86 guests the classic `0x80000000` split.
pub fn system_range_start(is_x64: bool) -> u64 {
    if is_x64 {
        0xFFFF_8000_0000_0000
    } else {
        0x8000_0000
    }
}

/// Assemble the module list from the loader's real tables: the mapped main
/// image plus every DLL table entry, with the module-name table supplying the
/// path and `.sys` images flagged kernel-mode.  Sorted by base address.
pub fn assemble_modules(
    mapped_base: u64,
    mapped_size: u32,
    main_path: &str,
    main_name: &str,
    dlls: &[(u64, u32, String, u16, u32)],
    module_names: &std::collections::BTreeMap<u64, String>,
) -> Vec<KernelModule> {
    let mut modules: Vec<KernelModule> = Vec::new();
    if mapped_base != 0 {
        let path = if main_path.is_empty() {
            main_name.to_string()
        } else {
            main_path.to_string()
        };
        modules.push(KernelModule {
            base: mapped_base,
            size: mapped_size,
            path,
            load_count: 1,
            entry_rva: 0,
            kernel_mode: false,
        });
    }
    for (handle, size, module_name, load_count, entry_rva) in dlls {
        if *handle == mapped_base {
            continue;
        }
        let path = module_names
            .get(handle)
            .cloned()
            .unwrap_or_else(|| module_name.clone());
        let kernel_mode = path.to_ascii_lowercase().ends_with(".sys");
        modules.push(KernelModule {
            base: *handle,
            size: *size,
            path,
            load_count: *load_count,
            entry_rva: *entry_rva,
            kernel_mode,
        });
    }
    modules.sort_by_key(|module| module.base);
    modules
}

/// Assemble this process's thread list from the main thread plus the guest
/// scheduler's pending threads, using one shared creation/CPU-time tuple.
pub fn assemble_threads(
    main: (u32, u64),
    main_stack: (u64, u64),
    pending: &[(u32, u64, u32, u64, u64, u64)],
    times: [u64; 4],
) -> Vec<KernelThread> {
    let mut threads = vec![KernelThread {
        thread_id: main.0,
        create_time: times[0] as i64,
        user_time: times[3] as i64,
        kernel_time: times[2] as i64,
        start_address: 0,
        win32_start_address: 0,
        priority: 8,
        base_priority: 8,
        context_switches: 0,
        state: 5,
        wait_reason: 0,
        wait_time: 0,
        teb_base: main.1,
        stack_base: main_stack.0,
        stack_limit: main_stack.1,
    }];
    for (thread_id, start_address, suspended, teb_base, stack_base, stack_limit) in pending {
        threads.push(KernelThread {
            thread_id: *thread_id,
            create_time: times[0] as i64,
            user_time: times[3] as i64,
            kernel_time: times[2] as i64,
            start_address: *start_address,
            win32_start_address: *start_address,
            priority: 8,
            base_priority: 8,
            context_switches: 0,
            state: 5,
            wait_reason: if *suspended > 0 { 6 } else { 0 },
            wait_time: 0,
            teb_base: *teb_base,
            stack_base: *stack_base,
            stack_limit: *stack_limit,
        });
    }
    threads.sort_by_key(|thread| thread.thread_id);
    threads
}

/// Assemble the process list from the real guest process set (the toolhelp
/// snapshot), attaching this process's thread set and its real live-handle
/// count.  Only process ids that are guests (never the host provenance entry)
/// are reported.
#[allow(clippy::too_many_arguments)]
pub fn assemble_processes(
    guest_pid: u32,
    host_pid: u32,
    handle_count: u32,
    threads: &[KernelThread],
    toolhelp: &[(u32, String)],
    times: [u64; 4],
    committed: u64,
) -> Vec<KernelProcess> {
    let mut processes: Vec<KernelProcess> = toolhelp
        .iter()
        .filter(|(pid, _)| *pid != host_pid)
        .map(|(pid, image_name)| {
            let is_self = *pid == guest_pid;
            KernelProcess {
                pid: *pid,
                parent_pid: 0,
                image_name: image_name.clone(),
                base_priority: 8,
                handle_count: if is_self { handle_count } else { 0 },
                session_id: 1,
                create_time: times[0] as i64,
                user_time: times[3] as i64,
                kernel_time: times[2] as i64,
                virtual_size: committed,
                peak_virtual_size: committed,
                working_set: committed,
                peak_working_set: committed,
                page_fault_count: 0,
                threads: if is_self {
                    threads.to_vec()
                } else {
                    Vec::new()
                },
            }
        })
        .collect();
    processes.sort_by_key(|process| process.pid);
    processes
}

/// `SYSTEM_MODULE_INFORMATION` (x64): `Count` then the module array.
pub fn serialize_module_information(modules: &[KernelModule]) -> Vec<u8> {
    let count = modules.len();
    let mut bytes = vec![0_u8; 8 + SYSTEM_MODULE_ENTRY_SIZE * count];
    bytes[0..4].copy_from_slice(&(count as u32).to_le_bytes());
    for (index, module) in modules.iter().enumerate() {
        let entry = 8 + index * SYSTEM_MODULE_ENTRY_SIZE;
        // Reserved[2] stays zero.
        bytes[entry + 16..entry + 24].copy_from_slice(&module.base.to_le_bytes());
        bytes[entry + 24..entry + 28].copy_from_slice(&module.size.to_le_bytes());
        bytes[entry + 28..entry + 32].copy_from_slice(&0_u32.to_le_bytes());
        bytes[entry + 32..entry + 34].copy_from_slice(&(index as u16).to_le_bytes());
        bytes[entry + 34..entry + 36].copy_from_slice(&0_u16.to_le_bytes());
        bytes[entry + 36..entry + 38].copy_from_slice(&module.load_count.to_le_bytes());
        let name = module.file_name();
        let name_offset = module.path.len().saturating_sub(name.len());
        bytes[entry + 38..entry + 40].copy_from_slice(&((40 + name_offset) as u16).to_le_bytes());
        let path = module.path.as_bytes();
        let copy = path.len().min(255);
        bytes[entry + 40..entry + 40 + copy].copy_from_slice(&path[..copy]);
        // FullPathName is NUL-terminated inside the 256-byte field.
        bytes[entry + 40 + copy] = 0;
    }
    bytes
}

/// `SYSTEM_HANDLE_INFORMATION` (x64): `NumberOfHandles` then the array.
pub fn serialize_handle_information(handles: &[KernelHandle]) -> Vec<u8> {
    let count = handles.len();
    let mut bytes = vec![0_u8; 8 + SYSTEM_HANDLE_TABLE_ENTRY_SIZE * count];
    bytes[0..4].copy_from_slice(&(count as u32).to_le_bytes());
    for (index, handle) in handles.iter().enumerate() {
        let entry = 8 + index * SYSTEM_HANDLE_TABLE_ENTRY_SIZE;
        bytes[entry..entry + 2].copy_from_slice(&(handle.process_id as u16).to_le_bytes());
        bytes[entry + 2..entry + 4].copy_from_slice(&0_u16.to_le_bytes()); // CreatorBackTraceIndex
        bytes[entry + 4] = handle.object_type_index;
        bytes[entry + 5] = 0; // HandleAttributes
        bytes[entry + 6..entry + 8].copy_from_slice(&(handle.handle as u16).to_le_bytes());
        bytes[entry + 8..entry + 16].copy_from_slice(&handle.object.to_le_bytes());
        bytes[entry + 16..entry + 20].copy_from_slice(&handle.access.to_le_bytes());
    }
    bytes
}

/// `SYSTEM_HANDLE_INFORMATION_EX` (x64): two `ULONG_PTR` then 40-byte entries.
pub fn serialize_extended_handle_information(handles: &[KernelHandle]) -> Vec<u8> {
    let count = handles.len();
    let mut bytes = vec![0_u8; 16 + SYSTEM_HANDLE_TABLE_ENTRY_EX_SIZE * count];
    bytes[0..8].copy_from_slice(&(count as u64).to_le_bytes());
    for (index, handle) in handles.iter().enumerate() {
        let entry = 16 + index * SYSTEM_HANDLE_TABLE_ENTRY_EX_SIZE;
        bytes[entry..entry + 8].copy_from_slice(&handle.object.to_le_bytes());
        bytes[entry + 8..entry + 16].copy_from_slice(&u64::from(handle.process_id).to_le_bytes());
        bytes[entry + 16..entry + 24].copy_from_slice(&u64::from(handle.handle).to_le_bytes());
        bytes[entry + 24..entry + 28].copy_from_slice(&handle.access.to_le_bytes());
        bytes[entry + 28..entry + 30].copy_from_slice(&0_u16.to_le_bytes()); // CreatorBackTraceIndex
        bytes[entry + 30..entry + 32]
            .copy_from_slice(&u16::from(handle.object_type_index).to_le_bytes());
        bytes[entry + 32..entry + 36].copy_from_slice(&0_u32.to_le_bytes()); // HandleAttributes
        bytes[entry + 36..entry + 40].copy_from_slice(&handle.handle_count.to_le_bytes());
    }
    bytes
}

/// `SYSTEM_PROCESS_INFORMATION` for every process (x64), with each process's
/// thread array inline and its `ImageName` UNICODE_STRING pointing into the
/// same buffer at `buffer_address`.
pub fn serialize_process_information(processes: &[KernelProcess], buffer_address: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let count = processes.len();
    for (index, process) in processes.iter().enumerate() {
        let entry_start = bytes.len();
        let name: Vec<u8> = process
            .image_name
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let fixed = SYSTEM_PROCESS_INFORMATION_FIXED_SIZE;
        let threads_size = SYSTEM_THREAD_INFORMATION_SIZE * process.threads.len();
        let name_offset = fixed + threads_size;
        let entry_size = name_offset + name.len();
        bytes.resize(entry_start + entry_size, 0);
        let entry = &mut bytes[entry_start..];
        let next = if index + 1 < count {
            align8(entry_size) as u32
        } else {
            0
        };
        entry[0..4].copy_from_slice(&next.to_le_bytes());
        entry[4..8].copy_from_slice(&(process.threads.len() as u32).to_le_bytes());
        entry[0x20..0x28].copy_from_slice(&process.create_time.to_le_bytes());
        entry[0x28..0x30].copy_from_slice(&process.user_time.to_le_bytes());
        entry[0x30..0x38].copy_from_slice(&process.kernel_time.to_le_bytes());
        // UNICODE_STRING ImageName.
        entry[0x38..0x3A].copy_from_slice(&(name.len() as u16).to_le_bytes());
        entry[0x3A..0x3C].copy_from_slice(&(name.len() as u16).to_le_bytes());
        let buffer_ptr = buffer_address
            .wrapping_add(entry_start as u64)
            .wrapping_add(name_offset as u64);
        entry[0x40..0x48].copy_from_slice(&buffer_ptr.to_le_bytes());
        entry[0x48..0x4C].copy_from_slice(&process.base_priority.to_le_bytes());
        entry[0x50..0x58].copy_from_slice(&u64::from(process.pid).to_le_bytes());
        entry[0x58..0x60].copy_from_slice(&u64::from(process.parent_pid).to_le_bytes());
        entry[0x60..0x64].copy_from_slice(&process.handle_count.to_le_bytes());
        entry[0x64..0x68].copy_from_slice(&process.session_id.to_le_bytes());
        entry[0x70..0x78].copy_from_slice(&process.peak_virtual_size.to_le_bytes());
        entry[0x78..0x80].copy_from_slice(&process.virtual_size.to_le_bytes());
        entry[0x80..0x84].copy_from_slice(&process.page_fault_count.to_le_bytes());
        entry[0x88..0x90].copy_from_slice(&process.peak_working_set.to_le_bytes());
        entry[0x90..0x98].copy_from_slice(&process.working_set.to_le_bytes());
        for (thread_index, thread) in process.threads.iter().enumerate() {
            let base = fixed + thread_index * SYSTEM_THREAD_INFORMATION_SIZE;
            entry[base..base + 8].copy_from_slice(&thread.kernel_time.to_le_bytes());
            entry[base + 8..base + 16].copy_from_slice(&thread.user_time.to_le_bytes());
            entry[base + 16..base + 24].copy_from_slice(&thread.create_time.to_le_bytes());
            entry[base + 24..base + 28].copy_from_slice(&thread.wait_time.to_le_bytes());
            entry[base + 32..base + 40].copy_from_slice(&thread.start_address.to_le_bytes());
            entry[base + 40..base + 48].copy_from_slice(&u64::from(process.pid).to_le_bytes());
            entry[base + 48..base + 56].copy_from_slice(&u64::from(thread.thread_id).to_le_bytes());
            entry[base + 56..base + 60].copy_from_slice(&thread.priority.to_le_bytes());
            entry[base + 60..base + 64].copy_from_slice(&thread.base_priority.to_le_bytes());
            entry[base + 64..base + 68].copy_from_slice(&thread.context_switches.to_le_bytes());
            entry[base + 68..base + 72].copy_from_slice(&thread.state.to_le_bytes());
            entry[base + 72..base + 76].copy_from_slice(&thread.wait_reason.to_le_bytes());
        }
        entry[name_offset..name_offset + name.len()].copy_from_slice(&name);
    }
    bytes
}

/// `SystemExtendedProcessInformation` (x64): the same process array as
/// `SystemProcessInformation`, but every thread record is a
/// `SYSTEM_EXTENDED_THREAD_INFORMATION` carrying the real stack bounds,
/// Win32 start address and TEB base from the guest thread table.
///
/// Returns `None` when a required field is not backed by real state (a zero
/// stack base/limit or TEB base) — the dispatcher then refuses the query with
/// [`STATUS_NOT_SUPPORTED`] instead of inventing values.
pub fn serialize_extended_process_information(
    processes: &[KernelProcess],
    buffer_address: u64,
) -> Option<Vec<u8>> {
    if processes.iter().any(|process| {
        process
            .threads
            .iter()
            .any(|thread| thread.stack_base == 0 || thread.stack_limit == 0 || thread.teb_base == 0)
    }) {
        return None;
    }
    let mut bytes = Vec::new();
    let count = processes.len();
    for (index, process) in processes.iter().enumerate() {
        let entry_start = bytes.len();
        let name: Vec<u8> = process
            .image_name
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let fixed = SYSTEM_PROCESS_INFORMATION_FIXED_SIZE;
        let threads_size = SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE * process.threads.len();
        let name_offset = fixed + threads_size;
        let entry_size = name_offset + name.len();
        bytes.resize(entry_start + entry_size, 0);
        let entry = &mut bytes[entry_start..];
        let next = if index + 1 < count {
            align8(entry_size) as u32
        } else {
            0
        };
        entry[0..4].copy_from_slice(&next.to_le_bytes());
        entry[4..8].copy_from_slice(&(process.threads.len() as u32).to_le_bytes());
        entry[0x20..0x28].copy_from_slice(&process.create_time.to_le_bytes());
        entry[0x28..0x30].copy_from_slice(&process.user_time.to_le_bytes());
        entry[0x30..0x38].copy_from_slice(&process.kernel_time.to_le_bytes());
        entry[0x38..0x3A].copy_from_slice(&(name.len() as u16).to_le_bytes());
        entry[0x3A..0x3C].copy_from_slice(&(name.len() as u16).to_le_bytes());
        let buffer_ptr = buffer_address
            .wrapping_add(entry_start as u64)
            .wrapping_add(name_offset as u64);
        entry[0x40..0x48].copy_from_slice(&buffer_ptr.to_le_bytes());
        entry[0x48..0x4C].copy_from_slice(&process.base_priority.to_le_bytes());
        entry[0x50..0x58].copy_from_slice(&u64::from(process.pid).to_le_bytes());
        entry[0x58..0x60].copy_from_slice(&u64::from(process.parent_pid).to_le_bytes());
        entry[0x60..0x64].copy_from_slice(&process.handle_count.to_le_bytes());
        entry[0x64..0x68].copy_from_slice(&process.session_id.to_le_bytes());
        entry[0x70..0x78].copy_from_slice(&process.peak_virtual_size.to_le_bytes());
        entry[0x78..0x80].copy_from_slice(&process.virtual_size.to_le_bytes());
        entry[0x80..0x84].copy_from_slice(&process.page_fault_count.to_le_bytes());
        entry[0x88..0x90].copy_from_slice(&process.peak_working_set.to_le_bytes());
        entry[0x90..0x98].copy_from_slice(&process.working_set.to_le_bytes());
        for (thread_index, thread) in process.threads.iter().enumerate() {
            let base = fixed + thread_index * SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE;
            entry[base..base + 8].copy_from_slice(&thread.kernel_time.to_le_bytes());
            entry[base + 8..base + 16].copy_from_slice(&thread.user_time.to_le_bytes());
            entry[base + 16..base + 24].copy_from_slice(&thread.create_time.to_le_bytes());
            entry[base + 24..base + 28].copy_from_slice(&thread.wait_time.to_le_bytes());
            entry[base + 32..base + 40].copy_from_slice(&thread.start_address.to_le_bytes());
            entry[base + 40..base + 48].copy_from_slice(&u64::from(process.pid).to_le_bytes());
            entry[base + 48..base + 56].copy_from_slice(&u64::from(thread.thread_id).to_le_bytes());
            entry[base + 56..base + 60].copy_from_slice(&thread.priority.to_le_bytes());
            entry[base + 60..base + 64].copy_from_slice(&thread.base_priority.to_le_bytes());
            entry[base + 64..base + 68].copy_from_slice(&thread.context_switches.to_le_bytes());
            entry[base + 68..base + 72].copy_from_slice(&thread.state.to_le_bytes());
            entry[base + 72..base + 76].copy_from_slice(&thread.wait_reason.to_le_bytes());
            // SYSTEM_EXTENDED_THREAD_INFORMATION tail.
            entry[base + 0x50..base + 0x58].copy_from_slice(&thread.stack_base.to_le_bytes());
            entry[base + 0x58..base + 0x60].copy_from_slice(&thread.stack_limit.to_le_bytes());
            entry[base + 0x60..base + 0x68]
                .copy_from_slice(&thread.win32_start_address.to_le_bytes());
            entry[base + 0x68..base + 0x70].copy_from_slice(&thread.teb_base.to_le_bytes());
        }
        entry[name_offset..name_offset + name.len()].copy_from_slice(&name);
    }
    Some(bytes)
}

/// `SystemExtendedProcessInformation` (x86): the real 32-bit
/// `SYSTEM_PROCESS_INFORMATION` array whose thread records are
/// `SYSTEM_EXTENDED_THREAD_INFORMATION`.
///
/// The x86 layout is NOT the x64 layout with truncated pointers: the fixed
/// process record is `0xB8` bytes, the plain thread record is `0x40` bytes and
/// the extended record is `0x60` bytes (8-aligned).  The same real stack
/// bounds, Win32 start address and TEB base back the extended tail.  Returns
/// `None` when a required field is unbacked, so the dispatcher can report
/// `STATUS_NOT_SUPPORTED` instead of zeroing.
pub fn serialize_extended_process_information_x86(
    processes: &[KernelProcess],
    buffer_address: u64,
) -> Option<Vec<u8>> {
    if processes.iter().any(|process| {
        process
            .threads
            .iter()
            .any(|thread| thread.stack_base == 0 || thread.stack_limit == 0 || thread.teb_base == 0)
    }) {
        return None;
    }
    let mut bytes = Vec::new();
    let count = processes.len();
    for (index, process) in processes.iter().enumerate() {
        let entry_start = bytes.len();
        let name: Vec<u8> = process
            .image_name
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let fixed = SYSTEM_PROCESS_INFORMATION_FIXED_SIZE_X86;
        let threads_size = SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE_X86 * process.threads.len();
        let name_offset = fixed + threads_size;
        let entry_size = name_offset + name.len();
        bytes.resize(entry_start + entry_size, 0);
        let entry = &mut bytes[entry_start..];
        let next = if index + 1 < count {
            align8(entry_size) as u32
        } else {
            0
        };
        entry[0..4].copy_from_slice(&next.to_le_bytes());
        entry[4..8].copy_from_slice(&(process.threads.len() as u32).to_le_bytes());
        entry[0x20..0x28].copy_from_slice(&process.create_time.to_le_bytes());
        entry[0x28..0x30].copy_from_slice(&process.user_time.to_le_bytes());
        entry[0x30..0x38].copy_from_slice(&process.kernel_time.to_le_bytes());
        // UNICODE_STRING ImageName (x86: Length, MaximumLength, Buffer).
        entry[0x38..0x3A].copy_from_slice(&(name.len() as u16).to_le_bytes());
        entry[0x3A..0x3C].copy_from_slice(&(name.len() as u16).to_le_bytes());
        let buffer_ptr = buffer_address
            .wrapping_add(entry_start as u64)
            .wrapping_add(name_offset as u64) as u32;
        entry[0x3C..0x40].copy_from_slice(&buffer_ptr.to_le_bytes());
        entry[0x40..0x44].copy_from_slice(&process.base_priority.to_le_bytes());
        entry[0x44..0x48].copy_from_slice(&process.pid.to_le_bytes());
        entry[0x48..0x4C].copy_from_slice(&process.parent_pid.to_le_bytes());
        entry[0x4C..0x50].copy_from_slice(&process.handle_count.to_le_bytes());
        entry[0x50..0x54].copy_from_slice(&process.session_id.to_le_bytes());
        entry[0x58..0x5C].copy_from_slice(
            &(process.peak_virtual_size.min(u64::from(u32::MAX)) as u32).to_le_bytes(),
        );
        entry[0x5C..0x60]
            .copy_from_slice(&(process.virtual_size.min(u64::from(u32::MAX)) as u32).to_le_bytes());
        entry[0x60..0x64].copy_from_slice(&process.page_fault_count.to_le_bytes());
        entry[0x64..0x68].copy_from_slice(
            &(process.peak_working_set.min(u64::from(u32::MAX)) as u32).to_le_bytes(),
        );
        entry[0x68..0x6C]
            .copy_from_slice(&(process.working_set.min(u64::from(u32::MAX)) as u32).to_le_bytes());
        for (thread_index, thread) in process.threads.iter().enumerate() {
            let base = fixed + thread_index * SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE_X86;
            entry[base..base + 8].copy_from_slice(&thread.kernel_time.to_le_bytes());
            entry[base + 8..base + 16].copy_from_slice(&thread.user_time.to_le_bytes());
            entry[base + 16..base + 24].copy_from_slice(&thread.create_time.to_le_bytes());
            entry[base + 24..base + 28].copy_from_slice(&thread.wait_time.to_le_bytes());
            entry[base + 28..base + 32]
                .copy_from_slice(&(thread.start_address as u32).to_le_bytes());
            // CLIENT_ID: UniqueProcess, UniqueThread.
            entry[base + 32..base + 36].copy_from_slice(&process.pid.to_le_bytes());
            entry[base + 36..base + 40].copy_from_slice(&thread.thread_id.to_le_bytes());
            entry[base + 40..base + 44].copy_from_slice(&thread.priority.to_le_bytes());
            entry[base + 44..base + 48].copy_from_slice(&thread.base_priority.to_le_bytes());
            entry[base + 48..base + 52].copy_from_slice(&thread.context_switches.to_le_bytes());
            entry[base + 52..base + 56].copy_from_slice(&thread.state.to_le_bytes());
            entry[base + 56..base + 60].copy_from_slice(&thread.wait_reason.to_le_bytes());
            // SYSTEM_EXTENDED_THREAD_INFORMATION tail.
            entry[base + 0x40..base + 0x44]
                .copy_from_slice(&(thread.stack_base as u32).to_le_bytes());
            entry[base + 0x44..base + 0x48]
                .copy_from_slice(&(thread.stack_limit as u32).to_le_bytes());
            entry[base + 0x48..base + 0x4C]
                .copy_from_slice(&(thread.win32_start_address as u32).to_le_bytes());
            entry[base + 0x4C..base + 0x50]
                .copy_from_slice(&(thread.teb_base as u32).to_le_bytes());
        }
        entry[name_offset..name_offset + name.len()].copy_from_slice(&name);
    }
    Some(bytes)
}

/// `SYSTEM_PAGEFILE_INFORMATION`: a single-entry linked list with the real
/// page-file facts and an inline `PageFileName`.
pub fn serialize_pagefile_information(
    page_file_path: &str,
    total: u32,
    in_use: u32,
    peak: u32,
) -> Vec<u8> {
    let name: Vec<u8> = page_file_path
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    let mut bytes = vec![0_u8; 18 + name.len()];
    bytes[0..4].copy_from_slice(&0_u32.to_le_bytes()); // NextEntryOffset (single entry)
    bytes[4..8].copy_from_slice(&total.to_le_bytes());
    bytes[8..12].copy_from_slice(&in_use.to_le_bytes());
    bytes[12..16].copy_from_slice(&peak.to_le_bytes());
    bytes[16..18].copy_from_slice(&(name.len() as u16).to_le_bytes());
    bytes[18..18 + name.len()].copy_from_slice(&name);
    bytes
}

/// `SYSTEM_KERNEL_DEBUGGER_INFORMATION`: two BOOLEANs (truthful).
pub fn serialize_kernel_debugger_information(enabled: bool, not_present: bool) -> Vec<u8> {
    vec![u8::from(enabled), u8::from(not_present)]
}

/// `SYSTEM_CODE_INTEGRITY_INFORMATION`: `Length` then the options word.
pub fn serialize_code_integrity_information(options: u32) -> Vec<u8> {
    let mut bytes = vec![0_u8; 8];
    bytes[0..4].copy_from_slice(&8_u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&options.to_le_bytes());
    bytes
}

/// `SYSTEM_RANGE_START_INFORMATION`: a single `PVOID`.
pub fn serialize_range_start_information(range_start: u64) -> Vec<u8> {
    range_start.to_le_bytes().to_vec()
}

/// `SYSTEM_LOOKASIDE_INFORMATION`: the first lookaside row (or a zeroed one).
pub fn serialize_lookaside_information(lookaside: Option<&KernelLookaside>) -> Vec<u8> {
    let mut bytes = vec![0_u8; 40];
    if let Some(row) = lookaside {
        bytes[0..4].copy_from_slice(&row.current_depth.to_le_bytes());
        bytes[4..8].copy_from_slice(&row.maximum_depth.to_le_bytes());
        bytes[8..12].copy_from_slice(&row.total_allocates.to_le_bytes());
        bytes[12..16].copy_from_slice(&row.allocate_misses.to_le_bytes());
        bytes[16..20].copy_from_slice(&row.total_frees.to_le_bytes());
        bytes[20..24].copy_from_slice(&row.free_misses.to_le_bytes());
        bytes[28..32].copy_from_slice(&row.tag.bytes());
        bytes[32..36].copy_from_slice(&row.size.to_le_bytes());
    }
    bytes
}

/// `SYSTEM_BIGPOOL_INFORMATION`: `Count` then 32-byte big-pool entries, one
/// per tagged-pool row (pool bytes rounded up to the allocation granularity).
pub fn serialize_bigpool_information(tags: &[KernelPoolTag]) -> Vec<u8> {
    let count = tags.len();
    let mut bytes = vec![0_u8; 8 + 32 * count];
    bytes[0..4].copy_from_slice(&(count as u32).to_le_bytes());
    for (index, row) in tags.iter().enumerate() {
        let entry = 8 + index * 32;
        // `AllocatedVa` / `AllocatedBlink` stay zero: the introspection layer
        // never invents a pool virtual address it has not observed.
        bytes[entry + 16..entry + 24].copy_from_slice(&row.used_bytes.to_le_bytes());
        let mut tag = [0_u8; 8];
        tag[..4].copy_from_slice(&row.tag.bytes());
        bytes[entry + 24..entry + 32].copy_from_slice(&tag);
    }
    bytes
}

/// `SYSTEM_FIRMWARE_TABLE_INFORMATION`: the caller's `(provider, table_id)`
/// echoed back followed by the truthful table payload.
pub fn serialize_firmware_table_information(provider: u32, table_id: u32, table: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 12 + table.len()];
    bytes[0..4].copy_from_slice(&provider.to_le_bytes());
    bytes[4..8].copy_from_slice(&table_id.to_le_bytes());
    bytes[8..12].copy_from_slice(&(table.len() as u32).to_le_bytes());
    bytes[12..12 + table.len()].copy_from_slice(table);
    bytes
}

/// `SYSTEM_PERFORMANCE_INFORMATION` (x64, 0x138 bytes): memory / pool / I/O
/// counters, all derived from the real pool accounting (unbacked counters are
/// truthful zeros, never invented activity).
pub fn serialize_performance_information(snapshot: &KernelSnapshot) -> Vec<u8> {
    let mut bytes = vec![0_u8; SYSTEM_PERFORMANCE_INFORMATION_SIZE];
    let page_size = 4096_u64;
    let available_pages = (snapshot.installed_memory_bytes / page_size).min(u32::MAX as u64) as u32;
    let committed_pages = (snapshot.pool_used_bytes / page_size).min(u32::MAX as u64) as u32;
    let commit_limit = (snapshot.pool_budget_bytes / page_size).min(u32::MAX as u64) as u32;
    bytes[0x2C..0x30].copy_from_slice(&available_pages.to_le_bytes());
    bytes[0x30..0x34].copy_from_slice(&committed_pages.to_le_bytes());
    bytes[0x34..0x38].copy_from_slice(&commit_limit.to_le_bytes());
    bytes[0x38..0x3C].copy_from_slice(&committed_pages.to_le_bytes());
    let paged_pages = (snapshot.pool_used_bytes)
        .div_ceil(page_size)
        .min(u32::MAX as u64) as u32;
    bytes[0x70..0x74].copy_from_slice(&paged_pages.to_le_bytes());
    bytes[0x78..0x7C].copy_from_slice(
        &(snapshot
            .pool_tags
            .iter()
            .map(|t| t.allocations)
            .sum::<u64>() as u32)
            .to_le_bytes(),
    );
    bytes[0x7C..0x80].copy_from_slice(
        &(snapshot.pool_tags.iter().map(|t| t.frees).sum::<u64>() as u32).to_le_bytes(),
    );
    bytes
}

/// x64 `SYSTEM_PERFORMANCE_INFORMATION` size.
pub const SYSTEM_PERFORMANCE_INFORMATION_SIZE: usize = 0x138;

fn align8(value: usize) -> usize {
    (value + 7) & !7
}

/// Serialize one `SYSTEM_INFORMATION_CLASS`.  `length` is the caller's buffer
/// size; `buffer_address` is the guest address of that buffer (needed for the
/// process class's inline `UNICODE_STRING.ImageName` buffer pointer).
pub fn serialize_system_information(
    class: u32,
    snapshot: &KernelSnapshot,
    length: u64,
    buffer_address: u64,
) -> SysInfoSerialized {
    let bytes = match class {
        SYSTEM_MODULE_INFORMATION_CLASS => serialize_module_information(&snapshot.modules),
        SYSTEM_HANDLE_INFORMATION_CLASS => serialize_handle_information(&snapshot.handles),
        SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS => {
            serialize_extended_handle_information(&snapshot.handles)
        }
        SYSTEM_PROCESS_INFORMATION_CLASS => {
            serialize_process_information(&snapshot.processes, buffer_address)
        }
        SYSTEM_EXTENDED_PROCESS_INFORMATION_CLASS => {
            let Some(bytes) =
                serialize_extended_process_information(&snapshot.processes, buffer_address)
            else {
                return SysInfoSerialized {
                    status: STATUS_NOT_SUPPORTED,
                    required: 0,
                    bytes: Vec::new(),
                };
            };
            bytes
        }
        SYSTEM_PAGEFILE_INFORMATION_CLASS => serialize_pagefile_information(
            &snapshot.page_file_path,
            snapshot.page_file_total_pages,
            snapshot.page_file_in_use_pages,
            snapshot.page_file_peak_pages,
        ),
        SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS => serialize_kernel_debugger_information(
            snapshot.debugger_enabled,
            !snapshot.debugger_present,
        ),
        SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS => {
            serialize_code_integrity_information(snapshot.code_integrity_options)
        }
        SYSTEM_RANGE_START_INFORMATION_CLASS => {
            serialize_range_start_information(snapshot.range_start)
        }
        SYSTEM_LOOKASIDE_INFORMATION_CLASS => {
            serialize_lookaside_information(snapshot.lookaside.first())
        }
        SYSTEM_BIGPOOL_INFORMATION_CLASS => serialize_bigpool_information(&snapshot.pool_tags),
        SYSTEM_FIRMWARE_TABLE_INFORMATION_CLASS => serialize_firmware_table_information(
            snapshot.firmware_provider,
            snapshot.firmware_table_id,
            &snapshot.firmware_table,
        ),
        SYSTEM_PERFORMANCE_INFORMATION_CLASS => serialize_performance_information(snapshot),
        _ => return SysInfoSerialized::invalid_class(),
    };
    if length < bytes.len() as u64 {
        SysInfoSerialized::mismatch(bytes.len() as u64)
    } else {
        SysInfoSerialized::success(bytes)
    }
}

/// The NT kernel object type indices (the `SystemHandleInformation`
/// `ObjectTypeIndex` numbering) for the Win32 subsystem's object kinds.
pub fn object_type_index(object_type: crate::win32::ObjectType) -> u8 {
    use crate::win32::ObjectType as Ot;
    match object_type {
        Ot::Process => 7,
        Ot::Thread => 8,
        Ot::Event => 2,
        Ot::Mutex => 1,
        Ot::Semaphore => 0,
        Ot::Section => 4,
        Ot::Key => 5,
        Ot::File | Ot::Pipe | Ot::DirectorySearch | Ot::Socket => 3,
        Ot::Timer => 6,
        Ot::IoCompletionPort => 9,
        Ot::WindowStation => 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG_ONE: PoolTag = PoolTag::new(b"Kasa");
    const ALL_CLASSES: [u32; 13] = [
        SYSTEM_MODULE_INFORMATION_CLASS,
        SYSTEM_HANDLE_INFORMATION_CLASS,
        SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS,
        SYSTEM_PROCESS_INFORMATION_CLASS,
        SYSTEM_EXTENDED_PROCESS_INFORMATION_CLASS,
        SYSTEM_PAGEFILE_INFORMATION_CLASS,
        SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS,
        SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS,
        SYSTEM_RANGE_START_INFORMATION_CLASS,
        SYSTEM_LOOKASIDE_INFORMATION_CLASS,
        SYSTEM_BIGPOOL_INFORMATION_CLASS,
        SYSTEM_FIRMWARE_TABLE_INFORMATION_CLASS,
        SYSTEM_PERFORMANCE_INFORMATION_CLASS,
    ];

    fn module(base: u64, size: u32, path: &str, load_count: u16) -> KernelModule {
        KernelModule {
            base,
            size,
            path: path.to_string(),
            load_count,
            entry_rva: 0x1000,
            kernel_mode: false,
        }
    }

    fn thread(id: u32) -> KernelThread {
        KernelThread {
            thread_id: id,
            create_time: 1,
            user_time: 2,
            kernel_time: 3,
            start_address: 0x1000,
            win32_start_address: 0x1000,
            priority: 8,
            base_priority: 8,
            context_switches: 1,
            state: 5,
            wait_reason: 0,
            wait_time: 0,
            teb_base: 0x7FFD_0000,
            stack_base: 0x1000_0000,
            stack_limit: 0x0FFF_0000,
        }
    }

    fn process(pid: u32, threads: Vec<KernelThread>) -> KernelProcess {
        KernelProcess {
            pid,
            parent_pid: 0,
            image_name: "game.exe".to_string(),
            base_priority: 8,
            handle_count: 2,
            session_id: 1,
            create_time: 10,
            user_time: 20,
            kernel_time: 30,
            virtual_size: 0x1000,
            peak_virtual_size: 0x2000,
            working_set: 0x3000,
            peak_working_set: 0x4000,
            page_fault_count: 7,
            threads,
        }
    }

    fn snap() -> KernelSnapshot {
        KernelSnapshot {
            processor_count: 8,
            active_processor_mask: 0xFF,
            system_time: 100,
            boot_time: 50,
            range_start: 0xFFFF_8000_0000_0000,
            modules: vec![
                module(0x1_4000_0000, 0x1000, r"C:\Windows\System32\ntdll.dll", 1),
                module(0x1_4001_0000, 0x2000, r"C:\Game\game.exe", 2),
            ],
            processes: vec![process(100, vec![thread(101), thread(102)])],
            handles: vec![KernelHandle {
                handle: 4,
                object: 0xFFFF_8000_0000_1000,
                process_id: 100,
                access: 0x001F_0003,
                object_type_index: 2,
                pointer_count: 1,
                handle_count: 1,
            }],
            pool_tags: vec![KernelPoolTag {
                tag: TAG_ONE,
                used_bytes: 4096,
                allocations: 3,
                frees: 1,
            }],
            pool_used_bytes: 4096,
            pool_budget_bytes: 0x10000,
            lookaside: vec![KernelLookaside {
                tag: TAG_ONE,
                current_depth: 2,
                maximum_depth: 4,
                total_allocates: 5,
                allocate_misses: 3,
                total_frees: 2,
                free_misses: 0,
                size: 32,
            }],
            debugger_present: false,
            debugger_enabled: false,
            code_integrity_options: 0,
            firmware_provider: 0x4143_5049,
            firmware_table_id: 7,
            firmware_table: vec![0xAA, 0xBB],
            page_file_path: r"C:\pagefile.sys".to_string(),
            page_file_total_pages: 0x40000,
            page_file_in_use_pages: 0x1000,
            page_file_peak_pages: 0x2000,
            installed_memory_bytes: 16 * 1024 * 1024 * 1024,
        }
    }

    #[test]
    fn invalid_information_class_is_status_invalid_info_class_not_a_fabricated_value() {
        let snapshot = snap();
        let result = serialize_system_information(0xDEAD, &snapshot, 4096, 0x1000);
        assert_eq!(result.status, STATUS_INVALID_INFO_CLASS);
        assert_eq!(result.required, 0);
        assert!(result.bytes.is_empty());
        // The class validator still recognizes the classes the surface backs.
        for class in ALL_CLASSES {
            assert_ne!(
                serialize_system_information(class, &snapshot, u64::MAX, 0x1000).status,
                STATUS_INVALID_INFO_CLASS,
                "class {class} must be backed"
            );
        }
    }

    #[test]
    fn every_class_rejects_a_buffer_one_byte_short_with_the_exact_required_length() {
        let snapshot = snap();
        for class in ALL_CLASSES {
            let full = serialize_system_information(class, &snapshot, u64::MAX, 0x1000);
            assert_eq!(full.status, STATUS_SUCCESS, "class {class}");
            assert_eq!(full.required, full.bytes.len() as u64, "class {class}");
            let short = serialize_system_information(class, &snapshot, full.required - 1, 0x1000);
            assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH, "class {class}");
            assert_eq!(short.required, full.required, "class {class}");
            assert!(short.bytes.is_empty(), "class {class}");
            let exact = serialize_system_information(class, &snapshot, full.required, 0x1000);
            assert_eq!(exact.status, STATUS_SUCCESS, "class {class}");
            assert_eq!(exact.bytes, full.bytes, "class {class}");
        }
    }

    #[test]
    fn module_information_truncates_a_maximum_path_and_keeps_the_base_and_size_exact() {
        let long = format!(r"C:\{}", "a".repeat(300));
        let modules = [
            module(0x1_4000_0000, 0x1234, &long, 5),
            module(0x7FFE_0000, 0x8000, r"C:\bare.dll", 1),
        ];
        let bytes = serialize_module_information(&modules);
        assert_eq!(bytes.len(), 8 + SYSTEM_MODULE_ENTRY_SIZE * 2);
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 2);
        assert_eq!(
            u64::from_le_bytes(bytes[8 + 16..8 + 24].try_into().unwrap()),
            0x1_4000_0000
        );
        assert_eq!(
            u32::from_le_bytes(bytes[8 + 24..8 + 28].try_into().unwrap()),
            0x1234
        );
        assert_eq!(
            u16::from_le_bytes(bytes[8 + 36..8 + 38].try_into().unwrap()),
            5,
            "LoadCount is the loader entry's real count"
        );
        let offset = u16::from_le_bytes(bytes[8 + 38..8 + 40].try_into().unwrap()) as usize;
        assert_eq!(
            offset, 43,
            "C:\\ prefix is 3 bytes past the FullPathName start"
        );
        // The over-long path is truncated to 255 bytes and NUL-terminated.
        assert_eq!(bytes[8 + 295], 0, "FullPathName is NUL-terminated");
        assert_eq!(modules[0].file_name(), "a".repeat(300));
        assert_eq!(modules[1].file_name(), "bare.dll");
        // A buffer shorter than one entry is a length mismatch, never a
        // partial write.
        let short =
            serialize_system_information(SYSTEM_MODULE_INFORMATION_CLASS, &snap(), 8, 0x1000);
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(short.required, (8 + SYSTEM_MODULE_ENTRY_SIZE * 2) as u64);
    }

    #[test]
    fn handle_information_rejects_a_short_buffer_and_entry_layout_is_exact() {
        let handles = [
            KernelHandle {
                handle: 0x1C,
                object: 0xFFFF_8000_0000_2000,
                process_id: 0x1234,
                access: 0x001F_0003,
                object_type_index: 2,
                pointer_count: 3,
                handle_count: 1,
            },
            KernelHandle {
                handle: 8,
                object: 0xFFFF_8000_0000_3000,
                process_id: 0x20,
                access: 0x0012_0089,
                object_type_index: 3,
                pointer_count: 1,
                handle_count: 2,
            },
        ];
        let basic = serialize_handle_information(&handles);
        assert_eq!(basic.len(), 8 + 24 * 2);
        assert_eq!(u32::from_le_bytes(basic[0..4].try_into().unwrap()), 2);
        assert_eq!(u16::from_le_bytes(basic[8..10].try_into().unwrap()), 0x1234);
        assert_eq!(basic[12], 2, "ObjectTypeIndex");
        assert_eq!(u16::from_le_bytes(basic[14..16].try_into().unwrap()), 0x1C);
        assert_eq!(
            u32::from_le_bytes(basic[24..28].try_into().unwrap()),
            0x001F_0003
        );
        assert_eq!(
            u64::from_le_bytes(basic[16..24].try_into().unwrap()),
            0xFFFF_8000_0000_2000,
            "the object identity is the kernel pointer slot"
        );
        let short =
            serialize_system_information(SYSTEM_HANDLE_INFORMATION_CLASS, &snap(), 8, 0x1000);
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(short.required, 8 + 24);
    }

    #[test]
    fn extended_handle_information_reports_pointer_counts_and_rejects_a_short_buffer() {
        let handles = [KernelHandle {
            handle: 0x1C,
            object: 0xFFFF_8000_0000_2000,
            process_id: 0x1234,
            access: 0x001F_0003,
            object_type_index: 2,
            pointer_count: 3,
            handle_count: 9,
        }];
        let extended = serialize_extended_handle_information(&handles);
        assert_eq!(extended.len(), 16 + 40);
        assert_eq!(u64::from_le_bytes(extended[0..8].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(extended[16..24].try_into().unwrap()),
            0xFFFF_8000_0000_2000
        );
        assert_eq!(
            u64::from_le_bytes(extended[32..40].try_into().unwrap()),
            0x1C
        );
        assert_eq!(
            u32::from_le_bytes(extended[52..56].try_into().unwrap()),
            9,
            "HandleCount carries the object's real live handle count"
        );
        let short = serialize_system_information(
            SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS,
            &snap(),
            16,
            0x1000,
        );
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(short.required, 16 + 40);
    }

    #[test]
    fn process_information_rejects_a_truncated_buffer_and_chains_entries_with_real_ids() {
        let processes = vec![process(100, vec![thread(101)]), process(200, vec![])];
        let buffer_address = 0x10_0000;
        let bytes = serialize_process_information(&processes, buffer_address);
        let first_next = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_ne!(first_next, 0, "first process chains to the next");
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(bytes[0x50..0x58].try_into().unwrap()),
            100
        );
        let name_len = u16::from_le_bytes(bytes[0x38..0x3A].try_into().unwrap());
        let name_ptr = u64::from_le_bytes(bytes[0x40..0x48].try_into().unwrap());
        assert_eq!(name_len, "game.exe".encode_utf16().count() as u16 * 2);
        assert!(
            name_ptr > buffer_address,
            "ImageName.Buffer points into the buffer"
        );
        let name_offset = (name_ptr - buffer_address) as usize;
        let wide: Vec<u16> = bytes[name_offset..name_offset + name_len as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&wide).unwrap(), "game.exe");
        assert_eq!(
            u64::from_le_bytes(bytes[0x100 + 48..0x100 + 56].try_into().unwrap()),
            101,
            "UniqueThread"
        );
        let second = first_next as usize;
        assert_eq!(
            u32::from_le_bytes(bytes[second..second + 4].try_into().unwrap()),
            0
        );
        assert_eq!(
            u64::from_le_bytes(bytes[second + 0x50..second + 0x58].try_into().unwrap()),
            200
        );
        let short =
            serialize_system_information(SYSTEM_PROCESS_INFORMATION_CLASS, &snap(), 0x100, 0x1000);
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert!(short.required > 0x100);
    }

    #[test]
    fn extended_process_information_rejects_unbacked_fields_and_short_buffers_exactly() {
        let processes = vec![process(100, vec![thread(101)]), process(200, vec![])];
        let buffer_address = 0x20_0000;
        let bytes = serialize_extended_process_information(&processes, buffer_address)
            .expect("stack and TEB fields are backed");
        let first_next = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(
            first_next as usize,
            align8(
                0x100
                    + SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE
                    + "game.exe".encode_utf16().count() * 2
            ),
            "the next-entry offset accounts for the extended thread record and name"
        );
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 1);
        assert_eq!(
            u64::from_le_bytes(bytes[0x100 + 0x50..0x100 + 0x58].try_into().unwrap()),
            0x1000_0000,
            "StackBase"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[0x100 + 0x58..0x100 + 0x60].try_into().unwrap()),
            0x0FFF_0000,
            "StackLimit"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[0x100 + 0x60..0x100 + 0x68].try_into().unwrap()),
            0x1000,
            "Win32StartAddress"
        );
        assert_eq!(
            u64::from_le_bytes(bytes[0x100 + 0x68..0x100 + 0x70].try_into().unwrap()),
            0x7FFD_0000,
            "TebBase"
        );
        let name_len = u16::from_le_bytes(bytes[0x38..0x3A].try_into().unwrap());
        let name_ptr = u64::from_le_bytes(bytes[0x40..0x48].try_into().unwrap());
        let name_offset = (name_ptr - buffer_address) as usize;
        assert_eq!(
            name_offset,
            0x100 + SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE,
            "ImageName starts after the extended thread array"
        );
        let wide: Vec<u16> = bytes[name_offset..name_offset + name_len as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(String::from_utf16(&wide).unwrap(), "game.exe");

        let full = serialize_system_information(
            SYSTEM_EXTENDED_PROCESS_INFORMATION_CLASS,
            &snap(),
            0x1_0000,
            0x1000,
        );
        assert_eq!(full.status, STATUS_SUCCESS);
        let short = serialize_system_information(
            SYSTEM_EXTENDED_PROCESS_INFORMATION_CLASS,
            &snap(),
            full.bytes.len() as u64 - 1,
            0x1000,
        );
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(short.required, full.bytes.len() as u64);

        let mut unbacked = process(300, vec![thread(301)]);
        unbacked.threads[0].stack_limit = 0;
        let refused = serialize_system_information(
            SYSTEM_EXTENDED_PROCESS_INFORMATION_CLASS,
            &KernelSnapshot {
                processes: vec![unbacked],
                ..snap()
            },
            0x1000,
            0x1000,
        );
        assert_eq!(refused.status, STATUS_NOT_SUPPORTED);
        assert_eq!(refused.required, 0);
        assert!(refused.bytes.is_empty());
        assert_eq!(
            serialize_extended_process_information(
                &[KernelProcess {
                    threads: vec![KernelThread {
                        teb_base: 0,
                        ..thread(302)
                    }],
                    ..process(301, Vec::new())
                }],
                0x1000
            ),
            None
        );
    }

    #[test]
    fn x86_extended_process_information_uses_the_real_32_bit_layout_and_rejects_invalid_unbacked_fields()
     {
        assert_eq!(SYSTEM_PROCESS_INFORMATION_FIXED_SIZE_X86, 0xB8);
        assert_eq!(SYSTEM_THREAD_INFORMATION_SIZE_X86, 0x40);
        assert_eq!(SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE_X86, 0x60);

        let processes = vec![process(100, vec![thread(101)]), process(200, vec![])];
        let buffer_address = 0x20_0000u64;
        let bytes = serialize_extended_process_information_x86(&processes, buffer_address)
            .expect("x86 stack and TEB fields are backed");
        let first_next = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(
            first_next as usize,
            align8(
                SYSTEM_PROCESS_INFORMATION_FIXED_SIZE_X86
                    + SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE_X86
                    + "game.exe".encode_utf16().count() * 2
            ),
            "the x86 next-entry offset accounts for the 0xB8/0x60 records"
        );
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(bytes[0x44..0x48].try_into().unwrap()),
            100,
            "UniqueProcessId is a 32-bit HANDLE at 0x44"
        );
        assert_eq!(
            u32::from_le_bytes(bytes[0x48..0x4C].try_into().unwrap()),
            0,
            "InheritedFromUniqueProcessId"
        );
        let name_len = u16::from_le_bytes(bytes[0x38..0x3A].try_into().unwrap());
        let name_ptr = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap());
        assert_eq!(
            name_ptr as u64,
            buffer_address
                + SYSTEM_PROCESS_INFORMATION_FIXED_SIZE_X86 as u64
                + SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE_X86 as u64,
            "the x86 ImageName.Buffer is the 32-bit in-buffer pointer"
        );
        let name_offset =
            SYSTEM_PROCESS_INFORMATION_FIXED_SIZE_X86 + SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE_X86;
        let wide: Vec<u16> = bytes[name_offset..name_offset + name_len as usize]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        assert_eq!(String::from_utf16(&wide).unwrap(), "game.exe");

        let thread_base = SYSTEM_PROCESS_INFORMATION_FIXED_SIZE_X86;
        assert_eq!(
            u32::from_le_bytes(
                bytes[thread_base + 0x24..thread_base + 0x28]
                    .try_into()
                    .unwrap()
            ),
            101,
            "UniqueThread at the x86 CLIENT_ID offset"
        );
        assert_eq!(
            u32::from_le_bytes(
                bytes[thread_base + 0x28..thread_base + 0x2C]
                    .try_into()
                    .unwrap()
            ),
            8,
            "Priority"
        );
        assert_eq!(
            u32::from_le_bytes(
                bytes[thread_base + 0x40..thread_base + 0x44]
                    .try_into()
                    .unwrap()
            ),
            0x1000_0000,
            "x86 StackBase"
        );
        assert_eq!(
            u32::from_le_bytes(
                bytes[thread_base + 0x44..thread_base + 0x48]
                    .try_into()
                    .unwrap()
            ),
            0x0FFF_0000,
            "x86 StackLimit"
        );
        assert_eq!(
            u32::from_le_bytes(
                bytes[thread_base + 0x48..thread_base + 0x4C]
                    .try_into()
                    .unwrap()
            ),
            0x1000,
            "x86 Win32StartAddress"
        );
        assert_eq!(
            u32::from_le_bytes(
                bytes[thread_base + 0x4C..thread_base + 0x50]
                    .try_into()
                    .unwrap()
            ),
            0x7FFD_0000,
            "x86 TebBase"
        );
        let second = first_next as usize;
        assert_eq!(
            u32::from_le_bytes(bytes[second..second + 4].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(bytes[second + 0x44..second + 0x48].try_into().unwrap()),
            200
        );

        let mut unbacked = process(300, vec![thread(301)]);
        unbacked.threads[0].stack_base = 0;
        assert_eq!(
            serialize_extended_process_information_x86(&[unbacked], buffer_address),
            None
        );
    }

    #[test]
    fn kernel_debugger_information_is_truthful_for_attached_and_detached_states() {
        // No debugger attached: enabled=false, not_present=true.
        assert_eq!(
            serialize_kernel_debugger_information(false, true),
            vec![0, 1]
        );
        // Debugger attached: enabled=true, not_present=false.
        assert_eq!(
            serialize_kernel_debugger_information(true, false),
            vec![1, 0]
        );
        let result =
            serialize_system_information(SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS, &snap(), 2, 0);
        assert_eq!(result.status, STATUS_SUCCESS);
        assert_eq!(result.bytes, vec![0, 1], "the live state has no debugger");
        let short =
            serialize_system_information(SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS, &snap(), 1, 0);
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(short.required, 2);
    }

    #[test]
    fn code_integrity_options_are_zero_and_a_short_buffer_is_rejected() {
        let integrity = serialize_code_integrity_information(0);
        assert_eq!(u32::from_le_bytes(integrity[0..4].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(integrity[4..8].try_into().unwrap()), 0);
        let result =
            serialize_system_information(SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS, &snap(), 8, 0);
        assert_eq!(result.status, STATUS_SUCCESS);
        assert_eq!(result.bytes, integrity);
        let short =
            serialize_system_information(SYSTEM_CODE_INTEGRITY_INFORMATION_CLASS, &snap(), 7, 0);
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(short.required, 8);
    }

    #[test]
    fn pagefile_information_rejects_a_short_buffer_and_names_the_file() {
        let pagefile = serialize_pagefile_information(r"C:\pagefile.sys", 0x40000, 0x1000, 0x2000);
        assert_eq!(u32::from_le_bytes(pagefile[0..4].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(pagefile[4..8].try_into().unwrap()),
            0x40000
        );
        assert_eq!(
            u32::from_le_bytes(pagefile[8..12].try_into().unwrap()),
            0x1000
        );
        assert_eq!(
            u32::from_le_bytes(pagefile[12..16].try_into().unwrap()),
            0x2000
        );
        let name_len = u16::from_le_bytes(pagefile[16..18].try_into().unwrap());
        assert_eq!(
            name_len,
            r"C:\pagefile.sys".encode_utf16().count() as u16 * 2
        );
        let short = serialize_system_information(SYSTEM_PAGEFILE_INFORMATION_CLASS, &snap(), 4, 0);
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert!(short.required > 4);
    }

    #[test]
    fn lookaside_information_is_a_zeroed_row_without_a_list_and_short_buffers_are_rejected() {
        let row = KernelLookaside {
            tag: TAG_ONE,
            current_depth: 1,
            maximum_depth: 4,
            total_allocates: 9,
            allocate_misses: 5,
            total_frees: 4,
            free_misses: 0,
            size: 48,
        };
        let bytes = serialize_lookaside_information(Some(&row));
        assert_eq!(bytes.len(), 40);
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 9);
        assert_eq!(&bytes[28..32], b"Kasa");
        assert_eq!(u32::from_le_bytes(bytes[32..36].try_into().unwrap()), 48);
        // No lookaside list is a zeroed row, never an invented one.
        assert_eq!(serialize_lookaside_information(None), vec![0_u8; 40]);
        let short =
            serialize_system_information(SYSTEM_LOOKASIDE_INFORMATION_CLASS, &snap(), 39, 0);
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(short.required, 40);
    }

    #[test]
    fn bigpool_information_reports_no_entries_without_a_tagged_pool_and_rejects_short_buffers() {
        let tags = [
            KernelPoolTag {
                tag: TAG_ONE,
                used_bytes: 0x2000,
                allocations: 4,
                frees: 2,
            },
            KernelPoolTag {
                tag: PoolTag::new(b"Kbdy"),
                used_bytes: 0,
                allocations: 1,
                frees: 1,
            },
        ];
        let pool = serialize_bigpool_information(&tags);
        assert_eq!(pool.len(), 8 + 32 * 2);
        assert_eq!(u32::from_le_bytes(pool[0..4].try_into().unwrap()), 2);
        assert_eq!(
            u64::from_le_bytes(pool[8 + 16..8 + 24].try_into().unwrap()),
            0x2000
        );
        assert_eq!(&pool[8 + 24..8 + 28], b"Kasa");
        // A zero-byte tag has no allocated virtual address.
        assert_eq!(
            u64::from_le_bytes(pool[8 + 32..8 + 40].try_into().unwrap()),
            0
        );
        // An empty tagged pool is an empty entry list, never stale rows.
        let empty = serialize_bigpool_information(&[]);
        assert_eq!(empty.len(), 8);
        assert_eq!(u32::from_le_bytes(empty[0..4].try_into().unwrap()), 0);
        let short = serialize_system_information(SYSTEM_BIGPOOL_INFORMATION_CLASS, &snap(), 7, 0);
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(short.required, 8 + 32);
    }

    #[test]
    fn performance_information_derives_counts_and_rejects_a_short_buffer() {
        let snapshot = snap();
        let bytes = serialize_performance_information(&snapshot);
        assert_eq!(bytes.len(), SYSTEM_PERFORMANCE_INFORMATION_SIZE);
        assert_eq!(
            u32::from_le_bytes(bytes[0x2C..0x30].try_into().unwrap()),
            (16 * 1024 * 1024 * 1024u64 / 4096) as u32
        );
        assert_eq!(u32::from_le_bytes(bytes[0x30..0x34].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(bytes[0x34..0x38].try_into().unwrap()),
            0x10
        );
        let result = serialize_system_information(
            SYSTEM_PERFORMANCE_INFORMATION_CLASS,
            &snapshot,
            u64::MAX,
            0,
        );
        assert_eq!(result.status, STATUS_SUCCESS);
        assert_eq!(result.required, SYSTEM_PERFORMANCE_INFORMATION_SIZE as u64);
        let short = serialize_system_information(
            SYSTEM_PERFORMANCE_INFORMATION_CLASS,
            &snapshot,
            (SYSTEM_PERFORMANCE_INFORMATION_SIZE - 1) as u64,
            0,
        );
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
    }

    #[test]
    fn firmware_table_information_echoes_the_query_and_rejects_a_short_buffer() {
        let bytes = serialize_firmware_table_information(0x4143_5049, 7, &[1, 2, 3, 4]);
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            0x4143_5049
        );
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 4);
        assert_eq!(&bytes[12..16], &[1, 2, 3, 4]);
        let short =
            serialize_system_information(SYSTEM_FIRMWARE_TABLE_INFORMATION_CLASS, &snap(), 11, 0);
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(short.required, 12 + 2);
    }

    #[test]
    fn empty_module_and_handle_lists_report_zero_counts_and_are_never_stale() {
        let modules = serialize_module_information(&[]);
        assert_eq!(modules.len(), 8);
        assert_eq!(u32::from_le_bytes(modules[0..4].try_into().unwrap()), 0);
        let handles = serialize_handle_information(&[]);
        assert_eq!(handles.len(), 8);
        assert_eq!(u32::from_le_bytes(handles[0..4].try_into().unwrap()), 0);
        let extended = serialize_extended_handle_information(&[]);
        assert_eq!(extended.len(), 16);
        assert_eq!(u64::from_le_bytes(extended[0..8].try_into().unwrap()), 0);
        assert!(serialize_process_information(&[], 0x1000).is_empty());
    }

    #[test]
    fn object_type_index_mismatch_for_the_file_family_is_intentional_and_distinct_elsewhere() {
        // The whole File family (file / pipe / socket / directory search)
        // shares the kernel File type index by design.
        assert_eq!(object_type_index(crate::win32::ObjectType::File), 3);
        assert_eq!(object_type_index(crate::win32::ObjectType::Pipe), 3);
        assert_eq!(object_type_index(crate::win32::ObjectType::Socket), 3);
        assert_eq!(
            object_type_index(crate::win32::ObjectType::DirectorySearch),
            3
        );
        // Every other kind is distinct and within the kernel type table.
        let distinct = [
            object_type_index(crate::win32::ObjectType::Semaphore),
            object_type_index(crate::win32::ObjectType::Mutex),
            object_type_index(crate::win32::ObjectType::Event),
            object_type_index(crate::win32::ObjectType::Section),
            object_type_index(crate::win32::ObjectType::Key),
            object_type_index(crate::win32::ObjectType::Timer),
            object_type_index(crate::win32::ObjectType::Process),
            object_type_index(crate::win32::ObjectType::Thread),
            object_type_index(crate::win32::ObjectType::IoCompletionPort),
            object_type_index(crate::win32::ObjectType::WindowStation),
        ];
        for index in distinct {
            assert!(index <= 10, "type index within the kernel table");
        }
        let mut unique = distinct.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            distinct.len(),
            "no two distinct kernel types may share an index"
        );
    }

    #[test]
    fn system_range_start_boundary_follows_the_architecture_split() {
        assert_eq!(system_range_start(true), 0xFFFF_8000_0000_0000);
        assert_eq!(system_range_start(false), 0x8000_0000);
        let range = serialize_range_start_information(system_range_start(true));
        assert_eq!(
            u64::from_le_bytes(range[..8].try_into().unwrap()),
            0xFFFF_8000_0000_0000
        );
        let short =
            serialize_system_information(SYSTEM_RANGE_START_INFORMATION_CLASS, &snap(), 7, 0);
        assert_eq!(short.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(short.required, 8);
    }

    #[test]
    fn assemble_modules_skips_duplicate_main_image_and_flags_kernel_drivers() {
        let mut names = std::collections::BTreeMap::new();
        names.insert(0x2000_u64, r"C:\Game\lib.dll".to_string());
        names.insert(0x3000_u64, r"C:\Windows\System32\driver.sys".to_string());
        let dlls = vec![
            (
                0x2000_u64,
                0x1000_u32,
                "stale.dll".to_string(),
                3_u16,
                0x10_u32,
            ),
            (
                0x2500_u64,
                0x800_u32,
                "fallback.dll".to_string(),
                1_u16,
                0_u32,
            ),
            (
                0x3000_u64,
                0x2000_u32,
                "nested.sys".to_string(),
                2_u16,
                0_u32,
            ),
            (0x1000_u64, 0x9999_u32, "dup.exe".to_string(), 1_u16, 0_u32),
        ];
        let modules = assemble_modules(
            0x1000,
            0x4000,
            r"C:\Game\game.exe",
            "game.exe",
            &dlls,
            &names,
        );
        assert_eq!(
            modules.len(),
            4,
            "main + 3 distinct DLLs (the duplicate is skipped)"
        );
        assert_eq!(modules[0].base, 0x1000);
        assert_eq!(modules[0].path, r"C:\Game\game.exe");
        assert!(!modules[0].kernel_mode);
        assert_eq!(
            modules[1].path, r"C:\Game\lib.dll",
            "name table wins over the stale entry"
        );
        assert_eq!(
            modules[2].path, "fallback.dll",
            "no name-table entry falls back"
        );
        assert!(modules[3].kernel_mode, ".sys images are kernel-mode");
        // An empty main path falls back to the main module name.
        let modules = assemble_modules(0x1000, 0x4000, "", "game.exe", &[], &names);
        assert_eq!(modules[0].path, "game.exe");
        // No mapped image: no main-module row.
        assert!(assemble_modules(0, 0, "", "game.exe", &[], &names).is_empty());
    }

    #[test]
    fn assemble_threads_boundary_suspended_and_runnable_wait_reasons_are_exact() {
        let pending = vec![
            (
                200_u32,
                0xABC_u64,
                0_u32,
                0x7FFD_1000_u64,
                0x2000_u64,
                0x1000_u64,
            ),
            (201, 0xDEF, 1, 0x7FFD_2000, 0x3000, 0x2000),
        ];
        let threads =
            assemble_threads((100, 0x7FFD_0000), (0x3000, 0x1000), &pending, [1, 2, 3, 4]);
        assert_eq!(threads.len(), 3);
        assert_eq!(threads[0].thread_id, 100);
        assert_eq!(threads[0].wait_reason, 0, "the main thread is runnable");
        assert_eq!(threads[0].stack_base, 0x3000);
        assert_eq!(threads[0].stack_limit, 0x1000);
        assert_eq!(threads[1].wait_reason, 0);
        assert_eq!(threads[2].wait_reason, 6, "suspended -> WrSuspended");
        assert_eq!(threads[2].stack_base, 0x3000);
        assert_eq!(threads[2].stack_limit, 0x2000);
        assert_eq!(threads[2].start_address, 0xDEF);
        assert_eq!(threads[0].create_time, 1);
        assert_eq!(threads[0].kernel_time, 3);
        assert_eq!(threads[0].user_time, 4);
    }

    #[test]
    fn assemble_processes_rejects_the_host_entry_and_zeroes_unknown_handles() {
        let threads = assemble_threads((100, 0x7FFD_0000), (0x3000, 0x1000), &[], [1, 2, 3, 4]);
        let toolhelp = vec![
            (std::process::id(), "macwin".to_string()),
            (100, "game.exe".to_string()),
            (200, "other.exe".to_string()),
        ];
        let processes = assemble_processes(
            100,
            std::process::id(),
            7,
            &threads,
            &toolhelp,
            [1, 2, 3, 4],
            0x2000,
        );
        assert_eq!(processes.len(), 2, "the host provenance entry is filtered");
        assert_eq!(processes[0].pid, 100);
        assert_eq!(
            processes[0].handle_count, 7,
            "self gets the real live count"
        );
        assert_eq!(processes[0].threads.len(), 1);
        assert_eq!(processes[1].pid, 200);
        assert_eq!(
            processes[1].handle_count, 0,
            "other processes have no observed handles"
        );
        assert!(processes[1].threads.is_empty());
    }
}
