//! Anti-cheat detection surface and genuine attestation.
//!
//! This module is the *real* anti-cheat / anti-debug / timing / attestation
//! surface.  Nothing here fabricates a trust verdict: every answer is derived
//! from live runtime state (a debugger-attach state machine, the host
//! monotonic counter, the canonical guest [`VirtualMemory`] and
//! [`crate::cpu::MemoryImage`], a real on-disk module file, or a real ECDSA
//! signature key).  When a real mechanism cannot decide (for example no
//! attestation provider is installed) it returns a documented failure instead
//! of a hard-coded success.
//!
//! Sections:
//! 1. Anti-debug surface — PEB `BeingDebugged` / `NtGlobalFlag`, the
//!    `NtQueryInformationProcess` debug classes, `NtQueryInformationThread` /
//!    `NtSetInformationThread` hide-from-debugger, `DebugActiveProcess` /
//!    `DebugActiveProcessStop`, debug-object creation, the hardware
//!    breakpoint registers `Dr0`-`Dr7`, exception dispatch whose outcome
//!    depends on the live debugger state, heap flags, and
//!    `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` reading that state.
//! 2. Timing surface — one monotonic source feeding `RDTSC` / `RDTSCP` /
//!    `QueryPerformanceCounter` / `QueryPerformanceFrequency` /
//!    `GetTickCount64` / `GetSystemTimePreciseAsFileTime`, with a *measured*
//!    counter frequency (invariant-TSC semantics: the value is global and
//!    identical on every thread).
//! 3. Memory integrity / scan surface — real module protections and image
//!    ranges from the canonical VM, real code hashes from guest memory and
//!    from Casa1's own on-disk modules, and
//!    `NtQueryVirtualMemory` / `NtProtectVirtualMemory` round-trips.
//! 4. Attestation — a persisted P-256 key pair, a signed quote over a real
//!    measurement of the Casa1 build, nonce challenge-response with replay
//!    protection, provider registration / revocation / expiry, and quote
//!    verification.  With no registered provider the verifier returns
//!    [`AttestationError::NoProvider`].

use crate::cpu::MemoryImage;
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::vm::{VirtualMemory, VmProtection, VmQueryResult, VmRegionKind, VmState};
use ecdsa::signature::{Signer, Verifier};
use p256::FieldBytes;
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

// ===========================================================================
// 1. Anti-debug surface
// ===========================================================================

/// `NtQueryInformationProcess` class selecting the process debug port.
pub const PROCESS_DEBUG_PORT: u32 = 7;
/// `NtQueryInformationProcess` class selecting the debug-object handle.
pub const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 30;
/// `NtQueryInformationProcess` class selecting the process debug flags.
pub const PROCESS_DEBUG_FLAGS: u32 = 31;
/// `NtQueryInformationThread` / `NtSetInformationThread` class hiding a
/// thread from an attached debugger.
pub const THREAD_HIDE_FROM_DEBUGGER: u32 = 17;

/// NTSTATUS: the requested information class is not handled.
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
/// NTSTATUS: the supplied buffer length does not match the class.
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
/// NTSTATUS: an argument (breakpoint slot/length/condition) is invalid.
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// `FLG_HEAP_ENABLE_TAIL_CHECK` — heap tail checking is on.
pub const FLG_HEAP_ENABLE_TAIL_CHECK: u32 = 0x0000_0010;
/// `FLG_HEAP_ENABLE_FREE_CHECK` — heap free checking is on.
pub const FLG_HEAP_ENABLE_FREE_CHECK: u32 = 0x0000_0020;
/// `FLG_HEAP_VALIDATE_PARAMETERS` — heap parameter validation is on.
pub const FLG_HEAP_VALIDATE_PARAMETERS: u32 = 0x0000_0040;

/// The `NtGlobalFlag` value a debuggee sees while a debugger is attached:
/// the three heap-debug bits Windows sets under a debugger.
pub const NT_GLOBAL_FLAG_DEBUG: u32 =
    FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;

/// `HEAP_GROWABLE` — always set on the process heap.
pub const HEAP_GROWABLE: u32 = 0x0000_0002;
/// `HEAP_TAIL_CHECKING_ENABLED` — heap tail checking is active.
pub const HEAP_TAIL_CHECKING_ENABLED: u32 = 0x0000_0020;
/// `HEAP_FREE_CHECKING_ENABLED` — heap free checking is active.
pub const HEAP_FREE_CHECKING_ENABLED: u32 = 0x0000_0040;

/// `DBG_CONTINUE` — the debugger handled the exception.
pub const DBG_CONTINUE: u32 = 0x0001_0002;
/// `DBG_EXCEPTION_NOT_HANDLED` — the debugger declines the exception.
pub const DBG_EXCEPTION_NOT_HANDLED: u32 = 0x8001_0001;

/// `EXCEPTION_BREAKPOINT` — the `int3` exception code.
pub const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;

/// Failure of a debugger attach / detach / thread operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugError {
    /// The requested process id is not the debuggee.
    ProcessNotFound,
    /// A debugger is already attached.
    AlreadyAttached,
    /// No debugger is attached.
    NotAttached,
    /// The referenced thread is not known to the surface.
    ThreadNotFound,
}

/// A debug object created by `DebugActiveProcess`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugObject {
    /// Handle handed to the debugger.
    pub handle: u64,
    /// Debuggee process id.
    pub process_id: u32,
}

/// Hardware breakpoint registers of one thread.
///
/// `dr0`-`dr3` hold the breakpoint addresses, `dr6` the debug-status bits and
/// `dr7` the control/enable bits.  Reading the context always reflects the
/// live register values — there is no separate "shadow" copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ThreadContext {
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

impl ThreadContext {
    /// The address programmed in breakpoint register `slot` (`0..=3`), or
    /// `None` when `slot` is out of range.
    pub fn breakpoint_address(&self, slot: u8) -> Option<u64> {
        match slot {
            0 => Some(self.dr0),
            1 => Some(self.dr1),
            2 => Some(self.dr2),
            3 => Some(self.dr3),
            _ => None,
        }
    }

    /// Whether breakpoint `slot` is locally enabled in `dr7` (`L0..L3`).
    pub fn breakpoint_enabled(&self, slot: u8) -> bool {
        slot <= 3 && (self.dr7 >> (slot as u32 * 2)) & 1 == 1
    }

    /// The `R/W` field (bits 0-1) of breakpoint `slot`'s nibble in `dr7`.
    pub fn breakpoint_condition(&self, slot: u8) -> Option<u8> {
        (slot <= 3).then(|| ((self.dr7 >> (16 + slot as u32 * 4)) & 0x3) as u8)
    }

    /// The `LEN` field (bits 2-3) of breakpoint `slot`'s nibble in `dr7`,
    /// returned as the encoded value Windows stores (not the byte length).
    pub fn breakpoint_length_code(&self, slot: u8) -> Option<u8> {
        (slot <= 3).then(|| ((self.dr7 >> (18 + slot as u32 * 4)) & 0x3) as u8)
    }
}

/// Where an exception ends up after dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExceptionDisposition {
    /// An attached debugger owns the exception.
    HandledByDebugger,
    /// The guest exception handlers own the exception.
    DeliveredToGuest,
    /// Nothing handled the exception; the process terminates.
    ProcessTerminated,
}

/// Live anti-debug state of one guest process.
///
/// Every flag is derived from [`AntiDebugSurface::attached`] and the
/// per-thread hidden set — there are no hard-coded "no debugger" answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiDebugSurface {
    /// Guest process id this surface describes.
    pub process_id: u32,
    attached: bool,
    debug_port: u64,
    debug_object: Option<DebugObject>,
    next_handle: u64,
    hidden_threads: BTreeSet<u32>,
    contexts: BTreeMap<u32, ThreadContext>,
    exception_dispatch_count: u64,
}

impl AntiDebugSurface {
    /// A surface for `process_id` with no debugger attached.
    pub fn new(process_id: u32) -> Self {
        Self {
            process_id,
            attached: false,
            debug_port: 0,
            debug_object: None,
            next_handle: 0x1_0000,
            hidden_threads: BTreeSet::new(),
            contexts: BTreeMap::new(),
            exception_dispatch_count: 0,
        }
    }

    /// Whether a debugger is attached (the PEB `BeingDebugged` source).
    pub fn is_debugger_present(&self) -> bool {
        self.attached
    }

    /// Whether a debugger is attached (remote-debugger source).
    pub fn check_remote_debugger_present(&self) -> bool {
        self.attached
    }

    /// The PEB `BeingDebugged` byte.
    pub fn being_debugged(&self) -> u8 {
        u8::from(self.attached)
    }

    /// The PEB `NtGlobalFlag` value implied by the current attach state.
    pub fn nt_global_flag(&self) -> u32 {
        if self.attached {
            NT_GLOBAL_FLAG_DEBUG
        } else {
            0
        }
    }

    /// The process heap flags implied by the current attach state.
    pub fn heap_flags(&self) -> u32 {
        let mut flags = HEAP_GROWABLE;
        let global = self.nt_global_flag();
        if global & FLG_HEAP_ENABLE_TAIL_CHECK != 0 {
            flags |= HEAP_TAIL_CHECKING_ENABLED;
        }
        if global & FLG_HEAP_ENABLE_FREE_CHECK != 0 {
            flags |= HEAP_FREE_CHECKING_ENABLED;
        }
        flags
    }

    /// The current debug-object handle, if any.
    pub fn debug_object(&self) -> Option<DebugObject> {
        self.debug_object
    }

    /// The debug port observed through `ProcessDebugPort`.
    pub fn debug_port(&self) -> u64 {
        self.debug_port
    }

    /// Number of exception dispatches performed.
    pub fn exception_dispatch_count(&self) -> u64 {
        self.exception_dispatch_count
    }

    /// Allocates a fresh debug-object handle.
    pub fn create_debug_object(&mut self) -> DebugObject {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(4);
        DebugObject {
            handle,
            process_id: self.process_id,
        }
    }

    /// `DebugActiveProcess`: attach a debugger to `pid`.
    ///
    /// Creates a debug object, sets the debug port to `(ULONG_PTR)-1` and
    /// flips `BeingDebugged`.  Rejects a wrong pid and a double attach.
    pub fn attach(&mut self, pid: u32) -> Result<DebugObject, DebugError> {
        if pid != self.process_id {
            return Err(DebugError::ProcessNotFound);
        }
        if self.attached {
            return Err(DebugError::AlreadyAttached);
        }
        let object = self.create_debug_object();
        self.debug_object = Some(object);
        self.debug_port = u64::MAX;
        self.attached = true;
        Ok(object)
    }

    /// `DebugActiveProcessStop`: detach from `pid`.
    ///
    /// Rejects a wrong pid and a detach while no debugger is attached; the
    /// debug object is closed and `BeingDebugged` clears.
    pub fn detach(&mut self, pid: u32) -> Result<(), DebugError> {
        if !self.attached {
            return Err(DebugError::NotAttached);
        }
        if pid != self.process_id {
            return Err(DebugError::ProcessNotFound);
        }
        self.attached = false;
        self.debug_port = 0;
        self.debug_object = None;
        Ok(())
    }

    /// `NtQueryInformationProcess` for the debug-related classes.
    ///
    /// Returns `Err(STATUS_INVALID_INFO_CLASS)` for any class this surface
    /// does not model.
    pub fn query_information_process(&self, info_class: u32) -> Result<u64, u32> {
        match info_class {
            PROCESS_DEBUG_PORT => Ok(self.debug_port),
            PROCESS_DEBUG_OBJECT_HANDLE => {
                Ok(self.debug_object.map(|object| object.handle).unwrap_or(0))
            }
            PROCESS_DEBUG_FLAGS => Ok(u64::from(!self.attached)),
            _ => Err(STATUS_INVALID_INFO_CLASS),
        }
    }

    /// `NtSetInformationThread`: the only class handled here is
    /// `ThreadHideFromDebugger`, which requires a null (zero-length) buffer.
    pub fn set_information_thread(
        &mut self,
        thread_id: u32,
        info_class: u32,
        buffer_len: usize,
    ) -> Result<(), u32> {
        match info_class {
            THREAD_HIDE_FROM_DEBUGGER => {
                if buffer_len != 0 {
                    return Err(STATUS_INFO_LENGTH_MISMATCH);
                }
                self.hidden_threads.insert(thread_id);
                Ok(())
            }
            _ => Err(STATUS_INVALID_INFO_CLASS),
        }
    }

    /// `NtQueryInformationThread` for `ThreadHideFromDebugger`.
    pub fn query_information_thread(&self, thread_id: u32, info_class: u32) -> Result<u64, u32> {
        match info_class {
            THREAD_HIDE_FROM_DEBUGGER => Ok(u64::from(self.is_thread_hidden(thread_id))),
            _ => Err(STATUS_INVALID_INFO_CLASS),
        }
    }

    /// Whether `thread_id` has been hidden from the debugger.
    pub fn is_thread_hidden(&self, thread_id: u32) -> bool {
        self.hidden_threads.contains(&thread_id)
    }

    /// The hardware-breakpoint context of `thread_id`, creating a zeroed
    /// context on first use.
    pub fn thread_context(&self, thread_id: u32) -> ThreadContext {
        self.contexts.get(&thread_id).copied().unwrap_or_default()
    }

    /// Programs hardware breakpoint `slot` to trigger on `address`.
    ///
    /// `condition` is the `R/W` field (0 = execute, 1 = write, 3 = read/write)
    /// and `length` is the watched byte count (1, 2, 4 or 8).  Invalid slot,
    /// condition or length return `STATUS_INVALID_PARAMETER`.
    pub fn set_hardware_breakpoint(
        &mut self,
        thread_id: u32,
        slot: u8,
        address: u64,
        condition: u8,
        length: u8,
    ) -> Result<(), u32> {
        let length_code = match length {
            1 => 0u64,
            2 => 1,
            4 => 3,
            8 => 2,
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        if slot > 3 || condition > 3 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let context = self.contexts.entry(thread_id).or_default();
        match slot {
            0 => context.dr0 = address,
            1 => context.dr1 = address,
            2 => context.dr2 = address,
            _ => context.dr3 = address,
        }
        let nibble = (length_code << 2) | u64::from(condition);
        let shift = 16 + u32::from(slot) * 4;
        context.dr7 &= !(0xF_u64 << shift);
        context.dr7 |= nibble << shift;
        context.dr7 |= 1 << (u32::from(slot) * 2);
        Ok(())
    }

    /// Clears hardware breakpoint `slot` (address left intact, enable bit and
    /// control nibble cleared) for `thread_id`.
    pub fn clear_hardware_breakpoint(&mut self, thread_id: u32, slot: u8) -> Result<(), u32> {
        if slot > 3 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let context = self.contexts.entry(thread_id).or_default();
        let shift = 16 + u32::from(slot) * 4;
        context.dr7 &= !(0xF_u64 << shift);
        context.dr7 &= !(1 << (u32::from(slot) * 2));
        Ok(())
    }

    /// Dispatches `exception_code` raised on `thread_id`.
    ///
    /// With a debugger attached (and the thread not hidden) the debugger owns
    /// the exception; otherwise a guest handler (if present) owns it and an
    /// unhandled exception terminates the process.  The outcome therefore
    /// depends on the live attach state, not on a constant.
    pub fn dispatch_exception(
        &mut self,
        thread_id: u32,
        _exception_code: u32,
        guest_handler_present: bool,
    ) -> ExceptionDisposition {
        self.exception_dispatch_count = self.exception_dispatch_count.saturating_add(1);
        if self.attached && !self.is_thread_hidden(thread_id) {
            ExceptionDisposition::HandledByDebugger
        } else if guest_handler_present {
            ExceptionDisposition::DeliveredToGuest
        } else {
            ExceptionDisposition::ProcessTerminated
        }
    }

    /// Resolves an exception previously given to a debugger with the
    /// debugger's continue status.
    pub fn resolve_exception(&self, continue_status: u32) -> ExceptionDisposition {
        match continue_status {
            DBG_CONTINUE => ExceptionDisposition::HandledByDebugger,
            DBG_EXCEPTION_NOT_HANDLED => ExceptionDisposition::DeliveredToGuest,
            _ => ExceptionDisposition::ProcessTerminated,
        }
    }
}

// ---------------------------------------------------------------------------
// Anti-cheat provider detection (real name → provider mapping)
// ---------------------------------------------------------------------------

/// Anti-cheat provider identified from a driver name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AntiCheatProvider {
    EasyAntiCheat,
    BattlEye,
    RiotVanguard,
    Xigncode,
    Faceit,
    Hoyoverse,
    NProtect,
    Equ8,
    Unknown,
}

/// A driver-name needle and the provider it implies.
struct DriverRule {
    needle: &'static str,
    provider: AntiCheatProvider,
    label: &'static str,
}

/// Known anti-cheat driver-name needles (lowercase).
const DRIVER_RULES: &[DriverRule] = &[
    DriverRule {
        needle: "easyanticheat.sys",
        provider: AntiCheatProvider::EasyAntiCheat,
        label: "Easy Anti-Cheat kernel driver",
    },
    DriverRule {
        needle: "easyanticheat_eos.sys",
        provider: AntiCheatProvider::EasyAntiCheat,
        label: "Easy Anti-Cheat EOS kernel driver",
    },
    DriverRule {
        needle: "eac.sys",
        provider: AntiCheatProvider::EasyAntiCheat,
        label: "Easy Anti-Cheat kernel driver",
    },
    DriverRule {
        needle: "bedaisy.sys",
        provider: AntiCheatProvider::BattlEye,
        label: "BattlEye kernel driver",
    },
    DriverRule {
        needle: "battleye.sys",
        provider: AntiCheatProvider::BattlEye,
        label: "BattlEye kernel driver",
    },
    DriverRule {
        needle: "vgk.sys",
        provider: AntiCheatProvider::RiotVanguard,
        label: "Riot Vanguard kernel driver",
    },
    DriverRule {
        needle: "xhunter1.sys",
        provider: AntiCheatProvider::Xigncode,
        label: "Xigncode/XHunter kernel driver",
    },
    DriverRule {
        needle: "faceit.sys",
        provider: AntiCheatProvider::Faceit,
        label: "FACEIT kernel driver",
    },
    DriverRule {
        needle: "mhyprot2.sys",
        provider: AntiCheatProvider::Hoyoverse,
        label: "HoYoverse kernel driver",
    },
    DriverRule {
        needle: "mhyprot3.sys",
        provider: AntiCheatProvider::Hoyoverse,
        label: "HoYoverse kernel driver v3",
    },
    DriverRule {
        needle: "gameguard",
        provider: AntiCheatProvider::NProtect,
        label: "GameGuard component",
    },
    DriverRule {
        needle: "equ8.sys",
        provider: AntiCheatProvider::Equ8,
        label: "EQU8 kernel driver",
    },
];

/// Detects the provider implied by a driver filename.
pub fn detect_provider(driver_name: &str) -> AntiCheatProvider {
    let normalized = driver_name.to_ascii_lowercase().replace('\\', "/");
    for rule in DRIVER_RULES {
        if normalized.contains(rule.needle) {
            return rule.provider;
        }
    }
    AntiCheatProvider::Unknown
}

/// Whether `driver_name` matches any known anti-cheat driver.
pub fn is_known_driver(driver_name: &str) -> bool {
    let normalized = driver_name.to_ascii_lowercase().replace('\\', "/");
    DRIVER_RULES
        .iter()
        .any(|rule| normalized.contains(rule.needle))
}

/// A human-readable label for `driver_name`, if it is a known driver.
pub fn driver_label(driver_name: &str) -> Option<&'static str> {
    let normalized = driver_name.to_ascii_lowercase().replace('\\', "/");
    DRIVER_RULES
        .iter()
        .find(|rule| normalized.contains(rule.needle))
        .map(|rule| rule.label)
}

// ===========================================================================
// 2. Timing surface
// ===========================================================================

/// The host monotonic counter, in its native units.
///
/// On macOS this is the hardware timebase read through `mach_absolute_time`,
/// which is invariant (global, monotonic and identical on every core) — the
/// exact semantics the guest expects from an invariant TSC.  No value here is
/// a constant: caller-visible time is this counter scaled by a *measured*
/// frequency.
#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn host_counter() -> u64 {
    // SAFETY: `mach_absolute_time` is a pure read of the process-wide
    // timebase and has no preconditions.
    unsafe { libc::mach_absolute_time() }
}

/// Fallback counter for non-macOS builds (Casa1 is macOS-only; this keeps the
/// module buildable elsewhere).
#[cfg(not(target_os = "macos"))]
fn host_counter() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static ANCHOR: OnceLock<Instant> = OnceLock::new();
    let anchor = ANCHOR.get_or_init(Instant::now);
    anchor.elapsed().as_nanos() as u64
}

/// Number of host-counter ticks per second.
///
/// Measured empirically at construction by sampling the counter across a real
/// elapsed interval — never a hard-coded constant.
pub fn measure_counter_frequency_hz() -> u64 {
    use std::time::{Duration, Instant};
    let start = Instant::now();
    let ticks_before = host_counter();
    while start.elapsed() < Duration::from_micros(2_000) {
        std::hint::spin_loop();
    }
    let elapsed = start.elapsed();
    let ticks = host_counter().saturating_sub(ticks_before);
    let nanos = elapsed.as_nanos();
    if ticks == 0 || nanos == 0 {
        return 0; // coverage: unreachable — the calibration window is real time
    }
    ((ticks as u128 * 1_000_000_000) / nanos) as u64
}

/// Converts a counter delta to nanoseconds using the measured frequency.
pub fn ticks_to_nanos(ticks: u64, frequency_hz: u64) -> u64 {
    if frequency_hz == 0 {
        return 0;
    }
    ((ticks as u128 * 1_000_000_000) / frequency_hz as u128) as u64
}

/// A coherent snapshot of every clock surface, all taken from one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingSample {
    /// `RDTSC` value (raw counter).
    pub tsc: u64,
    /// `QueryPerformanceCounter` value.
    pub qpc: i64,
    /// `QueryPerformanceFrequency` value.
    pub qpf: i64,
    /// `GetTickCount64` value (milliseconds since the clock anchor).
    pub tick_ms: u64,
    /// `GetSystemTimePreciseAsFileTime` value (100 ns units since 1601).
    pub filetime_100ns: u64,
}

/// Ways a [`TimingSample`] can fail to be coherent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingError {
    /// The performance-counter frequency is not positive.
    FrequencyZero,
    /// The performance-counter value is negative.
    NegativeInterval,
    /// `RDTSC` and `QPC` disagree even though they share one source.
    IncoherentTscQpc { tsc: u64, qpc: i64 },
}

/// Verifies that the derived clock values are mutually coherent.
pub fn verify_coherence(sample: &TimingSample) -> Result<(), TimingError> {
    if sample.qpf <= 0 {
        return Err(TimingError::FrequencyZero);
    }
    if sample.qpc < 0 {
        return Err(TimingError::NegativeInterval);
    }
    if sample.tsc != sample.qpc as u64 {
        return Err(TimingError::IncoherentTscQpc {
            tsc: sample.tsc,
            qpc: sample.qpc,
        });
    }
    Ok(())
}

/// The single monotonic clock feeding every timing API.
#[derive(Debug, Clone)]
pub struct MonotonicClock {
    anchor_counter: u64,
    anchor_wall_filetime_100ns: u64,
    frequency_hz: u64,
}

/// 100 ns intervals between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;

impl MonotonicClock {
    /// Creates a clock anchored at the current wall time with a freshly
    /// measured counter frequency.
    pub fn new() -> Self {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let anchor_wall_filetime_100ns = (wall.as_secs() as u128 * 10_000_000
            + wall.subsec_nanos() as u128 / 100) as u64
            + FILETIME_UNIX_EPOCH_100NS;
        Self {
            anchor_counter: host_counter(),
            anchor_wall_filetime_100ns,
            frequency_hz: measure_counter_frequency_hz(),
        }
    }

    /// The measured host-counter frequency in Hz.
    pub fn frequency_hz(&self) -> u64 {
        self.frequency_hz
    }

    /// The counter value captured when the clock was created.
    pub fn anchor_counter(&self) -> u64 {
        self.anchor_counter
    }

    /// `RDTSC`: the current raw counter value.
    pub fn rdtsc(&self) -> u64 {
        host_counter()
    }

    /// `RDTSCP`: the counter value plus the caller-supplied TSC_AUX (the
    /// guest logical processor id).
    pub fn rdtscp(&self, aux: u32) -> (u64, u32) {
        (host_counter(), aux)
    }

    /// `QueryPerformanceCounter`: the same source, in counter units.
    pub fn query_performance_counter(&self) -> i64 {
        host_counter() as i64
    }

    /// `QueryPerformanceFrequency`: the measured counter frequency.
    pub fn query_performance_frequency(&self) -> i64 {
        self.frequency_hz as i64
    }

    /// Counter ticks elapsed since the anchor.
    pub fn elapsed_ticks(&self) -> u64 {
        host_counter().saturating_sub(self.anchor_counter)
    }

    /// Nanoseconds elapsed since the anchor.
    pub fn elapsed_nanos(&self) -> u64 {
        ticks_to_nanos(self.elapsed_ticks(), self.frequency_hz)
    }

    /// `GetTickCount64`: milliseconds since the anchor.
    pub fn tick_count64(&self) -> u64 {
        self.elapsed_nanos() / 1_000_000
    }

    /// `GetSystemTimePreciseAsFileTime`: the wall-clock time implied by the
    /// monotonic anchor plus elapsed monotonic time, in 100 ns units.
    pub fn system_time_precise_file_time(&self) -> u64 {
        self.anchor_wall_filetime_100ns
            .saturating_add(self.elapsed_nanos().saturating_mul(10))
    }

    /// Takes a coherent snapshot of every clock surface at one instant.
    pub fn sample(&self, aux: u32) -> TimingSample {
        let (tsc, _aux) = self.rdtscp(aux);
        TimingSample {
            tsc,
            qpc: tsc as i64,
            qpf: self.frequency_hz as i64,
            tick_ms: self.tick_count64(),
            filetime_100ns: self.system_time_precise_file_time(),
        }
    }
}

/// Allocates a distinct TSC_AUX value for a guest logical processor, so that
/// `RDTSCP` reports a stable per-core id while the TSC value itself stays
/// invariant.
pub fn allocate_tsc_aux() -> u32 {
    static NEXT_AUX: AtomicU32 = AtomicU32::new(0);
    NEXT_AUX.fetch_add(1, Ordering::Relaxed)
}

// ===========================================================================
// 3. Memory integrity / scan surface
// ===========================================================================

/// Failure of a memory-protection round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemError {
    /// The target range has no committed page to protect.
    NotCommitted,
}

/// A real committed image range: base, size and protection from the VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageRange {
    pub base: u64,
    pub size: u64,
    pub protection: VmProtection,
    pub kind: VmRegionKind,
}

/// `NtQueryVirtualMemory`: the canonical VM's coalesced page query.
pub fn query_virtual_memory(vm: &VirtualMemory, address: u64) -> VmQueryResult {
    vm.query(address)
}

/// `NtProtectVirtualMemory`: applies `new_protection` and returns the
/// previous protection of the first committed page in the range.
///
/// Returns [`MemError::NotCommitted`] when the first page is not committed,
/// matching the Windows behaviour where the change is rejected.
pub fn protect_virtual_memory(
    vm: &mut VirtualMemory,
    base: u64,
    size: u64,
    new_protection: VmProtection,
) -> Result<VmProtection, MemError> {
    vm.protect(base, size, new_protection)
        .ok_or(MemError::NotCommitted)
}

/// Scans the image range containing `address`; `None` when free.
pub fn scan_image_range(vm: &VirtualMemory, address: u64) -> Option<ImageRange> {
    let query = vm.query(address);
    if query.state == VmState::Free {
        return None;
    }
    Some(ImageRange {
        base: query.base,
        size: query.region_size,
        protection: query.protection,
        kind: query.kind,
    })
}

/// The SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The real SHA-256 of the guest bytes in `[base, base + size)`.
pub fn code_hash(memory: &MemoryImage, base: u64, size: u32) -> AppResult<[u8; 32]> {
    let bytes = memory.read_bytes(base, size as usize)?;
    Ok(sha256(&bytes))
}

/// Compares the guest bytes against `expected`; `false` on any mismatch.
pub fn verify_code_hash(
    memory: &MemoryImage,
    base: u64,
    size: u32,
    expected: &[u8; 32],
) -> AppResult<bool> {
    Ok(code_hash(memory, base, size)? == *expected)
}

/// The size and SHA-256 of an on-disk module.
pub fn measure_file_sha256(path: &Path) -> std::io::Result<(u64, [u8; 32])> {
    let bytes = std::fs::read(path)?;
    Ok((bytes.len() as u64, sha256(&bytes)))
}

/// Whether Casa1's own executable module matches `expected`.
///
/// Returns `false` when the executable cannot be read — a real failure, never
/// a fabricated pass.
pub fn host_module_integrity(expected: &[u8; 32]) -> bool {
    let Ok(path) = std::env::current_exe() else {
        return false; // coverage: unreachable — the running exe always resolves
    };
    measure_file_sha256(&path).is_ok_and(|(_, hash)| hash == *expected)
}

// ===========================================================================
// 4. Attestation
// ===========================================================================

/// One measured module: its path, size and SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleMeasurement {
    pub path: String,
    pub size: u64,
    pub sha256: [u8; 32],
}

/// A real measurement of the Casa1 build and its modules/features.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurement {
    pub build_id: String,
    pub modules: Vec<ModuleMeasurement>,
    pub features: Vec<String>,
}

/// A verifier-issued nonce challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub nonce: [u8; 32],
    pub issued_at_ms: u64,
    pub ttl_ms: u64,
    pub verifier: String,
}

impl Challenge {
    /// Issues a challenge with a random nonce.
    pub fn new(verifier: &str, ttl_ms: u64, now_ms: u64) -> Self {
        Self {
            nonce: random_nonce(),
            issued_at_ms: now_ms,
            ttl_ms,
            verifier: verifier.to_string(),
        }
    }

    /// A challenge is well-formed when its nonce is non-zero, it has a
    /// positive TTL and names a verifier.
    pub fn is_well_formed(&self) -> bool {
        self.nonce != [0u8; 32] && self.ttl_ms > 0 && !self.verifier.is_empty()
    }

    /// Whether the challenge has expired at `now_ms`.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.issued_at_ms) > self.ttl_ms
    }
}

/// A signed attestation quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quote {
    pub provider_id: String,
    pub measurement: Measurement,
    pub nonce: [u8; 32],
    pub signer_public_key_spki: Vec<u8>,
    pub signature_der: Vec<u8>,
}

/// A provider's registered public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderKey {
    pub provider_id: String,
    pub public_key_spki: Vec<u8>,
    pub registered_at_ms: u64,
    pub valid_until_ms: Option<u64>,
}

/// The successful result of verifying a quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedAttestation {
    pub provider_id: String,
    pub measurement: Measurement,
    pub nonce: [u8; 32],
}

/// Every way attestation can fail — including the documented "cannot attest"
/// outcome when nothing is installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationError {
    /// No provider is registered/installed: deterministic "cannot attest".
    NoProvider,
    /// The quote names a provider that is not registered.
    UnknownProvider,
    /// A provider with this id is already enrolled.
    DuplicateProvider,
    /// The provider has been revoked.
    RevokedProvider,
    /// The provider key is past its validity window.
    ProviderKeyExpired,
    /// The quote's embedded key does not match the registered key.
    KeyMismatch,
    /// The challenge is malformed (zero nonce, zero TTL or no verifier).
    MalformedChallenge,
    /// The quote is malformed (empty or unparseable signature/key).
    MalformedQuote,
    /// The quote's nonce does not match the challenge.
    NonceMismatch,
    /// The challenge nonce has already been consumed.
    ChallengeReplayed,
    /// The challenge has expired.
    ChallengeExpired,
    /// The signature does not verify against the provider key.
    InvalidSignature,
    /// The signed measurement does not match the expected one.
    MeasurementMismatch,
    /// A persisted key is malformed.
    MalformedKey,
    /// An underlying I/O failure.
    Io(String),
}

/// A Casa1 attestation key pair (ECDSA P-256).
pub struct AttestationKeyPair {
    key: SigningKey,
}

impl AttestationKeyPair {
    /// Generates a fresh key pair from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            key: SigningKey::random(&mut OsRng),
        }
    }

    /// Restores a key pair from its 32-byte secret scalar.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, AttestationError> {
        SigningKey::from_bytes(FieldBytes::from_slice(bytes))
            .map(|key| Self { key })
            .map_err(|_| AttestationError::MalformedKey)
    }

    /// The 32-byte secret scalar.
    pub fn secret_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.key.to_bytes());
        out
    }

    /// The public key in SubjectPublicKeyInfo DER form.
    pub fn public_key_spki(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .unwrap_or_default()
    }

    /// Signs a quote binding `measurement` to `nonce` and `provider_id`.
    pub fn sign_quote(
        &self,
        provider_id: &str,
        measurement: &Measurement,
        nonce: &[u8; 32],
    ) -> Quote {
        let digest = measurement_digest(measurement);
        let message = attest_message(provider_id, nonce, &digest);
        let signature: EcdsaSignature = self.key.sign(&message);
        Quote {
            provider_id: provider_id.to_string(),
            measurement: measurement.clone(),
            nonce: *nonce,
            signer_public_key_spki: self.public_key_spki(),
            signature_der: signature.to_der().as_bytes().to_vec(),
        }
    }
}

/// A registry of trusted attestation providers with replay protection.
#[derive(Debug, Default)]
pub struct AttestationRegistry {
    providers: BTreeMap<String, ProviderKey>,
    revoked: BTreeSet<String>,
    consumed_nonces: BTreeSet<[u8; 32]>,
}

impl AttestationRegistry {
    /// An empty registry (no provider ⇒ every verification fails with
    /// [`AttestationError::NoProvider`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a provider key.  A revoked provider cannot be re-registered
    /// and an already-enrolled provider is a duplicate, never an overwrite.
    pub fn register_provider(&mut self, key: ProviderKey) -> Result<(), AttestationError> {
        if self.revoked.contains(&key.provider_id) {
            return Err(AttestationError::RevokedProvider);
        }
        if self.providers.contains_key(&key.provider_id) {
            return Err(AttestationError::DuplicateProvider);
        }
        self.providers.insert(key.provider_id.clone(), key);
        Ok(())
    }

    /// The ids of every registered provider, sorted.
    pub fn provider_ids(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }

    /// Revokes `provider_id`; returns whether the provider was registered.
    pub fn revoke_provider(&mut self, provider_id: &str) -> bool {
        let existed = self.providers.contains_key(provider_id);
        self.revoked.insert(provider_id.to_string());
        existed
    }

    /// Whether `provider_id` has been revoked.
    pub fn is_revoked(&self, provider_id: &str) -> bool {
        self.revoked.contains(provider_id)
    }

    /// The registered key for `provider_id`, if any.
    pub fn provider(&self, provider_id: &str) -> Option<&ProviderKey> {
        self.providers.get(provider_id)
    }

    /// Number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Verifies a returned quote against a challenge.
    ///
    /// `expected` is the measurement the verifier requires (when known).  On
    /// success the challenge nonce is consumed so a replay of the same
    /// challenge is rejected.
    pub fn verify_quote(
        &mut self,
        quote: &Quote,
        challenge: &Challenge,
        expected: Option<&Measurement>,
        now_ms: u64,
    ) -> Result<VerifiedAttestation, AttestationError> {
        if self.providers.is_empty() && self.revoked.is_empty() {
            return Err(AttestationError::NoProvider);
        }
        if !challenge.is_well_formed() {
            return Err(AttestationError::MalformedChallenge);
        }
        if self.revoked.contains(&quote.provider_id) {
            return Err(AttestationError::RevokedProvider);
        }
        let provider = self
            .providers
            .get(&quote.provider_id)
            .ok_or(AttestationError::UnknownProvider)?;
        if let Some(until) = provider.valid_until_ms
            && now_ms > until
        {
            return Err(AttestationError::ProviderKeyExpired);
        }
        if provider.public_key_spki != quote.signer_public_key_spki {
            return Err(AttestationError::KeyMismatch);
        }
        if quote.nonce != challenge.nonce {
            return Err(AttestationError::NonceMismatch);
        }
        if self.consumed_nonces.contains(&challenge.nonce) {
            return Err(AttestationError::ChallengeReplayed);
        }
        if challenge.is_expired(now_ms) {
            return Err(AttestationError::ChallengeExpired);
        }
        if quote.signature_der.is_empty() {
            return Err(AttestationError::MalformedQuote);
        }
        let verifying_key = VerifyingKey::from_public_key_der(&provider.public_key_spki)
            .map_err(|_| AttestationError::MalformedQuote)?;
        let signature = EcdsaSignature::from_der(&quote.signature_der)
            .map_err(|_| AttestationError::MalformedQuote)?;
        let digest = measurement_digest(&quote.measurement);
        let message = attest_message(&quote.provider_id, &quote.nonce, &digest);
        verifying_key
            .verify(&message, &signature)
            .map_err(|_| AttestationError::InvalidSignature)?;
        if let Some(expected) = expected
            && measurement_digest(expected) != digest
        {
            return Err(AttestationError::MeasurementMismatch);
        }
        self.consumed_nonces.insert(challenge.nonce);
        Ok(VerifiedAttestation {
            provider_id: quote.provider_id.clone(),
            measurement: quote.measurement.clone(),
            nonce: quote.nonce,
        })
    }
}

/// The deterministic "cannot attest" outcome when nothing is installed.
pub fn cannot_attest(reason: &AttestationError) -> &'static str {
    match reason {
        AttestationError::NoProvider => "cannot attest: no provider registered or installed",
        _ => "attestation failed",
    }
}

/// The canonical NTSTATUS a guest-facing attestation verifier reports for one
/// [`AttestationError`].  The mapping is part of the guest ABI (the guests
/// pin these exact values), so every attestation thunk uses this one table.
pub fn attestation_ntstatus(reason: &AttestationError) -> u32 {
    match reason {
        AttestationError::NoProvider => 0xC000_00BB, // STATUS_NOT_SUPPORTED
        AttestationError::UnknownProvider => 0xC000_0034, // STATUS_OBJECT_NAME_NOT_FOUND
        AttestationError::DuplicateProvider => 0xC000_0035, // STATUS_OBJECT_NAME_COLLISION
        AttestationError::RevokedProvider
        | AttestationError::KeyMismatch
        | AttestationError::ChallengeReplayed
        | AttestationError::InvalidSignature
        | AttestationError::MeasurementMismatch => 0xC000_0022, // STATUS_ACCESS_DENIED
        AttestationError::ProviderKeyExpired | AttestationError::ChallengeExpired => 0xC000_0102, // STATUS_TIMEOUT
        AttestationError::MalformedChallenge
        | AttestationError::MalformedQuote
        | AttestationError::NonceMismatch
        | AttestationError::MalformedKey => 0xC000_000D, // STATUS_INVALID_PARAMETER
        AttestationError::Io(_) => 0xC000_0001, // STATUS_UNSUCCESSFUL
    }
}

/// The wire size of a guest-issued challenge: a 32-byte nonce, the issue
/// timestamp and the TTL, each a little-endian `u64`.
pub const ATTESTATION_CHALLENGE_WIRE_SIZE: usize = 48;

/// Serialize a challenge into the fixed guest wire layout.
///
/// The verifier name is deliberately not part of the wire layout: it is not
/// covered by the signature and every guest verifier in Casa1 uses the one
/// documented verifier identity ([`ATTESTATION_VERIFIER`]).
pub fn challenge_to_wire(challenge: &Challenge) -> [u8; ATTESTATION_CHALLENGE_WIRE_SIZE] {
    let mut bytes = [0_u8; ATTESTATION_CHALLENGE_WIRE_SIZE];
    bytes[0..32].copy_from_slice(&challenge.nonce);
    bytes[32..40].copy_from_slice(&challenge.issued_at_ms.to_le_bytes());
    bytes[40..48].copy_from_slice(&challenge.ttl_ms.to_le_bytes());
    bytes
}

/// Parse the fixed guest wire layout back into a [`Challenge`].
///
/// The resulting challenge uses [`ATTESTATION_VERIFIER`]; malformed wire
/// data (a zero nonce or a zero TTL) is [`AttestationError::MalformedChallenge`].
pub fn challenge_from_wire(bytes: &[u8]) -> Result<Challenge, AttestationError> {
    if bytes.len() < ATTESTATION_CHALLENGE_WIRE_SIZE {
        return Err(AttestationError::MalformedChallenge);
    }
    let mut nonce = [0_u8; 32];
    nonce.copy_from_slice(&bytes[0..32]);
    let issued_at_ms = u64::from_le_bytes(
        bytes[32..40]
            .try_into()
            .map_err(|_| AttestationError::MalformedChallenge)?,
    );
    let ttl_ms = u64::from_le_bytes(
        bytes[40..48]
            .try_into()
            .map_err(|_| AttestationError::MalformedChallenge)?,
    );
    let challenge = Challenge {
        nonce,
        issued_at_ms,
        ttl_ms,
        verifier: ATTESTATION_VERIFIER.to_string(),
    };
    if challenge.is_well_formed() {
        Ok(challenge)
    } else {
        Err(AttestationError::MalformedChallenge)
    }
}

/// The verifier identity a Casa1 guest verifier announces to itself.
pub const ATTESTATION_VERIFIER: &str = "casa1-guest";

/// Maximum length of an attestation provider id accepted by the guest ABI.
pub const MAX_PROVIDER_ID_LENGTH: usize = 128;

/// Whether `provider_id` is a safe, persistable provider id: one to
/// [`MAX_PROVIDER_ID_LENGTH`] ASCII alphanumerics, `-`, `_` or `.`.  The id
/// becomes a file name in the install store, so separators and control
/// characters are rejected outright.
pub fn is_valid_provider_id(provider_id: &str) -> bool {
    !provider_id.is_empty()
        && provider_id.len() <= MAX_PROVIDER_ID_LENGTH
        && provider_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Derive the Casa1 attestation key from the persisted install identity.
///
/// The real install id is stable across reboots, so this is the same key on
/// every launch of the installation.  Derivation is a domain-separated
/// SHA-256; a digest that is not a valid P-256 scalar is
/// [`AttestationError::MalformedKey`] and never silently replaced.
pub fn install_attestation_key(install_id: &str) -> Result<AttestationKeyPair, AttestationError> {
    if install_id.is_empty() {
        return Err(AttestationError::MalformedKey);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"casa1-attestation-key:");
    hasher.update(install_id.as_bytes());
    let digest = hasher.finalize();
    let bytes: [u8; 32] = digest.into();
    AttestationKeyPair::from_secret_bytes(&bytes)
}

/// On-disk install identity store holding the attestation key and provider
/// registrations.
#[derive(Debug, Clone)]
pub struct InstallIdentityStore {
    root: PathBuf,
}

impl InstallIdentityStore {
    /// Opens (but does not create) the store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The store root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn key_path(&self) -> PathBuf {
        self.root.join("attestation_key.hex")
    }

    fn provider_path(&self, provider_id: &str) -> PathBuf {
        self.root
            .join("providers")
            .join(format!("{provider_id}.pub"))
    }

    fn revoked_path(&self, provider_id: &str) -> PathBuf {
        self.root.join("revoked").join(provider_id)
    }

    /// Loads the persisted key pair, generating and persisting one on first
    /// use.
    pub fn load_or_create_keypair(&self) -> Result<AttestationKeyPair, AttestationError> {
        let path = self.key_path();
        if path.is_file() {
            let text = std::fs::read_to_string(&path).map_err(io_error)?;
            let bytes = hex::decode(text.trim()).map_err(|_| AttestationError::MalformedKey)?;
            let array: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| AttestationError::MalformedKey)?;
            AttestationKeyPair::from_secret_bytes(&array)
        } else {
            std::fs::create_dir_all(&self.root).map_err(io_error)?;
            let key_pair = AttestationKeyPair::generate();
            std::fs::write(&path, hex::encode(key_pair.secret_bytes())).map_err(io_error)?;
            Ok(key_pair)
        }
    }

    /// Installs a provider whose key is Casa1's own attestation key.
    pub fn install_provider(
        &self,
        provider_id: &str,
        valid_until_ms: Option<u64>,
        now_ms: u64,
    ) -> Result<ProviderKey, AttestationError> {
        if self.is_revoked(provider_id) {
            return Err(AttestationError::RevokedProvider);
        }
        let key_pair = self.load_or_create_keypair()?;
        let key = ProviderKey {
            provider_id: provider_id.to_string(),
            public_key_spki: key_pair.public_key_spki(),
            registered_at_ms: now_ms,
            valid_until_ms,
        };
        let path = self.provider_path(provider_id);
        std::fs::create_dir_all(path.parent().unwrap_or(self.root.as_path())).map_err(io_error)?;
        let encoded = serde_json::to_vec(&key).expect("provider key is serializable");
        std::fs::write(&path, encoded).map_err(io_error)?;
        Ok(key)
    }

    /// Enrolls a guest-supplied provider public key (P-256 SPKI DER).
    ///
    /// The id is validated before it becomes a store file name, the key must
    /// parse as a P-256 SubjectPublicKeyInfo, a revoked provider is refused,
    /// and an already-enrolled id is a duplicate — never an overwrite.
    pub fn enroll_provider_key(
        &self,
        provider_id: &str,
        public_key_spki: &[u8],
        valid_until_ms: Option<u64>,
        now_ms: u64,
    ) -> Result<ProviderKey, AttestationError> {
        if !is_valid_provider_id(provider_id) || public_key_spki.is_empty() {
            return Err(AttestationError::MalformedKey);
        }
        VerifyingKey::from_public_key_der(public_key_spki)
            .map_err(|_| AttestationError::MalformedKey)?;
        if self.is_revoked(provider_id) {
            return Err(AttestationError::RevokedProvider);
        }
        if self.provider_path(provider_id).is_file() {
            return Err(AttestationError::DuplicateProvider);
        }
        let key = ProviderKey {
            provider_id: provider_id.to_string(),
            public_key_spki: public_key_spki.to_vec(),
            registered_at_ms: now_ms,
            valid_until_ms,
        };
        let path = self.provider_path(provider_id);
        std::fs::create_dir_all(path.parent().unwrap_or(self.root.as_path())).map_err(io_error)?;
        let encoded = serde_json::to_vec(&key).expect("provider key is serializable");
        std::fs::write(&path, encoded).map_err(io_error)?;
        Ok(key)
    }

    /// Loads an installed provider key, if present.
    pub fn load_provider(
        &self,
        provider_id: &str,
    ) -> Result<Option<ProviderKey>, AttestationError> {
        let path = self.provider_path(provider_id);
        if !path.is_file() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(io_error)?;
        let key: ProviderKey =
            serde_json::from_slice(&bytes).map_err(|_| AttestationError::MalformedKey)?;
        Ok(Some(key))
    }

    /// Revokes `provider_id` by writing a revocation marker; returns whether
    /// an installed, not-previously-revoked provider was revoked.
    pub fn revoke_provider(&self, provider_id: &str) -> Result<bool, AttestationError> {
        let newly_revoked =
            self.provider_path(provider_id).is_file() && !self.is_revoked(provider_id);
        let marker = self.revoked_path(provider_id);
        std::fs::create_dir_all(marker.parent().unwrap_or(self.root.as_path()))
            .map_err(io_error)?;
        std::fs::write(&marker, b"revoked").map_err(io_error)?;
        Ok(newly_revoked)
    }

    /// Whether `provider_id` has a revocation marker.
    pub fn is_revoked(&self, provider_id: &str) -> bool {
        self.revoked_path(provider_id).is_file()
    }
}

/// Maps an I/O error into [`AttestationError::Io`].
fn io_error(error: std::io::Error) -> AttestationError {
    AttestationError::Io(error.to_string())
}

/// A 32-byte random nonce from the OS CSPRNG.
pub fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// The byte-exact canonical encoding of a measurement.
fn canonical_measurement(measurement: &Measurement) -> Vec<u8> {
    let mut out = Vec::new();
    push_len_prefixed(&mut out, measurement.build_id.as_bytes());
    out.extend_from_slice(&(measurement.modules.len() as u32).to_le_bytes());
    for module in &measurement.modules {
        push_len_prefixed(&mut out, module.path.as_bytes());
        out.extend_from_slice(&module.size.to_le_bytes());
        out.extend_from_slice(&module.sha256);
    }
    out.extend_from_slice(&(measurement.features.len() as u32).to_le_bytes());
    for feature in &measurement.features {
        push_len_prefixed(&mut out, feature.as_bytes());
    }
    out
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// The SHA-256 digest of the canonical measurement encoding.
pub fn measurement_digest(measurement: &Measurement) -> [u8; 32] {
    sha256(&canonical_measurement(measurement))
}

/// The signed message: domain tag, provider id, nonce and measurement digest.
fn attest_message(provider_id: &str, nonce: &[u8; 32], digest: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"casa1-attest-v1");
    push_len_prefixed(&mut message, provider_id.as_bytes());
    message.extend_from_slice(nonce);
    message.extend_from_slice(digest);
    message
}

/// A real measurement of Casa1's own build: build id, enabled features and
/// the SHA-256 of the running executable.
pub fn measure_casa1_build() -> Measurement {
    let mut modules = Vec::new();
    if let Ok(path) = std::env::current_exe()
        && let Ok((size, sha256)) = measure_file_sha256(&path)
    {
        modules.push(ModuleMeasurement {
            path: path.to_string_lossy().into_owned(),
            size,
            sha256,
        });
    }
    Measurement {
        build_id: crate::BUILD_ID.to_string(),
        modules,
        features: enabled_features(),
    }
}

/// The Casa1 feature set enabled in this build.
fn enabled_features() -> Vec<String> {
    let mut features = Vec::new();
    #[cfg(feature = "vulkan")]
    features.push("vulkan".to_string());
    #[cfg(feature = "opengl")]
    features.push("opengl".to_string());
    #[cfg(feature = "websocket")]
    features.push("websocket".to_string());
    #[cfg(feature = "moltenvk")]
    features.push("moltenvk".to_string());
    #[cfg(feature = "angle")]
    features.push("angle".to_string());
    #[cfg(feature = "ffmpeg")]
    features.push("ffmpeg".to_string());
    features
}

// ---------------------------------------------------------------------------
// Reason-coded helpers (share the crate's AppError surface)
// ---------------------------------------------------------------------------

/// Builds a reason-coded error for a failed attestation.
pub fn attestation_error(reason: &AttestationError) -> AppError {
    AppError::new(ReasonCode::RcInvalidState, cannot_attest(reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let unique = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "casa1-attest-{}-{tag}-{unique}",
            std::process::id()
        ))
    }

    fn sample_measurement() -> Measurement {
        Measurement {
            build_id: "casa1-test".to_string(),
            modules: vec![ModuleMeasurement {
                path: "/tmp/casa1-test.dll".to_string(),
                size: 4,
                sha256: sha256(b"test module"),
            }],
            features: vec!["vulkan".to_string()],
        }
    }

    fn register_test_provider(registry: &mut AttestationRegistry, id: &str) -> AttestationKeyPair {
        let key_pair = AttestationKeyPair::generate();
        registry
            .register_provider(ProviderKey {
                provider_id: id.to_string(),
                public_key_spki: key_pair.public_key_spki(),
                registered_at_ms: 0,
                valid_until_ms: None,
            })
            .expect("registration succeeds");
        key_pair
    }

    #[test]
    fn debugger_attach_detach_reject_invalid_transitions() {
        let mut surface = AntiDebugSurface::new(4242);
        assert_eq!(surface.detach(4242), Err(DebugError::NotAttached));

        let object = surface.attach(4242).expect("attach succeeds");
        assert_eq!(object.process_id, 4242);
        assert_eq!(surface.attach(4242), Err(DebugError::AlreadyAttached));
        assert_eq!(surface.attach(7), Err(DebugError::ProcessNotFound));
        assert_eq!(surface.detach(7), Err(DebugError::ProcessNotFound));

        // Still attached after the rejected detach.
        assert!(surface.is_debugger_present());
        assert_eq!(surface.detach(4242), Ok(()));
        assert_eq!(surface.debug_object(), None);
        assert_eq!(surface.detach(4242), Err(DebugError::NotAttached));
    }

    #[test]
    fn debugger_flags_and_query_classes_mismatch_once_attached() {
        let mut surface = AntiDebugSurface::new(99);
        assert_eq!(surface.being_debugged(), 0);
        assert_eq!(surface.nt_global_flag(), 0);
        assert_eq!(surface.heap_flags(), HEAP_GROWABLE);
        assert_eq!(
            surface.query_information_process(PROCESS_DEBUG_FLAGS),
            Ok(1)
        );
        assert_eq!(surface.query_information_process(PROCESS_DEBUG_PORT), Ok(0));
        assert_eq!(
            surface.query_information_process(PROCESS_DEBUG_OBJECT_HANDLE),
            Ok(0)
        );
        assert_eq!(
            surface.query_information_process(0x1234),
            Err(STATUS_INVALID_INFO_CLASS)
        );

        let object = surface.attach(99).expect("attach succeeds");
        assert_eq!(surface.being_debugged(), 1);
        assert_eq!(surface.nt_global_flag(), NT_GLOBAL_FLAG_DEBUG);
        assert_eq!(
            surface.heap_flags(),
            HEAP_GROWABLE | HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED
        );
        assert_eq!(
            surface.query_information_process(PROCESS_DEBUG_FLAGS),
            Ok(0)
        );
        assert_eq!(
            surface.query_information_process(PROCESS_DEBUG_PORT),
            Ok(u64::MAX)
        );
        assert_eq!(
            surface.query_information_process(PROCESS_DEBUG_OBJECT_HANDLE),
            Ok(object.handle)
        );
        assert!(surface.check_remote_debugger_present());
        assert_eq!(surface.debug_port(), u64::MAX);
    }

    #[test]
    fn thread_hide_from_debugger_rejects_bad_length_and_class() {
        let mut surface = AntiDebugSurface::new(1);
        assert_eq!(
            surface.set_information_thread(7, THREAD_HIDE_FROM_DEBUGGER, 4),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert!(!surface.is_thread_hidden(7));
        assert_eq!(
            surface.set_information_thread(7, 0x99, 0),
            Err(STATUS_INVALID_INFO_CLASS)
        );
        assert_eq!(
            surface.set_information_thread(7, THREAD_HIDE_FROM_DEBUGGER, 0),
            Ok(())
        );
        assert!(surface.is_thread_hidden(7));
        assert_eq!(
            surface.query_information_thread(7, THREAD_HIDE_FROM_DEBUGGER),
            Ok(1)
        );
        assert_eq!(
            surface.query_information_thread(8, THREAD_HIDE_FROM_DEBUGGER),
            Ok(0)
        );
        assert_eq!(
            surface.query_information_thread(7, 0x99),
            Err(STATUS_INVALID_INFO_CLASS)
        );
    }

    #[test]
    fn hardware_breakpoints_reject_invalid_slot_condition_and_length() {
        let mut surface = AntiDebugSurface::new(1);
        assert_eq!(
            surface.set_hardware_breakpoint(7, 4, 0x1000, 1, 4),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            surface.set_hardware_breakpoint(7, 0, 0x1000, 9, 4),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            surface.set_hardware_breakpoint(7, 0, 0x1000, 1, 3),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            surface.clear_hardware_breakpoint(7, 9),
            Err(STATUS_INVALID_PARAMETER)
        );

        for (slot, condition, length) in [(0u8, 0u8, 1u8), (1, 1, 2), (2, 3, 8), (3, 1, 4)] {
            assert_eq!(
                surface.set_hardware_breakpoint(7, slot, 0x1000 + slot as u64, condition, length),
                Ok(())
            );
        }
        let context = surface.thread_context(7);
        assert_eq!(context.breakpoint_address(0), Some(0x1000));
        assert_eq!(context.breakpoint_address(1), Some(0x1001));
        assert_eq!(context.breakpoint_address(2), Some(0x1002));
        assert_eq!(context.breakpoint_address(3), Some(0x1003));
        assert_eq!(context.breakpoint_address(4), None);
        assert!(context.breakpoint_enabled(2));
        assert_eq!(context.breakpoint_condition(1), Some(1));
        assert_eq!(context.breakpoint_length_code(2), Some(2));
        assert_eq!(context.breakpoint_condition(9), None);
        assert_eq!(context.breakpoint_length_code(9), None);

        assert_eq!(surface.clear_hardware_breakpoint(7, 2), Ok(()));
        assert!(!surface.thread_context(7).breakpoint_enabled(2));
        // An unknown thread comes back as a zeroed context.
        assert_eq!(surface.thread_context(1234), ThreadContext::default());
    }

    #[test]
    fn debugger_exception_dispatch_mismatch_when_thread_hidden() {
        let mut surface = AntiDebugSurface::new(1);
        assert_eq!(
            surface.dispatch_exception(1, EXCEPTION_BREAKPOINT, true),
            ExceptionDisposition::DeliveredToGuest
        );
        assert_eq!(
            surface.dispatch_exception(1, EXCEPTION_BREAKPOINT, false),
            ExceptionDisposition::ProcessTerminated
        );

        surface.attach(1).expect("attach succeeds");
        assert_eq!(
            surface.dispatch_exception(1, EXCEPTION_BREAKPOINT, false),
            ExceptionDisposition::HandledByDebugger
        );
        surface
            .set_information_thread(1, THREAD_HIDE_FROM_DEBUGGER, 0)
            .expect("hide succeeds");
        assert_eq!(
            surface.dispatch_exception(1, EXCEPTION_BREAKPOINT, false),
            ExceptionDisposition::ProcessTerminated
        );
        assert_eq!(surface.exception_dispatch_count(), 4);

        assert_eq!(
            surface.resolve_exception(DBG_CONTINUE),
            ExceptionDisposition::HandledByDebugger
        );
        assert_eq!(
            surface.resolve_exception(DBG_EXCEPTION_NOT_HANDLED),
            ExceptionDisposition::DeliveredToGuest
        );
        assert_eq!(
            surface.resolve_exception(0xDEAD_BEEF),
            ExceptionDisposition::ProcessTerminated
        );
    }

    #[test]
    fn driver_provider_detection_rejects_unknown_or_wrong_names() {
        assert_eq!(
            detect_provider(r"C:\Windows\System32\drivers\EasyAntiCheat.sys"),
            AntiCheatProvider::EasyAntiCheat
        );
        assert_eq!(detect_provider("vgk.sys"), AntiCheatProvider::RiotVanguard);
        assert_eq!(detect_provider("bedaisy.sys"), AntiCheatProvider::BattlEye);
        assert_eq!(detect_provider("xhunter1.sys"), AntiCheatProvider::Xigncode);
        assert_eq!(detect_provider("faceit.sys"), AntiCheatProvider::Faceit);
        assert_eq!(
            detect_provider("mhyprot2.sys"),
            AntiCheatProvider::Hoyoverse
        );
        assert_eq!(
            detect_provider("gameguard.sys"),
            AntiCheatProvider::NProtect
        );
        assert_eq!(detect_provider("equ8.sys"), AntiCheatProvider::Equ8);
        assert_eq!(detect_provider("eac.sys"), AntiCheatProvider::EasyAntiCheat);
        assert_eq!(detect_provider("ntoskrnl.exe"), AntiCheatProvider::Unknown);
        assert!(!is_known_driver("ntoskrnl.exe"));
        assert!(is_known_driver("mhyprot3.sys"));
        assert_eq!(driver_label("battleye.sys"), Some("BattlEye kernel driver"));
        assert_eq!(driver_label("ntoskrnl.exe"), None);
    }

    #[test]
    fn timing_coherence_rejects_mismatched_tsc_and_qpc() {
        let coherent = TimingSample {
            tsc: 1_000,
            qpc: 1_000,
            qpf: 1_000_000,
            tick_ms: 0,
            filetime_100ns: 0,
        };
        assert_eq!(verify_coherence(&coherent), Ok(()));

        let mismatch = TimingSample {
            tsc: 1_000,
            qpc: 999,
            qpf: 1_000_000,
            tick_ms: 0,
            filetime_100ns: 0,
        };
        assert_eq!(
            verify_coherence(&mismatch),
            Err(TimingError::IncoherentTscQpc {
                tsc: 1_000,
                qpc: 999
            })
        );

        let zero_frequency = TimingSample {
            tsc: 1,
            qpc: 1,
            qpf: 0,
            tick_ms: 0,
            filetime_100ns: 0,
        };
        assert_eq!(
            verify_coherence(&zero_frequency),
            Err(TimingError::FrequencyZero)
        );

        let negative = TimingSample {
            tsc: 0,
            qpc: -1,
            qpf: 1,
            tick_ms: 0,
            filetime_100ns: 0,
        };
        assert_eq!(
            verify_coherence(&negative),
            Err(TimingError::NegativeInterval)
        );
    }

    #[test]
    fn monotonic_clock_cross_thread_tsc_incoherence_is_rejected() {
        let clock = Arc::new(MonotonicClock::new());
        assert!(clock.frequency_hz() > 0);
        assert_eq!(
            clock.query_performance_frequency(),
            clock.frequency_hz() as i64
        );
        let qpc = clock.query_performance_counter();
        assert_eq!(qpc >= 0, true);

        let sample = clock.sample(allocate_tsc_aux());
        assert_eq!(verify_coherence(&sample), Ok(()));
        assert_eq!(sample.qpc, sample.tsc as i64);
        assert_eq!(ticks_to_nanos(0, 0), 0);
        assert_ne!(
            ticks_to_nanos(clock.frequency_hz(), clock.frequency_hz()),
            0
        );

        let mut handles = Vec::new();
        for _ in 0..4 {
            let clock = Arc::clone(&clock);
            handles.push(std::thread::spawn(move || {
                let aux = allocate_tsc_aux();
                let (first, first_aux) = clock.rdtscp(aux);
                let second = clock.rdtsc();
                assert_eq!(first_aux, aux);
                assert!(second >= first);
                assert!(first >= clock.anchor_counter());
                clock.tick_count64()
            }));
        }
        let ticks: Vec<u64> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread joins"))
            .collect();
        assert_eq!(ticks.len(), 4);

        let later = clock.sample(0);
        assert!(later.filetime_100ns >= sample.filetime_100ns);
        assert_ne!(allocate_tsc_aux(), allocate_tsc_aux());
    }

    #[test]
    fn virtual_memory_protection_round_trip_mismatch_is_reported() {
        let mut vm = VirtualMemory::new(0x7400_0000);
        let base = vm.reserve(Some(0x7400_0000), 0x4000);
        assert_eq!(base, 0x7400_0000);
        vm.commit(base, 0x2000, VmProtection::READ, false);

        let previous =
            protect_virtual_memory(&mut vm, base, 0x2000, VmProtection::READ_WRITE_EXECUTE)
                .expect("protect committed range");
        assert_eq!(previous, VmProtection::READ);
        let query = query_virtual_memory(&vm, base);
        assert_eq!(query.protection, VmProtection::READ_WRITE_EXECUTE);
        assert_eq!(query.state, VmState::Committed);

        let range = scan_image_range(&vm, base).expect("committed range");
        assert_eq!(range.base, base);
        assert_eq!(range.size, 0x2000);
        assert_eq!(range.protection, VmProtection::READ_WRITE_EXECUTE);
        assert_eq!(range.kind, VmRegionKind::Private);

        // Protecting the reserved tail fails: nothing committed there.
        assert_eq!(
            protect_virtual_memory(&mut vm, base + 0x2000, 0x1000, VmProtection::READ),
            Err(MemError::NotCommitted)
        );
        assert_eq!(scan_image_range(&vm, base + 0x8000), None);
    }

    #[test]
    fn code_integrity_hash_mismatch_is_detected() {
        let mut memory = MemoryImage::default();
        let base = 0x1_0000_0000u64;
        memory.map_bytes(base, &[0x90, 0x90, 0xC3, 0x90]);
        let expected = sha256(&[0x90, 0x90, 0xC3, 0x90]);
        assert_eq!(code_hash(&memory, base, 4).expect("hash"), expected);
        assert_eq!(
            verify_code_hash(&memory, base, 4, &expected).expect("verify"),
            true
        );
        assert_eq!(
            verify_code_hash(&memory, base, 4, &[0u8; 32]).expect("verify"),
            false
        );

        memory.map_bytes(base, &[0xCC, 0x90, 0xC3, 0x90]);
        assert_eq!(
            verify_code_hash(&memory, base, 4, &expected).expect("verify"),
            false
        );
        assert!(code_hash(&memory, 0xDEAD_0000, 4).is_err());
    }

    #[test]
    fn host_module_integrity_rejects_mismatch_and_missing_files() {
        let (size, hash) = measure_file_sha256(Path::new(env!("CARGO_MANIFEST_DIR")))
            .err()
            .map(|error| (0u64, sha256(error.to_string().as_bytes())))
            .expect("directory read fails");
        assert_eq!(size, 0);
        assert_ne!(hash, [0u8; 32]);

        assert!(!host_module_integrity(&[0u8; 32]));
        let exe = std::env::current_exe().expect("current exe");
        let (_, exe_hash) = measure_file_sha256(&exe).expect("hash exe");
        assert!(host_module_integrity(&exe_hash));
    }

    #[test]
    fn casa1_build_measurement_rejects_stale_digest_mismatch() {
        let measurement = measure_casa1_build();
        assert_eq!(measurement.build_id, crate::BUILD_ID);
        assert_eq!(measurement.modules.len(), 1);
        assert_ne!(measurement.modules[0].sha256, [0u8; 32]);
        assert_ne!(
            measurement_digest(&measurement),
            measurement_digest(&sample_measurement())
        );
        assert_eq!(
            measurement_digest(&measurement),
            measurement_digest(&measurement.clone())
        );
    }

    #[test]
    fn attestation_without_provider_returns_cannot_attest_failure() {
        let mut registry = AttestationRegistry::new();
        let key_pair = AttestationKeyPair::generate();
        let measurement = sample_measurement();
        let challenge = Challenge::new("verifier", 60_000, 0);
        let quote = key_pair.sign_quote("provider", &measurement, &challenge.nonce);
        assert_eq!(
            registry.verify_quote(&quote, &challenge, None, 0),
            Err(AttestationError::NoProvider)
        );
        assert_eq!(
            cannot_attest(&AttestationError::NoProvider),
            "cannot attest: no provider registered or installed"
        );
        assert_eq!(
            attestation_error(&AttestationError::NoProvider).code,
            ReasonCode::RcInvalidState
        );
        assert_eq!(registry.provider_count(), 0);
        assert_eq!(
            cannot_attest(&AttestationError::InvalidSignature),
            "attestation failed"
        );
    }

    #[test]
    fn attestation_quote_verification_rejects_forged_and_replayed_quotes() {
        let mut registry = AttestationRegistry::new();
        let key_pair = register_test_provider(&mut registry, "casa1");
        let measurement = sample_measurement();
        let challenge = Challenge::new("verifier", 60_000, 1_000);
        let quote = key_pair.sign_quote("casa1", &measurement, &challenge.nonce);

        let verified = registry
            .verify_quote(&quote, &challenge, Some(&measurement), 2_000)
            .expect("verification succeeds");
        assert_eq!(verified.provider_id, "casa1");
        assert_eq!(verified.nonce, challenge.nonce);

        // Replaying the same challenge is refused.
        assert_eq!(
            registry.verify_quote(&quote, &challenge, Some(&measurement), 2_000),
            Err(AttestationError::ChallengeReplayed)
        );

        // A quote for a different nonce is refused.
        let mut other_nonce = challenge.clone();
        other_nonce.nonce = random_nonce();
        assert_eq!(
            registry.verify_quote(&quote, &other_nonce, None, 3_000),
            Err(AttestationError::NonceMismatch)
        );

        // An empty signature is malformed.
        let mut empty_signature = quote.clone();
        empty_signature.signature_der.clear();
        let fresh = Challenge::new("verifier", 60_000, 1_000);
        let mut empty_quote = empty_signature.clone();
        empty_quote.nonce = fresh.nonce;
        assert_eq!(
            registry.verify_quote(&empty_quote, &fresh, None, 2_000),
            Err(AttestationError::MalformedQuote)
        );

        // A forged quote signed by another key is refused.
        let forged_key = AttestationKeyPair::generate();
        let forged_challenge = Challenge::new("verifier", 60_000, 1_000);
        let mut forged = forged_key.sign_quote("casa1", &measurement, &forged_challenge.nonce);
        forged.signer_public_key_spki = key_pair.public_key_spki();
        assert_eq!(
            registry.verify_quote(&forged, &forged_challenge, None, 2_000),
            Err(AttestationError::InvalidSignature)
        );

        // A well-signed quote for the wrong measurement is refused.
        let mismatch_challenge = Challenge::new("verifier", 60_000, 1_000);
        let mismatch_quote = key_pair.sign_quote("casa1", &measurement, &mismatch_challenge.nonce);
        let mut different = sample_measurement();
        different.build_id = "casa1-other".to_string();
        assert_eq!(
            registry.verify_quote(
                &mismatch_quote,
                &mismatch_challenge,
                Some(&different),
                2_000
            ),
            Err(AttestationError::MeasurementMismatch)
        );

        // An expired challenge is refused.
        let expired_challenge = Challenge::new("verifier", 10, 0);
        let expired_quote = key_pair.sign_quote("casa1", &measurement, &expired_challenge.nonce);
        assert_eq!(
            registry.verify_quote(&expired_quote, &expired_challenge, None, 100_000),
            Err(AttestationError::ChallengeExpired)
        );

        // A malformed challenge (zero nonce) is refused.
        let mut malformed = Challenge::new("verifier", 60_000, 0);
        malformed.nonce = [0u8; 32];
        assert_eq!(
            registry.verify_quote(&quote, &malformed, None, 10),
            Err(AttestationError::MalformedChallenge)
        );

        // A provider whose registered public key does not parse is malformed.
        registry
            .register_provider(ProviderKey {
                provider_id: "badkey".to_string(),
                public_key_spki: vec![0x00, 0x01, 0x02],
                registered_at_ms: 0,
                valid_until_ms: None,
            })
            .expect("registration succeeds");
        let badkey_challenge = Challenge::new("verifier", 60_000, 1_000);
        let mut badkey_quote = key_pair.sign_quote("badkey", &measurement, &badkey_challenge.nonce);
        badkey_quote.signer_public_key_spki = vec![0x00, 0x01, 0x02];
        assert_eq!(
            registry.verify_quote(&badkey_quote, &badkey_challenge, None, 2_000),
            Err(AttestationError::MalformedQuote)
        );

        // A non-empty but unparseable signature is malformed.
        let garbage_challenge = Challenge::new("verifier", 60_000, 1_000);
        let mut garbage_quote =
            key_pair.sign_quote("casa1", &measurement, &garbage_challenge.nonce);
        garbage_quote.signature_der = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            registry.verify_quote(&garbage_quote, &garbage_challenge, None, 2_000),
            Err(AttestationError::MalformedQuote)
        );
    }

    #[test]
    fn attestation_registry_rejects_revoked_expired_unknown_and_mismatched_keys() {
        let mut registry = AttestationRegistry::new();
        let key_pair = register_test_provider(&mut registry, "casa1");
        let measurement = sample_measurement();

        // Unknown provider.
        let unknown_challenge = Challenge::new("verifier", 60_000, 0);
        let unknown_quote = key_pair.sign_quote("ghost", &measurement, &unknown_challenge.nonce);
        assert_eq!(
            registry.verify_quote(&unknown_quote, &unknown_challenge, None, 1),
            Err(AttestationError::UnknownProvider)
        );

        // Key mismatch: quote carries a different key than registered.
        let other = AttestationKeyPair::generate();
        let mismatch_challenge = Challenge::new("verifier", 60_000, 0);
        let mut mismatch_quote = other.sign_quote("casa1", &measurement, &mismatch_challenge.nonce);
        mismatch_quote.signer_public_key_spki = other.public_key_spki();
        assert_eq!(
            registry.verify_quote(&mismatch_quote, &mismatch_challenge, None, 1),
            Err(AttestationError::KeyMismatch)
        );

        // Expired provider key.
        registry
            .register_provider(ProviderKey {
                provider_id: "expiring".to_string(),
                public_key_spki: key_pair.public_key_spki(),
                registered_at_ms: 0,
                valid_until_ms: Some(500),
            })
            .expect("registration succeeds");
        let expired_challenge = Challenge::new("verifier", 600_000, 0);
        let expired_quote = key_pair.sign_quote("expiring", &measurement, &expired_challenge.nonce);
        assert_eq!(
            registry.verify_quote(&expired_quote, &expired_challenge, None, 1_000),
            Err(AttestationError::ProviderKeyExpired)
        );

        // Revocation blocks verification and re-registration.
        assert!(registry.revoke_provider("casa1"));
        assert!(registry.is_revoked("casa1"));
        assert!(!registry.revoke_provider("never-registered"));
        let revoked_challenge = Challenge::new("verifier", 60_000, 0);
        let revoked_quote = key_pair.sign_quote("casa1", &measurement, &revoked_challenge.nonce);
        assert_eq!(
            registry.verify_quote(&revoked_quote, &revoked_challenge, None, 1),
            Err(AttestationError::RevokedProvider)
        );
        assert_eq!(
            registry.register_provider(ProviderKey {
                provider_id: "casa1".to_string(),
                public_key_spki: key_pair.public_key_spki(),
                registered_at_ms: 0,
                valid_until_ms: None,
            }),
            Err(AttestationError::RevokedProvider)
        );
        assert!(registry.provider("expiring").is_some());
    }

    #[test]
    fn attestation_key_pair_rejects_malformed_secret_bytes() {
        assert_eq!(
            AttestationKeyPair::from_secret_bytes(&[0u8; 32]).err(),
            Some(AttestationError::MalformedKey)
        );
        let key_pair = AttestationKeyPair::generate();
        let restored = AttestationKeyPair::from_secret_bytes(&key_pair.secret_bytes())
            .expect("restore succeeds");
        assert_eq!(restored.public_key_spki(), key_pair.public_key_spki());
        assert_ne!(key_pair.secret_bytes(), [0u8; 32]);
    }

    #[test]
    fn attestation_wire_rejects_malformed_challenges_and_pins_statuses() {
        let challenge = Challenge::new(ATTESTATION_VERIFIER, 60_000, 17);
        let wire = challenge_to_wire(&challenge);
        assert_eq!(wire.len(), ATTESTATION_CHALLENGE_WIRE_SIZE);
        let restored = challenge_from_wire(&wire).expect("wire round-trip");
        assert_eq!(restored.nonce, challenge.nonce);
        assert_eq!(restored.issued_at_ms, 17);
        assert_eq!(restored.ttl_ms, 60_000);
        assert_eq!(restored.verifier, ATTESTATION_VERIFIER);

        assert_eq!(
            challenge_from_wire(&wire[..ATTESTATION_CHALLENGE_WIRE_SIZE - 1]).err(),
            Some(AttestationError::MalformedChallenge)
        );

        let mut zero_nonce = wire;
        zero_nonce[0..32].fill(0);
        assert_eq!(
            challenge_from_wire(&zero_nonce).err(),
            Some(AttestationError::MalformedChallenge)
        );

        let mut zero_ttl = wire;
        zero_ttl[40..48].fill(0);
        assert_eq!(
            challenge_from_wire(&zero_ttl).err(),
            Some(AttestationError::MalformedChallenge)
        );

        assert_eq!(
            attestation_ntstatus(&AttestationError::NoProvider),
            0xC000_00BB
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::UnknownProvider),
            0xC000_0034
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::ChallengeReplayed),
            0xC000_0022
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::ChallengeExpired),
            0xC000_0102
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::MalformedQuote),
            0xC000_000D
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::RevokedProvider),
            0xC000_0022
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::KeyMismatch),
            0xC000_0022
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::InvalidSignature),
            0xC000_0022
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::MeasurementMismatch),
            0xC000_0022
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::ProviderKeyExpired),
            0xC000_0102
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::MalformedChallenge),
            0xC000_000D
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::NonceMismatch),
            0xC000_000D
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::MalformedKey),
            0xC000_000D
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::Io(String::new())),
            0xC000_0001
        );
        assert_eq!(
            install_attestation_key("").err(),
            Some(AttestationError::MalformedKey)
        );
        let first = install_attestation_key("install-one").expect("derived key");
        let second = install_attestation_key("install-one").expect("stable key");
        let other = install_attestation_key("install-two").expect("other key");
        assert_eq!(first.public_key_spki(), second.public_key_spki());
        assert_ne!(first.public_key_spki(), other.public_key_spki());
    }

    #[test]
    fn install_identity_store_persists_and_rejects_malformed_state() {
        let dir = temp_dir("store");
        let store = InstallIdentityStore::open(&dir);
        assert_eq!(store.root(), dir.as_path());

        let first = store.load_or_create_keypair().expect("create key");
        let second = store.load_or_create_keypair().expect("reload key");
        assert_eq!(first.public_key_spki(), second.public_key_spki());

        assert_eq!(store.load_provider("acme").expect("load missing"), None);
        let installed = store
            .install_provider("acme", Some(10_000), 5)
            .expect("install provider");
        assert_eq!(installed.provider_id, "acme");
        let loaded = store
            .load_provider("acme")
            .expect("load provider")
            .expect("provider present");
        assert_eq!(loaded.public_key_spki, installed.public_key_spki);

        assert!(!store.is_revoked("acme"));
        assert!(store.revoke_provider("acme").expect("revoke"));
        assert!(store.is_revoked("acme"));
        assert!(!store.revoke_provider("acme").expect("revoke again"));
        assert_eq!(
            store.install_provider("acme", None, 6),
            Err(AttestationError::RevokedProvider)
        );

        // Malformed provider JSON is rejected.
        std::fs::write(dir.join("providers/garbage.pub"), b"not json").expect("write garbage");
        assert_eq!(
            store.load_provider("garbage").err(),
            Some(AttestationError::MalformedKey)
        );

        // Non-hex key bytes and wrong-length key bytes are rejected.
        std::fs::write(dir.join("attestation_key.hex"), b"not-hex").expect("write bad hex");
        assert_eq!(
            store.load_or_create_keypair().err(),
            Some(AttestationError::MalformedKey)
        );
        std::fs::write(dir.join("attestation_key.hex"), b"00").expect("write short key");
        assert_eq!(
            store.load_or_create_keypair().err(),
            Some(AttestationError::MalformedKey)
        );

        // A store whose root is a regular file cannot be created.
        let base = temp_dir("bad");
        std::fs::create_dir_all(&base).expect("create base");
        let file_root = base.join("afile");
        std::fs::write(&file_root, b"x").expect("write file root");
        let bad_store = InstallIdentityStore::open(&file_root);
        assert!(matches!(
            bad_store.load_or_create_keypair(),
            Err(AttestationError::Io(_))
        ));
        assert!(!bad_store.is_revoked("acme"));

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn provider_enrollment_rejects_duplicate_malformed_and_revoked_ids_exactly() {
        let dir = temp_dir("enroll");
        let store = InstallIdentityStore::open(&dir);
        let key = AttestationKeyPair::generate();
        let spki = key.public_key_spki();

        // Provider ids become store file names; separators/empty/oversize are
        // malformed.
        assert!(!is_valid_provider_id(""));
        assert!(!is_valid_provider_id("bad/id"));
        assert!(!is_valid_provider_id("bad id"));
        assert!(is_valid_provider_id("acme.provider-1"));
        assert_eq!(
            store.enroll_provider_key("", &spki, None, 0).err(),
            Some(AttestationError::MalformedKey)
        );
        assert_eq!(
            store.enroll_provider_key("acme", &[], None, 0).err(),
            Some(AttestationError::MalformedKey)
        );
        assert_eq!(
            store
                .enroll_provider_key("acme", &[0x00, 0x01], None, 0)
                .err(),
            Some(AttestationError::MalformedKey)
        );

        let key_record = store
            .enroll_provider_key("acme", &spki, Some(10_000), 7)
            .expect("enroll provider");
        assert_eq!(key_record.provider_id, "acme");
        assert_eq!(key_record.public_key_spki, spki);
        assert_eq!(key_record.valid_until_ms, Some(10_000));
        assert_eq!(
            store.enroll_provider_key("acme", &spki, None, 8).err(),
            Some(AttestationError::DuplicateProvider)
        );
        assert_eq!(
            store.load_provider("acme").expect("load").expect("present"),
            key_record
        );
        assert_eq!(
            attestation_ntstatus(&AttestationError::DuplicateProvider),
            0xC000_0035
        );

        // Revocation persists and blocks re-enrollment.
        assert!(store.revoke_provider("acme").expect("revoke"));
        assert!(store.is_revoked("acme"));
        assert_eq!(
            store.enroll_provider_key("acme", &spki, None, 9).err(),
            Some(AttestationError::RevokedProvider)
        );
        assert!(
            !store
                .revoke_provider("never-enrolled")
                .expect("revoke unknown")
        );

        // In-memory registration is duplicate-rejecting too.
        let mut registry = AttestationRegistry::new();
        let record = ProviderKey {
            provider_id: "acme".to_string(),
            public_key_spki: spki,
            registered_at_ms: 0,
            valid_until_ms: None,
        };
        registry
            .register_provider(record.clone())
            .expect("register");
        assert_eq!(
            registry.register_provider(record).err(),
            Some(AttestationError::DuplicateProvider)
        );
        assert_eq!(registry.provider_ids(), vec!["acme".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn challenge_validity_rejects_malformed_and_expired() {
        let challenge = Challenge::new("verifier", 100, 1_000);
        assert_eq!(challenge.is_well_formed(), true);
        assert_eq!(challenge.is_expired(1_100), false);
        assert_eq!(challenge.is_expired(1_101), true);

        let mut zero_ttl = Challenge::new("verifier", 0, 0);
        assert_eq!(zero_ttl.is_well_formed(), false);
        zero_ttl.ttl_ms = 5;
        zero_ttl.verifier.clear();
        assert_eq!(zero_ttl.is_well_formed(), false);
    }
}
