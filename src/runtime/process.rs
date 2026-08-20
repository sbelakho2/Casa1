// Stage-3 canonical-state surface: the Win32Subsystem integration that consumes these types is the next work item; removing this allowance is part of that integration.
//! Canonical guest process model.
//!
//! The GUEST PID is a Casa1 guest identity: a runtime-side counter starting
//! at 4, allocated from ONE namespace ([`allocate_guest_pid`]).
//! `GetCurrentProcessId`/`GetCurrentProcess` return the guest pid; the
//! host's POSIX pid (`std::process::id()`) is confined to diagnostics only
//! (the runner's provenance, e.g. the toolhelp "macwin" snapshot entry).
//!
//! A [`GuestProcess`] owns its identity (pid, parent, image, command line,
//! argv, environment, cwd, arch, PEB), its address space — the canonical
//! [`crate::vm::VirtualMemory`] shared with the interpreter and the JIT —
//! its [`HandleTable`](crate::runtime::handle_table::HandleTable), its
//! module list and its exit state.

use crate::runtime::handle_table::HandleTable;
use crate::vm::VirtualMemory;
use std::collections::BTreeMap;

/// The guest environment block (a sorted key/value map; the UTF-16 block
/// serialization is a subsystem concern).
pub type EnvironmentBlock = BTreeMap<String, String>;

/// The guest process's loaded module list (image paths / module names).
pub type ModuleList = Vec<String>;

/// Guest thread id type.
pub type ThreadId = u32;

/// Exit state of a guest process: running, or exited with a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessExitState {
    Running,
    Exited(u32),
}

/// The runtime-side guest PID allocator.  ONE counter across every
/// subsystem instance, starting at 4 (Windows reserves 0-3; the main guest
/// process is the first allocation).
static NEXT_GUEST_PID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(4);

/// Allocate a guest process id from the single guest PID namespace.
pub fn allocate_guest_pid() -> u32 {
    NEXT_GUEST_PID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Initial process context passed to [`GuestProcess::new`]: image path,
/// command line, argv, environment, cwd and arch.
#[derive(Debug, Clone)]
pub struct InitialProcessContext {
    pub image_path: String,
    pub command_line: String,
    pub argv: Vec<String>,
    pub environment: EnvironmentBlock,
    pub cwd: String,
    pub arch: crate::cpu::GuestArch,
}

impl InitialProcessContext {
    /// The default standalone context (diagnostic "macwin" provenance).
    pub fn macwin_default() -> Self {
        Self {
            image_path: "macwin".to_string(),
            command_line: "macwin".to_string(),
            argv: vec!["macwin".to_string()],
            environment: EnvironmentBlock::new(),
            cwd: "C:\\".to_string(),
            arch: GuestArch::X64,
        }
    }
}

/// The canonical guest process.
#[derive(Debug)]
pub struct GuestProcess {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub image_path: String,
    pub command_line: String,
    pub argv: Vec<String>,
    pub environment: EnvironmentBlock,
    pub cwd: String,
    pub arch: crate::cpu::GuestArch,
    /// Guest PEB address (0 until the loader maps the process image).
    pub peb: u64,
    /// THE canonical guest address space: the SAME `VirtualMemory` instance
    /// the interpreter and the JIT validate every access through.
    pub address_space: VirtualMemory,
    /// THE canonical handle table of this process.
    pub handle_table: HandleTable,
    pub modules: ModuleList,
    pub primary_thread: ThreadId,
    pub exit_state: ProcessExitState,
}

impl GuestProcess {
    /// Construct a guest process with a pre-allocated pid and an initial
    /// process context (image path, argv, environment, cwd, arch).  The
    /// address space cursor `private_region_cursor` seeds anonymous
    /// reservations.
    pub fn new(
        pid: u32,
        parent_pid: Option<u32>,
        context: InitialProcessContext,
        private_region_cursor: u64,
    ) -> Self {
        let InitialProcessContext {
            image_path,
            command_line,
            argv,
            environment,
            cwd,
            arch,
        } = context;
        Self {
            pid,
            parent_pid,
            image_path,
            command_line,
            argv,
            environment,
            cwd,
            arch,
            peb: 0,
            address_space: VirtualMemory::new(private_region_cursor),
            handle_table: HandleTable::new(),
            modules: Vec::new(),
            primary_thread: 1,
            exit_state: ProcessExitState::Running,
        }
    }

    /// The initial guest process for a standalone subsystem (tests / oracle
    /// sessions): a fresh pid from the guest namespace, a diagnostic
    /// "macwin" image (the runner's provenance — the host pid is NEVER the
    /// guest identity) and the historical standalone address-space cursor.
    pub fn default_initial() -> Self {
        Self::new(
            allocate_guest_pid(),
            None,
            InitialProcessContext::macwin_default(),
            0x1_0000_0000,
        )
    }

    /// Replace the address space (arch switches rebuild the canonical VM
    /// with the arch's private-pages cursor).
    pub fn reset_address_space(&mut self, private_region_cursor: u64) {
        self.address_space = VirtualMemory::new(private_region_cursor);
    }
}

use super::*;

impl PeHostRuntime {
    /// Record an explicit exit request for the calling guest thread.
    ///
    /// While a pumped thread is active, the request is handed to the pump,
    /// which ends the thread immediately (`ExitThread`/`_endthreadex` fire
    /// DLL_THREAD_DETACH, `TerminateThread` does not).  On a non-pumped
    /// context (the main thread) the request ends only the MAIN thread's
    /// execution: Windows ends the process when its LAST thread exits, so
    /// the run keeps pumping pending guest threads while
    /// `main_thread_exit_code` is set, and ends with that code once no
    /// pending threads remain (or a process-exit API is called).
    pub(crate) fn request_current_thread_exit(&mut self, code: u32, fire_detach: bool) {
        if self.active_pumped_guest_thread.is_some() {
            self.pumped_thread_exit_requested = Some(code);
            self.pumped_thread_exit_with_detach = fire_detach;
        } else {
            self.main_thread_exit_code = Some(code);
            // Record the code in the kernel thread state so a wait on the
            // main thread's handle completes (Windows: a thread handle is
            // signaled once the thread exits, even mid-process).
            let _ = self
                .win32
                .set_thread_exit_code_by_id(self.win32.current_thread_id(), code);
        }
    }
}

impl PeHostRuntime {
    /// Pump pending guest threads to completion after the MAIN thread exited
    /// via an explicit thread-exit API (`ExitThread`/`_endthreadex`/
    /// `_endthread`/`TerminateThread` on self) while workers were still
    /// queued.  Windows only ends the process when the LAST thread exits, so
    /// the run must keep pumping until no pending threads remain.
    ///
    /// Returns the final process exit code: a worker that calls a
    /// process-exit API (`ExitProcess`/`exit`/...) wins (process exit
    /// abandons every thread, per Windows); otherwise the main thread's exit
    /// code ends the run.
    pub(crate) fn drain_pending_guest_threads_after_main_exit(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<i32> {
        let main_thread_code = self.main_thread_exit_code.unwrap_or(0) as i32;
        loop {
            if self.pending_guest_threads.is_empty() {
                return Ok(main_thread_code);
            }
            let pump_outcome = self.pump_pending_guest_thread(memory)?;
            if let Some(code) = pump_outcome.process_exit {
                return Ok(code);
            }
            if !pump_outcome.did_work {
                // Nothing runnable (sleeping/suspended workers): advance the
                // guest clock so wake_ticks expire, then retry.
                std::thread::sleep(std::time::Duration::from_millis(1));
                self.win32.record_sleep_observation(1, 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_pids_start_at_four_and_are_unique_across_instances() {
        let first = allocate_guest_pid();
        let second = allocate_guest_pid();
        let third = allocate_guest_pid();
        assert!(first >= 4, "the guest pid namespace starts at 4");
        assert!(second > first);
        assert!(third > second);
    }

    #[test]
    fn guest_pid_never_collides_with_the_host_pid_by_construction() {
        // The guest namespace is a runtime counter; the host pid comes from
        // the OS.  The invariant is that guest pids NEVER come from
        // std::process::id() — GetCurrentProcessId must not leak the host.
        let pid = GuestProcess::default_initial().pid;
        assert_ne!(pid, std::process::id());
    }

    #[test]
    fn guest_process_holds_its_context_and_canonical_state() {
        let mut process = GuestProcess::new(
            4,
            None,
            InitialProcessContext {
                image_path: "C:\\game.exe".to_string(),
                command_line: "game.exe --arg".to_string(),
                argv: vec!["game.exe".to_string(), "--arg".to_string()],
                environment: BTreeMap::from([("PATH".to_string(), "C:\\Windows".to_string())]),
                cwd: "C:\\Games".to_string(),
                arch: GuestArch::X64,
            },
            0x7fff_0000_0000,
        );
        assert_eq!(process.pid, 4);
        assert_eq!(process.image_path, "C:\\game.exe");
        assert_eq!(process.argv[1], "--arg");
        assert_eq!(process.cwd, "C:\\Games");
        assert_eq!(process.arch, GuestArch::X64);
        assert_eq!(process.peb, 0);
        assert_eq!(process.exit_state, ProcessExitState::Running);

        // The address space is the canonical instance: reservations land in
        // it and the handle table is empty but live.
        let base = process.address_space.reserve(None, 0x1000);
        assert_ne!(base, 0);
        let handle =
            process
                .handle_table
                .insert(crate::runtime::object_manager::ObjectId(1), 0, false);
        assert!(process.handle_table.is_live(handle));

        process.exit_state = ProcessExitState::Exited(0);
        assert_eq!(process.exit_state, ProcessExitState::Exited(0));
    }
}
