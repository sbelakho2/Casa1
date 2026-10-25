//! Process and thread executive for the CasaK personality.
//!
//! The manager owns real process/thread records with monotonic identifiers,
//! parent/child links, image-section ownership, termination state, and a real
//! per-process handle table with access masks.  Threads are attached to a
//! [`ThreadScheduler`] implementation at creation time and detached on
//! termination; the island supplies the adapter for the running guest thread.

use std::collections::{BTreeMap, BTreeSet};

use crate::casak::object::{
    DELETE, Handle, ObjectId, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, READ_CONTROL,
    SYNCHRONIZE, THREAD_QUERY_INFORMATION, THREAD_TERMINATE, WRITE_DAC,
};
use crate::casak::status::{
    STATUS_ACCESS_DENIED, STATUS_INVALID_DEVICE_STATE, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_OBJECT_TYPE_MISMATCH, STATUS_PROCESS_IS_TERMINATING,
    STATUS_THREAD_IS_TERMINATING,
};

/// A process identifier. Identifiers are multiples of four, like NT PIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessId(pub u32);

/// A thread identifier. Identifiers are multiples of four, like NT TIDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ThreadId(pub u32);

/// Lifecycle state of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    Active,
    Terminated,
}

/// Lifecycle state of a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Initialized,
    Ready,
    Running,
    Terminated,
}

/// A process record owned by the executive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    pub id: ProcessId,
    pub parent: Option<ProcessId>,
    pub image_name: String,
    pub image_section: Option<ObjectId>,
    pub token: Option<u64>,
    pub state: ProcessState,
    pub exit_status: i32,
    pub threads: BTreeSet<ThreadId>,
    pub children: BTreeSet<ProcessId>,
}

/// A thread record owned by the executive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadRecord {
    pub id: ThreadId,
    pub process: ProcessId,
    pub start_routine: u64,
    pub state: ThreadState,
}

impl ThreadRecord {
    /// Whether the thread can still be scheduled.
    pub fn is_live(&self) -> bool {
        self.state != ThreadState::Terminated
    }
}

/// The scheduler-facing half of a thread.  Implementors register a thread
/// with their dispatcher when it is created and release it on termination.
pub trait ThreadScheduler {
    fn attach_thread(
        &mut self,
        process: ProcessId,
        thread: ThreadId,
        start_routine: u64,
        context: u64,
        stack_base: u64,
        stack_size: u64,
    ) -> Result<(), i32>;
    fn detach_thread(&mut self, process: ProcessId, thread: ThreadId) -> Result<(), i32>;
}

/// A process/thread handle target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandleTarget {
    Process(ProcessId),
    Thread(ThreadId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessHandleEntry {
    owner: ProcessId,
    target: HandleTarget,
    access: u32,
    inheritable: bool,
}

const PROCESS_ALL_ACCESS: u32 =
    PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE | READ_CONTROL | DELETE | WRITE_DAC;
const THREAD_ALL_ACCESS: u32 =
    THREAD_TERMINATE | THREAD_QUERY_INFORMATION | SYNCHRONIZE | READ_CONTROL | DELETE | WRITE_DAC;

/// Process/thread manager with a real handle table and scheduler linkage.
#[derive(Debug)]
pub struct ProcessManager {
    processes: BTreeMap<ProcessId, ProcessRecord>,
    threads: BTreeMap<ThreadId, ThreadRecord>,
    handles: BTreeMap<Handle, ProcessHandleEntry>,
    next_process: u32,
    next_thread: u32,
    next_handle: u32,
}

impl ProcessManager {
    /// Creates an empty manager.  Identifiers start at 4.
    pub fn new() -> Self {
        Self {
            processes: BTreeMap::new(),
            threads: BTreeMap::new(),
            handles: BTreeMap::new(),
            next_process: 4,
            next_thread: 4,
            next_handle: 4,
        }
    }

    /// Creates a process.  A named image must be non-empty; a terminated or
    /// missing parent is rejected before any state changes.
    pub fn create_process(
        &mut self,
        parent: Option<ProcessId>,
        image_name: &str,
        image_section: Option<ObjectId>,
    ) -> Result<ProcessId, i32> {
        if image_name.trim().is_empty() || image_name.contains('\0') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if let Some(parent_id) = parent {
            let parent_record = self
                .processes
                .get(&parent_id)
                .ok_or(STATUS_INVALID_HANDLE)?;
            if parent_record.state == ProcessState::Terminated {
                return Err(STATUS_PROCESS_IS_TERMINATING);
            }
        }
        let id = ProcessId(self.next_process);
        self.next_process += 4;
        self.processes.insert(
            id,
            ProcessRecord {
                id,
                parent,
                image_name: image_name.to_string(),
                image_section,
                token: None,
                state: ProcessState::Active,
                exit_status: 0,
                threads: BTreeSet::new(),
                children: BTreeSet::new(),
            },
        );
        if let Some(parent_id) = parent {
            if let Some(record) = self.processes.get_mut(&parent_id) {
                record.children.insert(id);
            }
        }
        Ok(id)
    }

    /// Inserts a process with an externally supplied id (runtime identity
    /// adoption).  The id must be a non-zero multiple of four.
    pub fn ensure_process(
        &mut self,
        id: ProcessId,
        image_name: &str,
        parent: Option<ProcessId>,
    ) -> Result<(), i32> {
        if id.0 == 0 || image_name.trim().is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.processes.contains_key(&id) {
            return Ok(());
        }
        if let Some(parent_id) = parent {
            if !self.processes.contains_key(&parent_id) {
                return Err(STATUS_INVALID_HANDLE);
            }
        }
        self.next_process = self.next_process.max(id.0 + 4);
        self.processes.insert(
            id,
            ProcessRecord {
                id,
                parent,
                image_name: image_name.to_string(),
                image_section: None,
                token: None,
                state: ProcessState::Active,
                exit_status: 0,
                threads: BTreeSet::new(),
                children: BTreeSet::new(),
            },
        );
        if let Some(parent_id) = parent {
            if let Some(record) = self.processes.get_mut(&parent_id) {
                record.children.insert(id);
            }
        }
        Ok(())
    }

    /// Creates a thread and attaches it to `scheduler`.  A scheduler refusal
    /// aborts the creation without leaving a thread record behind.
    pub fn create_thread(
        &mut self,
        scheduler: &mut impl ThreadScheduler,
        process: ProcessId,
        start_routine: u64,
    ) -> Result<ThreadId, i32> {
        self.create_thread_ex(scheduler, process, start_routine, 0, 0, 0)
    }

    /// Creates a thread with the full island execution record: start context,
    /// kernel stack base and size.  The scheduler receives the same values so
    /// it can execute the thread without consulting private process state.
    pub fn create_thread_ex(
        &mut self,
        scheduler: &mut impl ThreadScheduler,
        process: ProcessId,
        start_routine: u64,
        context: u64,
        stack_base: u64,
        stack_size: u64,
    ) -> Result<ThreadId, i32> {
        let record = self.processes.get(&process).ok_or(STATUS_INVALID_HANDLE)?;
        if record.state == ProcessState::Terminated {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        if start_routine == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let id = ThreadId(self.next_thread);
        self.next_thread += 4;
        scheduler.attach_thread(process, id, start_routine, context, stack_base, stack_size)?;
        self.threads.insert(
            id,
            ThreadRecord {
                id,
                process,
                start_routine,
                state: ThreadState::Ready,
            },
        );
        if let Some(record) = self.processes.get_mut(&process) {
            record.threads.insert(id);
        }
        Ok(id)
    }

    /// Registers an externally created thread (runtime identity adoption)
    /// without re-attaching it to a second scheduler.
    pub fn ensure_thread(
        &mut self,
        process: ProcessId,
        id: ThreadId,
        start_routine: u64,
    ) -> Result<(), i32> {
        if id.0 == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let record = self.processes.get(&process).ok_or(STATUS_INVALID_HANDLE)?;
        if record.state == ProcessState::Terminated {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        if self.threads.contains_key(&id) {
            return Ok(());
        }
        self.next_thread = self.next_thread.max(id.0 + 4);
        self.threads.insert(
            id,
            ThreadRecord {
                id,
                process,
                start_routine,
                state: ThreadState::Running,
            },
        );
        if let Some(record) = self.processes.get_mut(&process) {
            record.threads.insert(id);
        }
        Ok(())
    }

    /// Moves a ready thread to running.  A running thread is already started.
    pub fn start_thread(&mut self, thread: ThreadId) -> Result<(), i32> {
        let record = self.threads.get_mut(&thread).ok_or(STATUS_INVALID_HANDLE)?;
        match record.state {
            ThreadState::Ready | ThreadState::Initialized => {
                record.state = ThreadState::Running;
                Ok(())
            }
            ThreadState::Running => Err(STATUS_INVALID_DEVICE_STATE),
            ThreadState::Terminated => Err(STATUS_THREAD_IS_TERMINATING),
        }
    }

    /// Terminates one thread and detaches it from the scheduler.
    pub fn terminate_thread(
        &mut self,
        scheduler: &mut impl ThreadScheduler,
        thread: ThreadId,
    ) -> Result<(), i32> {
        let process = {
            let record = self.threads.get(&thread).ok_or(STATUS_INVALID_HANDLE)?;
            if record.state == ThreadState::Terminated {
                return Err(STATUS_THREAD_IS_TERMINATING);
            }
            record.process
        };
        scheduler.detach_thread(process, thread)?;
        if let Some(record) = self.threads.get_mut(&thread) {
            record.state = ThreadState::Terminated;
        }
        if let Some(record) = self.processes.get_mut(&process) {
            record.threads.remove(&thread);
        }
        Ok(())
    }

    /// Terminates a process: every live thread is detached and marked
    /// terminated, the process leaves its parent's child set, and the record
    /// moves to the terminated state.  Returns the number of threads stopped.
    pub fn terminate_process(
        &mut self,
        scheduler: &mut impl ThreadScheduler,
        process: ProcessId,
    ) -> Result<usize, i32> {
        let (threads, parent) = {
            let record = self.processes.get(&process).ok_or(STATUS_INVALID_HANDLE)?;
            if record.state == ProcessState::Terminated {
                return Err(STATUS_PROCESS_IS_TERMINATING);
            }
            (record.threads.clone(), record.parent)
        };
        let mut terminated = 0;
        for thread in threads {
            scheduler.detach_thread(process, thread)?;
            if let Some(record) = self.threads.get_mut(&thread) {
                record.state = ThreadState::Terminated;
            }
            terminated += 1;
        }
        if let Some(record) = self.processes.get_mut(&process) {
            record.threads.clear();
            record.state = ProcessState::Terminated;
            record.exit_status = STATUS_PROCESS_IS_TERMINATING;
        }
        if let Some(parent_id) = parent {
            if let Some(record) = self.processes.get_mut(&parent_id) {
                record.children.remove(&process);
            }
        }
        Ok(terminated)
    }

    /// Opens a process, granting an access mask.  Unknown rights and
    /// terminated targets fail closed.
    pub fn open_process(
        &mut self,
        owner: ProcessId,
        target: ProcessId,
        access: u32,
        inheritable: bool,
    ) -> Result<Handle, i32> {
        self.require_owner(owner)?;
        let record = self.processes.get(&target).ok_or(STATUS_INVALID_HANDLE)?;
        if record.state == ProcessState::Terminated {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        if access == 0 || access & !PROCESS_ALL_ACCESS != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        self.insert_handle(owner, HandleTarget::Process(target), access, inheritable)
    }

    /// Opens a thread with an explicit access mask.
    pub fn open_thread(
        &mut self,
        owner: ProcessId,
        target: ThreadId,
        access: u32,
        inheritable: bool,
    ) -> Result<Handle, i32> {
        self.require_owner(owner)?;
        let record = self.threads.get(&target).ok_or(STATUS_INVALID_HANDLE)?;
        if record.state == ThreadState::Terminated {
            return Err(STATUS_THREAD_IS_TERMINATING);
        }
        if access == 0 || access & !THREAD_ALL_ACCESS != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        self.insert_handle(owner, HandleTarget::Thread(target), access, inheritable)
    }

    /// Duplicates a handle inside the same process.  Requested access must be
    /// covered by the source handle.
    pub fn duplicate_handle(
        &mut self,
        owner: ProcessId,
        source: Handle,
        access: u32,
        inheritable: bool,
    ) -> Result<Handle, i32> {
        let entry = self.lookup_handle(owner, source)?;
        let effective = if access == 0 { entry.access } else { access };
        if effective & !entry.access != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        self.insert_handle(owner, entry.target, effective, inheritable)
    }

    /// Duplicates every inheritable handle from `parent` into `child`.
    pub fn inherit_handles(
        &mut self,
        parent: ProcessId,
        child: ProcessId,
    ) -> Result<Vec<Handle>, i32> {
        self.require_owner(parent)?;
        self.require_owner(child)?;
        let inheritable: Vec<(HandleTarget, u32)> = self
            .handles
            .values()
            .filter(|entry| entry.owner == parent && entry.inheritable)
            .map(|entry| (entry.target, entry.access))
            .collect();
        let mut created = Vec::with_capacity(inheritable.len());
        for (target, access) in inheritable {
            created.push(self.insert_handle(child, target, access, true)?);
        }
        Ok(created)
    }

    /// Closes a handle.  Handles are not reference counted by target: closing
    /// removes only the caller's granted access.
    pub fn close_handle(&mut self, owner: ProcessId, handle: Handle) -> Result<(), i32> {
        let entry = self.lookup_handle(owner, handle)?;
        let _ = entry;
        self.handles.remove(&handle);
        Ok(())
    }

    /// Closes every handle owned by a process and returns the count.
    pub fn close_process_handles(&mut self, owner: ProcessId) -> usize {
        let handles: Vec<Handle> = self
            .handles
            .iter()
            .filter_map(|(handle, entry)| (entry.owner == owner).then_some(*handle))
            .collect();
        let count = handles.len();
        for handle in handles {
            self.handles.remove(&handle);
        }
        count
    }

    /// Validates that a handle carries `desired` for a process target.
    pub fn require_process_access(
        &self,
        owner: ProcessId,
        handle: Handle,
        desired: u32,
    ) -> Result<ProcessId, i32> {
        let entry = self.lookup_handle(owner, handle)?;
        let target = match entry.target {
            HandleTarget::Process(target) => target,
            HandleTarget::Thread(_) => return Err(STATUS_OBJECT_TYPE_MISMATCH),
        };
        if desired != 0 && desired & !entry.access != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(target)
    }

    /// Validates that a handle carries `desired` for a thread target.
    pub fn require_thread_access(
        &self,
        owner: ProcessId,
        handle: Handle,
        desired: u32,
    ) -> Result<ThreadId, i32> {
        let entry = self.lookup_handle(owner, handle)?;
        let target = match entry.target {
            HandleTarget::Thread(target) => target,
            HandleTarget::Process(_) => return Err(STATUS_OBJECT_TYPE_MISMATCH),
        };
        if desired != 0 && desired & !entry.access != 0 {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(target)
    }

    /// Binds an image section to a process.
    pub fn set_image_section(
        &mut self,
        process: ProcessId,
        section: Option<ObjectId>,
    ) -> Result<(), i32> {
        let record = self
            .processes
            .get_mut(&process)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if record.state == ProcessState::Terminated {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        record.image_section = section;
        Ok(())
    }

    /// Binds a security token identifier to a process.
    pub fn set_token(&mut self, process: ProcessId, token: Option<u64>) -> Result<(), i32> {
        let record = self
            .processes
            .get_mut(&process)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if record.state == ProcessState::Terminated {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        record.token = token;
        Ok(())
    }

    pub fn query_process(&self, process: ProcessId) -> Result<&ProcessRecord, i32> {
        self.processes.get(&process).ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn query_thread(&self, thread: ThreadId) -> Result<&ThreadRecord, i32> {
        self.threads.get(&thread).ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn children(&self, process: ProcessId) -> Result<Vec<ProcessId>, i32> {
        Ok(self
            .query_process(process)?
            .children
            .iter()
            .copied()
            .collect())
    }

    pub fn process_threads(&self, process: ProcessId) -> Result<Vec<ThreadId>, i32> {
        Ok(self
            .query_process(process)?
            .threads
            .iter()
            .copied()
            .collect())
    }

    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }

    pub fn handle_count(&self, owner: ProcessId) -> usize {
        self.handles
            .values()
            .filter(|entry| entry.owner == owner)
            .count()
    }

    pub fn handle_entry(&self, owner: ProcessId, handle: Handle) -> Result<(u32, bool), i32> {
        let entry = self.lookup_handle(owner, handle)?;
        Ok((entry.access, entry.inheritable))
    }

    fn require_owner(&self, owner: ProcessId) -> Result<(), i32> {
        let record = self.processes.get(&owner).ok_or(STATUS_INVALID_HANDLE)?;
        if record.state == ProcessState::Terminated {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        Ok(())
    }

    fn lookup_handle(&self, owner: ProcessId, handle: Handle) -> Result<ProcessHandleEntry, i32> {
        if handle.is_null() {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.handles
            .get(&handle)
            .copied()
            .filter(|entry| entry.owner == owner)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    fn insert_handle(
        &mut self,
        owner: ProcessId,
        target: HandleTarget,
        access: u32,
        inheritable: bool,
    ) -> Result<Handle, i32> {
        let handle = Handle(self.next_handle);
        self.next_handle = self.next_handle.saturating_add(4);
        self.handles.insert(
            handle,
            ProcessHandleEntry {
                owner,
                target,
                access,
                inheritable,
            },
        );
        Ok(handle)
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casak::status::STATUS_INSUFFICIENT_RESOURCES;

    #[derive(Default)]
    struct RecordingScheduler {
        attached: Vec<(ProcessId, ThreadId)>,
        detached: Vec<(ProcessId, ThreadId)>,
        fail_attach: bool,
        fail_detach: bool,
    }

    impl ThreadScheduler for RecordingScheduler {
        fn attach_thread(
            &mut self,
            process: ProcessId,
            thread: ThreadId,
            _start_routine: u64,
            _context: u64,
            _stack_base: u64,
            _stack_size: u64,
        ) -> Result<(), i32> {
            if self.fail_attach {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            self.attached.push((process, thread));
            Ok(())
        }

        fn detach_thread(&mut self, process: ProcessId, thread: ThreadId) -> Result<(), i32> {
            if self.fail_detach {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            self.detached.push((process, thread));
            Ok(())
        }
    }

    #[test]
    fn process_creation_rejects_invalid_parents_and_images() {
        assert_eq!(ProcessManager::default().process_count(), 0);
        let mut manager = ProcessManager::new();
        assert_eq!(
            manager.create_process(None, "", None),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.create_process(None, "bad\0name", None),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.create_process(Some(ProcessId(999)), "child.exe", None),
            Err(STATUS_INVALID_HANDLE)
        );
        let parent = manager.create_process(None, "parent.exe", None).unwrap();
        let child = manager
            .create_process(Some(parent), "child.exe", Some(ObjectId(7)))
            .unwrap();
        assert_eq!(manager.children(parent).unwrap(), vec![child]);
        assert_eq!(
            manager.query_process(child).unwrap().image_section,
            Some(ObjectId(7))
        );
        assert_eq!(
            manager.create_process(Some(ProcessId(0)), "orphan.exe", None),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.process_count(), 2);
    }

    #[test]
    fn adopted_process_identity_rejects_bad_ids_and_missing_parents() {
        let mut manager = ProcessManager::new();
        assert_eq!(
            manager.ensure_process(ProcessId(0), "system", None),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.ensure_process(ProcessId(8), "", None),
            Err(STATUS_INVALID_PARAMETER)
        );
        manager.ensure_process(ProcessId(6), "odd", None).unwrap();
        assert_eq!(
            manager.ensure_process(ProcessId(8), "child", Some(ProcessId(404))),
            Err(STATUS_INVALID_HANDLE)
        );
        manager
            .ensure_process(ProcessId(8), "system", None)
            .unwrap();
        manager
            .ensure_process(ProcessId(8), "ignored", None)
            .unwrap();
        manager
            .ensure_process(ProcessId(12), "child", Some(ProcessId(8)))
            .unwrap();
        assert_eq!(manager.children(ProcessId(8)).unwrap(), vec![ProcessId(12)]);
        assert_eq!(manager.process_count(), 3);
    }

    #[test]
    fn thread_creation_attach_and_termination_rejects_stale_state() {
        let mut manager = ProcessManager::new();
        let process = manager.create_process(None, "proc", None).unwrap();
        let mut scheduler = RecordingScheduler::default();
        assert_eq!(
            manager.create_thread(&mut scheduler, ProcessId(404), 0x1000),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.create_thread(&mut scheduler, process, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
        let thread = manager
            .create_thread(&mut scheduler, process, 0x1000)
            .unwrap();
        assert_eq!(scheduler.attached, vec![(process, thread)]);
        assert_eq!(manager.start_thread(thread), Ok(()));
        assert_eq!(
            manager.start_thread(thread),
            Err(STATUS_INVALID_DEVICE_STATE)
        );
        assert_eq!(manager.terminate_thread(&mut scheduler, thread), Ok(()));
        assert_eq!(
            manager.terminate_thread(&mut scheduler, thread),
            Err(STATUS_THREAD_IS_TERMINATING)
        );
        assert_eq!(
            manager.terminate_thread(&mut scheduler, ThreadId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(scheduler.detached, vec![(process, thread)]);
        assert!(!manager.query_thread(thread).unwrap().is_live());
        assert_eq!(
            manager.start_thread(thread),
            Err(STATUS_THREAD_IS_TERMINATING)
        );
    }

    #[test]
    fn scheduler_refusals_abort_thread_creation_and_detach() {
        let mut manager = ProcessManager::new();
        let process = manager.create_process(None, "proc", None).unwrap();
        let mut refusing = RecordingScheduler {
            fail_attach: true,
            ..RecordingScheduler::default()
        };
        assert_eq!(
            manager.create_thread(&mut refusing, process, 0x2000),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(manager.thread_count(), 0);
        let mut failing_detach = RecordingScheduler {
            fail_detach: true,
            ..RecordingScheduler::default()
        };
        let thread = manager
            .create_thread(&mut failing_detach, process, 0x2000)
            .unwrap();
        assert_eq!(
            manager.terminate_thread(&mut failing_detach, thread),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert!(manager.query_thread(thread).unwrap().is_live());
    }

    #[test]
    fn adopted_threads_reject_invalid_ids_and_terminated_processes() {
        let mut manager = ProcessManager::new();
        manager.ensure_process(ProcessId(16), "proc", None).unwrap();
        assert_eq!(
            manager.ensure_thread(ProcessId(16), ThreadId(0), 1),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.ensure_thread(ProcessId(404), ThreadId(20), 1),
            Err(STATUS_INVALID_HANDLE)
        );
        manager
            .ensure_thread(ProcessId(16), ThreadId(20), 0x3000)
            .unwrap();
        manager
            .ensure_thread(ProcessId(16), ThreadId(20), 0x3000)
            .unwrap();
        assert_eq!(
            manager.query_thread(ThreadId(20)).unwrap().state,
            ThreadState::Running
        );
        let mut scheduler = RecordingScheduler::default();
        manager
            .terminate_process(&mut scheduler, ProcessId(16))
            .unwrap();
        assert_eq!(
            manager.ensure_thread(ProcessId(16), ThreadId(24), 1),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
        assert_eq!(
            manager.create_process(Some(ProcessId(16)), "child", None),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
    }

    #[test]
    fn process_termination_detaches_threads_and_rejects_repeat() {
        let mut manager = ProcessManager::new();
        let parent = manager.create_process(None, "parent", None).unwrap();
        let child = manager.create_process(Some(parent), "child", None).unwrap();
        let mut scheduler = RecordingScheduler::default();
        let first = manager
            .create_thread(&mut scheduler, child, 0x1000)
            .unwrap();
        let second = manager
            .create_thread(&mut scheduler, child, 0x2000)
            .unwrap();
        assert_eq!(manager.terminate_process(&mut scheduler, child), Ok(2));
        assert_eq!(parent_children(&manager, parent), Vec::<ProcessId>::new());
        assert_eq!(
            manager.terminate_process(&mut scheduler, child),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
        assert_eq!(
            manager.create_thread(&mut scheduler, child, 0x3000),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
        assert_eq!(
            manager.terminate_process(&mut scheduler, ProcessId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(scheduler.detached.len(), 2);
        assert!(scheduler.detached.contains(&(child, first)));
        assert!(scheduler.detached.contains(&(child, second)));
        assert!(manager.process_threads(child).unwrap().is_empty());
        assert_eq!(
            manager.set_image_section(child, None),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
        assert_eq!(
            manager.set_image_section(ProcessId(404), None),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.set_token(child, Some(9)),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
        assert_eq!(
            manager.set_token(ProcessId(404), None),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    fn parent_children(manager: &ProcessManager, parent: ProcessId) -> Vec<ProcessId> {
        manager.children(parent).unwrap()
    }

    #[test]
    fn process_and_thread_handle_access_rejects_invalid_requests() {
        let mut manager = ProcessManager::new();
        let owner = manager.create_process(None, "owner", None).unwrap();
        let target = manager.create_process(None, "target", None).unwrap();
        let mut scheduler = RecordingScheduler::default();
        let thread = manager
            .create_thread(&mut scheduler, target, 0x1000)
            .unwrap();
        assert_eq!(
            manager.open_process(owner, target, 0, false),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            manager.open_process(owner, target, 0x8000_0000, false),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            manager.open_process(owner, ProcessId(404), PROCESS_TERMINATE, false),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.open_process(ProcessId(404), target, PROCESS_TERMINATE, false),
            Err(STATUS_INVALID_HANDLE)
        );
        let handle = manager
            .open_process(owner, target, PROCESS_TERMINATE, true)
            .unwrap();
        assert_eq!(
            manager.require_process_access(owner, Handle::NULL, PROCESS_TERMINATE),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.require_process_access(owner, handle, PROCESS_TERMINATE),
            Ok(target)
        );
        assert_eq!(
            manager.require_process_access(owner, handle, PROCESS_QUERY_INFORMATION),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            manager.require_process_access(ProcessId(404), handle, PROCESS_TERMINATE),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.require_thread_access(owner, handle, THREAD_TERMINATE),
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        );
        assert_eq!(
            manager.duplicate_handle(owner, handle, PROCESS_QUERY_INFORMATION, false),
            Err(STATUS_ACCESS_DENIED)
        );
        let duplicate = manager.duplicate_handle(owner, handle, 0, false).unwrap();
        assert_eq!(
            manager.handle_entry(owner, duplicate).unwrap(),
            (PROCESS_TERMINATE, false)
        );
        assert_eq!(manager.handle_count(owner), 2);
        assert_eq!(manager.close_handle(owner, duplicate), Ok(()));
        assert_eq!(
            manager.close_handle(owner, duplicate),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.close_handle(ProcessId(404), handle),
            Err(STATUS_INVALID_HANDLE)
        );

        let thread_handle = manager
            .open_thread(owner, thread, THREAD_TERMINATE, false)
            .unwrap();
        assert_eq!(
            manager.require_thread_access(owner, thread_handle, THREAD_TERMINATE),
            Ok(thread)
        );
        assert_eq!(
            manager.require_thread_access(owner, thread_handle, THREAD_QUERY_INFORMATION),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            manager.require_process_access(owner, thread_handle, PROCESS_TERMINATE),
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        );
        assert_eq!(
            manager.open_thread(owner, thread, 0, false),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            manager.open_thread(owner, thread, 0x8000_0000, false),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            manager.open_thread(owner, ThreadId(404), THREAD_TERMINATE, false),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.duplicate_handle(owner, Handle::NULL, 0, false),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.close_process_handles(owner), 2);
        assert_eq!(manager.handle_count(owner), 0);
    }

    #[test]
    fn terminated_targets_and_stale_handles_are_refused() {
        let mut manager = ProcessManager::new();
        let owner = manager.create_process(None, "owner", None).unwrap();
        let target = manager.create_process(None, "target", None).unwrap();
        let mut scheduler = RecordingScheduler::default();
        let thread = manager
            .create_thread(&mut scheduler, target, 0x1000)
            .unwrap();
        let handle = manager
            .open_process(owner, target, PROCESS_QUERY_INFORMATION, false)
            .unwrap();
        let thread_handle = manager
            .open_thread(owner, thread, THREAD_QUERY_INFORMATION, false)
            .unwrap();
        manager.terminate_thread(&mut scheduler, thread).unwrap();
        assert_eq!(
            manager.open_thread(owner, thread, THREAD_QUERY_INFORMATION, false),
            Err(STATUS_THREAD_IS_TERMINATING)
        );
        assert_eq!(
            manager.require_thread_access(owner, thread_handle, 0),
            Ok(thread)
        );
        manager.terminate_process(&mut scheduler, target).unwrap();
        assert_eq!(
            manager.open_process(owner, target, PROCESS_QUERY_INFORMATION, false),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
        assert_eq!(manager.require_process_access(owner, handle, 0), Ok(target));
        assert_eq!(
            manager.open_process(target, owner, PROCESS_QUERY_INFORMATION, false),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
    }

    #[test]
    fn inheritable_handles_duplicate_and_private_handles_do_not() {
        let mut manager = ProcessManager::new();
        let parent = manager.create_process(None, "parent", None).unwrap();
        let child = manager.create_process(None, "child", None).unwrap();
        let target = manager.create_process(None, "target", None).unwrap();
        let shared = manager
            .open_process(parent, target, PROCESS_QUERY_INFORMATION, true)
            .unwrap();
        let private = manager
            .open_process(parent, target, PROCESS_TERMINATE, false)
            .unwrap();
        let inherited = manager.inherit_handles(parent, child).unwrap();
        assert_eq!(inherited.len(), 1);
        assert_eq!(manager.handle_count(child), 1);
        assert_eq!(
            manager.require_process_access(child, inherited[0], PROCESS_QUERY_INFORMATION),
            Ok(target)
        );
        manager.close_handle(parent, shared).unwrap();
        assert_eq!(
            manager.require_process_access(child, inherited[0], 0),
            Ok(target)
        );
        manager.close_handle(parent, private).unwrap();
        assert_eq!(
            manager.inherit_handles(ProcessId(404), child),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.inherit_handles(parent, ProcessId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn record_queries_report_identity_and_counts() {
        let mut manager = ProcessManager::new();
        let process = manager.create_process(None, "proc", None).unwrap();
        assert_eq!(manager.query_process(process).unwrap().image_name, "proc");
        assert_eq!(
            manager.query_process(ProcessId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.query_thread(ThreadId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.thread_count(), 0);
        assert_eq!(manager.handle_count(process), 0);
        assert_eq!(manager.process_threads(process).unwrap(), Vec::new());
        assert!(manager.children(process).unwrap().is_empty());
        assert_eq!(
            manager.set_image_section(process, Some(ObjectId(2))),
            Ok(())
        );
        assert_eq!(
            manager.query_process(process).unwrap().image_section,
            Some(ObjectId(2))
        );
        assert_eq!(manager.set_token(process, Some(3)), Ok(()));
        assert_eq!(manager.query_process(process).unwrap().token, Some(3));
    }
}
