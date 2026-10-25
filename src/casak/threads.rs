//! Island kernel threads: real guest-executable system threads.
//!
//! A [`KernelThread`] is backed by a [`ProcessManager`] thread record and a
//! scheduler-owned execution record (start routine, context, kernel stack,
//! IRQL, APCs, exit status and a handle).  The driver island pumps ready
//! threads cooperatively: each slice enters translated guest code through the
//! runtime callback executor and returns to the scheduler when the routine
//! returns or calls `PsTerminateSystemThread`.

use std::collections::{BTreeMap, VecDeque};

use crate::casak::process::{ProcessId, ProcessManager, ThreadId, ThreadScheduler};
use crate::casak::status::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND,
    STATUS_THREAD_IS_TERMINATING, STATUS_UNSUCCESSFUL, STATUS_USER_APC,
};
use std::time::Instant;

/// A kernel thread handle.  Closing it never destroys the thread object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SystemThreadHandle(pub u64);

/// A queued APC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApcId(pub u64);

/// Thread lifecycle as seen by the island scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelThreadState {
    Ready,
    Running,
    Waiting,
    Terminated,
}

/// The object a system thread is waiting on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitTarget {
    Event(u64),
    Thread(ThreadId),
}

/// A blocked wait owned by the scheduler.  `None` deadline means infinite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemWait {
    pub target: WaitTarget,
    pub deadline: Option<Instant>,
    pub alertable: bool,
}

/// One deferred APC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemApc {
    pub id: ApcId,
    pub routine: u64,
    pub context: u64,
}

/// One executable kernel thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelThread {
    pub id: ThreadId,
    pub process: ProcessId,
    pub start_routine: u64,
    pub context: u64,
    pub stack_base: u64,
    pub stack_size: u64,
    pub state: KernelThreadState,
    pub exit_status: i32,
    pub irql: u8,
    pub termination_requested: Option<i32>,
    pub apcs: VecDeque<SystemApc>,
    pub wait: Option<SystemWait>,
    pub pending_wake_status: Option<i32>,
}

impl KernelThread {
    pub fn is_terminated(&self) -> bool {
        self.state == KernelThreadState::Terminated
    }
}

/// The runnable slice handed to the island executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnableThread {
    pub id: ThreadId,
    pub process: ProcessId,
    pub start_routine: u64,
    pub context: u64,
    pub stack_base: u64,
    pub stack_size: u64,
}

/// A thread created for the current island process plus its handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreatedThread {
    pub id: ThreadId,
    pub handle: SystemThreadHandle,
}

#[derive(Debug)]
struct PendingAttachment {
    handle: SystemThreadHandle,
    context: u64,
    stack_base: u64,
    stack_size: u64,
}

/// Cooperative kernel-thread scheduler.
#[derive(Debug)]
pub struct SystemThreadManager {
    threads: BTreeMap<ThreadId, KernelThread>,
    handles: BTreeMap<SystemThreadHandle, ThreadId>,
    ready: VecDeque<ThreadId>,
    running: Option<ThreadId>,
    pending_attachment: Option<PendingAttachment>,
    next_handle: u64,
    next_apc: u64,
    created: u64,
    started: u64,
    completed: u64,
    terminated: u64,
}

impl SystemThreadManager {
    pub fn new() -> Self {
        Self {
            threads: BTreeMap::new(),
            handles: BTreeMap::new(),
            ready: VecDeque::new(),
            running: None,
            pending_attachment: None,
            next_handle: 0x100,
            next_apc: 1,
            created: 0,
            started: 0,
            completed: 0,
            terminated: 0,
        }
    }

    /// Creates a kernel thread attached to `processes`.  The kernel stack must
    /// be 16-byte aligned and at least 0x1000 bytes; the start routine and
    /// process are validated by the process manager.
    pub fn create(
        &mut self,
        processes: &mut ProcessManager,
        process: ProcessId,
        start_routine: u64,
        context: u64,
        stack_base: u64,
        stack_size: u64,
    ) -> Result<CreatedThread, i32> {
        if stack_size < 0x1000
            || stack_base % 16 != 0
            || stack_base.checked_add(stack_size).is_none()
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.pending_attachment.is_some() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let handle = SystemThreadHandle(self.next_handle);
        self.next_handle = self.next_handle.saturating_add(4);
        self.pending_attachment = Some(PendingAttachment {
            handle,
            context,
            stack_base,
            stack_size,
        });
        let id = match processes.create_thread_ex(
            self,
            process,
            start_routine,
            context,
            stack_base,
            stack_size,
        ) {
            Ok(id) => id,
            Err(status) => {
                self.pending_attachment = None;
                return Err(status);
            }
        };
        self.created += 1;
        Ok(CreatedThread { id, handle })
    }

    /// Adopts an already-running island thread (the runtime's current thread)
    /// so process termination can detach it without inventing a handle.
    pub fn adopt_thread(&mut self, process: ProcessId, thread: ThreadId) -> Result<(), i32> {
        if self.threads.contains_key(&thread) {
            return Ok(());
        }
        self.threads.insert(
            thread,
            KernelThread {
                id: thread,
                process,
                start_routine: 0,
                context: 0,
                stack_base: 0,
                stack_size: 0,
                state: KernelThreadState::Running,
                exit_status: 0,
                irql: 0,
                termination_requested: None,
                apcs: VecDeque::new(),
                wait: None,
                pending_wake_status: None,
            },
        );
        Ok(())
    }

    /// Takes the next runnable slice.  Running more than one thread at a time
    /// is rejected, as is running a terminated thread.
    pub fn take_next(&mut self) -> Option<RunnableThread> {
        if self.running.is_some() {
            return None;
        }
        while let Some(id) = self.ready.pop_front() {
            let Some(thread) = self.threads.get_mut(&id) else {
                continue;
            };
            if thread.state != KernelThreadState::Ready {
                continue;
            }
            thread.state = KernelThreadState::Running;
            self.running = Some(id);
            self.started += 1;
            return Some(RunnableThread {
                id,
                process: thread.process,
                start_routine: thread.start_routine,
                context: thread.context,
                stack_base: thread.stack_base,
                stack_size: thread.stack_size,
            });
        }
        None
    }

    /// Records the exit of the running slice.  A pending termination request
    /// overrides the routine's return value.
    pub fn finish_current(&mut self, exit_status: i32) -> Result<ThreadId, i32> {
        let id = self.running.ok_or(STATUS_INVALID_HANDLE)?;
        let Some(thread) = self.threads.get_mut(&id) else {
            self.running = None;
            return Err(STATUS_INVALID_HANDLE);
        };
        let requested = thread.termination_requested;
        thread.state = KernelThreadState::Terminated;
        thread.irql = 0;
        thread.exit_status = requested.unwrap_or(exit_status);
        thread.wait = None;
        thread.pending_wake_status = None;
        self.running = None;
        self.completed += 1;
        if requested.is_some() {
            self.terminated += 1;
        }
        Ok(id)
    }

    /// Terminates a thread by handle.  A ready thread is terminated
    /// immediately (the caller must detach it from the process manager); a
    /// running thread records the request and exits at the end of its slice.
    pub fn request_terminate(
        &mut self,
        handle: SystemThreadHandle,
        exit_status: i32,
    ) -> Result<(ThreadId, bool), i32> {
        let id = *self.handles.get(&handle).ok_or(STATUS_INVALID_HANDLE)?;
        let thread = self.threads.get_mut(&id).ok_or(STATUS_INVALID_HANDLE)?;
        match thread.state {
            KernelThreadState::Terminated => Err(STATUS_THREAD_IS_TERMINATING),
            KernelThreadState::Running => {
                thread.termination_requested = Some(exit_status);
                Ok((id, false))
            }
            KernelThreadState::Ready | KernelThreadState::Waiting => {
                thread.state = KernelThreadState::Terminated;
                thread.exit_status = exit_status;
                thread.termination_requested = Some(exit_status);
                thread.wait = None;
                thread.pending_wake_status = None;
                self.ready.retain(|candidate| *candidate != id);
                self.completed += 1;
                self.terminated += 1;
                Ok((id, true))
            }
        }
    }

    /// Requests termination of the currently running thread (the
    /// `PsTerminateSystemThread` path).
    pub fn request_terminate_current(&mut self, exit_status: i32) -> Result<ThreadId, i32> {
        let id = self.running.ok_or(STATUS_INVALID_HANDLE)?;
        if let Some(thread) = self.threads.get_mut(&id) {
            thread.termination_requested = Some(exit_status);
            Ok(id)
        } else {
            self.running = None;
            Err(STATUS_INVALID_HANDLE)
        }
    }

    /// Queues an APC on a live thread.
    pub fn queue_apc(
        &mut self,
        handle: SystemThreadHandle,
        routine: u64,
        context: u64,
    ) -> Result<ApcId, i32> {
        if routine == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let id = *self.handles.get(&handle).ok_or(STATUS_INVALID_HANDLE)?;
        let thread = self.threads.get_mut(&id).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.is_terminated() {
            return Err(STATUS_THREAD_IS_TERMINATING);
        }
        let apc = ApcId(self.next_apc);
        self.next_apc += 1;
        thread.apcs.push_back(SystemApc {
            id: apc,
            routine,
            context,
        });
        if thread.state == KernelThreadState::Waiting
            && thread.wait.is_some_and(|wait| wait.alertable)
        {
            thread.state = KernelThreadState::Ready;
            thread.wait = None;
            thread.pending_wake_status = Some(STATUS_USER_APC);
            self.ready.push_back(id);
        }
        Ok(apc)
    }

    /// Drains the thread's APC queue by thread id (used while a slice runs).
    pub fn take_apcs_by_thread(&mut self, thread: ThreadId) -> Result<Vec<SystemApc>, i32> {
        let record = self.threads.get_mut(&thread).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(record.apcs.drain(..).collect())
    }

    /// Drains the thread's APC queue in FIFO order.
    pub fn take_apcs(&mut self, handle: SystemThreadHandle) -> Result<Vec<SystemApc>, i32> {
        let id = *self.handles.get(&handle).ok_or(STATUS_INVALID_HANDLE)?;
        let thread = self.threads.get_mut(&id).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(thread.apcs.drain(..).collect())
    }

    /// Cancels one queued APC.
    pub fn cancel_apc(&mut self, handle: SystemThreadHandle, apc: ApcId) -> Result<(), i32> {
        let id = *self.handles.get(&handle).ok_or(STATUS_INVALID_HANDLE)?;
        let thread = self.threads.get_mut(&id).ok_or(STATUS_INVALID_HANDLE)?;
        let index = thread
            .apcs
            .iter()
            .position(|candidate| candidate.id == apc)
            .ok_or(STATUS_NOT_FOUND)?;
        thread.apcs.remove(index);
        Ok(())
    }

    /// Closes a handle.  The thread object and its execution state survive.
    pub fn close_handle(&mut self, handle: SystemThreadHandle) -> Result<(), i32> {
        self.handles
            .remove(&handle)
            .map(|_| ())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Exit status for a live or terminated thread, or `None` while running.
    pub fn exit_status(&self, handle: SystemThreadHandle) -> Result<Option<i32>, i32> {
        let id = self.handles.get(&handle).ok_or(STATUS_INVALID_HANDLE)?;
        let thread = self.threads.get(id).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(thread.is_terminated().then_some(thread.exit_status))
    }

    pub fn query(&self, handle: SystemThreadHandle) -> Result<&KernelThread, i32> {
        let id = self.handles.get(&handle).ok_or(STATUS_INVALID_HANDLE)?;
        self.threads.get(id).ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn handle_for(&self, thread: ThreadId) -> Option<SystemThreadHandle> {
        self.handles
            .iter()
            .find_map(|(handle, id)| (*id == thread).then_some(*handle))
    }

    pub fn set_irql(&mut self, thread: ThreadId, irql: u8) -> Result<(), i32> {
        let record = self.threads.get_mut(&thread).ok_or(STATUS_INVALID_HANDLE)?;
        record.irql = irql;
        Ok(())
    }

    pub fn current(&self) -> Option<ThreadId> {
        self.running
    }

    /// Test hook: remove a thread from the ready queue and mark it running
    /// without claiming the scheduler's running slot.
    #[cfg(test)]
    pub fn park_for_wait_test(&mut self, thread: ThreadId) {
        if let Some(record) = self.threads.get_mut(&thread) {
            record.state = KernelThreadState::Running;
        }
        self.ready.retain(|candidate| *candidate != thread);
    }

    /// Test hook: resolve a handle even after the thread object is parked.
    #[cfg(test)]
    pub fn handle_for_target(&self, handle: SystemThreadHandle) -> ThreadId {
        self.handles[&handle]
    }

    /// Requeues the running slice at the tail after its quantum expires or a
    /// virtual interrupt was serviced.  The thread state and IRQL are kept.
    pub fn requeue_current(&mut self) -> Option<ThreadId> {
        let id = self.running.take()?;
        let thread = self
            .threads
            .get_mut(&id)
            .expect("the running thread has a scheduler record");
        if thread.state == KernelThreadState::Running {
            thread.state = KernelThreadState::Ready;
            self.ready.push_back(id);
        }
        Some(id)
    }

    /// Parks the running slice on `wait`.
    pub fn wait_current(&mut self, wait: SystemWait) -> Result<ThreadId, i32> {
        let id = self.running.take().ok_or(STATUS_INVALID_HANDLE)?;
        let thread = self.threads.get_mut(&id).ok_or(STATUS_INVALID_HANDLE)?;
        thread.state = KernelThreadState::Waiting;
        thread.wait = Some(wait);
        Ok(id)
    }

    /// Wakes a waiting thread with the status its wait call must observe.
    pub fn wake(&mut self, thread: ThreadId, status: i32) -> Result<(), i32> {
        let record = self.threads.get_mut(&thread).ok_or(STATUS_INVALID_HANDLE)?;
        if record.state != KernelThreadState::Waiting {
            return Err(STATUS_INVALID_PARAMETER);
        }
        record.state = KernelThreadState::Ready;
        record.wait = None;
        record.pending_wake_status = Some(status);
        self.ready.push_back(thread);
        Ok(())
    }

    /// Cancels a blocked wait on `handle` with `status`.
    pub fn cancel_wait(
        &mut self,
        handle: SystemThreadHandle,
        status: i32,
    ) -> Result<ThreadId, i32> {
        let id = *self.handles.get(&handle).ok_or(STATUS_INVALID_HANDLE)?;
        self.wake(id, status)?;
        Ok(id)
    }

    pub fn thread_record(&self, thread: ThreadId) -> Option<&KernelThread> {
        self.threads.get(&thread)
    }

    pub fn thread_state(&self, thread: ThreadId) -> Option<KernelThreadState> {
        self.threads.get(&thread).map(|record| record.state)
    }

    pub fn wait_of(&self, thread: ThreadId) -> Option<SystemWait> {
        self.threads.get(&thread).and_then(|record| record.wait)
    }

    pub fn waiting_threads(&self) -> Vec<(ThreadId, SystemWait)> {
        self.threads
            .iter()
            .filter_map(|(id, record)| record.wait.map(|wait| (*id, wait)))
            .collect()
    }

    pub fn has_waiting_threads(&self) -> bool {
        self.threads
            .values()
            .any(|record| record.state == KernelThreadState::Waiting)
    }

    pub fn apc_pending(&self, thread: ThreadId) -> bool {
        self.threads
            .get(&thread)
            .is_some_and(|record| !record.apcs.is_empty())
    }

    pub fn set_pending_wake_status(&mut self, thread: ThreadId, status: i32) -> Result<(), i32> {
        let record = self.threads.get_mut(&thread).ok_or(STATUS_INVALID_HANDLE)?;
        record.pending_wake_status = Some(status);
        Ok(())
    }

    pub fn take_wake_status(&mut self, thread: ThreadId) -> Option<i32> {
        self.threads
            .get_mut(&thread)
            .and_then(|record| record.pending_wake_status.take())
    }

    pub fn exit_status_by_id(&self, thread: ThreadId) -> Result<Option<i32>, i32> {
        let record = self.threads.get(&thread).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(record.is_terminated().then_some(record.exit_status))
    }

    /// Returns the next finite wait deadline, used by the pump to sleep only
    /// for the exact timeout window.
    pub fn next_wait_deadline(&self) -> Option<Instant> {
        self.threads
            .values()
            .filter_map(|record| record.wait.and_then(|wait| wait.deadline))
            .min()
    }

    /// Temporarily releases the running slot so a waiting thread can pump
    /// another ready thread.  The waiting record stays `Running`, so it is not
    /// eligible to be picked again.
    pub fn release_running_for_wait(&mut self) -> Option<ThreadId> {
        self.running.take()
    }

    /// Restores the running slot after a nested wait pump.
    pub fn restore_running(&mut self, thread: ThreadId) {
        self.running = Some(thread);
    }

    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }

    pub fn ready_count(&self) -> usize {
        self.ready.len()
    }

    pub fn created_count(&self) -> u64 {
        self.created
    }

    pub fn started_count(&self) -> u64 {
        self.started
    }

    pub fn completed_count(&self) -> u64 {
        self.completed
    }

    pub fn terminated_count(&self) -> u64 {
        self.terminated
    }

    /// Marks a failed slice as an unsuccessful exit.
    pub fn fail_current(&mut self) -> Result<ThreadId, i32> {
        let id = self.running.ok_or(STATUS_INVALID_HANDLE)?;
        self.finish_current(STATUS_UNSUCCESSFUL)?;
        Ok(id)
    }
}

impl ThreadScheduler for SystemThreadManager {
    fn attach_thread(
        &mut self,
        process: ProcessId,
        thread: ThreadId,
        start_routine: u64,
        _context: u64,
        _stack_base: u64,
        _stack_size: u64,
    ) -> Result<(), i32> {
        let pending = self
            .pending_attachment
            .take()
            .ok_or(STATUS_INVALID_PARAMETER)?;
        if self.threads.contains_key(&thread) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.handles.insert(pending.handle, thread);
        self.threads.insert(
            thread,
            KernelThread {
                id: thread,
                process,
                start_routine,
                context: pending.context,
                stack_base: pending.stack_base,
                stack_size: pending.stack_size,
                state: KernelThreadState::Ready,
                exit_status: 0,
                irql: 0,
                termination_requested: None,
                apcs: VecDeque::new(),
                wait: None,
                pending_wake_status: None,
            },
        );
        self.ready.push_back(thread);
        Ok(())
    }

    fn detach_thread(&mut self, _process: ProcessId, thread: ThreadId) -> Result<(), i32> {
        let record = self.threads.get_mut(&thread).ok_or(STATUS_INVALID_HANDLE)?;
        if record.state != KernelThreadState::Terminated {
            record.state = KernelThreadState::Terminated;
            record.exit_status = STATUS_UNSUCCESSFUL;
            self.terminated += 1;
        }
        self.ready.retain(|candidate| *candidate != thread);
        Ok(())
    }
}

impl Default for SystemThreadManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casak::process::ProcessId;
    use crate::casak::status::STATUS_PROCESS_IS_TERMINATING;

    fn manager_with_process() -> (SystemThreadManager, ProcessManager, ProcessId) {
        let manager = SystemThreadManager::new();
        let mut processes = ProcessManager::new();
        let process = processes.create_process(None, "island.sys", None).unwrap();
        (manager, processes, process)
    }

    #[test]
    fn create_rejects_invalid_stacks_routines_and_processes() {
        let (mut manager, mut processes, process) = manager_with_process();
        assert_eq!(
            manager.create(&mut processes, process, 0x1000, 0, 0x1000, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.create(&mut processes, process, 0x1000, 0, 0x1001, 0x1000),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.create(&mut processes, process, 0x1000, 0, 0x1000, 0xFFF),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.create(&mut processes, process, 0x1000, 0, u64::MAX & !0xF, 0x1000),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.create(&mut processes, process, 0, 0, 0x1000, 0x1000),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.create(&mut processes, ProcessId(404), 0x1000, 0, 0x1000, 0x1000),
            Err(STATUS_INVALID_HANDLE)
        );
        let created = manager
            .create(&mut processes, process, 0x1000, 0xAA, 0x1000, 0x1000)
            .unwrap();
        assert_eq!(manager.created_count(), 1);
        assert_eq!(manager.thread_count(), 1);
        assert_eq!(manager.ready_count(), 1);
        assert_eq!(manager.query(created.handle).unwrap().context, 0xAA);
        assert_eq!(manager.handle_for(created.id), Some(created.handle));
        assert_eq!(manager.handle_for(ThreadId(404)), None);
        manager.adopt_thread(process, ThreadId(100)).unwrap();
        manager.adopt_thread(process, ThreadId(100)).unwrap();
        assert_eq!(
            manager.query_by_id(ThreadId(100)).unwrap().state,
            KernelThreadState::Running
        );
        let target_id = manager.handle_for_target(created.handle);
        manager.park_for_wait_test(target_id);
        assert_eq!(
            manager.query(created.handle).unwrap().state,
            KernelThreadState::Running
        );
        assert_eq!(manager.ready_count(), 0);
        manager.pending_attachment = Some(PendingAttachment {
            handle: SystemThreadHandle(0x900),
            context: 0,
            stack_base: 0x2000,
            stack_size: 0x1000,
        });
        assert_eq!(
            manager.create(&mut processes, process, 0x1000, 0, 0x2000, 0x1000),
            Err(STATUS_INVALID_PARAMETER)
        );
        manager.pending_attachment = None;
        processes
            .terminate_process(&mut DummyScheduler, process)
            .unwrap();
        assert_eq!(
            manager.create(&mut processes, process, 0x1000, 0, 0x2000, 0x1000),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
        assert_eq!(
            manager.create(&mut processes, process, 0x1000, 0, 0x2000, 0x1000),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
    }

    struct DummyScheduler;
    impl ThreadScheduler for DummyScheduler {
        fn attach_thread(
            &mut self,
            _process: ProcessId,
            _thread: ThreadId,
            _start: u64,
            _context: u64,
            _stack_base: u64,
            _stack_size: u64,
        ) -> Result<(), i32> {
            Ok(())
        }
        fn detach_thread(&mut self, _process: ProcessId, _thread: ThreadId) -> Result<(), i32> {
            Ok(())
        }
    }

    #[test]
    fn scheduler_attachment_misuse_and_detach_are_rejected() {
        let mut manager = SystemThreadManager::new();
        assert_eq!(
            manager.attach_thread(ProcessId(4), ThreadId(4), 0x1000, 0, 0x1000, 0x1000),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.detach_thread(ProcessId(4), ThreadId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        let (mut manager, mut processes, process) = manager_with_process();
        let created = manager
            .create(&mut processes, process, 0x1000, 0, 0x1000, 0x1000)
            .unwrap();
        manager.pending_attachment = Some(PendingAttachment {
            handle: SystemThreadHandle(0x900),
            context: 0,
            stack_base: 0x2000,
            stack_size: 0x1000,
        });
        assert_eq!(
            manager.attach_thread(process, created.id, 0x1000, 0, 0x1000, 0x1000),
            Err(STATUS_INVALID_PARAMETER)
        );
        manager.pending_attachment = None;
        manager.detach_thread(process, created.id).unwrap();
        assert_eq!(manager.terminated_count(), 1);
        assert!(manager.query(created.handle).unwrap().is_terminated());
        manager.detach_thread(process, created.id).unwrap();
        assert_eq!(manager.terminated_count(), 1);
    }

    #[test]
    fn slices_run_one_at_a_time_and_finish_with_exit_status() {
        let (mut manager, mut processes, process) = manager_with_process();
        let first = manager
            .create(&mut processes, process, 0x1000, 1, 0x1000, 0x1000)
            .unwrap();
        let second = manager
            .create(&mut processes, process, 0x2000, 2, 0x3000, 0x1000)
            .unwrap();
        let run = manager.take_next().unwrap();
        assert_eq!(run.id, first.id);
        assert_eq!(run.context, 1);
        assert_eq!(manager.current(), Some(first.id));
        assert!(manager.take_next().is_none());
        assert_eq!(manager.finish_current(7).unwrap(), first.id);
        assert_eq!(manager.exit_status(first.handle).unwrap(), Some(7));
        assert_eq!(manager.started_count(), 1);
        assert_eq!(manager.completed_count(), 1);
        assert_eq!(manager.take_next().unwrap().id, second.id);
        assert_eq!(manager.exit_status(second.handle).unwrap(), None);
        manager.finish_current(9).unwrap();
        assert_eq!(manager.exit_status(second.handle).unwrap(), Some(9));
        assert_eq!(manager.take_next(), None);
        assert_eq!(manager.finish_current(0), Err(STATUS_INVALID_HANDLE));
        manager.ready.push_back(first.id);
        manager.threads.insert(
            first.id,
            KernelThread {
                id: first.id,
                process,
                start_routine: 0x1000,
                context: 0,
                stack_base: 0x1000,
                stack_size: 0x1000,
                state: KernelThreadState::Terminated,
                exit_status: 0,
                irql: 0,
                termination_requested: None,
                apcs: VecDeque::new(),
                wait: None,
                pending_wake_status: None,
            },
        );
        assert_eq!(manager.take_next(), None);
        assert_eq!(manager.fail_current(), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            manager.request_terminate_current(0),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn termination_races_ready_running_and_terminated_threads() {
        let (mut manager, mut processes, process) = manager_with_process();
        let ready = manager
            .create(&mut processes, process, 0x1000, 0, 0x1000, 0x1000)
            .unwrap();
        assert_eq!(
            manager.request_terminate(ready.handle, 0x11),
            Ok((ready.id, true))
        );
        assert_eq!(manager.exit_status(ready.handle).unwrap(), Some(0x11));
        assert_eq!(
            manager.request_terminate(ready.handle, 0x12),
            Err(STATUS_THREAD_IS_TERMINATING)
        );
        assert_eq!(manager.ready_count(), 0);
        assert_eq!(
            manager.request_terminate(SystemThreadHandle(0xDEAD), 0),
            Err(STATUS_INVALID_HANDLE)
        );

        let running = manager
            .create(&mut processes, process, 0x2000, 0, 0x2000, 0x1000)
            .unwrap();
        manager.take_next().unwrap();
        assert_eq!(manager.request_terminate_current(0x22), Ok(running.id));
        assert_eq!(
            manager.request_terminate(running.handle, 0x23),
            Ok((running.id, false))
        );
        manager.finish_current(0x99).unwrap();
        assert_eq!(manager.exit_status(running.handle).unwrap(), Some(0x23));
        assert_eq!(manager.terminated_count(), 2);
        assert_eq!(manager.completed_count(), 2);
    }

    #[test]
    fn apc_queues_are_fifo_and_cancel_is_exact() {
        let (mut manager, mut processes, process) = manager_with_process();
        let thread = manager
            .create(&mut processes, process, 0x1000, 0, 0x1000, 0x1000)
            .unwrap();
        assert_eq!(
            manager.queue_apc(thread.handle, 0, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.queue_apc(SystemThreadHandle(0xDEAD), 0x10, 0),
            Err(STATUS_INVALID_HANDLE)
        );
        let first = manager.queue_apc(thread.handle, 0x10, 0xA).unwrap();
        let second = manager.queue_apc(thread.handle, 0x20, 0xB).unwrap();
        assert_eq!(manager.query(thread.handle).unwrap().apcs.len(), 2);
        assert_eq!(manager.cancel_apc(thread.handle, first), Ok(()));
        assert_eq!(
            manager.cancel_apc(thread.handle, first),
            Err(STATUS_NOT_FOUND)
        );
        assert_eq!(
            manager.cancel_apc(SystemThreadHandle(0xDEAD), second),
            Err(STATUS_INVALID_HANDLE)
        );
        let drained = manager.take_apcs(thread.handle).unwrap();
        let by_id = manager.queue_apc(thread.handle, 0x40, 0xC).unwrap();
        assert_eq!(
            manager.take_apcs_by_thread(thread.id).unwrap(),
            vec![SystemApc {
                id: by_id,
                routine: 0x40,
                context: 0xC
            }]
        );
        assert_eq!(
            drained,
            vec![SystemApc {
                id: second,
                routine: 0x20,
                context: 0xB
            }]
        );
        assert_eq!(
            manager.take_apcs(SystemThreadHandle(0xDEAD)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.set_irql(thread.id, 2), Ok(()));
        assert_eq!(
            manager.set_irql(ThreadId(404), 2),
            Err(STATUS_INVALID_HANDLE)
        );
        manager.request_terminate(thread.handle, 0).unwrap();
        assert_eq!(
            manager.queue_apc(thread.handle, 0x30, 0),
            Err(STATUS_THREAD_IS_TERMINATING)
        );
    }

    #[test]
    fn handles_close_without_killing_threads_and_invalid_lookups_fail() {
        let (mut manager, mut processes, process) = manager_with_process();
        assert_eq!(SystemThreadManager::default().thread_count(), 0);
        let thread = manager
            .create(&mut processes, process, 0x1000, 0, 0x1000, 0x1000)
            .unwrap();
        assert_eq!(manager.close_handle(thread.handle), Ok(()));
        assert_eq!(
            manager.close_handle(thread.handle),
            Err(STATUS_INVALID_HANDLE)
        );
        assert!(manager.threads.contains_key(&thread.id));
        assert_eq!(
            manager.exit_status(thread.handle),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.query(thread.handle), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            manager.exit_status(SystemThreadHandle(0xDEAD)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.query(SystemThreadHandle(0xDEAD)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.take_apcs(SystemThreadHandle(0xDEAD)),
            Err(STATUS_INVALID_HANDLE)
        );
        let run = manager.take_next().unwrap();
        manager.fail_current().unwrap();
        assert_eq!(
            manager.query_by_id(run.id).unwrap().exit_status,
            STATUS_UNSUCCESSFUL
        );
    }

    #[test]
    fn missing_thread_records_and_handle_targets_are_rejected() {
        let (mut manager, mut processes, process) = manager_with_process();
        let thread = manager
            .create(&mut processes, process, 0x1000, 0, 0x1000, 0x1000)
            .unwrap();
        manager.threads.remove(&thread.id);
        assert_eq!(manager.finish_current(0), Err(STATUS_INVALID_HANDLE));
        manager.running = Some(thread.id);
        assert_eq!(manager.finish_current(0), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            manager.request_terminate_current(0),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.detach_thread(process, thread.id),
            Err(STATUS_INVALID_HANDLE)
        );
        manager.running = Some(thread.id);
        manager.threads.insert(
            thread.id,
            KernelThread {
                id: thread.id,
                process,
                start_routine: 0x1000,
                context: 0,
                stack_base: 0x1000,
                stack_size: 0x1000,
                state: KernelThreadState::Running,
                exit_status: 0,
                irql: 0,
                termination_requested: None,
                apcs: VecDeque::new(),
                wait: None,
                pending_wake_status: None,
            },
        );
        manager.running = Some(thread.id);
        assert_eq!(manager.request_terminate_current(0), Ok(thread.id));
        manager.threads.remove(&thread.id);
        assert_eq!(
            manager.request_terminate_current(0),
            Err(STATUS_INVALID_HANDLE)
        );
        // Reinsert a ready record and exercise the missing-map branches.
        manager.threads.insert(
            thread.id,
            KernelThread {
                id: thread.id,
                process,
                start_routine: 0x1000,
                context: 0,
                stack_base: 0x1000,
                stack_size: 0x1000,
                state: KernelThreadState::Ready,
                exit_status: 0,
                irql: 0,
                termination_requested: None,
                apcs: VecDeque::new(),
                wait: None,
                pending_wake_status: None,
            },
        );
        manager.handles.insert(thread.handle, thread.id);
        manager.threads.remove(&thread.id);
        assert_eq!(
            manager.exit_status(thread.handle),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.query(thread.handle), Err(STATUS_INVALID_HANDLE));
        assert_eq!(manager.take_apcs(thread.handle), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            manager.cancel_apc(thread.handle, ApcId(1)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.request_terminate(thread.handle, 0),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.set_irql(thread.id, 0), Err(STATUS_INVALID_HANDLE));
        manager.running = None;
        assert_eq!(manager.take_next(), None);
        assert_eq!(manager.fail_current(), Err(STATUS_INVALID_HANDLE));
        assert_eq!(manager.release_running_for_wait(), None);
        manager.restore_running(ThreadId(8));
        assert_eq!(manager.current(), Some(ThreadId(8)));
        assert_eq!(
            manager.take_apcs_by_thread(ThreadId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    impl SystemThreadManager {
        fn query_by_id(&self, id: ThreadId) -> Result<&KernelThread, i32> {
            self.threads.get(&id).ok_or(STATUS_INVALID_HANDLE)
        }
    }
}

#[cfg(test)]
mod wait_tests {
    use super::*;
    use crate::casak::status::{STATUS_CANCELLED, STATUS_TIMEOUT};
    use std::time::Duration;

    fn fixture() -> (
        SystemThreadManager,
        ProcessManager,
        ProcessId,
        CreatedThread,
    ) {
        let mut manager = SystemThreadManager::new();
        let mut processes = ProcessManager::new();
        let process = processes.create_process(None, "island.sys", None).unwrap();
        let created = manager
            .create(&mut processes, process, 0x1000, 0, 0x1000, 0x1000)
            .unwrap();
        (manager, processes, process, created)
    }

    #[test]
    fn ready_requeue_and_wait_state_transitions_are_exact() {
        let (mut manager, _processes, _process, created) = fixture();
        assert_eq!(manager.take_next().unwrap().id, created.id);
        assert_eq!(manager.requeue_current(), Some(created.id));
        assert_eq!(
            manager.thread_state(created.id),
            Some(KernelThreadState::Ready)
        );
        assert_eq!(manager.requeue_current(), None);
        assert_eq!(
            manager.wait_current(SystemWait {
                target: WaitTarget::Event(1),
                deadline: None,
                alertable: false,
            }),
            Err(STATUS_INVALID_HANDLE)
        );

        assert_eq!(manager.take_next().unwrap().id, created.id);
        assert_eq!(
            manager.wait_current(SystemWait {
                target: WaitTarget::Event(1),
                deadline: None,
                alertable: false,
            }),
            Ok(created.id)
        );
        assert_eq!(
            manager.thread_state(created.id),
            Some(KernelThreadState::Waiting)
        );
        assert_eq!(
            manager.wait_of(created.id),
            Some(SystemWait {
                target: WaitTarget::Event(1),
                deadline: None,
                alertable: false
            })
        );
        assert_eq!(manager.waiting_threads().len(), 1);
        assert!(manager.has_waiting_threads());
        assert_eq!(manager.next_wait_deadline(), None);
        assert_eq!(manager.wake(created.id, STATUS_TIMEOUT), Ok(()));
        assert_eq!(
            manager.thread_state(created.id),
            Some(KernelThreadState::Ready)
        );
        assert_eq!(manager.take_wake_status(created.id), Some(STATUS_TIMEOUT));
        assert_eq!(manager.take_wake_status(created.id), None);
        assert_eq!(
            manager.wake(created.id, STATUS_TIMEOUT),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(manager.wait_of(created.id), None);
        assert!(!manager.has_waiting_threads());
        assert_eq!(
            manager.cancel_wait(SystemThreadHandle(0xDEAD), 0),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.cancel_wait(created.handle, STATUS_CANCELLED),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(manager.thread_record(created.id).unwrap().id, created.id);
        assert!(manager.thread_record(ThreadId(404)).is_none());
        assert_eq!(manager.thread_state(ThreadId(404)), None);
        assert_eq!(
            manager.set_pending_wake_status(ThreadId(404), 0),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.exit_status_by_id(ThreadId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.exit_status_by_id(created.id), Ok(None));
    }

    #[test]
    fn alertable_apcs_wake_wait_and_non_alertable_apcs_do_not() {
        let (mut manager, _processes, _process, created) = fixture();
        assert!(!manager.apc_pending(created.id));
        manager.take_next().unwrap();
        manager
            .wait_current(SystemWait {
                target: WaitTarget::Event(1),
                deadline: None,
                alertable: true,
            })
            .unwrap();
        let apc = manager.queue_apc(created.handle, 0x10, 0).unwrap();
        assert_eq!(
            manager.thread_state(created.id),
            Some(KernelThreadState::Ready)
        );
        assert_eq!(manager.take_wake_status(created.id), Some(STATUS_USER_APC));
        assert!(manager.apc_pending(created.id));
        assert_eq!(manager.take_apcs_by_thread(created.id).unwrap().len(), 1);
        let _ = apc;

        manager.take_next().unwrap();
        manager
            .wait_current(SystemWait {
                target: WaitTarget::Event(1),
                deadline: None,
                alertable: false,
            })
            .unwrap();
        manager.queue_apc(created.handle, 0x20, 0).unwrap();
        assert_eq!(
            manager.thread_state(created.id),
            Some(KernelThreadState::Waiting)
        );
        assert_eq!(
            manager.cancel_wait(created.handle, STATUS_CANCELLED),
            Ok(created.id)
        );
        assert_eq!(manager.take_wake_status(created.id), Some(STATUS_CANCELLED));
    }

    #[test]
    fn waiting_thread_termination_and_waiting_ready_skip_are_exact() {
        let (mut manager, _processes, _process, created) = fixture();
        let deadline = Instant::now() + Duration::from_millis(5);
        manager.take_next().unwrap();
        manager
            .wait_current(SystemWait {
                target: WaitTarget::Event(1),
                deadline: Some(deadline),
                alertable: false,
            })
            .unwrap();
        assert_eq!(manager.next_wait_deadline(), Some(deadline));
        manager.ready.push_back(created.id);
        assert_eq!(manager.take_next(), None);
        assert_eq!(
            manager.request_terminate(created.handle, 0x55),
            Ok((created.id, true))
        );
        assert_eq!(
            manager.thread_state(created.id),
            Some(KernelThreadState::Terminated)
        );
        assert_eq!(manager.exit_status_by_id(created.id), Ok(Some(0x55)));
    }
}
