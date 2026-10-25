//! Executive services: logical system/interrupt time, timers, APC/DPC
//! queues, dispatcher objects and wait semantics.
//!
//! Time is a deterministic 100 ns counter owned by the executive: `advance`
//! moves system and interrupt time forward and fires due timers.  APCs are
//! per-thread FIFO queues; dispatcher waits consume signals exactly once and
//! report abandoned mutants.

use std::collections::{BTreeMap, VecDeque};

use crate::casak::exec::DpcQueue;
use crate::casak::status::{
    STATUS_ABANDONED_WAIT_0, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND,
    STATUS_SEMAPHORE_LIMIT_EXCEEDED, STATUS_TIMEOUT, STATUS_WAIT_0,
};

/// Monotonic timer identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TimerId(pub u64);

/// Monotonic APC identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApcId(pub u64);

/// Monotonic dispatcher-object identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DispatcherId(pub u64);

/// APC delivery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApcKind {
    Kernel,
    User,
    SpecialUser,
}

struct Apc {
    id: ApcId,
    thread: u32,
    kind: ApcKind,
    routine: u64,
    context: u64,
    callback: Box<dyn FnMut()>,
}

/// A timer object owned by the executive.
struct Timer {
    deadline: u64,
    period: u64,
    active: bool,
    callback: Box<dyn FnMut()>,
}

/// A dispatcher object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatcherObject {
    Event {
        manual: bool,
        signaled: bool,
    },
    Mutant {
        owner: Option<u32>,
        recursion: u32,
        abandoned: bool,
    },
    Semaphore {
        count: u32,
        limit: u32,
    },
    Timer {
        signaled: bool,
    },
}

/// The result of a satisfied wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitResult {
    pub index: usize,
    pub abandoned: bool,
    pub status: i32,
}

/// The executive service table.
pub struct Executive {
    clock: u64,
    interrupt_time: u64,
    timers: BTreeMap<TimerId, Timer>,
    fired: Vec<TimerId>,
    next_timer: u64,
    apcs: VecDeque<Apc>,
    next_apc: u64,
    delivered_apcs: u64,
    objects: BTreeMap<DispatcherId, DispatcherObject>,
    next_object: u64,
    dpcs: DpcQueue,
}

impl Executive {
    pub fn new() -> Self {
        Self {
            clock: 1,
            interrupt_time: 1,
            timers: BTreeMap::new(),
            fired: Vec::new(),
            next_timer: 1,
            apcs: VecDeque::new(),
            next_apc: 1,
            delivered_apcs: 0,
            objects: BTreeMap::new(),
            next_object: 1,
            dpcs: DpcQueue::new(),
        }
    }

    pub fn system_time(&self) -> u64 {
        self.clock
    }

    pub fn interrupt_time(&self) -> u64 {
        self.interrupt_time
    }

    /// Advances both clocks by `ticks` and fires every timer that is due once.
    pub fn advance(&mut self, ticks: u64) -> usize {
        if ticks == 0 {
            return 0;
        }
        self.clock = self.clock.saturating_add(ticks);
        self.interrupt_time = self.interrupt_time.saturating_add(ticks);
        let due: Vec<(TimerId, u64)> = self
            .timers
            .iter()
            .filter(|(_, timer)| timer.active && timer.deadline <= self.clock)
            .map(|(id, timer)| (*id, timer.period))
            .collect();
        let fired = due.len();
        for (id, period) in due {
            let timer = self
                .timers
                .get_mut(&id)
                .expect("due timers are present in the timer table");
            (timer.callback)();
            if period == 0 {
                timer.active = false;
            } else {
                let next = self.clock.saturating_add(period);
                timer.deadline = next;
            }
            self.fired.push(id);
        }
        fired
    }

    /// Creates a timer due after `relative_ticks`, optionally repeating.
    pub fn set_timer(
        &mut self,
        relative_ticks: u64,
        period_ticks: u64,
        callback: impl FnMut() + 'static,
    ) -> TimerId {
        let id = TimerId(self.next_timer);
        self.next_timer += 1;
        self.timers.insert(
            id,
            Timer {
                deadline: self.clock.saturating_add(relative_ticks),
                period: period_ticks,
                active: true,
                callback: Box::new(callback),
            },
        );
        id
    }

    /// Cancels a live timer.
    pub fn cancel_timer(&mut self, id: TimerId) -> Result<(), i32> {
        match self.timers.get(&id) {
            Some(timer) if timer.active => {
                self.timers.remove(&id);
                Ok(())
            }
            _ => Err(STATUS_NOT_FOUND),
        }
    }

    pub fn timer_count(&self) -> usize {
        self.timers.len()
    }

    pub fn is_timer_active(&self, id: TimerId) -> bool {
        self.timers.get(&id).is_some_and(|timer| timer.active)
    }

    pub fn fired_timers(&self) -> &[TimerId] {
        &self.fired
    }

    /// Queues an APC for a thread.  Delivery is FIFO per thread.
    pub fn queue_apc(
        &mut self,
        thread: u32,
        kind: ApcKind,
        routine: u64,
        context: u64,
        callback: impl FnMut() + 'static,
    ) -> ApcId {
        let id = ApcId(self.next_apc);
        self.next_apc += 1;
        self.apcs.push_back(Apc {
            id,
            thread,
            kind,
            routine,
            context,
            callback: Box::new(callback),
        });
        id
    }

    /// Delivers every queued APC for `thread`, in enqueue order.
    pub fn deliver_apcs(&mut self, thread: u32) -> Vec<ApcId> {
        let mut remaining = VecDeque::new();
        let mut delivered = Vec::new();
        while let Some(mut apc) = self.apcs.pop_front() {
            if apc.thread == thread {
                (apc.callback)();
                delivered.push(apc.id);
                self.delivered_apcs += 1;
            } else {
                remaining.push_back(apc);
            }
        }
        self.apcs = remaining;
        delivered
    }

    /// Cancels a queued APC.
    pub fn cancel_apc(&mut self, id: ApcId) -> Result<(), i32> {
        let index = self
            .apcs
            .iter()
            .position(|apc| apc.id == id)
            .ok_or(STATUS_NOT_FOUND)?;
        self.apcs.remove(index);
        Ok(())
    }

    pub fn pending_apc_count(&self) -> usize {
        self.apcs.len()
    }

    pub fn delivered_apc_count(&self) -> u64 {
        self.delivered_apcs
    }

    /// The kind and target of a queued APC (for introspection).
    pub fn queued_apc(&self, id: ApcId) -> Option<(u32, ApcKind, u64, u64)> {
        self.apcs
            .iter()
            .find(|apc| apc.id == id)
            .map(|apc| (apc.thread, apc.kind, apc.routine, apc.context))
    }

    /// Queues a DPC; returns its monotonic sequence.
    pub fn queue_dpc(&mut self, callback: impl FnOnce() + 'static) -> u64 {
        self.dpcs.queue(callback)
    }

    /// Runs every pending DPC in FIFO order.
    pub fn drain_dpcs(&mut self) -> usize {
        self.dpcs.execute_pending()
    }

    pub fn pending_dpc_count(&self) -> usize {
        self.dpcs.pending_count()
    }

    pub fn create_event(&mut self, manual: bool, signaled: bool) -> DispatcherId {
        self.insert_object(DispatcherObject::Event { manual, signaled })
    }

    pub fn create_mutant(&mut self) -> DispatcherId {
        self.insert_object(DispatcherObject::Mutant {
            owner: None,
            recursion: 0,
            abandoned: false,
        })
    }

    pub fn create_semaphore(&mut self, count: u32, limit: u32) -> Result<DispatcherId, i32> {
        if limit == 0 || count > limit {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(self.insert_object(DispatcherObject::Semaphore { count, limit }))
    }

    pub fn create_timer_object(&mut self) -> DispatcherId {
        self.insert_object(DispatcherObject::Timer { signaled: false })
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn query_object(&self, id: DispatcherId) -> Result<DispatcherObject, i32> {
        self.objects.get(&id).copied().ok_or(STATUS_INVALID_HANDLE)
    }

    /// Signals an object.  Semaphores refuse to exceed their limit and
    /// mutants cannot be signaled directly.
    pub fn signal(&mut self, id: DispatcherId) -> Result<(), i32> {
        let object = self.objects.get_mut(&id).ok_or(STATUS_INVALID_HANDLE)?;
        match object {
            DispatcherObject::Event { signaled, .. } => {
                *signaled = true;
                Ok(())
            }
            DispatcherObject::Timer { signaled } => {
                *signaled = true;
                Ok(())
            }
            DispatcherObject::Semaphore { count, limit } => {
                if *count >= *limit {
                    Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED)
                } else {
                    *count += 1;
                    Ok(())
                }
            }
            DispatcherObject::Mutant { .. } => Err(STATUS_INVALID_PARAMETER),
        }
    }

    /// Resets an event or timer object.
    pub fn reset(&mut self, id: DispatcherId) -> Result<(), i32> {
        let object = self.objects.get_mut(&id).ok_or(STATUS_INVALID_HANDLE)?;
        match object {
            DispatcherObject::Event { signaled, .. } => {
                *signaled = false;
                Ok(())
            }
            DispatcherObject::Timer { signaled } => {
                *signaled = false;
                Ok(())
            }
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }

    /// Waits for the first satisfiable object in `ids`.  On timeout the
    /// logical clock advances by the timeout.
    pub fn wait_any(
        &mut self,
        ids: &[DispatcherId],
        timeout_ticks: u64,
        thread: u32,
    ) -> Result<WaitResult, i32> {
        if ids.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for id in ids {
            if !self.objects.contains_key(id) {
                return Err(STATUS_INVALID_HANDLE);
            }
        }
        for (index, id) in ids.iter().enumerate() {
            match self.try_acquire(*id, thread)? {
                Some(abandoned) => {
                    return Ok(WaitResult {
                        index,
                        abandoned,
                        status: if abandoned {
                            STATUS_ABANDONED_WAIT_0
                        } else {
                            STATUS_WAIT_0
                        },
                    });
                }
                None => {}
            }
        }
        if timeout_ticks > 0 {
            self.advance(timeout_ticks);
        }
        Err(STATUS_TIMEOUT)
    }

    /// Waits for every object.  No object is consumed unless all can be.
    pub fn wait_all(
        &mut self,
        ids: &[DispatcherId],
        timeout_ticks: u64,
        thread: u32,
    ) -> Result<WaitResult, i32> {
        if ids.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for id in ids {
            if !self.objects.contains_key(id) {
                return Err(STATUS_INVALID_HANDLE);
            }
        }
        if ids.iter().all(|id| self.satisfiable(*id, thread)) {
            for id in ids {
                let _ = self.try_acquire(*id, thread)?;
            }
            return Ok(WaitResult {
                index: 0,
                abandoned: false,
                status: STATUS_WAIT_0,
            });
        }
        if timeout_ticks > 0 {
            self.advance(timeout_ticks);
        }
        Err(STATUS_TIMEOUT)
    }

    /// Abandons every mutant owned by `thread`, returning the count.
    pub fn abandon_mutants(&mut self, thread: u32) -> usize {
        let mut count = 0;
        for object in self.objects.values_mut() {
            if let DispatcherObject::Mutant {
                owner,
                recursion,
                abandoned,
            } = object
            {
                if *owner == Some(thread) {
                    *owner = None;
                    *recursion = 0;
                    *abandoned = true;
                    count += 1;
                }
            }
        }
        count
    }

    fn insert_object(&mut self, object: DispatcherObject) -> DispatcherId {
        let id = DispatcherId(self.next_object);
        self.next_object += 1;
        self.objects.insert(id, object);
        id
    }

    fn satisfiable(&self, id: DispatcherId, thread: u32) -> bool {
        let object = self
            .objects
            .get(&id)
            .expect("wait_all validates every dispatcher id");
        match object {
            DispatcherObject::Event { signaled, .. } => *signaled,
            DispatcherObject::Mutant { owner, .. } => owner.is_none() || *owner == Some(thread),
            DispatcherObject::Semaphore { count, .. } => *count > 0,
            DispatcherObject::Timer { signaled } => *signaled,
        }
    }

    fn try_acquire(&mut self, id: DispatcherId, thread: u32) -> Result<Option<bool>, i32> {
        let object = self.objects.get_mut(&id).ok_or(STATUS_INVALID_HANDLE)?;
        match object {
            DispatcherObject::Event { manual, signaled } => {
                if !*signaled {
                    return Ok(None);
                }
                if !*manual {
                    *signaled = false;
                }
                Ok(Some(false))
            }
            DispatcherObject::Mutant {
                owner,
                recursion,
                abandoned,
            } => match *owner {
                None => {
                    let was_abandoned = *abandoned;
                    *owner = Some(thread);
                    *recursion = 1;
                    *abandoned = false;
                    Ok(Some(was_abandoned))
                }
                Some(current) if current == thread => {
                    *recursion += 1;
                    Ok(Some(false))
                }
                Some(_) => Ok(None),
            },
            DispatcherObject::Semaphore { count, .. } => {
                if *count == 0 {
                    Ok(None)
                } else {
                    *count -= 1;
                    Ok(Some(false))
                }
            }
            DispatcherObject::Timer { signaled } => {
                if !*signaled {
                    Ok(None)
                } else {
                    *signaled = false;
                    Ok(Some(false))
                }
            }
        }
    }
}

impl Default for Executive {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casak::status::STATUS_INVALID_DEVICE_REQUEST;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn timers_fire_in_deadline_order_and_cancel_is_exact() {
        let fired = Rc::new(RefCell::new(Vec::<u64>::new()));
        let mut executive = Executive::new();
        let base = executive.system_time();
        let late = {
            let fired = Rc::clone(&fired);
            executive.set_timer(10, 0, move || fired.borrow_mut().push(10))
        };
        let early = {
            let fired = Rc::clone(&fired);
            executive.set_timer(5, 0, move || fired.borrow_mut().push(5))
        };
        let periodic = {
            let fired = Rc::clone(&fired);
            executive.set_timer(3, 2, move || fired.borrow_mut().push(99))
        };
        assert_eq!(executive.timer_count(), 3);
        assert!(executive.is_timer_active(late));
        assert_eq!(executive.advance(0), 0);
        assert_eq!(executive.advance(3), 1);
        assert_eq!(*fired.borrow(), vec![99]);
        assert_eq!(executive.advance(2), 2);
        assert_eq!(*fired.borrow(), vec![99, 5, 99]);
        assert_eq!(executive.cancel_timer(early), Err(STATUS_NOT_FOUND));
        assert_eq!(executive.cancel_timer(late), Ok(()));
        assert!(!executive.is_timer_active(late));
        assert_eq!(executive.cancel_timer(late), Err(STATUS_NOT_FOUND));
        assert_eq!(executive.advance(10), 1);
        assert_eq!(*fired.borrow(), vec![99, 5, 99, 99]);
        assert_eq!(
            executive.fired_timers(),
            &[periodic, early, periodic, periodic]
        );
        assert_eq!(executive.system_time(), base + 15);
        assert_eq!(executive.interrupt_time(), base + 15);
    }

    #[test]
    fn apc_delivery_is_per_thread_fifo_with_exact_cancellation() {
        let order = Rc::new(RefCell::new(Vec::<u64>::new()));
        let mut executive = Executive::new();
        let first = {
            let order = Rc::clone(&order);
            executive.queue_apc(1, ApcKind::User, 0x10, 0xA1, move || {
                order.borrow_mut().push(1)
            })
        };
        let second = {
            let order = Rc::clone(&order);
            executive.queue_apc(1, ApcKind::Kernel, 0x20, 0xA2, move || {
                order.borrow_mut().push(2)
            })
        };
        let other = {
            let order = Rc::clone(&order);
            executive.queue_apc(2, ApcKind::SpecialUser, 0x30, 0xA3, move || {
                order.borrow_mut().push(3)
            })
        };
        assert_eq!(
            executive.queued_apc(first),
            Some((1, ApcKind::User, 0x10, 0xA1))
        );
        assert_eq!(executive.pending_apc_count(), 3);
        assert_eq!(executive.deliver_apcs(1), vec![first, second]);
        assert_eq!(*order.borrow(), vec![1, 2]);
        assert_eq!(executive.delivered_apc_count(), 2);
        assert_eq!(executive.deliver_apcs(2), vec![other]);
        assert_eq!(executive.pending_apc_count(), 0);
        assert_eq!(executive.queued_apc(first), None);
        let canceled = {
            let order = Rc::clone(&order);
            executive.queue_apc(3, ApcKind::User, 0, 0, move || order.borrow_mut().push(4))
        };
        assert_eq!(executive.cancel_apc(canceled), Ok(()));
        assert_eq!(executive.cancel_apc(canceled), Err(STATUS_NOT_FOUND));
        assert!(executive.deliver_apcs(3).is_empty());
    }

    #[test]
    fn dpcs_drain_fifo_once_and_invalid_sequences_are_rejected() {
        let order = Rc::new(RefCell::new(Vec::<u64>::new()));
        let mut executive = Executive::new();
        {
            let order = Rc::clone(&order);
            assert_eq!(executive.queue_dpc(move || order.borrow_mut().push(1)), 1);
        }
        {
            let order = Rc::clone(&order);
            assert_eq!(executive.queue_dpc(move || order.borrow_mut().push(2)), 2);
        }
        assert_eq!(executive.pending_dpc_count(), 2);
        assert_eq!(executive.drain_dpcs(), 2);
        assert_eq!(*order.borrow(), vec![1, 2]);
        assert_eq!(executive.drain_dpcs(), 0);
    }

    #[test]
    fn wait_any_consumes_events_semaphores_and_abandoned_mutants() {
        let mut executive = Executive::new();
        let auto = executive.create_event(false, false);
        let manual = executive.create_event(true, false);
        let semaphore = executive.create_semaphore(1, 2).unwrap();
        let mutant = executive.create_mutant();
        let timer = executive.create_timer_object();
        assert_eq!(
            executive.create_semaphore(2, 1),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            executive.create_semaphore(1, 0),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(executive.wait_any(&[], 0, 1), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            executive.wait_any(&[DispatcherId(404)], 0, 1),
            Err(STATUS_INVALID_HANDLE)
        );
        executive.signal(auto).unwrap();
        let result = executive.wait_any(&[auto], 0, 1).unwrap();
        assert_eq!(result.index, 0);
        assert_eq!(result.status, STATUS_WAIT_0);
        assert_eq!(executive.wait_any(&[auto], 0, 1), Err(STATUS_TIMEOUT));
        executive.signal(manual).unwrap();
        assert_eq!(executive.wait_any(&[manual], 0, 1).unwrap().index, 0);
        assert_eq!(executive.wait_any(&[manual], 0, 2).unwrap().index, 0);
        assert_eq!(executive.wait_any(&[semaphore], 0, 1).unwrap().index, 0);
        assert_eq!(executive.wait_any(&[semaphore], 0, 1), Err(STATUS_TIMEOUT));
        executive.signal(semaphore).unwrap();
        executive.signal(semaphore).unwrap();
        assert_eq!(
            executive.signal(semaphore),
            Err(STATUS_SEMAPHORE_LIMIT_EXCEEDED)
        );
        assert_eq!(executive.wait_any(&[semaphore], 0, 1).unwrap().index, 0);
        executive.signal(timer).unwrap();
        assert_eq!(executive.wait_any(&[timer], 0, 1).unwrap().index, 0);
        assert_eq!(executive.wait_any(&[timer], 0, 1), Err(STATUS_TIMEOUT));

        assert_eq!(executive.wait_any(&[mutant], 0, 7).unwrap().index, 0);
        assert_eq!(
            executive.query_object(mutant).unwrap(),
            DispatcherObject::Mutant {
                owner: Some(7),
                recursion: 1,
                abandoned: false
            }
        );
        assert_eq!(executive.wait_any(&[mutant], 0, 8), Err(STATUS_TIMEOUT));
        assert_eq!(executive.wait_any(&[mutant], 5, 8), Err(STATUS_TIMEOUT));
        assert_eq!(executive.abandon_mutants(7), 1);
        let result = executive.wait_any(&[mutant], 0, 8).unwrap();
        assert_eq!(result.abandoned, true);
        assert_eq!(result.status, STATUS_ABANDONED_WAIT_0);
        assert_eq!(executive.abandon_mutants(7), 0);

        assert_eq!(executive.signal(mutant), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(executive.reset(semaphore), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(executive.reset(auto), Ok(()));
        assert_eq!(executive.reset(timer), Ok(()));
        assert_eq!(
            executive.signal(DispatcherId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            executive.reset(DispatcherId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            executive.query_object(DispatcherId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(executive.object_count(), 5);
    }

    #[test]
    fn wait_all_requires_every_object_and_consumes_nothing_on_timeout() {
        let mut executive = Executive::new();
        let event = executive.create_event(false, false);
        let semaphore = executive.create_semaphore(1, 1).unwrap();
        assert_eq!(executive.wait_all(&[], 0, 1), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            executive.wait_all(&[event, DispatcherId(404)], 0, 1),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            executive.wait_all(&[event, semaphore], 0, 1),
            Err(STATUS_TIMEOUT)
        );
        assert_eq!(
            executive.query_object(semaphore).unwrap(),
            DispatcherObject::Semaphore { count: 1, limit: 1 }
        );
        executive.signal(event).unwrap();
        assert_eq!(
            executive.wait_all(&[event, semaphore], 0, 1).unwrap().index,
            0
        );
        assert_eq!(
            executive.query_object(event).unwrap(),
            DispatcherObject::Event {
                manual: false,
                signaled: false
            }
        );
        assert_eq!(
            executive.query_object(semaphore).unwrap(),
            DispatcherObject::Semaphore { count: 0, limit: 1 }
        );
        assert_eq!(
            executive.wait_all(&[event, semaphore], 1, 1),
            Err(STATUS_TIMEOUT)
        );
        let mutex = executive.create_mutant();
        let timer = executive.create_timer_object();
        assert_eq!(
            executive.wait_all(&[mutex, timer], 0, 2),
            Err(STATUS_TIMEOUT)
        );
        executive.signal(timer).unwrap();
        assert_eq!(executive.wait_all(&[mutex, timer], 0, 2).unwrap().index, 0);
        assert_eq!(
            executive.query_object(mutex).unwrap(),
            DispatcherObject::Mutant {
                owner: Some(2),
                recursion: 1,
                abandoned: false
            }
        );
    }

    #[test]
    fn clocks_saturate_and_timer_zero_ticks_is_a_no_op() {
        assert_eq!(Executive::default().system_time(), 1);
        let mut executive = Executive::new();
        let before = executive.system_time();
        assert_eq!(executive.advance(0), 0);
        assert_eq!(executive.system_time(), before);
        assert_eq!(executive.cancel_timer(TimerId(404)), Err(STATUS_NOT_FOUND));
        executive.advance(u64::MAX);
        assert_eq!(executive.system_time(), u64::MAX);
        assert_eq!(executive.interrupt_time(), u64::MAX);
    }

    #[test]
    fn invalid_wait_object_type_is_rejected() {
        let mut executive = Executive::new();
        let mutant = executive.create_mutant();
        let manual = executive.create_event(true, true);
        assert_eq!(executive.reset(mutant), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            executive.query_object(DispatcherId(0)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            executive.wait_any(&[manual], 0, 1).unwrap().status,
            STATUS_WAIT_0
        );
        assert_eq!(
            executive.signal(DispatcherId(99)),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn mutant_recursion_is_observable_and_delivery_rejects_unknown_thread() {
        let mut executive = Executive::new();
        let mutant = executive.create_mutant();
        assert_eq!(executive.wait_any(&[mutant], 0, 4).unwrap().index, 0);
        assert_eq!(executive.wait_any(&[mutant], 0, 4).unwrap().index, 0);
        assert_eq!(
            executive.query_object(mutant).unwrap(),
            DispatcherObject::Mutant {
                owner: Some(4),
                recursion: 2,
                abandoned: false
            }
        );
        assert_eq!(
            executive.signal(DispatcherId(77)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert!(executive.deliver_apcs(9).is_empty());
    }
}
