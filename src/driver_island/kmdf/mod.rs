//! KMDF object model: driver, device, queue, request, memory, locks,
//! timers, workitems, DMA, USB, interrupts and child lists.

use super::*;

mod child_list;
mod collection;
mod dma;
mod driver;
mod interrupt;
mod iotarget;
mod memory;
mod object;
mod queue;
mod registry;
mod request;
mod sync;
mod types;
mod usb;

#[allow(unused_imports)]
pub(crate) use self::child_list::*;
#[allow(unused_imports)]
pub(crate) use self::collection::*;
#[allow(unused_imports)]
pub(crate) use self::dma::*;
#[allow(unused_imports)]
pub(crate) use self::driver::*;
#[allow(unused_imports)]
pub(crate) use self::interrupt::*;
#[allow(unused_imports)]
pub(crate) use self::iotarget::*;
#[allow(unused_imports)]
pub(crate) use self::memory::*;
#[allow(unused_imports)]
pub(crate) use self::object::*;
#[allow(unused_imports)]
pub(crate) use self::queue::*;
#[allow(unused_imports)]
pub(crate) use self::registry::*;
#[allow(unused_imports)]
pub(crate) use self::request::*;
#[allow(unused_imports)]
pub(crate) use self::sync::*;
#[allow(unused_imports)]
pub(crate) use self::types::*;
#[allow(unused_imports)]
pub(crate) use self::usb::*;

impl DriverIsland {
    #[cfg(test)]
    pub(crate) fn kmdf_driver_handle(&self) -> u64 {
        self.inner.borrow().kmdf.driver_handle
    }

    /// Test hook: preload device-side data for an IN pipe so a read
    /// drains a non-empty stage (the device's endpoint FIFO).
    #[cfg(test)]
    pub(crate) fn kmdf_usb_stage_in_for_test(&self, pipe: u64, bytes: &[u8]) -> bool {
        let mut state = self.inner.borrow_mut();
        let Some(pipe_record) = state.kmdf.usb_pipes.get(&pipe).copied() else {
            return false;
        };
        state
            .kmdf
            .usb_targets
            .get_mut(&pipe_record.target)
            .is_some_and(|target| {
                let staged = target.staged.entry(pipe_record.endpoint_index).or_default();
                staged.extend_from_slice(bytes);
                true
            })
    }

    /// Test hook: simulate a device-side STALL on a configured pipe.
    /// Returns `true` when the pipe existed and was not already stalled.
    #[cfg(test)]
    pub(crate) fn kmdf_usb_stall_pipe_for_test(&self, pipe: u64) -> bool {
        let mut state = self.inner.borrow_mut();
        let Some(pipe_record) = state.kmdf.usb_pipes.get(&pipe).copied() else {
            return false;
        };
        state
            .kmdf
            .usb_targets
            .get_mut(&pipe_record.target)
            .is_some_and(|target| target.stalled.insert(pipe_record.endpoint_index))
    }

    #[cfg(test)]
    pub(crate) fn kmdf_device_handles(&self) -> Vec<u64> {
        self.inner.borrow().kmdf.devices.keys().copied().collect()
    }

    #[cfg(test)]
    pub(crate) fn kmdf_wait_lock_handles(&self) -> Vec<u64> {
        self.inner
            .borrow()
            .kmdf
            .wait_locks
            .keys()
            .copied()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn kmdf_wait_lock_gate(&self, handle: u64) -> Option<Arc<(Mutex<bool>, Condvar)>> {
        self.inner
            .borrow()
            .kmdf
            .wait_locks
            .get(&handle)
            .map(|lock| lock.gate.clone())
    }

    #[cfg(test)]
    pub(crate) fn kmdf_request_state(&self, handle: u64) -> Option<(bool, i32, usize, u64)> {
        self.inner
            .borrow()
            .kmdf
            .requests
            .get(&handle)
            .map(|request| {
                (
                    request.completed,
                    request.status,
                    request.information,
                    request.outer_irp_guest,
                )
            })
    }

    #[cfg(test)]
    pub(crate) fn kmdf_queue_state(&self, handle: u64) -> Option<(usize, usize, bool, bool, bool)> {
        self.inner.borrow().kmdf.queues.get(&handle).map(|queue| {
            (
                queue.queued.len(),
                queue.in_flight.len(),
                queue.stopped,
                queue.draining,
                queue.power_managed,
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn kmdf_timer_state(&self, handle: u64) -> Option<(bool, u64)> {
        self.inner
            .borrow()
            .kmdf
            .timers
            .get(&handle)
            .map(|timer| (timer.running, timer.fired))
    }

    #[cfg(test)]
    pub(crate) fn kmdf_work_item_state(&self, handle: u64) -> Option<(bool, u64)> {
        self.inner
            .borrow()
            .kmdf
            .work_items
            .get(&handle)
            .map(|item| (item.queued, item.completed))
    }

    #[cfg(test)]
    pub(crate) fn kmdf_spinlock_held(&self, handle: u64) -> Option<bool> {
        self.inner
            .borrow()
            .kmdf
            .spinlocks
            .get(&handle)
            .map(|lock| lock.held)
    }

    #[cfg(test)]
    pub(crate) fn kmdf_device_runtime_state(
        &self,
        handle: u64,
    ) -> Option<(bool, bool, bool, bool, u32, u32)> {
        self.inner.borrow().kmdf.devices.get(&handle).map(|device| {
            (
                device.started,
                device.removed,
                device.surprised,
                device.idle,
                device.power_state,
                device.idle_refs,
            )
        })
    }

    #[cfg(test)]
    pub(crate) fn kmdf_counters(&self) -> (u64, u64, u64, u64, u64) {
        let state = self.inner.borrow();
        (
            state.kmdf.timer_fires,
            state.kmdf.work_item_runs,
            state.kmdf.power_managed_defers,
            state.kmdf.surprise_removals,
            state.kmdf.irp_forwards,
        )
    }

    #[cfg(test)]
    pub(crate) fn kmdf_context_size(&self, handle: u64) -> Option<usize> {
        self.inner
            .borrow()
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_size)
    }

    #[cfg(test)]
    pub(crate) fn kmdf_typed_context(&self, handle: u64) -> Option<u64> {
        self.inner
            .borrow()
            .kmdf
            .objects
            .get(&handle)
            .map(|object| object.context_guest)
    }
}
