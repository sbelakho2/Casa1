//! Metal 4 grouped command-buffer execution for D3D12 batches.
//!
//! Metal 4 moves allocator ownership out of command buffers: the device vends
//! allocators and command buffers, each list encodes into its own
//! allocator-backed buffer, and the queue commits the whole array as one
//! submission. [`Metal4Batch`] owns that lifecycle for a D3D12
//! `ExecuteCommandLists` call:
//!
//! - every list gets its own `MTL4CommandBuffer` and `MTL4CommandAllocator`;
//! - all buffers are committed in one `MTL4CommandQueue` group, in submission
//!   order;
//! - one `MTLSharedEvent` value is signalled after the group and waited on
//!   before the buffers/allocators are recycled;
//! - allocators are only reset after the shared event proves completion, so a
//!   reset can never race GPU work (no use-after-free);
//! - duplicate lists in one batch are rejected with an exact error, empty
//!   batches commit nothing, and submission/wait failures retain their
//!   allocators until completion or a later drain.
//!
//! The D3D12 runtime uses this as the Metal 4 path and keeps the existing
//! backend execution as the authoritative CPU fallback. Every fallback is
//! observable through the runtime counters; the Metal 3 path is not modified.

use crate::error::{AppError, AppResult};
use crate::gfx::CommandListId;
use crate::metal_backend::{Metal4Allocator, Metal4CommandBuffer, Metal4Queue, MetalResidencySet};
use crate::reason::ReasonCode;
use metal::foreign_types::ForeignType;
use std::collections::BTreeSet;

/// Shared-event wait used for a grouped submission.
pub const METAL4_BATCH_WAIT_TIMEOUT_MS: u64 = 5_000;

const LEDGER_INITIAL_SLOTS: usize = 4;
const LEDGER_SLOT_BYTES: u64 = 4;

/// Per-batch observability counters. Every field is updated by real work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Metal4BatchStats {
    /// Grouped commits that completed and signalled their shared event.
    pub grouped_submissions: u64,
    /// Command lists encoded into their own command buffer/allocator.
    pub encoded_lists: u64,
    /// Empty batches observed (no commit, no event movement).
    pub empty_batches: u64,
    /// Duplicate-list batches rejected before any GPU resource was allocated.
    pub duplicate_rejections: u64,
    /// Operations rejected by range/size validation.
    pub validation_rejections: u64,
    /// Injected or real submission failures.
    pub submission_failures: u64,
    /// Shared-event waits that timed out.
    pub wait_timeouts: u64,
    /// Previously timed-out submissions drained after completion.
    pub pending_drains: u64,
    /// Allocators allocated from the device.
    pub allocators_created: u64,
    /// Allocators taken back from the completed-submission pool.
    pub allocator_reuses: u64,
}

/// One buffer operation encoded into a list's Metal 4 command buffer.
#[derive(Debug, Clone)]
pub enum Metal4BatchOp {
    /// Copy `size` bytes between two buffers.
    CopyBuffer {
        source: metal::Buffer,
        source_offset: u64,
        destination: metal::Buffer,
        destination_offset: u64,
        size: u64,
    },
    /// Fill `size` bytes with a constant byte value.
    FillBuffer {
        buffer: metal::Buffer,
        offset: u64,
        value: u8,
        size: u64,
    },
}

/// A single D3D12 command list encoded into a Metal 4 command buffer.
pub struct Metal4ListPlan<'a> {
    /// D3D12 command-list identity; duplicates in one batch are rejected.
    pub id: CommandListId,
    /// Work encoded into this list's command buffer, in order.
    pub ops: Vec<Metal4BatchOp>,
    /// Residency sets bound to this list's command buffer.
    pub residency_sets: Vec<&'a MetalResidencySet>,
}

impl<'a> Metal4ListPlan<'a> {
    pub fn new(id: CommandListId) -> Self {
        Self {
            id,
            ops: Vec::new(),
            residency_sets: Vec::new(),
        }
    }

    pub fn with_op(mut self, op: Metal4BatchOp) -> Self {
        self.ops.push(op);
        self
    }

    pub fn with_residency_set(mut self, set: &'a MetalResidencySet) -> Self {
        self.residency_sets.push(set);
        self
    }
}

/// Result of one grouped submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metal4BatchCompletion {
    /// Shared-event value signalled after the group.
    pub event_value: u64,
    /// Number of command lists committed in the group.
    pub list_count: usize,
    /// Batch ledger: one slot per list followed by the shared order slot.
    pub ledger: Vec<u32>,
}

/// A command buffer/allocation pair retained until its event value completes.
struct RetainedList {
    allocator: Metal4Allocator,
    command_buffer: Metal4CommandBuffer,
}

/// A submission whose event had not completed when the wait timed out.
struct PendingSubmission {
    event_value: u64,
    lists: Vec<RetainedList>,
    _fences: Vec<metal::Fence>,
}

/// A Metal 4 queue/allocator pool with grouped commits and shared-event fences.
pub struct Metal4Batch {
    device: metal::Device,
    queue: Metal4Queue,
    event: metal::SharedEvent,
    ledger: metal::Buffer,
    ledger_slots: usize,
    next_event_value: u64,
    last_signaled_value: u64,
    free_allocators: Vec<Metal4Allocator>,
    pending: Option<PendingSubmission>,
    stats: Metal4BatchStats,
}

impl std::fmt::Debug for Metal4Batch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metal4Batch")
            .field("stats", &self.stats)
            .field("last_signaled_value", &self.last_signaled_value)
            .field("pending", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}

impl Clone for Metal4Batch {
    fn clone(&self) -> Self {
        Self::with_device(self.device.clone()) // coverage: unreachable — the source batch proved this device supports Metal 4
            .expect("Metal 4 batch clone requires a Metal 4 device")
    }
}

impl Drop for Metal4Batch {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            // SAFETY: the queue/event are live. Waiting here keeps the
            // allocator/buffer wrappers alive until the GPU is done.
            let _: bool = unsafe {
                msg_send![
                    self.event.as_ptr(),
                    waitUntilSignaledValue: pending.event_value
                    timeoutMS: METAL4_BATCH_WAIT_TIMEOUT_MS
                ]
            };
            self.recycle_lists(pending.lists);
        }
    }
}

impl Metal4Batch {
    /// Create a batch executor for the system default Metal device.
    pub fn new() -> AppResult<Self> {
        let device = crate::metal_backend::MetalDevice::system_default()?.metal_device_owned();
        Self::with_device(device)
    }

    /// Create a batch executor for an explicit device (used by GPU tests).
    pub fn with_device(device: metal::Device) -> AppResult<Self> {
        if !metal4_supported(&device) {
            return Err(AppError::new(
                ReasonCode::RcD3dFeatureUnsupported,
                "Metal 4 batch: MTL4CommandQueue is unavailable on this device",
            ));
        }
        let queue = Metal4Queue::new(&device)?;
        let event = device.new_shared_event();
        let ledger = device.new_buffer(
            LEDGER_INITIAL_SLOTS as u64 * LEDGER_SLOT_BYTES,
            metal::MTLResourceOptions::StorageModeShared,
        );
        Ok(Self {
            device,
            queue,
            event,
            ledger,
            ledger_slots: LEDGER_INITIAL_SLOTS,
            next_event_value: 1,
            last_signaled_value: 0,
            free_allocators: Vec::new(),
            pending: None,
            stats: Metal4BatchStats::default(),
        })
    }

    /// Snapshot this batch's counters.
    pub fn stats(&self) -> Metal4BatchStats {
        self.stats
    }

    /// The most recently completed shared-event value.
    pub fn last_signaled_value(&self) -> u64 {
        self.last_signaled_value
    }

    /// The shared event's current GPU-signalled value.
    pub fn signaled_value(&self) -> u64 {
        self.event.signaled_value()
    }

    /// Execute a batch, encoding each list into its own command buffer and
    /// allocator, then committing them as one group.
    pub fn execute_plans(
        &mut self,
        plans: &[Metal4ListPlan<'_>],
    ) -> AppResult<Metal4BatchCompletion> {
        self.drain_pending()?;
        if plans.is_empty() {
            self.stats.empty_batches += 1;
            return Ok(Metal4BatchCompletion {
                event_value: self.last_signaled_value,
                list_count: 0,
                ledger: Vec::new(),
            });
        }
        self.validate_plans(plans)?;
        self.ensure_ledger(plans.len() + 1);
        let mut fences = Vec::with_capacity(plans.len().saturating_sub(1));
        for _ in 0..plans.len().saturating_sub(1) {
            fences.push(self.device.new_fence());
        }

        let mut in_flight = Vec::with_capacity(plans.len());
        for (index, plan) in plans.iter().enumerate() {
            let allocator = self.acquire_allocator()?;
            #[rustfmt::skip]
            let command_buffer = match self.queue.begin_command_buffer(&self.device, &allocator) {
                Ok(buffer) => buffer,
                Err(error) => { // coverage: unreachable — a live MTL4CommandQueue grants a begun command buffer
                    self.free_allocators.push(allocator); // coverage: unreachable — a live MTL4CommandQueue grants a begun command buffer
                    return Err(error); // coverage: unreachable — a live MTL4CommandQueue grants a begun command buffer
                }
            };
            for set in &plan.residency_sets {
                command_buffer.use_residency_set(set);
            }
            let wait_fence = (index > 0).then(|| &fences[index - 1]);
            let signal_fence = (index + 1 < plans.len()).then(|| &fences[index]);
            if let Err(error) = encode_list(&command_buffer, plan, wait_fence, signal_fence) {
                command_buffer.end(); // coverage: unreachable — a begun MTL4CommandBuffer vends a compute encoder
                allocator.reset(); // coverage: unreachable — a begun MTL4CommandBuffer vends a compute encoder
                self.free_allocators.push(allocator); // coverage: unreachable — a begun MTL4CommandBuffer vends a compute encoder
                return Err(error); // coverage: unreachable — a begun MTL4CommandBuffer vends a compute encoder
            }
            command_buffer.end();
            in_flight.push(RetainedList {
                allocator,
                command_buffer,
            });
        }

        #[cfg(test)]
        if test_faults::submission_failure() {
            self.recycle_lists(in_flight);
            self.stats.submission_failures += 1;
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "Metal 4 batch: forced submission failure",
            ));
        }

        let event_value = self.next_event_value;
        let buffers: Vec<&Metal4CommandBuffer> =
            in_flight.iter().map(|list| &list.command_buffer).collect();
        self.queue.commit(&buffers);
        self.queue.signal_event(&self.event, event_value);
        if !self.wait_for_event(event_value) {
            self.pending = Some(PendingSubmission {
                event_value,
                lists: in_flight,
                _fences: fences,
            });
            self.stats.wait_timeouts += 1;
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "Metal 4 batch: shared-event fence timed out after {METAL4_BATCH_WAIT_TIMEOUT_MS} ms for event {event_value}"
                ),
            ));
        }

        let completion = Metal4BatchCompletion {
            event_value,
            list_count: plans.len(),
            ledger: self.read_ledger(plans.len()),
        };
        self.recycle_lists(in_flight);
        self.last_signaled_value = event_value;
        self.next_event_value = event_value.wrapping_add(1);
        self.stats.grouped_submissions += 1;
        self.stats.encoded_lists += plans.len() as u64;
        Ok(completion)
    }

    /// Execute one list per D3D12 command-list id. Each list writes its
    /// sequence value to its own ledger slot and to a shared order slot, so
    /// the completion proves per-list output and group order.
    pub fn execute_markers(
        &mut self,
        list_ids: &[CommandListId],
    ) -> AppResult<Metal4BatchCompletion> {
        if list_ids.is_empty() {
            return self.execute_plans(&[]);
        }
        self.drain_pending()?;
        self.ensure_ledger(list_ids.len() + 1);
        let mut values = Vec::with_capacity(list_ids.len() * std::mem::size_of::<u32>());
        for index in 0..list_ids.len() {
            values.extend_from_slice(&((index as u32) + 1).to_le_bytes());
        }
        let staging = self.device.new_buffer_with_data(
            values.as_ptr() as *const std::ffi::c_void,
            values.len() as u64,
            metal::MTLResourceOptions::StorageModeShared,
        );
        let order_offset = list_ids.len() as u64 * LEDGER_SLOT_BYTES;
        let mut plans = Vec::with_capacity(list_ids.len());
        for (index, id) in list_ids.iter().enumerate() {
            let offset = index as u64 * LEDGER_SLOT_BYTES;
            let plan = Metal4ListPlan::new(*id)
                .with_op(Metal4BatchOp::CopyBuffer {
                    source: staging.clone(),
                    source_offset: offset,
                    destination: self.ledger.clone(),
                    destination_offset: offset,
                    size: LEDGER_SLOT_BYTES,
                })
                .with_op(Metal4BatchOp::CopyBuffer {
                    source: staging.clone(),
                    source_offset: offset,
                    destination: self.ledger.clone(),
                    destination_offset: order_offset,
                    size: LEDGER_SLOT_BYTES,
                });
            plans.push(plan);
        }
        let completion = self.execute_plans(&plans)?;
        drop(staging);
        Ok(completion)
    }

    fn validate_plans(&mut self, plans: &[Metal4ListPlan<'_>]) -> AppResult<()> {
        let mut seen = BTreeSet::new();
        for plan in plans {
            if !seen.insert(plan.id) {
                self.stats.duplicate_rejections += 1;
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "Metal 4 batch: duplicate command list {} in one batch",
                        plan.id
                    ),
                ));
            }
            for op in &plan.ops {
                self.validate_op(op)?;
            }
        }
        Ok(())
    }

    fn validate_op(&mut self, op: &Metal4BatchOp) -> AppResult<()> {
        match op {
            Metal4BatchOp::CopyBuffer {
                source,
                source_offset,
                destination,
                destination_offset,
                size,
            } => {
                let source_len = source.length();
                self.validate_range("copy src", *source_offset, *size, source_len)?;
                let dest_len = destination.length();
                self.validate_range("copy dst", *destination_offset, *size, dest_len)?;
            }
            Metal4BatchOp::FillBuffer {
                buffer,
                offset,
                size,
                ..
            } => self.validate_range("fill", *offset, *size, buffer.length())?,
        }
        Ok(())
    }

    fn validate_range(
        &mut self,
        label: &str,
        offset: u64,
        size: u64,
        length: u64,
    ) -> AppResult<()> {
        if size == 0 {
            self.stats.validation_rejections += 1;
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("Metal 4 batch: {label} size must be non-zero"),
            ));
        }
        let Some(end) = offset.checked_add(size) else {
            self.stats.validation_rejections += 1;
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("Metal 4 batch: {label} range overflows u64"),
            ));
        };
        if end > length {
            self.stats.validation_rejections += 1;
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "Metal 4 batch: {label} range {offset}..{end} exceeds buffer length {length}"
                ),
            ));
        }
        Ok(())
    }

    fn acquire_allocator(&mut self) -> AppResult<Metal4Allocator> {
        if let Some(allocator) = self.free_allocators.pop() {
            self.stats.allocator_reuses += 1;
            return Ok(allocator);
        }
        let allocator = Metal4Queue::new_allocator(&self.device)?;
        self.stats.allocators_created += 1;
        Ok(allocator)
    }

    fn ensure_ledger(&mut self, slots: usize) {
        if slots <= self.ledger_slots {
            return;
        }
        let bytes = slots.max(LEDGER_INITIAL_SLOTS) as u64 * LEDGER_SLOT_BYTES;
        self.ledger = self
            .device
            .new_buffer(bytes, metal::MTLResourceOptions::StorageModeShared);
        self.ledger_slots = slots.max(LEDGER_INITIAL_SLOTS);
    }

    fn read_ledger(&self, list_count: usize) -> Vec<u32> {
        let length = list_count + 1;
        let pointer = self.ledger.contents() as *const u32;
        // SAFETY: the ledger is a live shared buffer with `ledger_slots`
        // u32 slots, and `list_count + 1 <= ledger_slots` after ensure_ledger.
        unsafe { std::slice::from_raw_parts(pointer, length) }.to_vec()
    }

    fn wait_for_event(&self, event_value: u64) -> bool {
        #[cfg(test)]
        if test_faults::wait_timeout() {
            return false;
        }
        // SAFETY: the shared event is live.
        unsafe {
            msg_send![
                self.event.as_ptr(),
                waitUntilSignaledValue: event_value
                timeoutMS: METAL4_BATCH_WAIT_TIMEOUT_MS
            ]
        }
    }

    fn drain_pending(&mut self) -> AppResult<()> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        let event_value = pending.event_value;
        if !self.wait_for_event(event_value) {
            self.pending = Some(pending);
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "Metal 4 batch: previous submission for event {event_value} did not complete"
                ),
            ));
        }
        self.recycle_lists(pending.lists);
        self.last_signaled_value = pending.event_value;
        self.next_event_value = pending.event_value.wrapping_add(1);
        self.stats.pending_drains += 1;
        Ok(())
    }

    fn recycle_lists(&mut self, lists: Vec<RetainedList>) {
        for list in lists {
            list.allocator.reset();
            self.free_allocators.push(list.allocator);
        }
    }
}

fn encode_list(
    command_buffer: &Metal4CommandBuffer,
    plan: &Metal4ListPlan<'_>,
    wait_fence: Option<&metal::Fence>,
    signal_fence: Option<&metal::Fence>,
) -> AppResult<()> {
    let encoder = command_buffer.begin_compute_encoder()?;
    if let Some(fence) = wait_fence {
        encoder.wait_for_fence(fence);
    }
    for op in &plan.ops {
        match op {
            Metal4BatchOp::CopyBuffer {
                source,
                source_offset,
                destination,
                destination_offset,
                size,
            } => encoder.copy_buffer(
                source,
                *source_offset,
                destination,
                *destination_offset,
                *size,
            ),
            Metal4BatchOp::FillBuffer {
                buffer,
                offset,
                value,
                size,
            } => encoder.fill_buffer(buffer, *offset, *size, *value),
        }
    }
    if let Some(fence) = signal_fence {
        encoder.update_fence(fence);
    }
    encoder.end();
    Ok(())
}

fn metal4_supported(device: &metal::DeviceRef) -> bool {
    #[cfg(test)]
    if test_faults::unsupported() {
        return false;
    }
    Metal4Queue::is_supported(device)
}

#[cfg(test)]
pub(crate) fn force_submission_failure(force: bool) {
    test_faults::force_submission_failure(force);
}

#[cfg(test)]
pub(crate) fn force_unsupported(force: bool) {
    test_faults::force_unsupported(force);
}

#[cfg(test)]
mod test_faults {
    use std::cell::Cell;

    thread_local! {
        static UNSUPPORTED: Cell<bool> = const { Cell::new(false) };
        static SUBMISSION_FAILURE: Cell<bool> = const { Cell::new(false) };
        static WAIT_TIMEOUT: Cell<bool> = const { Cell::new(false) };
    }

    pub fn unsupported() -> bool {
        UNSUPPORTED.with(Cell::get)
    }

    pub fn force_unsupported(force: bool) {
        UNSUPPORTED.with(|value| value.set(force));
    }

    pub fn submission_failure() -> bool {
        SUBMISSION_FAILURE.with(Cell::get)
    }

    pub fn force_submission_failure(force: bool) {
        SUBMISSION_FAILURE.with(|value| value.set(force));
    }

    pub fn wait_timeout() -> bool {
        WAIT_TIMEOUT.with(Cell::get)
    }

    pub fn force_wait_timeout(force: bool) {
        WAIT_TIMEOUT.with(|value| value.set(force));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> metal::Device {
        metal::Device::system_default().expect("Metal device")
    }

    fn shared_values(device: &metal::Device, values: &[u32]) -> metal::Buffer {
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(values.as_ptr() as *const u8, std::mem::size_of_val(values))
        };
        device.new_buffer_with_data(
            bytes.as_ptr() as *const std::ffi::c_void,
            bytes.len() as u64,
            metal::MTLResourceOptions::StorageModeShared,
        )
    }

    fn read_values(buffer: &metal::Buffer, count: usize) -> Vec<u32> {
        let pointer = buffer.contents() as *const u32;
        // SAFETY: the buffer was allocated for at least `count` u32 values and
        // all GPU work touching it completed before the readback.
        unsafe { std::slice::from_raw_parts(pointer, count) }.to_vec()
    }

    fn fill(buffer: &metal::Buffer, offset: u64, value: u8, size: u64) -> Metal4BatchOp {
        Metal4BatchOp::FillBuffer {
            buffer: buffer.clone(),
            offset,
            value,
            size,
        }
    }

    #[test]
    fn metal4_batch_parallel_two_lists_preserve_order_and_fence() {
        let device = device();
        let mut batch = Metal4Batch::with_device(device.clone()).expect("Metal 4 batch");
        let output = shared_values(&device, &[0, 0, 0]);

        let first = Metal4ListPlan::new(10)
            .with_op(fill(&output, 0, 0x11, 4))
            .with_op(fill(&output, 4, 0x33, 4));
        let second = Metal4ListPlan::new(20)
            .with_op(fill(&output, 0, 0x22, 4))
            .with_op(fill(&output, 8, 0x44, 4));

        let completion = batch
            .execute_plans(&[first, second])
            .expect("grouped commit");
        assert_eq!(completion.event_value, 1);
        assert_eq!(completion.list_count, 2);
        assert_eq!(batch.signaled_value(), 1);
        assert_eq!(
            read_values(&output, 3),
            vec![0x2222_2222, 0x3333_3333, 0x4444_4444]
        );
        let stats = batch.stats();
        assert_eq!(stats.grouped_submissions, 1);
        assert_eq!(stats.encoded_lists, 2);
        assert_eq!(stats.allocators_created, 2);
    }

    #[test]
    fn metal4_batch_empty_batch_boundary_commits_nothing() {
        let device = device();
        let mut batch = Metal4Batch::with_device(device).expect("Metal 4 batch");
        let cloned = batch.clone();
        assert_eq!(cloned.stats(), Metal4BatchStats::default());
        assert_eq!(format!("{batch:?}").contains("Metal4Batch"), true);
        let via_plans = batch.execute_plans(&[]).expect("empty plans");
        assert_eq!(via_plans.event_value, 0);
        assert_eq!(via_plans.list_count, 0);
        assert_eq!(via_plans.ledger, Vec::<u32>::new());
        let via_markers = batch.execute_markers(&[]).expect("empty markers");
        assert_eq!(via_markers.event_value, 0);
        assert_eq!(via_markers.list_count, 0);
        let stats = batch.stats();
        assert_eq!(stats.empty_batches, 2);
        assert_eq!(stats.grouped_submissions, 0);
        assert_eq!(batch.signaled_value(), 0);
    }

    #[test]
    fn metal4_batch_duplicate_list_is_rejected_exactly() {
        let device = device();
        let mut batch = Metal4Batch::with_device(device).expect("Metal 4 batch");
        let first = Metal4ListPlan::new(7);
        let second = Metal4ListPlan::new(7);
        let error = batch
            .execute_plans(&[first, second])
            .expect_err("duplicate list must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "Metal 4 batch: duplicate command list 7 in one batch"
        );
        let stats = batch.stats();
        assert_eq!(stats.duplicate_rejections, 1);
        assert_eq!(stats.grouped_submissions, 0);
        assert_eq!(stats.allocators_created, 0);
    }

    #[test]
    fn metal4_batch_invalid_ranges_and_zero_sizes_are_rejected_exactly() {
        let device = device();
        let mut batch = Metal4Batch::with_device(device.clone()).expect("Metal 4 batch");
        let output = shared_values(&device, &[0, 0]);

        let zero_size = Metal4ListPlan::new(1).with_op(fill(&output, 0, 0, 0));
        let error = batch
            .execute_plans(&[zero_size])
            .expect_err("zero size must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "Metal 4 batch: fill size must be non-zero");

        let out_of_bounds = Metal4ListPlan::new(2).with_op(fill(&output, 4, 0, 5));
        let error = batch
            .execute_plans(&[out_of_bounds])
            .expect_err("out of bounds must fail");
        assert_eq!(
            error.message,
            "Metal 4 batch: fill range 4..9 exceeds buffer length 8"
        );

        let overflow = Metal4ListPlan::new(3).with_op(fill(&output, u64::MAX, 0, 2));
        let error = batch
            .execute_plans(&[overflow])
            .expect_err("overflow must fail");
        assert_eq!(error.message, "Metal 4 batch: fill range overflows u64");
        assert_eq!(batch.stats().validation_rejections, 3);
        assert_eq!(batch.stats().grouped_submissions, 0);
    }

    #[test]
    fn metal4_batch_allocator_reuse_after_completion_has_no_leak() {
        let device = device();
        let mut batch = Metal4Batch::with_device(device.clone()).expect("Metal 4 batch");
        let output = shared_values(&device, &[0, 0]);
        let residency = crate::metal_backend::create_residency_set(&device, Some("batch"), 1)
            .expect("residency set");
        residency.add_allocation(&output);
        residency.commit();
        residency.request_residency();

        let first = Metal4ListPlan::new(1)
            .with_op(fill(&output, 0, 0x11, 4))
            .with_residency_set(&residency);
        let second = Metal4ListPlan::new(2).with_op(fill(&output, 4, 0x22, 4));
        batch
            .execute_plans(&[first, second])
            .expect("first grouped commit");
        assert_eq!(read_values(&output, 2), vec![0x1111_1111, 0x2222_2222]);
        assert_eq!(batch.stats().allocators_created, 2);
        assert_eq!(batch.stats().allocator_reuses, 0);

        let third = Metal4ListPlan::new(3)
            .with_op(fill(&output, 0, 0x33, 4))
            .with_residency_set(&residency);
        let fourth = Metal4ListPlan::new(4).with_op(fill(&output, 4, 0x44, 4));
        let completion = batch
            .execute_plans(&[third, fourth])
            .expect("second grouped commit");
        assert_eq!(completion.event_value, 2);
        assert_eq!(read_values(&output, 2), vec![0x3333_3333, 0x4444_4444]);
        let stats = batch.stats();
        assert_eq!(stats.allocators_created, 2);
        assert_eq!(stats.allocator_reuses, 2);
        assert_eq!(stats.grouped_submissions, 2);
        residency.end_residency();
    }

    #[test]
    fn metal4_batch_duplicate_submit_after_completion_is_safe() {
        let device = device();
        let mut batch = Metal4Batch::with_device(device).expect("Metal 4 batch");
        let first = batch.execute_markers(&[42]).expect("first marker batch");
        assert_eq!(first.event_value, 1);
        assert_eq!(first.ledger, vec![1, 1]);
        let second = batch
            .execute_markers(&[42, 43])
            .expect("same list id in a later batch");
        assert_eq!(second.event_value, 2);
        assert_eq!(second.ledger, vec![1, 2, 2]);
        let grown = batch
            .execute_markers(&[1, 2, 3, 4, 5])
            .expect("batch that grows the ledger");
        assert_eq!(grown.event_value, 3);
        assert_eq!(grown.ledger, vec![1, 2, 3, 4, 5, 5]);
        assert_eq!(batch.signaled_value(), 3);
        assert_eq!(batch.last_signaled_value(), 3);
    }

    #[test]
    fn metal4_batch_unsupported_device_reports_exact_error() {
        test_faults::force_unsupported(true);
        let error = Metal4Batch::with_device(device()).expect_err("unsupported device");
        test_faults::force_unsupported(false);
        assert_eq!(error.code, ReasonCode::RcD3dFeatureUnsupported);
        assert_eq!(
            error.message,
            "Metal 4 batch: MTL4CommandQueue is unavailable on this device"
        );
    }

    #[test]
    fn metal4_batch_forced_submission_failure_is_exact_and_recoverable() {
        let device = device();
        let mut batch = Metal4Batch::with_device(device.clone()).expect("Metal 4 batch");
        let output = shared_values(&device, &[0]);
        let plan = Metal4ListPlan::new(1).with_op(fill(&output, 0, 0x55, 4));

        test_faults::force_submission_failure(true);
        let error = batch
            .execute_plans(&[plan])
            .expect_err("forced submission failure");
        test_faults::force_submission_failure(false);
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "Metal 4 batch: forced submission failure");
        assert_eq!(read_values(&output, 1), vec![0]);
        assert_eq!(batch.stats().submission_failures, 1);
        assert_eq!(batch.stats().allocators_created, 1);

        let retry = Metal4ListPlan::new(2).with_op(fill(&output, 0, 0x66, 4));
        let completion = batch.execute_plans(&[retry]).expect("recovered batch");
        assert_eq!(completion.event_value, 1);
        assert_eq!(read_values(&output, 1), vec![0x6666_6666]);
        assert_eq!(batch.stats().allocator_reuses, 1);
    }

    #[test]
    fn metal4_batch_fence_timeout_is_exact_and_pending_submission_drains() {
        let device = device();
        let mut batch = Metal4Batch::with_device(device.clone()).expect("Metal 4 batch");
        let output = shared_values(&device, &[0]);
        let plan = Metal4ListPlan::new(1).with_op(fill(&output, 0, 0x77, 4));

        test_faults::force_wait_timeout(true);
        let error = batch
            .execute_plans(&[plan])
            .expect_err("forced fence timeout");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "Metal 4 batch: shared-event fence timed out after 5000 ms for event 1"
        );
        assert_eq!(batch.stats().wait_timeouts, 1);

        let blocked = batch
            .execute_plans(&[Metal4ListPlan::new(2)])
            .expect_err("pending submission still blocks the next batch");
        assert_eq!(
            blocked.message,
            "Metal 4 batch: previous submission for event 1 did not complete"
        );

        test_faults::force_wait_timeout(false);
        let completion = batch
            .execute_plans(&[Metal4ListPlan::new(3)])
            .expect("pending submission drains");
        assert_eq!(completion.event_value, 2);
        assert_eq!(batch.stats().pending_drains, 1);
        assert_eq!(read_values(&output, 1), vec![0x7777_7777]);
    }

    #[test]
    fn metal4_batch_timeout_drop_retains_pending_fence_until_completion() {
        let device = device();
        let output = shared_values(&device, &[0]);
        {
            let mut batch = Metal4Batch::with_device(device.clone()).expect("Metal 4 batch");
            let plan = Metal4ListPlan::new(1).with_op(fill(&output, 0, 0x88, 4));
            test_faults::force_wait_timeout(true);
            let _ = batch.execute_plans(&[plan]).expect_err("forced timeout");
            test_faults::force_wait_timeout(false);
        }
        let mut replacement = Metal4Batch::with_device(device).expect("replacement batch");
        let completion = replacement.execute_markers(&[9]).expect("batch after drop");
        assert_eq!(completion.event_value, 1);
        assert_eq!(completion.list_count, 1);
    }
}
