//! Virtual interrupt objects for the island.
//!
//! The manager validates line-based interrupt connections, owns the
//! vector/affinity/IRQL contract, and tracks in-flight ISR dispatches so a
//! disconnect requested from inside an ISR is completed only after the ISR
//! returns.  Message-signaled interrupts have no guest-visible MSI backing and
//! fail closed.

use std::collections::BTreeMap;

use crate::casak::status::{
    STATUS_DELETE_PENDING, STATUS_INVALID_DEVICE_STATE, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_COLLISION,
};

/// Lowest device IRQL accepted by the virtual controller.
pub const MIN_DEVICE_IRQL: u8 = 3;
/// Highest guest IRQL.
pub const MAX_IRQL: u8 = 15;
/// Processors the synthetic controller can target.
pub const ONLINE_AFFINITY: u64 = 0xFFFF;
/// `Latched`.
pub const INTERRUPT_LATCHED: u32 = 0;
/// `LevelSensitive`.
pub const INTERRUPT_LEVEL_SENSITIVE: u32 = 1;
/// `CONNECT_LINE_BASED`.
pub const CONNECT_LINE_BASED: u32 = 0;
/// `CONNECT_MESSAGE_BASED`.
pub const CONNECT_MESSAGE_BASED: u32 = 1;
/// `CONNECT_FULLY_SPECIFIED`.
pub const CONNECT_FULLY_SPECIFIED: u32 = 2;

/// Monotonic interrupt-object identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct InterruptId(pub u64);

/// A validated connection request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectRequest {
    pub guest_object: u64,
    pub service_routine: u64,
    pub service_context: u64,
    pub spin_lock: u64,
    pub vector: u32,
    pub irql: u8,
    pub synchronize_irql: u8,
    pub mode: u32,
    pub share_vector: bool,
    pub affinity: u64,
}

/// One connected virtual interrupt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualInterrupt {
    pub id: InterruptId,
    pub guest_object: u64,
    pub service_routine: u64,
    pub service_context: u64,
    pub spin_lock: u64,
    pub vector: u32,
    pub irql: u8,
    pub synchronize_irql: u8,
    pub mode: u32,
    pub share_vector: bool,
    pub affinity: u64,
    pub connected: bool,
    pub in_flight: u32,
    pub disconnect_pending: bool,
}

/// The dispatch ticket returned by [`InterruptManager::begin_dispatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchTicket {
    pub id: InterruptId,
    pub guest_object: u64,
    pub service_routine: u64,
    pub service_context: u64,
    pub irql: u8,
}

/// The result of a disconnect request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectOutcome {
    /// The object is still executing an ISR; removal completes at
    /// `end_dispatch`.
    Deferred,
    /// The object was idle and has been removed.
    Removed,
}

/// The virtual interrupt controller.
#[derive(Debug)]
pub struct InterruptManager {
    interrupts: BTreeMap<u64, VirtualInterrupt>,
    by_id: BTreeMap<InterruptId, u64>,
    vectors: BTreeMap<u32, Vec<u64>>,
    next_id: u64,
    isr_invocations: u64,
    dispatches: u64,
    disconnected: u64,
}

impl InterruptManager {
    pub fn new() -> Self {
        Self {
            interrupts: BTreeMap::new(),
            by_id: BTreeMap::new(),
            vectors: BTreeMap::new(),
            next_id: 1,
            isr_invocations: 0,
            dispatches: 0,
            disconnected: 0,
        }
    }

    /// Validates and records a line-based connection.
    pub fn connect(&mut self, request: ConnectRequest) -> Result<InterruptId, i32> {
        if request.guest_object == 0 || request.service_routine == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if request.vector == 0 || request.vector > 255 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if !(MIN_DEVICE_IRQL..=MAX_IRQL).contains(&request.irql)
            || request.synchronize_irql < request.irql
            || request.synchronize_irql > MAX_IRQL
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if request.mode != INTERRUPT_LATCHED && request.mode != INTERRUPT_LEVEL_SENSITIVE {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if request.affinity == 0 || request.affinity & !ONLINE_AFFINITY != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if request.share_vector
            && (request.spin_lock == 0 || request.mode != INTERRUPT_LEVEL_SENSITIVE)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.interrupts.contains_key(&request.guest_object) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        if let Some(existing) = self.vectors.get(&request.vector) {
            for guest_object in existing {
                let Some(record) = self.interrupts.get(guest_object) else {
                    continue;
                };
                if !record.share_vector
                    || !request.share_vector
                    || record.mode != request.mode
                    || record.irql != request.irql
                {
                    return Err(STATUS_OBJECT_NAME_COLLISION);
                }
            }
        }
        let id = InterruptId(self.next_id);
        self.next_id += 1;
        self.interrupts.insert(
            request.guest_object,
            VirtualInterrupt {
                id,
                guest_object: request.guest_object,
                service_routine: request.service_routine,
                service_context: request.service_context,
                spin_lock: request.spin_lock,
                vector: request.vector,
                irql: request.irql,
                synchronize_irql: request.synchronize_irql,
                mode: request.mode,
                share_vector: request.share_vector,
                affinity: request.affinity,
                connected: true,
                in_flight: 0,
                disconnect_pending: false,
            },
        );
        self.by_id.insert(id, request.guest_object);
        self.vectors
            .entry(request.vector)
            .or_default()
            .push(request.guest_object);
        Ok(id)
    }

    /// Begins an ISR dispatch.  A disconnected or pending-disconnect object
    /// fails closed.
    pub fn begin_dispatch(&mut self, guest_object: u64) -> Result<DispatchTicket, i32> {
        let record = self
            .interrupts
            .get_mut(&guest_object)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if !record.connected || record.disconnect_pending {
            return Err(STATUS_DELETE_PENDING);
        }
        record.in_flight += 1;
        self.isr_invocations += 1;
        Ok(DispatchTicket {
            id: record.id,
            guest_object: record.guest_object,
            service_routine: record.service_routine,
            service_context: record.service_context,
            irql: record.irql,
        })
    }

    /// Completes an ISR dispatch.  A deferred disconnect is finalized here.
    pub fn end_dispatch(&mut self, ticket: DispatchTicket) -> Result<bool, i32> {
        let guest_object = *self.by_id.get(&ticket.id).ok_or(STATUS_INVALID_HANDLE)?;
        let record = self
            .interrupts
            .get_mut(&guest_object)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if record.in_flight == 0 {
            return Err(STATUS_INVALID_DEVICE_STATE);
        }
        record.in_flight -= 1;
        self.dispatches += 1;
        let disconnected = record.in_flight == 0 && record.disconnect_pending;
        if disconnected {
            self.remove(guest_object);
        }
        Ok(disconnected)
    }

    /// Requests disconnect.  An in-flight ISR defers removal to
    /// `end_dispatch`; an idle object is removed immediately.
    pub fn disconnect(&mut self, guest_object: u64) -> Result<DisconnectOutcome, i32> {
        let record = self
            .interrupts
            .get_mut(&guest_object)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if record.in_flight > 0 {
            record.disconnect_pending = true;
            return Ok(DisconnectOutcome::Deferred);
        }
        self.remove(guest_object);
        Ok(DisconnectOutcome::Removed)
    }

    /// Returns the guest objects attached to a vector in connection order.
    pub fn vector_objects(&self, vector: u32) -> Vec<u64> {
        self.vectors.get(&vector).cloned().unwrap_or_default()
    }

    pub fn query(&self, guest_object: u64) -> Result<&VirtualInterrupt, i32> {
        self.interrupts
            .get(&guest_object)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Test hook: inject a stale guest object into a vector list.
    #[cfg(test)]
    pub(crate) fn inject_stale_vector(&mut self, vector: u32, guest_object: u64) {
        self.vectors
            .entry(vector)
            .or_default()
            .insert(0, guest_object);
    }

    pub fn is_connected(&self, guest_object: u64) -> bool {
        self.interrupts
            .get(&guest_object)
            .is_some_and(|record| record.connected)
    }

    pub fn connected_count(&self) -> usize {
        self.interrupts.len()
    }

    pub fn isr_invocations(&self) -> u64 {
        self.isr_invocations
    }

    pub fn dispatch_count(&self) -> u64 {
        self.dispatches
    }

    pub fn disconnected_count(&self) -> u64 {
        self.disconnected
    }
    /// Validates the interrupt version selector.
    pub fn validate_version(version: u32) -> Result<u32, i32> {
        match version {
            CONNECT_LINE_BASED | CONNECT_FULLY_SPECIFIED => Ok(version),
            CONNECT_MESSAGE_BASED => Err(STATUS_NOT_SUPPORTED),
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }

    fn remove(&mut self, guest_object: u64) {
        let record = self
            .interrupts
            .remove(&guest_object)
            .expect("remove is only called for a connected interrupt");
        self.by_id.remove(&record.id);
        if let Some(list) = self.vectors.get_mut(&record.vector) {
            list.retain(|candidate| *candidate != guest_object);
            if list.is_empty() {
                self.vectors.remove(&record.vector);
            }
        }
        self.disconnected += 1;
    }
}

impl Default for InterruptManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(guest: u64, vector: u32) -> ConnectRequest {
        ConnectRequest {
            guest_object: guest,
            service_routine: 0x1000,
            service_context: 0xAA,
            spin_lock: 0,
            vector,
            irql: 5,
            synchronize_irql: 5,
            mode: INTERRUPT_LATCHED,
            share_vector: false,
            affinity: 1,
        }
    }

    #[test]
    fn connection_validation_rejects_invalid_vectors_irql_affinity_and_polarity() {
        let mut manager = InterruptManager::new();
        assert_eq!(InterruptManager::default().connected_count(), 0);
        let mut bad = request(0, 0x30);
        bad.guest_object = 0;
        assert_eq!(manager.connect(bad), Err(STATUS_INVALID_PARAMETER));
        let mut bad = request(0x500, 0x30);
        bad.service_routine = 0;
        assert_eq!(manager.connect(bad), Err(STATUS_INVALID_PARAMETER));
        for vector in [0, 256] {
            assert_eq!(
                manager.connect(request(0x500, vector)),
                Err(STATUS_INVALID_PARAMETER)
            );
        }
        let mut bad = request(0x500, 0x30);
        bad.irql = 2;
        assert_eq!(manager.connect(bad), Err(STATUS_INVALID_PARAMETER));
        let mut bad = request(0x500, 0x30);
        bad.irql = 16;
        assert_eq!(manager.connect(bad), Err(STATUS_INVALID_PARAMETER));
        let mut bad = request(0x500, 0x30);
        bad.synchronize_irql = 4;
        assert_eq!(manager.connect(bad), Err(STATUS_INVALID_PARAMETER));
        let mut bad = request(0x500, 0x30);
        bad.synchronize_irql = 16;
        assert_eq!(manager.connect(bad), Err(STATUS_INVALID_PARAMETER));
        let mut bad = request(0x500, 0x30);
        bad.mode = 2;
        assert_eq!(manager.connect(bad), Err(STATUS_INVALID_PARAMETER));
        let mut bad = request(0x500, 0x30);
        bad.affinity = 0;
        assert_eq!(manager.connect(bad), Err(STATUS_INVALID_PARAMETER));
        let mut bad = request(0x500, 0x30);
        bad.affinity = ONLINE_AFFINITY + 1;
        assert_eq!(manager.connect(bad), Err(STATUS_INVALID_PARAMETER));
        let mut bad = request(0x500, 0x30);
        bad.share_vector = true;
        assert_eq!(manager.connect(bad), Err(STATUS_INVALID_PARAMETER));
        let mut bad = request(0x500, 0x30);
        bad.share_vector = true;
        bad.spin_lock = 0x9000;
        assert_eq!(manager.connect(bad), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn duplicate_vectors_and_shared_polarity_are_exact() {
        let mut manager = InterruptManager::new();
        let first = manager.connect(request(0x500, 0x30)).unwrap();
        assert_eq!(manager.connected_count(), 1);
        assert!(manager.is_connected(0x500));
        assert_eq!(manager.query(0x500).unwrap().id, first);
        assert_eq!(manager.query(0x999), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            manager.connect(request(0x500, 0x31)),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            manager.connect(request(0x501, 0x30)),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        let mut shared = request(0x600, 0x40);
        shared.share_vector = true;
        shared.spin_lock = 0x9000;
        shared.mode = INTERRUPT_LEVEL_SENSITIVE;
        manager.connect(shared).unwrap();
        let mut shared_two = request(0x601, 0x40);
        shared_two.share_vector = true;
        shared_two.spin_lock = 0x9000;
        shared_two.mode = INTERRUPT_LEVEL_SENSITIVE;
        manager.connect(shared_two).unwrap();
        assert_eq!(manager.vector_objects(0x40), vec![0x600, 0x601]);
        assert_eq!(manager.vector_objects(0x41), Vec::<u64>::new());
        let mut mismatched = shared_two;
        mismatched.guest_object = 0x602;
        mismatched.irql = 6;
        mismatched.synchronize_irql = 6;
        assert_eq!(
            manager.connect(mismatched),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        let mut shared_into_latched = request(0x603, 0x30);
        shared_into_latched.share_vector = true;
        shared_into_latched.spin_lock = 0x9000;
        shared_into_latched.mode = INTERRUPT_LEVEL_SENSITIVE;
        assert_eq!(
            manager.connect(shared_into_latched),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        manager.vectors.insert(0x50, vec![0x777]);
        manager.connect(request(0x604, 0x50)).unwrap();
    }

    #[test]
    fn dispatch_and_deferred_disconnect_wait_for_in_flight_isr() {
        let mut manager = InterruptManager::new();
        assert_eq!(manager.begin_dispatch(0x500), Err(STATUS_INVALID_HANDLE));
        manager.connect(request(0x500, 0x30)).unwrap();
        let ticket = manager.begin_dispatch(0x500).unwrap();
        assert_eq!(ticket.guest_object, 0x500);
        assert_eq!(ticket.service_routine, 0x1000);
        assert_eq!(ticket.service_context, 0xAA);
        assert_eq!(ticket.irql, 5);
        assert_eq!(manager.isr_invocations(), 1);
        assert_eq!(manager.disconnect(0x500), Ok(DisconnectOutcome::Deferred));
        assert_eq!(manager.begin_dispatch(0x500), Err(STATUS_DELETE_PENDING));
        assert!(manager.end_dispatch(ticket).unwrap());
        assert_eq!(manager.dispatch_count(), 1);
        assert_eq!(manager.disconnected_count(), 1);
        assert!(!manager.is_connected(0x500));
        assert_eq!(manager.disconnect(0x500), Err(STATUS_INVALID_HANDLE));
        assert_eq!(manager.end_dispatch(ticket), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn idle_disconnect_frees_the_vector_and_double_end_is_rejected() {
        let mut manager = InterruptManager::new();
        manager.connect(request(0x500, 0x30)).unwrap();
        let ticket = manager.begin_dispatch(0x500).unwrap();
        assert!(!manager.end_dispatch(ticket).unwrap());
        assert_eq!(
            manager.end_dispatch(ticket),
            Err(STATUS_INVALID_DEVICE_STATE)
        );
        assert_eq!(manager.disconnect(0x500), Ok(DisconnectOutcome::Removed));
        assert_eq!(manager.connected_count(), 0);
        assert_eq!(manager.vector_objects(0x30), Vec::<u64>::new());
        manager.connect(request(0x501, 0x30)).unwrap();
        assert_eq!(manager.vector_objects(0x30), vec![0x501]);
        manager.vectors.remove(&0x30);
        assert_eq!(manager.disconnect(0x501), Ok(DisconnectOutcome::Removed));
        manager.connect(request(0x501, 0x31)).unwrap();
        let record = manager.interrupts.get_mut(&0x501).unwrap();
        record.connected = false;
        assert_eq!(manager.begin_dispatch(0x501), Err(STATUS_DELETE_PENDING));
    }

    #[test]
    fn versions_and_compatibility_helpers_are_exact() {
        assert_eq!(
            InterruptManager::validate_version(CONNECT_LINE_BASED),
            Ok(CONNECT_LINE_BASED)
        );
        assert_eq!(
            InterruptManager::validate_version(CONNECT_FULLY_SPECIFIED),
            Ok(CONNECT_FULLY_SPECIFIED)
        );
        assert_eq!(
            InterruptManager::validate_version(CONNECT_MESSAGE_BASED),
            Err(STATUS_NOT_SUPPORTED)
        );
        assert_eq!(
            InterruptManager::validate_version(99),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(MIN_DEVICE_IRQL, 3);
        assert_eq!(MAX_IRQL, 15);
    }
}
