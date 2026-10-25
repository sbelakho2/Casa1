//! CasaK executive shim.
//!
//! This module wires together the NT object manager ([`object`]) and the
//! executive support primitives ([`exec`]) used by the kernel emulation:
//!
//! - [`ObjectManager`] — typed objects, reference counts, per-process handle
//!   tables, handle duplication/inheritance, and a `\BaseNamedObjects`
//!   namespace returning real NTSTATUS codes
//! - [`TaggedPool`] — tagged pool allocation with accounting, hard budget
//!   exhaustion, and double-free detection
//! - [`LookasideList`] — cached block reuse verified by pointer identity
//! - [`DpcQueue`] — FIFO deferred procedure call execution with monotonic
//!   sequence numbers
//!
//! Everything is self-contained: no guest execution, no global mutable state.

pub mod alpc;
pub mod config;
pub mod diagnostics;
pub mod exec;
pub mod executive;
pub mod interrupt;
pub mod introspection;
pub mod io;
pub mod memory;
pub mod object;
pub mod pnp;
pub mod process;
pub mod security;
pub mod status;
pub mod threads;

pub use exec::*;
pub use io::*;
pub use object::*;

#[cfg(test)]
mod tests {
    use super::exec::{DpcQueue, LookasideList, PoolTag, TagStats, TaggedPool};
    use super::object::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    const TAG_ONE: PoolTag = PoolTag::new(b"Kasa");
    const TAG_TWO: PoolTag = PoolTag::new(b"Kbdy");

    fn event_payload(manual_reset: bool) -> ObjectPayload {
        ObjectPayload::Event(EventPayload::new(manual_reset, false))
    }

    #[test]
    fn refcount_dup_close_semantics() {
        let mut manager = ObjectManager::new();
        let id = manager
            .create_object(ObjectType::Event, event_payload(false), Some("RefEvent"))
            .expect("create named event");
        assert_eq!(manager.ref_count(id).unwrap(), 1);
        assert_eq!(manager.name_count(), 1);

        let first = manager
            .grant_handle(10, id, EVENT_MODIFY_STATE | SYNCHRONIZE, false)
            .unwrap();
        assert_eq!(manager.ref_count(id).unwrap(), 2);
        let second = manager
            .duplicate_handle(10, first, 20, EVENT_MODIFY_STATE, false)
            .unwrap();
        assert_eq!(manager.ref_count(id).unwrap(), 3);
        assert_eq!(manager.lookup_handle(10, first).unwrap().object, id);
        assert_eq!(manager.lookup_handle(20, second).unwrap().object, id);

        manager.close_handle(10, first).unwrap();
        assert_eq!(manager.ref_count(id).unwrap(), 2);
        manager.close_handle(20, second).unwrap();
        assert_eq!(manager.ref_count(id).unwrap(), 1);
        assert_eq!(manager.release_object(id).unwrap(), 0);

        assert_eq!(manager.ref_count(id), Err(STATUS_INVALID_HANDLE));
        assert_eq!(manager.finalized_count(), 1);
        assert_eq!(manager.object_count(), 0);
        assert_eq!(manager.name_count(), 0);
        assert_eq!(manager.close_handle(10, first), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn duplicate_handle_checks_access() {
        let mut manager = ObjectManager::new();
        let payload = ObjectPayload::File(FilePayload::new("C:\\casa\\data.bin", true, false));
        let id = manager
            .create_object(ObjectType::File, payload, None)
            .unwrap();
        let source = manager.grant_handle(1, id, GENERIC_READ, false).unwrap();
        assert_eq!(
            manager.duplicate_handle(1, source, 2, FILE_WRITE_DATA, false),
            Err(STATUS_ACCESS_DENIED)
        );
        let dup = manager
            .duplicate_handle(1, source, 2, GENERIC_READ, false)
            .unwrap();
        assert_eq!(manager.require_access(2, dup, FILE_READ_DATA).unwrap(), id);
        assert_eq!(
            manager.require_access(2, dup, FILE_WRITE_DATA),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            manager.require_access(2, dup, GENERIC_WRITE),
            Err(STATUS_ACCESS_DENIED)
        );
        manager.close_handle(1, source).unwrap();
        manager.close_handle(2, dup).unwrap();
        manager.release_object(id).unwrap();
        assert_eq!(manager.finalized_count(), 1);
    }

    #[test]
    fn namespace_create_open_conflict() {
        let mut manager = ObjectManager::new();
        let path = "\\BaseNamedObjects\\CasaKName";
        let payload = || ObjectPayload::Section(SectionPayload::new(4096));
        let id = manager
            .create_object(ObjectType::Section, payload(), Some(path))
            .unwrap();
        assert_eq!(
            manager.create_object(ObjectType::Section, payload(), Some(path)),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            manager.create_object(
                ObjectType::Section,
                payload(),
                Some("\\BASENAMEDOBJECTS\\casakname")
            ),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );

        let opened = manager.open_object(path, ObjectType::Section).unwrap();
        assert_eq!(opened, id);
        assert_eq!(manager.ref_count(id).unwrap(), 2);
        let short = manager
            .open_object("CasaKName", ObjectType::Section)
            .unwrap();
        assert_eq!(short, id);
        assert_eq!(manager.ref_count(id).unwrap(), 3);

        assert_eq!(
            manager.open_object("\\BaseNamedObjects\\Missing", ObjectType::Section),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.open_object("", ObjectType::Section),
            Err(STATUS_OBJECT_NAME_INVALID)
        );

        manager.release_object(id).unwrap();
        manager.release_object(id).unwrap();
        assert_eq!(manager.release_object(id).unwrap(), 0);
        assert_eq!(manager.finalized_count(), 1);
        assert_eq!(manager.name_count(), 0);
        assert_eq!(
            manager.open_object(path, ObjectType::Section),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn namespace_type_mismatch() {
        let mut manager = ObjectManager::new();
        let payload = ObjectPayload::File(FilePayload::new("C:\\casa\\type.bin", true, true));
        let file = manager
            .create_object(ObjectType::File, payload, Some("TypeCheck"))
            .unwrap();
        assert_eq!(
            manager.open_object("TypeCheck", ObjectType::Event),
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        );
        assert_eq!(
            manager.open_object("TypeCheck", ObjectType::File).unwrap(),
            file
        );
        assert_eq!(manager.ref_count(file).unwrap(), 2);
        assert_eq!(
            manager.create_object(
                ObjectType::Event,
                ObjectPayload::File(FilePayload::new("C:\\casa\\bad.bin", true, false)),
                None
            ),
            Err(STATUS_OBJECT_TYPE_MISMATCH)
        );
        assert_eq!(manager.set_event(file), Err(STATUS_OBJECT_TYPE_MISMATCH));
        assert_eq!(manager.release_object(file).unwrap(), 1);
    }

    #[test]
    fn finalization_runs_exactly_once() {
        let calls = Rc::new(RefCell::new(Vec::<(ObjectId, ObjectType)>::new()));
        let sink = Rc::clone(&calls);
        let mut manager = ObjectManager::with_finalizer(Box::new(move |id, kind, _payload| {
            sink.borrow_mut().push((id, kind));
        }));
        let id = manager
            .create_object(
                ObjectType::Mutant,
                ObjectPayload::Mutant(MutantPayload::new()),
                None,
            )
            .unwrap();
        let handle = manager
            .grant_handle(1, id, MUTANT_QUERY_STATE, false)
            .unwrap();
        assert!(manager.acquire_mutant(id, 77).unwrap());
        assert!(!manager.acquire_mutant(id, 78).unwrap());
        assert_eq!(manager.release_mutant(id, 78), Err(STATUS_ACCESS_DENIED));
        manager.release_mutant(id, 77).unwrap();

        manager.close_handle(1, handle).unwrap();
        assert_eq!(manager.ref_count(id).unwrap(), 1);
        manager.release_object(id).unwrap();
        assert_eq!(manager.ref_count(id), Err(STATUS_INVALID_HANDLE));
        assert_eq!(manager.close_handle(1, handle), Err(STATUS_INVALID_HANDLE));
        assert_eq!(manager.release_object(id), Err(STATUS_INVALID_HANDLE));

        assert_eq!(manager.finalized_count(), 1);
        assert_eq!(manager.finalized_log(), &[id]);
        assert_eq!(calls.borrow().len(), 1);
        assert_eq!(calls.borrow()[0], (id, ObjectType::Mutant));
    }

    #[test]
    fn process_close_and_inheritance() {
        let mut manager = ObjectManager::new();
        let shared = manager
            .create_object(ObjectType::Event, event_payload(true), None)
            .unwrap();
        let private = manager
            .create_object(
                ObjectType::File,
                ObjectPayload::File(FilePayload::new("C:\\casa\\private.bin", true, true)),
                None,
            )
            .unwrap();
        let shared_handle = manager
            .grant_handle(7, shared, EVENT_MODIFY_STATE, true)
            .unwrap();
        let private_handle = manager
            .grant_handle(7, private, GENERIC_READ, false)
            .unwrap();
        assert_eq!(manager.handle_count(7), 2);

        let inherited = manager.inherit_handles(7, 8).unwrap();
        assert_eq!(inherited.len(), 1);
        assert_eq!(manager.handle_count(8), 1);
        assert_eq!(
            manager.lookup_handle(8, inherited[0]).unwrap().object,
            shared
        );
        assert_eq!(manager.ref_count(shared).unwrap(), 3);

        assert_eq!(manager.close_process(7).unwrap(), 2);
        assert_eq!(manager.handle_count(7), 0);
        assert_eq!(manager.ref_count(shared).unwrap(), 2);
        assert_eq!(manager.ref_count(private).unwrap(), 1);

        assert_eq!(manager.close_process(8).unwrap(), 1);
        assert_eq!(manager.ref_count(shared).unwrap(), 1);
        manager.release_object(shared).unwrap();
        manager.release_object(private).unwrap();
        assert_eq!(manager.object_count(), 0);
        assert_eq!(manager.finalized_count(), 2);
        assert_eq!(manager.finalized_log().len(), 2);
        assert_eq!(manager.close_process(7), Ok(0));
        assert_eq!(
            manager.close_handle(7, private_handle),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.close_handle(7, shared_handle),
            Err(STATUS_INVALID_HANDLE)
        );
    }

    #[test]
    fn pool_accounting_exhaustion_and_double_free() {
        let mut pool = TaggedPool::new(64);
        let first = pool.allocate(TAG_ONE, 48).unwrap();
        assert_eq!(pool.used_bytes(), 48);
        assert_eq!(pool.peak_bytes(), 48);
        assert_eq!(pool.live_count(), 1);
        assert_eq!(
            pool.tag_stats(TAG_ONE),
            TagStats {
                bytes: 48,
                count: 1
            }
        );

        assert_eq!(
            pool.allocate(TAG_TWO, 32),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(pool.used_bytes(), 48);
        assert_eq!(pool.tag_stats(TAG_TWO), TagStats::default());

        pool.free(first).unwrap();
        assert_eq!(pool.used_bytes(), 0);
        assert_eq!(pool.live_count(), 0);
        assert_eq!(pool.tag_stats(TAG_ONE), TagStats { bytes: 0, count: 0 });
        assert_eq!(pool.free_count(), 1);

        let second = pool.allocate(TAG_TWO, 32).unwrap();
        assert_eq!(second.tag, TAG_TWO);
        assert_eq!(pool.used_bytes(), 32);
        assert_eq!(
            pool.allocate(TAG_TWO, 33),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        let third = pool.allocate(TAG_ONE, 32).unwrap();
        assert_eq!(pool.used_bytes(), 64);
        assert_eq!(pool.peak_bytes(), 64);

        assert_eq!(pool.free(first), Err(STATUS_INVALID_ADDRESS));
        assert_eq!(pool.free(second), Ok(()));
        assert_eq!(pool.free(second), Err(STATUS_INVALID_ADDRESS));
        assert_eq!(pool.free_count(), 2);
        assert_eq!(pool.live_count(), 1);
        pool.free(third).unwrap();
        assert_eq!(pool.used_bytes(), 0);
        assert_eq!(pool.allocation_count(), 3);
    }

    #[test]
    fn lookaside_reuses_freed_block_by_pointer() {
        let mut list = LookasideList::new(TAG_ONE, 4, 128);
        let first = list.allocate(32).unwrap();
        assert_eq!((list.misses(), list.hits()), (1, 0));
        assert_eq!(list.in_use(), 1);
        list.free(first).unwrap();
        assert_eq!(list.free_depth(), 1);
        assert_eq!(list.held_bytes(), 32);
        assert_eq!(list.in_use(), 0);

        let reused = list.allocate(32).unwrap();
        assert_eq!(reused.ptr, first.ptr);
        assert_ne!(reused.epoch, first.epoch);
        assert_eq!((list.misses(), list.hits()), (1, 1));
        list.free(reused).unwrap();
        assert_eq!(list.free(first), Err(STATUS_INVALID_ADDRESS));

        let grown = list.allocate(48).unwrap();
        assert_eq!(list.misses(), 2);
        list.free(grown).unwrap();
        assert_eq!(
            list.allocate(128).unwrap_err(),
            STATUS_INSUFFICIENT_RESOURCES
        );
        assert_eq!(list.in_use(), 0);
    }

    #[test]
    fn lookaside_depth_limit_releases_memory() {
        let mut list = LookasideList::new(TAG_ONE, 1, 64);
        let first = list.allocate(16).unwrap();
        let second = list.allocate(16).unwrap();
        assert_eq!(list.held_bytes(), 32);
        list.free(first).unwrap();
        list.free(second).unwrap();
        assert_eq!(list.free_depth(), 1);
        assert_eq!(list.depth_high_water(), 1);
        assert_eq!(list.held_bytes(), 16);
        assert_eq!(list.free(second), Err(STATUS_INVALID_ADDRESS));
        let reused = list.allocate(16).unwrap();
        assert_eq!(reused.ptr, first.ptr);
        assert_eq!(list.hits(), 1);
        list.free(reused).unwrap();
    }

    #[test]
    fn dpc_executes_fifo_with_monotonic_sequence() {
        let mut queue = DpcQueue::new();
        let log = Rc::new(RefCell::new(Vec::<u64>::new()));
        let mut sequences = Vec::new();
        for index in 0..5u64 {
            let log = Rc::clone(&log);
            sequences.push(queue.queue(move || log.borrow_mut().push(index)));
        }
        assert_eq!(sequences, vec![1, 2, 3, 4, 5]);
        assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(queue.pending_count(), 5);
        assert_eq!(queue.pending_sequences(), sequences);
        assert_eq!(queue.executed_count(), 0);

        assert_eq!(queue.execute_pending(), 5);
        assert_eq!(*log.borrow(), vec![0, 1, 2, 3, 4]);
        assert_eq!(queue.executed_count(), 5);
        assert_eq!(queue.pending_count(), 0);
        assert_eq!(queue.execute_pending(), 0);

        let next = queue.queue(|| {});
        assert_eq!(next, 6);
        assert_eq!(queue.cancel(next), Ok(()));
        assert_eq!(queue.cancelled_count(), 1);
        assert_eq!(queue.pending_count(), 0);
        assert_eq!(queue.cancel(999), Err(STATUS_NOT_FOUND));
    }
}
