#![allow(dead_code, unused_imports)]
//! Stage 3 canonical state: the Win32 subsystem is backed by ONE object
//! manager, ONE generation-protected handle table, ONE guest-process model
//! (guest PID namespace) and ONE canonical VirtualMemory shared with the
//! CPU/JIT.
//!
//! Guest identity contract: `GetCurrentProcessId`/`GetCurrentProcess` return
//! the GUEST pid (a Casa1 runtime-side identity starting at 4) — never the
//! host's POSIX pid.  The host pid appears ONLY as diagnostic provenance
//! (the toolhelp "macwin" snapshot entry).

mod support;

use casa1::ge::{GameEnvironment, GeArch};
use casa1::win32::{MemoryProtection, Win32Subsystem};
use tempfile::TempDir;

fn setup_win32() -> (TempDir, Win32Subsystem) {
    let temp_dir = TempDir::new().expect("temp dir");
    let ge =
        GameEnvironment::create_in(temp_dir.path(), "test-canonical", GeArch::X64, "win11-23h2")
            .expect("create GE");
    let win32 = Win32Subsystem::new(ge, true);
    (temp_dir, win32)
}

#[test]
fn named_objects_resolve_through_one_namespace() {
    let (_tmp, mut win32) = setup_win32();
    // Events, mutexes, semaphores and sections all resolve through the
    // single named-object namespace (prefix spellings are equivalent).
    let (event, existed) = win32.create_event(false, false, false, Some("Global\\CanonicalEvent"));
    assert!(!existed);
    let (event2, existed) = win32.create_event(
        false,
        false,
        false,
        Some("\\BaseNamedObjects\\CanonicalEvent"),
    );
    assert!(
        existed,
        "Global\\ and \\BaseNamedObjects\\ name the same object"
    );
    // CreateEventW mints a fresh handle per call, but both handles
    // reference the SAME object (shared state, one refcount).
    assert_ne!(event, event2);
    assert_eq!(
        win32.describe_handle(event).expect("descriptor").refcount,
        2
    );
    let opened = win32
        .open_event(0x1F0003, false, "Local\\CanonicalEvent")
        .expect("open by another prefix spelling");
    assert_eq!(
        win32.describe_handle(opened).expect("descriptor").refcount,
        3
    );
    // The object state is shared: signal through one handle, observe
    // through the other.
    win32.set_event(event).expect("set event");
    assert_eq!(
        win32
            .wait_for_single_object(event2, 0, false, None)
            .expect("wait via second handle"),
        casa1::win32::WaitStatus::Object0
    );
    win32.close_handle(event).expect("close event");
    win32.close_handle(event2).expect("close event");
    win32.close_handle(opened).expect("close opened");
    // The last handle close forgets the name.
    let (_, existed) = win32.create_event(false, false, false, Some("Global\\CanonicalEvent"));
    assert!(!existed, "name forgotten after the last handle closes");
}

#[test]
fn named_object_namespace_resolves_across_prefixes() {
    let (_tmp, mut win32) = setup_win32();
    // Every prefix spelling of the same session-local object resolves to
    // the SAME object: bare names, Global\, Local\,
    // \BaseNamedObjects\ and \Sessions\<n>\BaseNamedObjects\.
    let (first, existed) = win32.create_event(false, false, false, Some("CrossPrefixEvent"));
    assert!(!existed, "bare name creates the object");
    for prefix in [
        "Global\\CrossPrefixEvent",
        "Local\\CrossPrefixEvent",
        "\\BaseNamedObjects\\CrossPrefixEvent",
        "\\Sessions\\2\\BaseNamedObjects\\CrossPrefixEvent",
    ] {
        let (handle, existed) = win32.create_event(false, false, false, Some(prefix));
        assert!(existed, "{prefix} must resolve to the existing object");
        assert_ne!(handle, first, "CreateEventW mints a fresh handle");
    }
    // Named mutexes and semaphores resolve through the same namespace.
    let (mutex, existed) = win32.create_named_mutex("Global\\CrossPrefixMutex", false, false);
    assert!(!existed);
    assert_eq!(
        win32
            .open_named_mutex("\\Sessions\\1\\BaseNamedObjects\\CrossPrefixMutex")
            .expect("mutex resolves across prefixes"),
        mutex,
        "the SAME handle is returned for the same object"
    );
    let (semaphore, existed) =
        win32.create_named_semaphore("Local\\CrossPrefixSemaphore", 1, 1, false);
    assert!(!existed);
    assert_eq!(
        win32
            .open_named_semaphore("\\BaseNamedObjects\\CrossPrefixSemaphore")
            .expect("semaphore resolves across prefixes"),
        semaphore
    );
    // Named sections resolve through the same namespace too.
    let (section, existed) = win32
        .create_file_mapping_w(
            Some("Global\\CrossPrefixSection"),
            0x1000,
            MemoryProtection {
                read: true,
                write: true,
                execute: false,
            },
            false,
        )
        .expect("create mapping");
    assert!(!existed);
    let (second, existed) = win32
        .create_file_mapping_w(
            Some("\\BaseNamedObjects\\CrossPrefixSection"),
            0x1000,
            MemoryProtection {
                read: true,
                write: true,
                execute: false,
            },
            false,
        )
        .expect("open mapping across prefixes");
    assert!(existed);
    assert_ne!(section, second, "a fresh handle per open");
    assert_eq!(
        win32
            .describe_handle(section)
            .expect("section descriptor")
            .refcount,
        2,
        "both handles reference the same section object"
    );
}

#[test]
fn duplicate_handles_share_the_object_and_refcount() {
    let (_tmp, mut win32) = setup_win32();
    let (event, _) = win32.create_event(false, false, false, None);
    assert_eq!(
        win32.describe_handle(event).expect("descriptor").refcount,
        1
    );
    let duplicate = win32
        .duplicate_handle(event, 0x1F0003, true, false, false)
        .expect("duplicate");
    assert_ne!(duplicate, event);
    assert_eq!(
        win32.describe_handle(event).expect("descriptor").refcount,
        2,
        "the object manager tracks per-object handle counts"
    );
    // Both handles observe the SAME object state: setting through one is
    // visible through the other.
    win32.set_event(event).expect("set event");
    assert_eq!(
        win32
            .wait_for_single_object(duplicate, 0, false, None)
            .expect("wait via duplicate"),
        casa1::win32::WaitStatus::Object0
    );
    win32.close_handle(event).expect("close source");
    win32.close_handle(duplicate).expect("close duplicate");
}

#[test]
fn handle_table_generations_are_recycled_safely() {
    let (_tmp, mut win32) = setup_win32();
    let (event, _) = win32.create_event(false, false, false, None);
    let generation = win32
        .handle_generation(event)
        .expect("live handle has a generation");
    assert_eq!(generation, 0, "generations start at zero");
    assert!(
        win32.validate_handle_generation(event, 0).is_ok(),
        "the cached (value, generation) pair is valid while live"
    );
    win32.close_handle(event).expect("close");
    // The value is recycled FIFO; the fresh incarnation carries a NEW
    // generation so a stale reference to the old object is detectable.
    let (recycled, _) = win32.create_event(false, false, false, None);
    assert_eq!(
        recycled, event,
        "closed handle values are recycled FIFO like Windows"
    );
    assert_eq!(
        win32.handle_generation(recycled),
        Some(1),
        "reuse gets a fresh generation"
    );
    assert!(
        win32.validate_handle_generation(recycled, 0).is_err(),
        "a stale (value, generation) pair is rejected"
    );
    assert!(
        win32.validate_handle_generation(recycled, 1).is_ok(),
        "the current (value, generation) pair validates"
    );
    win32.close_handle(recycled).expect("close recycled");
}

#[test]
fn object_manager_names_events_and_mutexes() {
    let (_tmp, mut win32) = setup_win32();
    // Events and mutexes share ONE name namespace: each type's objects
    // resolve through the same map, and opening by name returns a handle to
    // the SAME object (shared state, one refcount).
    let (event, existed) = win32.create_event(false, false, false, Some("SharedEvent"));
    assert!(!existed);
    let (mutex, existed) = win32.create_named_mutex("SharedMutex", false, false);
    assert!(!existed);
    // Opening the event by name resolves the EVENT object; opening the
    // mutex by name resolves the MUTEX object.
    let opened_event = win32
        .open_event(0x1F0003, false, "SharedEvent")
        .expect("open the event");
    assert_eq!(
        win32
            .describe_handle(opened_event)
            .expect("descriptor")
            .object_type,
        casa1::win32::ObjectType::Event
    );
    assert_eq!(
        win32
            .describe_handle(event)
            .expect("descriptor")
            .object_type,
        casa1::win32::ObjectType::Event
    );
    assert_eq!(
        win32
            .describe_handle(mutex)
            .expect("descriptor")
            .object_type,
        casa1::win32::ObjectType::Mutex
    );
    // The event object state is shared through the unified namespace.
    win32.set_event(event).expect("set event");
    assert_eq!(
        win32
            .wait_for_single_object(opened_event, 0, false, None)
            .expect("wait via opened handle"),
        casa1::win32::WaitStatus::Object0,
        "the event opened through the namespace is the SAME object"
    );
    win32.close_handle(event).expect("close event");
    win32
        .close_handle(opened_event)
        .expect("close opened event");
    win32.close_handle(mutex).expect("close mutex");
}
