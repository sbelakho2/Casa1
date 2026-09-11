//! NT-style object manager for the CasaK executive.
//!
//! This module implements a small but real subset of the NT object manager:
//!
//! - typed objects ([`ObjectType`]) with typed payloads ([`ObjectPayload`])
//! - a global object table keyed by monotonic [`ObjectId`]s
//! - per-process handle tables mapping [`Handle`]s to objects and access rights
//! - real reference counting: duplication increments, close-on-last-reference
//!   destroys the object and invokes the finalization callback exactly once
//! - a `\BaseNamedObjects` namespace with create/open/name-conflict semantics
//! - NTSTATUS error codes for all failure paths
//!
//! The manager performs no guest execution and has no global mutable state:
//! identifiers are issued by the manager itself, so tests are deterministic.

use std::collections::{BTreeMap, HashMap};

/// NTSTATUS as used by the object manager entry points.
pub type NtStatus = i32;

pub const STATUS_SUCCESS: NtStatus = 0;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = 0xC000_0034u32 as NtStatus;
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = 0xC000_0035u32 as NtStatus;
pub const STATUS_OBJECT_NAME_INVALID: NtStatus = 0xC000_0033u32 as NtStatus;
pub const STATUS_INVALID_HANDLE: NtStatus = 0xC000_0008u32 as NtStatus;
pub const STATUS_OBJECT_TYPE_MISMATCH: NtStatus = 0xC000_00EAu32 as NtStatus;
pub const STATUS_ACCESS_DENIED: NtStatus = 0xC000_0022u32 as NtStatus;
pub const STATUS_INSUFFICIENT_RESOURCES: NtStatus = 0xC000_009Au32 as NtStatus;
pub const STATUS_INVALID_ADDRESS: NtStatus = 0xC000_0141u32 as NtStatus;
pub const STATUS_MUTANT_NOT_OWNED: NtStatus = 0xC000_0046u32 as NtStatus;
pub const STATUS_NOT_FOUND: NtStatus = 0xC000_0225u32 as NtStatus;

/// Monotonic identifier of an object in the global object table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(pub u64);

/// Per-process handle value. Handles are multiples of four and never zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle(pub u32);

impl Handle {
    /// The reserved null handle.
    pub const NULL: Handle = Handle(0);

    /// Returns `true` when this is the null handle.
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

/// Object types managed by the executive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObjectType {
    Process,
    Thread,
    File,
    Event,
    Mutant,
    Section,
    Key,
    Device,
    Driver,
    IoCompletion,
}

impl ObjectType {
    /// Every object type, in declaration order.
    pub const ALL: [ObjectType; 10] = [
        ObjectType::Process,
        ObjectType::Thread,
        ObjectType::File,
        ObjectType::Event,
        ObjectType::Mutant,
        ObjectType::Section,
        ObjectType::Key,
        ObjectType::Device,
        ObjectType::Driver,
        ObjectType::IoCompletion,
    ];

    /// Stable lowercase type name.
    pub const fn name(self) -> &'static str {
        match self {
            ObjectType::Process => "Process",
            ObjectType::Thread => "Thread",
            ObjectType::File => "File",
            ObjectType::Event => "Event",
            ObjectType::Mutant => "Mutant",
            ObjectType::Section => "Section",
            ObjectType::Key => "Key",
            ObjectType::Device => "Device",
            ObjectType::Driver => "Driver",
            ObjectType::IoCompletion => "IoCompletion",
        }
    }
}

impl std::fmt::Display for ObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Typed payload for a process object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessPayload {
    pub process_id: u32,
    pub image_name: String,
    pub terminated: bool,
}

impl ProcessPayload {
    pub fn new(process_id: u32, image_name: impl Into<String>) -> Self {
        Self {
            process_id,
            image_name: image_name.into(),
            terminated: false,
        }
    }
}

/// Typed payload for a thread object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadPayload {
    pub thread_id: u32,
    pub owner_process_id: u32,
    pub suspended: bool,
}

impl ThreadPayload {
    pub fn new(thread_id: u32, owner_process_id: u32) -> Self {
        Self {
            thread_id,
            owner_process_id,
            suspended: false,
        }
    }
}

/// Typed payload for a file object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePayload {
    pub path: String,
    pub readable: bool,
    pub writable: bool,
    pub position: u64,
}

impl FilePayload {
    pub fn new(path: impl Into<String>, readable: bool, writable: bool) -> Self {
        Self {
            path: path.into(),
            readable,
            writable,
            position: 0,
        }
    }
}

/// Typed payload for an event object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPayload {
    pub manual_reset: bool,
    pub signaled: bool,
}

impl EventPayload {
    pub fn new(manual_reset: bool, signaled: bool) -> Self {
        Self {
            manual_reset,
            signaled,
        }
    }
}

/// Typed payload for a mutant (mutex) object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutantPayload {
    pub owner_thread: Option<u32>,
    pub recursion: u32,
    pub abandoned: bool,
}

impl MutantPayload {
    pub fn new() -> Self {
        Self {
            owner_thread: None,
            recursion: 0,
            abandoned: false,
        }
    }
}

impl Default for MutantPayload {
    fn default() -> Self {
        Self::new()
    }
}

/// Typed payload for a section object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionPayload {
    pub maximum_size: u64,
    pub mapped: bool,
}

impl SectionPayload {
    pub fn new(maximum_size: u64) -> Self {
        Self {
            maximum_size,
            mapped: false,
        }
    }
}

/// Typed payload for a registry key object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyPayload {
    pub path: String,
    pub values: BTreeMap<String, String>,
}

impl KeyPayload {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            values: BTreeMap::new(),
        }
    }
}

/// Typed payload for a device object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePayload {
    pub device_name: String,
}

impl DevicePayload {
    pub fn new(device_name: impl Into<String>) -> Self {
        Self {
            device_name: device_name.into(),
        }
    }
}

/// Typed payload for a driver object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverPayload {
    pub driver_name: String,
    pub loaded: bool,
}

impl DriverPayload {
    pub fn new(driver_name: impl Into<String>) -> Self {
        Self {
            driver_name: driver_name.into(),
            loaded: true,
        }
    }
}

/// Typed payload for an I/O completion object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoCompletionPayload {
    pub queue_depth: u32,
    pub pending: u32,
}

impl IoCompletionPayload {
    pub fn new(queue_depth: u32) -> Self {
        Self {
            queue_depth,
            pending: 0,
        }
    }
}

/// A typed object payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectPayload {
    Process(ProcessPayload),
    Thread(ThreadPayload),
    File(FilePayload),
    Event(EventPayload),
    Mutant(MutantPayload),
    Section(SectionPayload),
    Key(KeyPayload),
    Device(DevicePayload),
    Driver(DriverPayload),
    IoCompletion(IoCompletionPayload),
}

impl ObjectPayload {
    /// The object type this payload belongs to.
    pub fn kind(&self) -> ObjectType {
        match self {
            ObjectPayload::Process(_) => ObjectType::Process,
            ObjectPayload::Thread(_) => ObjectType::Thread,
            ObjectPayload::File(_) => ObjectType::File,
            ObjectPayload::Event(_) => ObjectType::Event,
            ObjectPayload::Mutant(_) => ObjectType::Mutant,
            ObjectPayload::Section(_) => ObjectType::Section,
            ObjectPayload::Key(_) => ObjectType::Key,
            ObjectPayload::Device(_) => ObjectType::Device,
            ObjectPayload::Driver(_) => ObjectType::Driver,
            ObjectPayload::IoCompletion(_) => ObjectType::IoCompletion,
        }
    }

    pub fn as_event(&self) -> Option<&EventPayload> {
        match self {
            ObjectPayload::Event(event) => Some(event),
            _ => None,
        }
    }

    pub fn as_mutant(&self) -> Option<&MutantPayload> {
        match self {
            ObjectPayload::Mutant(mutant) => Some(mutant),
            _ => None,
        }
    }
}

pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;

pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_EXECUTE: u32 = 0x0000_0020;
pub const EVENT_MODIFY_STATE: u32 = 0x0000_0002;
pub const EVENT_QUERY_STATE: u32 = 0x0000_0001;
pub const MUTANT_QUERY_STATE: u32 = 0x0000_0001;
pub const SECTION_QUERY: u32 = 0x0000_0001;
pub const SECTION_MAP_WRITE: u32 = 0x0000_0002;
pub const SECTION_MAP_READ: u32 = 0x0000_0004;
pub const KEY_QUERY_VALUE: u32 = 0x0000_0001;
pub const KEY_SET_VALUE: u32 = 0x0000_0002;
pub const PROCESS_TERMINATE: u32 = 0x0000_0001;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0000_0400;
pub const THREAD_TERMINATE: u32 = 0x0000_0001;
pub const THREAD_QUERY_INFORMATION: u32 = 0x0000_0400;
pub const IO_COMPLETION_MODIFY_STATE: u32 = 0x0000_0002;

const fn specific_read(kind: ObjectType) -> u32 {
    match kind {
        ObjectType::Process => PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
        ObjectType::Thread => THREAD_QUERY_INFORMATION | SYNCHRONIZE,
        ObjectType::File => FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE,
        ObjectType::Event => EVENT_QUERY_STATE | SYNCHRONIZE,
        ObjectType::Mutant => MUTANT_QUERY_STATE | SYNCHRONIZE,
        ObjectType::Section => SECTION_QUERY | SECTION_MAP_READ | SYNCHRONIZE,
        ObjectType::Key => KEY_QUERY_VALUE,
        ObjectType::Device => SYNCHRONIZE,
        ObjectType::Driver => SYNCHRONIZE,
        ObjectType::IoCompletion => SYNCHRONIZE,
    }
}

const fn specific_write(kind: ObjectType) -> u32 {
    match kind {
        ObjectType::Process => PROCESS_TERMINATE,
        ObjectType::Thread => THREAD_TERMINATE,
        ObjectType::File => FILE_WRITE_DATA | FILE_APPEND_DATA,
        ObjectType::Event => EVENT_MODIFY_STATE,
        ObjectType::Mutant => 0,
        ObjectType::Section => SECTION_MAP_WRITE,
        ObjectType::Key => KEY_SET_VALUE,
        ObjectType::Device => 0,
        ObjectType::Driver => 0,
        ObjectType::IoCompletion => IO_COMPLETION_MODIFY_STATE,
    }
}

const fn specific_all(kind: ObjectType) -> u32 {
    specific_read(kind) | specific_write(kind) | DELETE | READ_CONTROL | WRITE_DAC
}

/// Expands generic access bits into type-specific access bits.
pub fn map_generic_access(kind: ObjectType, access: u32) -> u32 {
    let mut expanded = access & !(GENERIC_READ | GENERIC_WRITE | GENERIC_ALL);
    if access & GENERIC_ALL != 0 {
        expanded |= specific_all(kind);
    } else {
        if access & GENERIC_READ != 0 {
            expanded |= specific_read(kind);
        }
        if access & GENERIC_WRITE != 0 {
            expanded |= specific_write(kind);
        }
    }
    expanded
}

/// Returns `true` when `granted` (expanded) covers `desired` for `kind`.
pub fn access_granted(granted: u32, desired: u32, kind: ObjectType) -> bool {
    let needed = map_generic_access(kind, desired);
    needed == 0 || (granted & needed) == needed
}

/// An object in the global object table.
#[derive(Debug)]
pub struct ObjectEntry {
    pub id: ObjectId,
    pub kind: ObjectType,
    pub name: Option<String>,
    pub payload: ObjectPayload,
    ref_count: u32,
}

impl ObjectEntry {
    /// Current reference count. The object is destroyed when this reaches zero.
    pub fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// Stable type name of this object.
    pub fn type_name(&self) -> &'static str {
        self.kind.name()
    }
}

/// A handle table entry mapping a handle to an object and granted access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleEntry {
    pub handle: Handle,
    pub object: ObjectId,
    pub access: u32,
    pub inheritable: bool,
}

/// Per-process handle table. Handles are allocated as multiples of four.
#[derive(Debug)]
pub struct ProcessHandleTable {
    next_handle: u32,
    handles: BTreeMap<Handle, HandleEntry>,
}

impl ProcessHandleTable {
    fn new() -> Self {
        Self {
            next_handle: 4,
            handles: BTreeMap::new(),
        }
    }

    fn allocate_handle(&mut self) -> Handle {
        let handle = Handle(self.next_handle);
        self.next_handle += 4;
        handle
    }

    pub fn len(&self) -> usize {
        self.handles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    pub fn get(&self, handle: Handle) -> Option<&HandleEntry> {
        self.handles.get(&handle)
    }

    pub fn iter(&self) -> impl Iterator<Item = &HandleEntry> {
        self.handles.values()
    }
}

impl Default for ProcessHandleTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Finalization callback invoked once when an object's last reference drops.
pub type FinalizeCallback = Box<dyn FnMut(ObjectId, ObjectType, &ObjectPayload)>;

/// The global object manager.
pub struct ObjectManager {
    objects: HashMap<ObjectId, ObjectEntry>,
    namespace: BTreeMap<String, ObjectId>,
    processes: HashMap<u32, ProcessHandleTable>,
    next_object_id: u64,
    finalized: u64,
    finalized_log: Vec<ObjectId>,
    on_finalize: Option<FinalizeCallback>,
}

impl ObjectManager {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            namespace: BTreeMap::new(),
            processes: HashMap::new(),
            next_object_id: 1,
            finalized: 0,
            finalized_log: Vec::new(),
            on_finalize: None,
        }
    }

    /// Creates a manager that invokes `callback` for every finalized object.
    pub fn with_finalizer(callback: FinalizeCallback) -> Self {
        let mut manager = Self::new();
        manager.on_finalize = Some(callback);
        manager
    }

    /// Normalizes an object name. Unqualified names are placed under
    /// `\BaseNamedObjects`; names are canonicalized with a leading backslash.
    pub fn normalize_name(name: &str) -> Result<String, NtStatus> {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.contains('\0') {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if trimmed.contains('\\') {
            if trimmed.starts_with('\\') {
                Ok(trimmed.to_string())
            } else {
                Ok(format!("\\{trimmed}"))
            }
        } else {
            Ok(format!("\\BaseNamedObjects\\{trimmed}"))
        }
    }

    fn name_key(name: &str) -> String {
        name.to_lowercase()
    }

    /// Builds the canonical name of an object under `\BaseNamedObjects`.
    pub fn base_named_objects_path(name: &str) -> String {
        Self::normalize_name(name).unwrap_or_else(|_| format!("\\BaseNamedObjects\\{name}"))
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn name_count(&self) -> usize {
        self.namespace.len()
    }

    pub fn finalized_count(&self) -> u64 {
        self.finalized
    }

    pub fn finalized_log(&self) -> &[ObjectId] {
        &self.finalized_log
    }

    pub fn query_object(&self, id: ObjectId) -> Result<&ObjectEntry, NtStatus> {
        self.objects.get(&id).ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn ref_count(&self, id: ObjectId) -> Result<u32, NtStatus> {
        Ok(self.query_object(id)?.ref_count())
    }

    pub fn object_type(&self, id: ObjectId) -> Result<ObjectType, NtStatus> {
        Ok(self.query_object(id)?.kind)
    }

    /// Creates a typed object. A named object fails with
    /// `STATUS_OBJECT_NAME_COLLISION` when the (case-insensitive) name is taken.
    pub fn create_object(
        &mut self,
        kind: ObjectType,
        payload: ObjectPayload,
        name: Option<&str>,
    ) -> Result<ObjectId, NtStatus> {
        if payload.kind() != kind {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        let normalized = match name {
            Some(name) => {
                let canonical = Self::normalize_name(name)?;
                if self.namespace.contains_key(&Self::name_key(&canonical)) {
                    return Err(STATUS_OBJECT_NAME_COLLISION);
                }
                Some(canonical)
            }
            None => None,
        };
        let id = ObjectId(self.next_object_id);
        self.next_object_id += 1;
        let entry = ObjectEntry {
            id,
            kind,
            name: normalized.clone(),
            payload,
            ref_count: 1,
        };
        self.objects.insert(id, entry);
        if let Some(canonical) = normalized {
            self.namespace.insert(Self::name_key(&canonical), id);
        }
        Ok(id)
    }

    /// Opens an existing named object, adding a reference for the opener.
    /// Returns `STATUS_OBJECT_TYPE_MISMATCH` when the type differs.
    pub fn open_object(&mut self, name: &str, kind: ObjectType) -> Result<ObjectId, NtStatus> {
        let canonical = Self::normalize_name(name)?;
        let id = *self
            .namespace
            .get(&Self::name_key(&canonical))
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let entry = self
            .objects
            .get_mut(&id)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if entry.kind != kind {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        entry.ref_count += 1;
        Ok(id)
    }

    /// Drops a creator/opener reference. Returns the remaining reference count.
    pub fn release_object(&mut self, id: ObjectId) -> Result<u32, NtStatus> {
        self.drop_reference(id)
    }

    fn drop_reference(&mut self, id: ObjectId) -> Result<u32, NtStatus> {
        let remaining = {
            let entry = self.objects.get_mut(&id).ok_or(STATUS_INVALID_HANDLE)?;
            entry.ref_count = entry.ref_count.saturating_sub(1);
            entry.ref_count
        };
        if remaining == 0 {
            self.destroy(id);
        }
        Ok(remaining)
    }

    fn destroy(&mut self, id: ObjectId) {
        if let Some(entry) = self.objects.remove(&id) {
            if let Some(name) = entry.name.as_deref() {
                self.namespace.remove(&Self::name_key(name));
            }
            self.finalized += 1;
            self.finalized_log.push(id);
            if let Some(callback) = self.on_finalize.as_mut() {
                callback(id, entry.kind, &entry.payload);
            }
        }
    }

    /// Grants a handle in `process_id`, adding a reference to the object.
    pub fn grant_handle(
        &mut self,
        process_id: u32,
        object: ObjectId,
        access: u32,
        inheritable: bool,
    ) -> Result<Handle, NtStatus> {
        let kind = self
            .objects
            .get(&object)
            .map(|entry| entry.kind)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let expanded = map_generic_access(kind, access);
        if let Some(entry) = self.objects.get_mut(&object) {
            entry.ref_count += 1;
        } else {
            return Err(STATUS_INVALID_HANDLE);
        }
        let table = self.processes.entry(process_id).or_default();
        let handle = table.allocate_handle();
        let entry = HandleEntry {
            handle,
            object,
            access: expanded,
            inheritable,
        };
        table.handles.insert(handle, entry);
        Ok(handle)
    }

    pub fn lookup_handle(&self, process_id: u32, handle: Handle) -> Result<&HandleEntry, NtStatus> {
        if handle.is_null() {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.processes
            .get(&process_id)
            .and_then(|table| table.get(handle))
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Validates that `handle` carries `desired_access`; returns the object id.
    pub fn require_access(
        &self,
        process_id: u32,
        handle: Handle,
        desired_access: u32,
    ) -> Result<ObjectId, NtStatus> {
        let handle_entry = self.lookup_handle(process_id, handle)?;
        let object = self
            .objects
            .get(&handle_entry.object)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if access_granted(handle_entry.access, desired_access, object.kind) {
            Ok(handle_entry.object)
        } else {
            Err(STATUS_ACCESS_DENIED)
        }
    }

    /// Duplicates a handle, adding a reference on the same object.
    /// Uses the source access when `desired_access` is zero.
    pub fn duplicate_handle(
        &mut self,
        source_process: u32,
        source_handle: Handle,
        target_process: u32,
        desired_access: u32,
        inheritable: bool,
    ) -> Result<Handle, NtStatus> {
        let (object, source_access) = {
            let entry = self.lookup_handle(source_process, source_handle)?;
            (entry.object, entry.access)
        };
        let kind = self.objects.get(&object).ok_or(STATUS_INVALID_HANDLE)?.kind;
        let effective = if desired_access == 0 {
            source_access
        } else {
            map_generic_access(kind, desired_access)
        };
        if !access_granted(source_access, effective, kind) {
            return Err(STATUS_ACCESS_DENIED);
        }
        self.grant_handle(target_process, object, effective, inheritable)
    }

    /// Closes a handle, dropping its reference. The last reference destroys
    /// the object and runs finalization exactly once.
    pub fn close_handle(&mut self, process_id: u32, handle: Handle) -> Result<(), NtStatus> {
        let removed = self
            .processes
            .get_mut(&process_id)
            .and_then(|table| table.handles.remove(&handle))
            .ok_or(STATUS_INVALID_HANDLE)?;
        self.drop_reference(removed.object)?;
        Ok(())
    }

    /// Closes every handle owned by a process, returning how many were closed.
    pub fn close_process(&mut self, process_id: u32) -> Result<u32, NtStatus> {
        let handles: Vec<Handle> = match self.processes.get(&process_id) {
            Some(table) => table.handles.keys().copied().collect(),
            None => return Ok(0),
        };
        for handle in &handles {
            self.close_handle(process_id, *handle)?;
        }
        self.processes.remove(&process_id);
        Ok(handles.len() as u32)
    }

    /// Duplicates every inheritable handle from `parent` into `child`,
    /// returning the newly created child handles.
    pub fn inherit_handles(&mut self, parent: u32, child: u32) -> Result<Vec<Handle>, NtStatus> {
        let inheritable: Vec<(ObjectId, u32)> = match self.processes.get(&parent) {
            Some(table) => table
                .handles
                .values()
                .filter(|entry| entry.inheritable)
                .map(|entry| (entry.object, entry.access))
                .collect(),
            None => Vec::new(),
        };
        let mut created = Vec::with_capacity(inheritable.len());
        for (object, access) in inheritable {
            created.push(self.grant_handle(child, object, access, true)?);
        }
        Ok(created)
    }

    pub fn handle_count(&self, process_id: u32) -> usize {
        self.processes
            .get(&process_id)
            .map(ProcessHandleTable::len)
            .unwrap_or(0)
    }

    pub fn handle_table(&self, process_id: u32) -> Option<&ProcessHandleTable> {
        self.processes.get(&process_id)
    }

    fn payload_mut(&mut self, id: ObjectId) -> Result<&mut ObjectPayload, NtStatus> {
        Ok(&mut self
            .objects
            .get_mut(&id)
            .ok_or(STATUS_INVALID_HANDLE)?
            .payload)
    }

    /// Signals an event object.
    pub fn set_event(&mut self, id: ObjectId) -> Result<(), NtStatus> {
        match self.payload_mut(id)? {
            ObjectPayload::Event(event) => {
                event.signaled = true;
                Ok(())
            }
            _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
        }
    }

    /// Resets an event object.
    pub fn reset_event(&mut self, id: ObjectId) -> Result<(), NtStatus> {
        match self.payload_mut(id)? {
            ObjectPayload::Event(event) => {
                event.signaled = false;
                Ok(())
            }
            _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
        }
    }

    /// Attempts to acquire a mutant. Returns `false` when another thread owns it.
    pub fn acquire_mutant(&mut self, id: ObjectId, thread_id: u32) -> Result<bool, NtStatus> {
        match self.payload_mut(id)? {
            ObjectPayload::Mutant(mutant) => match mutant.owner_thread {
                None => {
                    mutant.owner_thread = Some(thread_id);
                    mutant.recursion = 1;
                    mutant.abandoned = false;
                    Ok(true)
                }
                Some(owner) if owner == thread_id => {
                    mutant.recursion += 1;
                    Ok(true)
                }
                Some(_) => Ok(false),
            },
            _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
        }
    }

    /// Releases a mutant held by the calling thread.
    pub fn release_mutant(&mut self, id: ObjectId, thread_id: u32) -> Result<(), NtStatus> {
        match self.payload_mut(id)? {
            ObjectPayload::Mutant(mutant) => match mutant.owner_thread {
                Some(owner) if owner == thread_id => {
                    if mutant.recursion > 1 {
                        mutant.recursion -= 1;
                    } else {
                        mutant.owner_thread = None;
                        mutant.recursion = 0;
                    }
                    Ok(())
                }
                Some(_) => Err(STATUS_ACCESS_DENIED),
                None => Err(STATUS_MUTANT_NOT_OWNED),
            },
            _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
        }
    }
}

impl Default for ObjectManager {
    fn default() -> Self {
        Self::new()
    }
}
