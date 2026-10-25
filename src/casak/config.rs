//! Configuration manager: registry hives, keys, values, links,
//! notifications, volatile storage and transactions.
//!
//! Keys are canonicalized case-insensitively under `\Registry\Machine` or
//! `\Registry\User`.  Every mutation is observable through path-scoped
//! subscriptions, and transactions are real snapshots that can be committed
//! or rolled back.

use std::collections::{BTreeMap, BTreeSet};

use crate::casak::status::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_KEY_HAS_CHILDREN,
    STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND,
    STATUS_OBJECT_PATH_INVALID, STATUS_OBJECT_PATH_NOT_FOUND,
};

/// Largest value payload accepted by the configuration manager.
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;
const MACHINE_ROOT: &str = "\\registry\\machine";
const USER_ROOT: &str = "\\registry\\user";

/// A typed registry value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryValue {
    String(String),
    Dword(u32),
    Qword(u64),
    Binary(Vec<u8>),
    MultiString(Vec<String>),
}

impl RegistryValue {
    /// Stable registry type name.
    pub fn type_name(&self) -> &'static str {
        match self {
            RegistryValue::String(_) => "REG_SZ",
            RegistryValue::Dword(_) => "REG_DWORD",
            RegistryValue::Qword(_) => "REG_QWORD",
            RegistryValue::Binary(_) => "REG_BINARY",
            RegistryValue::MultiString(_) => "REG_MULTI_SZ",
        }
    }

    pub fn byte_len(&self) -> usize {
        match self {
            RegistryValue::String(value) => value.len(),
            RegistryValue::Dword(_) => 4,
            RegistryValue::Qword(_) => 8,
            RegistryValue::Binary(value) => value.len(),
            RegistryValue::MultiString(values) => values.iter().map(String::len).sum(),
        }
    }
}

/// A key record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyRecord {
    volatile: bool,
    link: Option<String>,
    values: BTreeMap<String, RegistryValue>,
    subkeys: BTreeSet<String>,
    last_write: u64,
}

/// Monotonic notification handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NotificationId(pub u64);

/// Monotonic transaction handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransactionId(pub u64);

/// The kind of change delivered to a notification subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryEventKind {
    KeyCreated,
    KeyDeleted,
    ValueSet,
    ValueDeleted,
    Linked,
}

/// One registry change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEvent {
    pub path: String,
    pub kind: RegistryEventKind,
    pub value_name: Option<String>,
}

#[derive(Debug)]
struct Subscription {
    path: String,
    events: Vec<RegistryEvent>,
}

/// The configuration manager.
#[derive(Debug)]
pub struct ConfigManager {
    keys: BTreeMap<String, KeyRecord>,
    subscriptions: BTreeMap<NotificationId, Subscription>,
    transactions: BTreeMap<TransactionId, BTreeMap<String, KeyRecord>>,
    next_notification: u64,
    next_transaction: u64,
    clock: u64,
}

impl ConfigManager {
    /// Creates a manager with the standard machine/user roots.
    pub fn new() -> Self {
        let mut manager = Self {
            keys: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            transactions: BTreeMap::new(),
            next_notification: 1,
            next_transaction: 1,
            clock: 1,
        };
        for root in [MACHINE_ROOT, USER_ROOT] {
            manager.keys.insert(
                root.to_string(),
                KeyRecord {
                    volatile: false,
                    link: None,
                    values: BTreeMap::new(),
                    subkeys: BTreeSet::new(),
                    last_write: 0,
                },
            );
        }
        manager
    }

    /// Canonicalizes a registry path.
    pub fn normalize(path: &str) -> Result<String, i32> {
        let trimmed = path.trim();
        if trimmed.is_empty() || trimmed.contains('\0') {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let mut canonical = trimmed.to_ascii_lowercase().replace('/', "\\");
        canonical = canonical.trim_end_matches('\\').to_string();
        let under_machine = canonical == MACHINE_ROOT
            || canonical
                .strip_prefix(MACHINE_ROOT)
                .is_some_and(|rest| rest.starts_with('\\'));
        let under_user = canonical == USER_ROOT
            || canonical
                .strip_prefix(USER_ROOT)
                .is_some_and(|rest| rest.starts_with('\\'));
        if !under_machine && !under_user {
            return Err(STATUS_OBJECT_PATH_INVALID);
        }
        Ok(canonical)
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    pub fn notification_count(&self) -> usize {
        self.subscriptions.len()
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Creates a key.  The parent must already exist; duplicates collide.
    pub fn create_key(&mut self, path: &str, volatile: bool) -> Result<String, i32> {
        let requested = Self::normalize(path)?;
        if requested == MACHINE_ROOT || requested == USER_ROOT {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        let (parent, name) = split_parent(&requested)?;
        let parent = self
            .resolve(&parent)
            .map_err(|_| STATUS_OBJECT_PATH_NOT_FOUND)?;
        let canonical = format!("{parent}\\{name}");
        if self.keys.contains_key(&canonical) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        self.clock += 1;
        self.keys.insert(
            canonical.clone(),
            KeyRecord {
                volatile,
                link: None,
                values: BTreeMap::new(),
                subkeys: BTreeSet::new(),
                last_write: self.clock,
            },
        );
        if let Some(record) = self.keys.get_mut(&parent) {
            record.subkeys.insert(name);
        }
        self.notify(&canonical, RegistryEventKind::KeyCreated, None);
        Ok(canonical)
    }

    /// Opens a key, following links.
    pub fn open_key(&self, path: &str) -> Result<String, i32> {
        let canonical = Self::normalize(path)?;
        self.resolve(&canonical)
    }

    /// Deletes an empty key.
    pub fn delete_key(&mut self, path: &str) -> Result<(), i32> {
        let canonical = Self::normalize(path)?;
        if canonical == MACHINE_ROOT || canonical == USER_ROOT {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let resolved = self.resolve(&canonical)?;
        let record = self
            .keys
            .get(&resolved)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if !record.subkeys.is_empty() {
            return Err(STATUS_KEY_HAS_CHILDREN);
        }
        let (parent, name) = split_parent(&resolved)?;
        self.keys.remove(&resolved);
        if let Some(parent_record) = self.keys.get_mut(&parent) {
            parent_record.subkeys.remove(&name);
        }
        self.notify(&resolved, RegistryEventKind::KeyDeleted, None);
        Ok(())
    }

    /// Turns an existing empty key into a symbolic link to `target`.
    pub fn link_key(&mut self, link_path: &str, target_path: &str) -> Result<(), i32> {
        let link = self.open_key(link_path)?;
        let target = self.open_key(target_path)?;
        if link == target {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let record = self.keys.get(&link).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if !record.subkeys.is_empty() || !record.values.is_empty() || record.link.is_some() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if let Some(record) = self.keys.get_mut(&link) {
            record.link = Some(target);
            record.last_write = self.clock;
        }
        self.clock += 1;
        self.notify(&link, RegistryEventKind::Linked, None);
        Ok(())
    }

    /// The link target of a key, if it is a link.
    pub fn link_target(&self, path: &str) -> Result<Option<String>, i32> {
        let canonical = Self::normalize(path)?;
        let record = self
            .keys
            .get(&canonical)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        Ok(record.link.clone())
    }

    /// Whether a key is volatile.
    pub fn is_volatile(&self, path: &str) -> Result<bool, i32> {
        let canonical = self.open_key(path)?;
        Ok(self
            .keys
            .get(&canonical)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?
            .volatile)
    }

    /// Sets a value on a key.
    pub fn set_value(&mut self, path: &str, name: &str, value: RegistryValue) -> Result<(), i32> {
        if name.len() > 255 || value.byte_len() > MAX_VALUE_BYTES {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let canonical = self.open_key(path)?;
        self.clock += 1;
        let key = self
            .keys
            .get_mut(&canonical)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        key.values.insert(name.to_ascii_lowercase(), value);
        key.last_write = self.clock;
        self.notify(
            &canonical,
            RegistryEventKind::ValueSet,
            Some(name.to_string()),
        );
        Ok(())
    }

    /// Reads a value.
    pub fn get_value(&self, path: &str, name: &str) -> Result<&RegistryValue, i32> {
        let canonical = self.open_key(path)?;
        let key = self
            .keys
            .get(&canonical)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        key.values
            .get(&name.to_ascii_lowercase())
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
    }

    /// Deletes a value.
    pub fn delete_value(&mut self, path: &str, name: &str) -> Result<(), i32> {
        let canonical = self.open_key(path)?;
        let key = self
            .keys
            .get_mut(&canonical)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        key.values
            .remove(&name.to_ascii_lowercase())
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        self.clock += 1;
        key.last_write = self.clock;
        self.notify(
            &canonical,
            RegistryEventKind::ValueDeleted,
            Some(name.to_string()),
        );
        Ok(())
    }

    /// Enumerates the full paths of a key's subkeys.
    pub fn enum_subkeys(&self, path: &str) -> Result<Vec<String>, i32> {
        let canonical = self.open_key(path)?;
        let record = self
            .keys
            .get(&canonical)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        Ok(record
            .subkeys
            .iter()
            .map(|name| format!("{canonical}\\{name}"))
            .collect())
    }

    /// Enumerates the (name, value) pairs of a key.
    pub fn enum_values(&self, path: &str) -> Result<Vec<(String, RegistryValue)>, i32> {
        let canonical = self.open_key(path)?;
        let record = self
            .keys
            .get(&canonical)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        Ok(record
            .values
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect())
    }

    /// Subscribes to changes at or below `path`.
    pub fn subscribe(&mut self, path: &str) -> Result<NotificationId, i32> {
        let canonical = self.open_key(path)?;
        let id = NotificationId(self.next_notification);
        self.next_notification += 1;
        self.subscriptions.insert(
            id,
            Subscription {
                path: canonical,
                events: Vec::new(),
            },
        );
        Ok(id)
    }

    /// Drains the events queued for a subscription.
    pub fn poll(&mut self, id: NotificationId) -> Result<Vec<RegistryEvent>, i32> {
        let subscription = self
            .subscriptions
            .get_mut(&id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        Ok(std::mem::take(&mut subscription.events))
    }

    /// Cancels a subscription.
    pub fn cancel_subscription(&mut self, id: NotificationId) -> Result<(), i32> {
        self.subscriptions
            .remove(&id)
            .map(|_| ())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Begins a transaction by snapshotting the key store.
    pub fn begin_transaction(&mut self) -> TransactionId {
        let id = TransactionId(self.next_transaction);
        self.next_transaction += 1;
        self.transactions.insert(id, self.keys.clone());
        id
    }

    /// Commits a transaction, discarding its snapshot.
    pub fn commit_transaction(&mut self, id: TransactionId) -> Result<(), i32> {
        self.transactions
            .remove(&id)
            .map(|_| ())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Rolls a transaction back to its snapshot.
    pub fn rollback_transaction(&mut self, id: TransactionId) -> Result<(), i32> {
        let snapshot = self.transactions.remove(&id).ok_or(STATUS_INVALID_HANDLE)?;
        self.keys = snapshot;
        self.notify(
            MACHINE_ROOT,
            RegistryEventKind::KeyDeleted,
            Some("rollback".to_string()),
        );
        Ok(())
    }

    /// Removes every volatile key (hive unload).  Non-volatile keys remain.
    pub fn unload_hive(&mut self) -> usize {
        let volatile: Vec<String> = self
            .keys
            .iter()
            .filter(|(_, record)| record.volatile)
            .map(|(path, _)| path.clone())
            .collect();
        for path in &volatile {
            let (parent, name) = split_parent(path).expect("a volatile key is never a hive root");
            if let Some(record) = self.keys.get_mut(&parent) {
                record.subkeys.remove(&name);
            }
        }
        let removed = volatile.len();
        for path in volatile {
            self.keys.remove(&path);
        }
        removed
    }

    fn resolve(&self, path: &str) -> Result<String, i32> {
        let mut cursor = path.to_string();
        let mut hops = 0;
        loop {
            hops += 1;
            if hops > 32 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            match self.keys.get(&cursor) {
                Some(record) => match record.link.clone() {
                    Some(target) => cursor = target,
                    None => return Ok(cursor),
                },
                None => {
                    let (parent, name) = split_parent(&cursor)?;
                    let parent = self.resolve(&parent)?;
                    let candidate = format!("{parent}\\{name}");
                    if !self.keys.contains_key(&candidate) {
                        return Err(STATUS_OBJECT_NAME_NOT_FOUND);
                    }
                    cursor = candidate;
                }
            }
        }
    }

    fn notify(&mut self, path: &str, kind: RegistryEventKind, value_name: Option<String>) {
        for subscription in self.subscriptions.values_mut() {
            let prefix = format!("{}\\", subscription.path);
            if path == subscription.path || path.starts_with(&prefix) {
                subscription.events.push(RegistryEvent {
                    path: path.to_string(),
                    kind,
                    value_name: value_name.clone(),
                });
            }
        }
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

fn split_parent(path: &str) -> Result<(String, String), i32> {
    let (parent, name) = path.rsplit_once('\\').ok_or(STATUS_OBJECT_PATH_INVALID)?;
    if name.is_empty() || parent.is_empty() {
        return Err(STATUS_OBJECT_PATH_INVALID);
    }
    Ok((parent.to_string(), name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOFTWARE: &str = "\\Registry\\Machine\\Software";
    const CASA: &str = "\\Registry\\Machine\\Software\\Casa";

    fn create_tree() -> ConfigManager {
        let mut manager = ConfigManager::new();
        manager.create_key(SOFTWARE, false).unwrap();
        manager.create_key(CASA, false).unwrap();
        manager
    }

    #[test]
    fn normalize_rejects_paths_outside_the_hives() {
        assert_eq!(ConfigManager::default().key_count(), 2);
        assert_eq!(
            split_parent("\\registry\\machine\\"),
            Err(STATUS_OBJECT_PATH_INVALID)
        );
        assert_eq!(split_parent("name"), Err(STATUS_OBJECT_PATH_INVALID));
        assert_eq!(
            ConfigManager::normalize(""),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(
            ConfigManager::normalize("bad\0path"),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(
            ConfigManager::normalize("\\Registry\\Other\\Key"),
            Err(STATUS_OBJECT_PATH_INVALID)
        );
        assert_eq!(
            ConfigManager::normalize("\\Registry\\MachineX\\Key"),
            Err(STATUS_OBJECT_PATH_INVALID)
        );
        assert_eq!(
            ConfigManager::normalize("\\Registry\\Machine\\"),
            Ok(MACHINE_ROOT.to_string())
        );
        assert_eq!(
            ConfigManager::normalize("\\Registry/User/Foo/Bar"),
            Ok("\\registry\\user\\foo\\bar".to_string())
        );
    }

    #[test]
    fn key_creation_and_deletion_reject_invalid_tree_edits() {
        let mut manager = ConfigManager::new();
        assert_eq!(
            manager.create_key("\\Registry\\Machine", false),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            manager.create_key("\\Registry\\User", true),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            manager.create_key("\\Registry\\Machine\\Missing\\Child", false),
            Err(STATUS_OBJECT_PATH_NOT_FOUND)
        );
        manager.create_key(SOFTWARE, false).unwrap();
        assert_eq!(
            manager.create_key(SOFTWARE, true),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        manager.create_key(CASA, false).unwrap();
        assert_eq!(
            manager.enum_subkeys(SOFTWARE).unwrap(),
            vec![CASA.to_ascii_lowercase()]
        );
        assert_eq!(manager.delete_key(SOFTWARE), Err(STATUS_KEY_HAS_CHILDREN));
        assert_eq!(
            manager.delete_key("\\Registry\\Machine"),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.delete_key("\\Registry\\Machine\\Absent"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(manager.delete_key(CASA), Ok(()));
        assert_eq!(manager.delete_key(CASA), Err(STATUS_OBJECT_NAME_NOT_FOUND));
        assert_eq!(manager.open_key(CASA), Err(STATUS_OBJECT_NAME_NOT_FOUND));
        assert_eq!(manager.key_count(), 3);
    }

    #[test]
    fn links_resolve_and_reject_nonempty_or_cyclic_targets() {
        let mut manager = create_tree();
        let target = manager
            .create_key("\\Registry\\Machine\\Target", false)
            .unwrap();
        let link = manager
            .create_key("\\Registry\\Machine\\Link", false)
            .unwrap();
        assert_eq!(manager.link_key(&link, &target), Ok(()));
        assert_eq!(manager.open_key(&link).unwrap(), target);
        assert_eq!(manager.link_target(&link).unwrap(), Some(target.clone()));
        assert_eq!(manager.link_target(&target).unwrap(), None);
        assert_eq!(
            manager.link_key(&link, &target),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.link_key(&link, &link),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.link_key("\\Registry\\Machine\\Absent", &target),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        let with_value = manager
            .create_key("\\Registry\\Machine\\WithValue", false)
            .unwrap();
        manager
            .set_value(&with_value, "x", RegistryValue::Dword(1))
            .unwrap();
        assert_eq!(
            manager.link_key(&with_value, &target),
            Err(STATUS_INVALID_PARAMETER)
        );
        let with_child = manager
            .create_key("\\Registry\\Machine\\WithChild", false)
            .unwrap();
        manager
            .create_key("\\Registry\\Machine\\WithChild\\Child", false)
            .unwrap();
        assert_eq!(
            manager.link_key(&with_child, &target),
            Err(STATUS_INVALID_PARAMETER)
        );
        let cycle = manager
            .create_key("\\Registry\\Machine\\Cycle", false)
            .unwrap();
        manager.keys.get_mut(&cycle).unwrap().link = Some(cycle.clone());
        assert_eq!(manager.open_key(&cycle), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(manager.link_target(&cycle).unwrap(), Some(cycle));
        assert_eq!(
            manager.link_target("\\Registry\\Machine\\Absent"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn values_are_typed_case_insensitive_and_bounded() {
        let mut manager = create_tree();
        manager
            .set_value(CASA, "Dword", RegistryValue::Dword(7))
            .unwrap();
        manager
            .set_value(CASA, "Qword", RegistryValue::Qword(9))
            .unwrap();
        manager
            .set_value(CASA, "String", RegistryValue::String("hello".to_string()))
            .unwrap();
        manager
            .set_value(CASA, "Binary", RegistryValue::Binary(vec![1, 2]))
            .unwrap();
        manager
            .set_value(
                CASA,
                "Multi",
                RegistryValue::MultiString(vec!["a".to_string(), "bb".to_string()]),
            )
            .unwrap();
        assert_eq!(
            manager.get_value(CASA, "dword"),
            Ok(&RegistryValue::Dword(7))
        );
        assert_eq!(
            manager.get_value(CASA, "QWORD"),
            Ok(&RegistryValue::Qword(9))
        );
        assert_eq!(
            manager.get_value(CASA, "string").unwrap().type_name(),
            "REG_SZ"
        );
        assert_eq!(
            manager.get_value(CASA, "dword").unwrap().type_name(),
            "REG_DWORD"
        );
        assert_eq!(
            manager.get_value(CASA, "qword").unwrap().type_name(),
            "REG_QWORD"
        );
        assert_eq!(
            manager.get_value(CASA, "binary").unwrap().type_name(),
            "REG_BINARY"
        );
        assert_eq!(
            manager.get_value(CASA, "multi").unwrap().type_name(),
            "REG_MULTI_SZ"
        );
        assert_eq!(manager.get_value(CASA, "multi").unwrap().byte_len(), 3);
        let values = manager.enum_values(CASA).unwrap();
        assert_eq!(values.len(), 5);
        assert_eq!(values[0].0, "binary");
        assert_eq!(
            manager.get_value(CASA, "absent"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.delete_value(CASA, "absent"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(manager.delete_value(CASA, "dword"), Ok(()));
        assert_eq!(
            manager.get_value(CASA, "dword"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.get_value("\\Registry\\Machine\\Absent", "x"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.set_value(CASA, &"n".repeat(256), RegistryValue::Dword(1)),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.set_value(
                CASA,
                "huge",
                RegistryValue::Binary(vec![0; MAX_VALUE_BYTES + 1])
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.set_value("\\Registry\\Machine\\Absent", "x", RegistryValue::Dword(1)),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn notifications_are_path_scoped_and_drain_exactly_once() {
        let mut manager = create_tree();
        let root_sub = manager.subscribe("\\Registry\\Machine").unwrap();
        let software_sub = manager.subscribe(SOFTWARE).unwrap();
        let unrelated = manager.subscribe("\\Registry\\User").unwrap();
        assert_eq!(manager.notification_count(), 3);
        let child = manager
            .create_key("\\Registry\\Machine\\Software\\Child", false)
            .unwrap();
        manager
            .set_value(&child, "Name", RegistryValue::String("value".to_string()))
            .unwrap();
        manager.delete_value(&child, "name").unwrap();
        manager.delete_key(&child).unwrap();
        let events = manager.poll(root_sub).unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].kind, RegistryEventKind::KeyCreated);
        assert_eq!(events[1].kind, RegistryEventKind::ValueSet);
        assert_eq!(events[1].value_name.as_deref(), Some("Name"));
        let software_events = manager.poll(software_sub).unwrap();
        assert_eq!(software_events.len(), 4);
        assert!(manager.poll(unrelated).unwrap().is_empty());
        assert!(manager.poll(root_sub).unwrap().is_empty());
        assert_eq!(
            manager.subscribe("\\Registry\\Machine\\Absent"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.poll(NotificationId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.cancel_subscription(NotificationId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.cancel_subscription(root_sub), Ok(()));
        assert_eq!(manager.notification_count(), 2);
    }

    #[test]
    fn transactions_commit_or_roll_back_real_snapshots() {
        let mut manager = create_tree();
        let transaction = manager.begin_transaction();
        assert_eq!(manager.transaction_count(), 1);
        manager
            .set_value(CASA, "Temp", RegistryValue::Dword(1))
            .unwrap();
        manager
            .create_key("\\Registry\\Machine\\Software\\New", false)
            .unwrap();
        assert_eq!(manager.rollback_transaction(transaction), Ok(()));
        assert_eq!(
            manager.get_value(CASA, "Temp"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.open_key("\\Registry\\Machine\\Software\\New"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(manager.transaction_count(), 0);
        assert_eq!(
            manager.rollback_transaction(transaction),
            Err(STATUS_INVALID_HANDLE)
        );
        let committed = manager.begin_transaction();
        manager
            .set_value(CASA, "Kept", RegistryValue::Dword(2))
            .unwrap();
        assert_eq!(manager.commit_transaction(committed), Ok(()));
        assert_eq!(
            manager.get_value(CASA, "Kept"),
            Ok(&RegistryValue::Dword(2))
        );
        assert_eq!(
            manager.commit_transaction(committed),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.transaction_count(), 0);
    }

    #[test]
    fn volatile_keys_unload_and_non_volatile_keys_survive() {
        let mut manager = create_tree();
        let volatile = manager
            .create_key("\\Registry\\Machine\\Volatile", true)
            .unwrap();
        let stable = manager
            .create_key("\\Registry\\Machine\\Stable", false)
            .unwrap();
        assert_eq!(manager.is_volatile(&volatile), Ok(true));
        assert_eq!(manager.is_volatile(&stable), Ok(false));
        assert_eq!(
            manager.is_volatile("\\Registry\\Machine\\Absent"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(manager.unload_hive(), 1);
        assert_eq!(
            manager.open_key(&volatile),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(manager.open_key(&stable).unwrap(), stable);
    }

    #[test]
    fn key_creation_through_a_link_resolves_and_rejects_unknown_children() {
        let mut manager = create_tree();
        let target = manager
            .create_key("\\Registry\\Machine\\Target", false)
            .unwrap();
        let link = manager
            .create_key("\\Registry\\Machine\\Link", false)
            .unwrap();
        manager.link_key(&link, &target).unwrap();
        manager
            .create_key("\\Registry\\Machine\\Link\\ViaLink", false)
            .unwrap();
        assert_eq!(
            manager.enum_subkeys(&target).unwrap(),
            vec!["\\registry\\machine\\target\\vialink".to_string()]
        );
        assert_eq!(
            manager
                .open_key("\\Registry\\Machine\\Link\\ViaLink")
                .unwrap(),
            "\\registry\\machine\\target\\vialink"
        );
    }
}
