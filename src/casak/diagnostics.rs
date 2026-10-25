//! WMI and ETW providers with in-process registration, filtering and
//! notification.
//!
//! ETW providers are registered by GUID, enabled/disabled with a level and
//! keyword mask, and deliver real event records to host callbacks.  WMI
//! providers define classes, publish instances and feed path-scoped
//! subscriptions.  Operations that have no host facility fail closed with the
//! exact NTSTATUS instead of returning synthetic success.

use std::collections::BTreeMap;

use crate::casak::status::{
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
    STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
};

/// A 128-bit provider GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderGuid(pub [u8; 16]);

/// Monotonic ETW/WMI provider identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProviderId(pub u64);

/// Monotonic WMI subscription identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WmiSubscriptionId(pub u64);

/// ETW event level.  Lower numeric values are more severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventLevel {
    Critical = 1,
    Error = 2,
    Warning = 3,
    Information = 4,
    Verbose = 5,
}

impl EventLevel {
    pub const fn raw(self) -> u8 {
        self as u8
    }

    pub fn from_raw(value: u8) -> Result<Self, i32> {
        match value {
            1 => Ok(Self::Critical),
            2 => Ok(Self::Error),
            3 => Ok(Self::Warning),
            4 => Ok(Self::Information),
            5 => Ok(Self::Verbose),
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }
}

/// The descriptor carried by an ETW event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventDescriptor {
    pub id: u16,
    pub level: EventLevel,
    pub keyword: u64,
}

/// One delivered event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub provider: ProviderGuid,
    pub descriptor: EventDescriptor,
    pub payload: Vec<u8>,
}

struct EtwProvider {
    name: String,
    enabled: bool,
    level: EventLevel,
    keyword: u64,
    callback: Box<dyn FnMut(&EventRecord)>,
}

/// One WMI class instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WmiClass {
    pub name: String,
    pub instances: Vec<BTreeMap<String, String>>,
}

#[derive(Debug)]
struct WmiProvider {
    name: String,
    classes: BTreeMap<String, WmiClass>,
}

#[derive(Debug)]
struct WmiSubscription {
    class: String,
    events: Vec<BTreeMap<String, String>>,
}

/// WMI/ETW manager.
pub struct DiagnosticsManager {
    etw: BTreeMap<ProviderGuid, EtwProvider>,
    etw_ids: BTreeMap<ProviderId, ProviderGuid>,
    next_etw: u64,
    events_written: u64,
    wmi: BTreeMap<String, WmiProvider>,
    wmi_ids: BTreeMap<ProviderId, String>,
    next_wmi: u64,
    subscriptions: BTreeMap<WmiSubscriptionId, WmiSubscription>,
    next_subscription: u64,
}

impl DiagnosticsManager {
    pub fn new() -> Self {
        Self {
            etw: BTreeMap::new(),
            etw_ids: BTreeMap::new(),
            next_etw: 1,
            events_written: 0,
            wmi: BTreeMap::new(),
            wmi_ids: BTreeMap::new(),
            next_wmi: 1,
            subscriptions: BTreeMap::new(),
            next_subscription: 1,
        }
    }

    /// Registers an ETW provider.  Providers start disabled.
    pub fn register_provider(
        &mut self,
        guid: ProviderGuid,
        name: &str,
        callback: impl FnMut(&EventRecord) + 'static,
    ) -> Result<ProviderId, i32> {
        if name.trim().is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.etw.contains_key(&guid) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        if self.etw.len() >= 64 {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let id = ProviderId(self.next_etw);
        self.next_etw += 1;
        self.etw.insert(
            guid,
            EtwProvider {
                name: name.to_string(),
                enabled: false,
                level: EventLevel::Verbose,
                keyword: 0,
                callback: Box::new(callback),
            },
        );
        self.etw_ids.insert(id, guid);
        Ok(id)
    }

    /// Removes a provider registration.
    pub fn unregister_provider(&mut self, id: ProviderId) -> Result<(), i32> {
        let guid = *self.etw_ids.get(&id).ok_or(STATUS_INVALID_HANDLE)?;
        self.etw_ids.remove(&id);
        self.etw.remove(&guid);
        Ok(())
    }

    /// Enables a provider up to `level` for `keyword`.
    pub fn enable_provider(
        &mut self,
        guid: ProviderGuid,
        level: EventLevel,
        keyword: u64,
    ) -> Result<(), i32> {
        let provider = self
            .etw
            .get_mut(&guid)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        provider.enabled = true;
        provider.level = level;
        provider.keyword = keyword;
        Ok(())
    }

    /// Disables a provider.
    pub fn disable_provider(&mut self, guid: ProviderGuid) -> Result<(), i32> {
        let provider = self
            .etw
            .get_mut(&guid)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        provider.enabled = false;
        Ok(())
    }

    pub fn is_enabled(&self, guid: ProviderGuid) -> Result<bool, i32> {
        Ok(self
            .etw
            .get(&guid)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?
            .enabled)
    }

    pub fn provider_count(&self) -> usize {
        self.etw.len()
    }

    /// Name recorded for a registered ETW provider.
    pub fn provider_guid(&self, id: ProviderId) -> Result<ProviderGuid, i32> {
        self.etw_ids.get(&id).copied().ok_or(STATUS_INVALID_HANDLE)
    }

    /// Name recorded for a registered ETW provider.
    pub fn provider_name(&self, id: ProviderId) -> Result<&str, i32> {
        let guid = self.etw_ids.get(&id).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(&self.etw.get(guid).ok_or(STATUS_INVALID_HANDLE)?.name)
    }

    /// Writes an event.  A disabled provider or one filtered by level/keyword
    /// accepts the write as a no-op; only a missing provider is an error.
    pub fn write_event(
        &mut self,
        guid: ProviderGuid,
        descriptor: EventDescriptor,
        payload: impl Into<Vec<u8>>,
    ) -> Result<bool, i32> {
        let payload = payload.into();
        if payload.len() > 64 * 1024 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let provider = self
            .etw
            .get_mut(&guid)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if !provider.enabled {
            return Ok(false);
        }
        if descriptor.level.raw() > provider.level.raw() {
            return Ok(false);
        }
        if descriptor.keyword != 0 && descriptor.keyword & provider.keyword == 0 {
            return Ok(false);
        }
        let record = EventRecord {
            provider: guid,
            descriptor,
            payload,
        };
        (provider.callback)(&record);
        self.events_written += 1;
        Ok(true)
    }

    pub fn events_written(&self) -> u64 {
        self.events_written
    }

    /// Registers a WMI provider.
    pub fn register_wmi_provider(&mut self, name: &str) -> Result<ProviderId, i32> {
        if name.trim().is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let key = name.to_ascii_lowercase();
        if self.wmi.contains_key(&key) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        let id = ProviderId(self.next_wmi);
        self.next_wmi += 1;
        self.wmi.insert(
            key.clone(),
            WmiProvider {
                name: name.to_string(),
                classes: BTreeMap::new(),
            },
        );
        self.wmi_ids.insert(id, key);
        Ok(id)
    }

    /// Defines a WMI class on a registered provider.
    pub fn define_wmi_class(&mut self, provider: ProviderId, class: &str) -> Result<(), i32> {
        if class.trim().is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let key = self
            .wmi_ids
            .get(&provider)
            .cloned()
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let record = self.wmi.get_mut(&key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if record.classes.contains_key(class) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        record.classes.insert(
            class.to_string(),
            WmiClass {
                name: class.to_string(),
                instances: Vec::new(),
            },
        );
        Ok(())
    }

    /// Publishes a class instance and notifies subscribers of that class.
    pub fn publish_wmi_instance(
        &mut self,
        provider: ProviderId,
        class: &str,
        fields: BTreeMap<String, String>,
    ) -> Result<u64, i32> {
        let key = self
            .wmi_ids
            .get(&provider)
            .cloned()
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let record = self.wmi.get_mut(&key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        let class_record = record
            .classes
            .get_mut(class)
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        class_record.instances.push(fields.clone());
        let index = class_record.instances.len() as u64;
        for subscription in self.subscriptions.values_mut() {
            if subscription.class == class {
                subscription.events.push(fields.clone());
            }
        }
        Ok(index)
    }

    /// Queries a class from any registered provider.
    pub fn query_wmi_class(&self, class: &str) -> Result<Vec<BTreeMap<String, String>>, i32> {
        self.wmi
            .values()
            .find_map(|provider| provider.classes.get(class))
            .map(|record| record.instances.clone())
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
    }

    /// Queries a namespace/class pair.  Only the in-process `root\cimv2`
    /// namespace is backed by the manager; everything else fails closed.
    pub fn query_wmi_namespace(
        &self,
        namespace: &str,
        class: &str,
    ) -> Result<Vec<BTreeMap<String, String>>, i32> {
        if !namespace.eq_ignore_ascii_case("root\\cimv2") {
            return Err(STATUS_NOT_SUPPORTED);
        }
        self.query_wmi_class(class)
    }

    /// Subscribes to a WMI class.
    pub fn subscribe_wmi(&mut self, class: &str) -> Result<WmiSubscriptionId, i32> {
        let known = self
            .wmi
            .values()
            .any(|provider| provider.classes.contains_key(class));
        if !known {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        let id = WmiSubscriptionId(self.next_subscription);
        self.next_subscription += 1;
        self.subscriptions.insert(
            id,
            WmiSubscription {
                class: class.to_string(),
                events: Vec::new(),
            },
        );
        Ok(id)
    }

    pub fn poll_wmi(
        &mut self,
        id: WmiSubscriptionId,
    ) -> Result<Vec<BTreeMap<String, String>>, i32> {
        let subscription = self
            .subscriptions
            .get_mut(&id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        Ok(std::mem::take(&mut subscription.events))
    }

    pub fn cancel_wmi_subscription(&mut self, id: WmiSubscriptionId) -> Result<(), i32> {
        self.subscriptions
            .remove(&id)
            .map(|_| ())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn wmi_provider_count(&self) -> usize {
        self.wmi.len()
    }

    /// Name recorded for a registered WMI provider.
    pub fn wmi_provider_name(&self, id: ProviderId) -> Result<&str, i32> {
        let key = self.wmi_ids.get(&id).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(&self.wmi.get(key).ok_or(STATUS_INVALID_HANDLE)?.name)
    }
}

impl Default for DiagnosticsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn guid(byte: u8) -> ProviderGuid {
        ProviderGuid([byte; 16])
    }

    fn descriptor(level: EventLevel, keyword: u64) -> EventDescriptor {
        EventDescriptor {
            id: 1,
            level,
            keyword,
        }
    }

    #[test]
    fn etw_registration_rejects_invalid_names_and_duplicates() {
        assert_eq!(DiagnosticsManager::default().provider_count(), 0);
        let mut manager = DiagnosticsManager::new();
        assert_eq!(
            manager.register_provider(guid(1), "  ", |_| {}),
            Err(STATUS_INVALID_PARAMETER)
        );
        let provider = manager
            .register_provider(guid(1), "CasaProvider", |_| {})
            .unwrap();
        assert_eq!(
            manager.register_provider(guid(1), "Other", |_| {}),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(manager.provider_count(), 1);
        assert_eq!(manager.provider_name(provider).unwrap(), "CasaProvider");
        assert_eq!(manager.provider_guid(provider).unwrap(), guid(1));
        assert_eq!(
            manager.provider_guid(ProviderId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.provider_name(ProviderId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.unregister_provider(ProviderId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.unregister_provider(provider), Ok(()));
        assert_eq!(manager.provider_count(), 0);
    }

    #[test]
    fn etw_provider_pool_exhaustion_is_exact() {
        let mut manager = DiagnosticsManager::new();
        for index in 0..64 {
            manager
                .register_provider(guid(index as u8), "P", |_| {})
                .unwrap();
        }
        assert_eq!(
            manager.register_provider(guid(200), "P", |_| {}),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(manager.provider_count(), 64);
    }

    #[test]
    fn etw_write_filters_disabled_level_keyword_and_length() {
        let records = Arc::new(Mutex::new(Vec::<EventRecord>::new()));
        let captured = Arc::clone(&records);
        let mut manager = DiagnosticsManager::new();
        let provider = manager
            .register_provider(guid(2), "Provider", move |record| {
                captured.lock().unwrap().push(record.clone());
            })
            .unwrap();
        assert_eq!(manager.is_enabled(guid(2)).unwrap(), false);
        assert_eq!(
            manager.write_event(guid(2), descriptor(EventLevel::Error, 0), vec![1]),
            Ok(false)
        );
        assert_eq!(
            manager.enable_provider(guid(2), EventLevel::Warning, 0x10),
            Ok(())
        );
        assert_eq!(manager.is_enabled(guid(2)).unwrap(), true);
        assert_eq!(
            manager.write_event(guid(2), descriptor(EventLevel::Verbose, 0x10), vec![1]),
            Ok(false)
        );
        assert_eq!(
            manager.write_event(guid(2), descriptor(EventLevel::Error, 0x20), vec![1]),
            Ok(false)
        );
        assert_eq!(
            manager.write_event(guid(2), descriptor(EventLevel::Error, 0x10), vec![1, 2]),
            Ok(true)
        );
        assert_eq!(
            manager.write_event(guid(2), descriptor(EventLevel::Error, 0), vec![3]),
            Ok(true)
        );
        assert_eq!(
            manager.write_event(
                guid(2),
                descriptor(EventLevel::Error, 0),
                vec![0; 64 * 1024 + 1]
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.write_event(guid(9), descriptor(EventLevel::Error, 0), Vec::new()),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(manager.events_written(), 2);
        let records = records.lock().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].provider, guid(2));
        assert_eq!(records[0].payload, vec![1, 2]);
        assert_eq!(records[1].payload, vec![3]);
        assert_eq!(manager.disable_provider(guid(2)), Ok(()));
        assert_eq!(
            manager.write_event(guid(2), descriptor(EventLevel::Error, 0), vec![4]),
            Ok(false)
        );
        assert_eq!(
            manager.enable_provider(guid(9), EventLevel::Verbose, 0),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.disable_provider(guid(9)),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.is_enabled(guid(9)),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(manager.unregister_provider(provider), Ok(()));
    }

    #[test]
    fn event_levels_map_exactly_and_reject_unknown_values() {
        assert_eq!(EventLevel::from_raw(1).unwrap(), EventLevel::Critical);
        assert_eq!(EventLevel::from_raw(2).unwrap(), EventLevel::Error);
        assert_eq!(EventLevel::from_raw(3).unwrap(), EventLevel::Warning);
        assert_eq!(EventLevel::from_raw(4).unwrap(), EventLevel::Information);
        assert_eq!(EventLevel::from_raw(5).unwrap(), EventLevel::Verbose);
        assert_eq!(EventLevel::from_raw(0), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(EventLevel::Verbose.raw(), 5);
    }

    #[test]
    fn wmi_providers_classes_and_queries_are_scoped_and_exact() {
        let mut manager = DiagnosticsManager::new();
        assert_eq!(
            manager.register_wmi_provider(""),
            Err(STATUS_INVALID_PARAMETER)
        );
        let provider = manager.register_wmi_provider("CasaWmi").unwrap();
        assert_eq!(
            manager.register_wmi_provider("casawmi"),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(manager.wmi_provider_count(), 1);
        assert_eq!(manager.wmi_provider_name(provider).unwrap(), "CasaWmi");
        assert_eq!(
            manager.wmi_provider_name(ProviderId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.define_wmi_class(ProviderId(404), "Class"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.define_wmi_class(provider, ""),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(manager.define_wmi_class(provider, "CasaClass"), Ok(()));
        assert_eq!(
            manager.define_wmi_class(provider, "CasaClass"),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(
            manager.publish_wmi_instance(ProviderId(404), "CasaClass", BTreeMap::new()),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.publish_wmi_instance(provider, "Missing", BTreeMap::new()),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        let mut fields = BTreeMap::new();
        fields.insert("Name".to_string(), "Casa".to_string());
        assert_eq!(
            manager
                .publish_wmi_instance(provider, "CasaClass", fields.clone())
                .unwrap(),
            1
        );
        assert_eq!(
            manager.query_wmi_class("CasaClass").unwrap(),
            vec![fields.clone()]
        );
        assert_eq!(
            manager.query_wmi_class("Missing"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.query_wmi_namespace("root\\other", "CasaClass"),
            Err(STATUS_NOT_SUPPORTED)
        );
        assert_eq!(
            manager
                .query_wmi_namespace("ROOT\\CIMV2", "CasaClass")
                .unwrap(),
            vec![fields.clone()]
        );
        assert_eq!(
            manager.query_wmi_namespace("root\\cimv2", "Missing"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn wmi_subscriptions_notify_and_drain_exactly_once() {
        let mut manager = DiagnosticsManager::new();
        let provider = manager.register_wmi_provider("Wmi").unwrap();
        manager.define_wmi_class(provider, "Class").unwrap();
        assert_eq!(
            manager.subscribe_wmi("Missing"),
            Err(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        let subscription = manager.subscribe_wmi("Class").unwrap();
        let mut fields = BTreeMap::new();
        fields.insert("Key".to_string(), "Value".to_string());
        manager
            .publish_wmi_instance(provider, "Class", fields.clone())
            .unwrap();
        assert_eq!(
            manager.poll_wmi(subscription).unwrap(),
            vec![fields.clone()]
        );
        assert!(manager.poll_wmi(subscription).unwrap().is_empty());
        assert_eq!(
            manager.poll_wmi(WmiSubscriptionId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(manager.cancel_wmi_subscription(subscription), Ok(()));
        assert_eq!(
            manager.cancel_wmi_subscription(subscription),
            Err(STATUS_INVALID_HANDLE)
        );
    }
}
