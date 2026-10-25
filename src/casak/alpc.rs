//! ALPC ports: connection, message queues, replies, cancellation and
//! timeouts.
//!
//! A port owns one real FIFO guarded by a mutex and a condition variable, so
//! `receive`/`receive_reply` block for their deadline and are woken by sends,
//! replies, cancellation and close.  Message ids are monotonic per port.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::casak::status::{
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_PORT_CONNECTION_REFUSED,
    STATUS_PORT_DISCONNECTED, STATUS_PORT_MESSAGE_TOO_LONG, STATUS_REPLY_MESSAGE_MISMATCH,
    STATUS_TIMEOUT,
};

/// Monotonic port identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortId(pub u64);

/// Monotonic message identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MessageId(pub u64);

/// A queued request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpcMessage {
    pub id: MessageId,
    pub payload: Vec<u8>,
    pub expects_reply: bool,
}

#[derive(Debug)]
struct PortState {
    name: String,
    max_queue: usize,
    max_message: usize,
    queue: VecDeque<AlpcMessage>,
    replies: BTreeMap<MessageId, Vec<u8>>,
    pending: BTreeSet<MessageId>,
    cancelled: BTreeSet<MessageId>,
    connections: usize,
    next_message: u64,
    closed: bool,
    sent: u64,
    delivered: u64,
    replies_sent: u64,
    dropped: u64,
}

#[derive(Debug)]
struct PortInner {
    state: Mutex<PortState>,
    wake: Condvar,
}

/// A connected ALPC port endpoint.  Clones share the same FIFO, reply slots
/// and waiters.
#[derive(Debug, Clone)]
pub struct AlpcPort {
    id: PortId,
    inner: Arc<PortInner>,
}

impl AlpcPort {
    pub fn id(&self) -> PortId {
        self.id
    }

    pub fn name(&self) -> String {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .name
            .clone()
    }

    /// Sends a request, returning its message id.  A full queue is refused.
    pub fn send(&self, payload: impl Into<Vec<u8>>, expects_reply: bool) -> Result<MessageId, i32> {
        let payload = payload.into();
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closed {
            return Err(STATUS_PORT_DISCONNECTED);
        }
        if payload.len() > state.max_message {
            return Err(STATUS_PORT_MESSAGE_TOO_LONG);
        }
        if state.queue.len() >= state.max_queue {
            return Err(STATUS_PORT_CONNECTION_REFUSED);
        }
        let id = MessageId(state.next_message);
        state.next_message += 1;
        state.queue.push_back(AlpcMessage {
            id,
            payload,
            expects_reply,
        });
        if expects_reply {
            state.pending.insert(id);
        }
        state.sent += 1;
        drop(state);
        self.inner.wake.notify_all();
        Ok(id)
    }

    /// Receives the next request, waiting at most `timeout`.
    pub fn receive(&self, timeout: Duration) -> Result<AlpcMessage, i32> {
        let deadline = Instant::now() + timeout;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if let Some(message) = state.queue.pop_front() {
                state.delivered += 1;
                return Ok(message);
            }
            if state.closed {
                return Err(STATUS_PORT_DISCONNECTED);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(STATUS_TIMEOUT);
            }
            let (next, _) = self
                .inner
                .wake
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
        }
    }

    /// Replies to a request that expects one.  Unknown, already answered or
    /// cancelled requests fail with `STATUS_REPLY_MESSAGE_MISMATCH`.
    pub fn reply(&self, request: MessageId, payload: impl Into<Vec<u8>>) -> Result<(), i32> {
        let payload = payload.into();
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closed {
            return Err(STATUS_PORT_DISCONNECTED);
        }
        if payload.len() > state.max_message {
            return Err(STATUS_PORT_MESSAGE_TOO_LONG);
        }
        if !state.pending.contains(&request) || state.replies.contains_key(&request) {
            return Err(STATUS_REPLY_MESSAGE_MISMATCH);
        }
        state.pending.remove(&request);
        state.replies.insert(request, payload);
        state.replies_sent += 1;
        drop(state);
        self.inner.wake.notify_all();
        Ok(())
    }

    /// Waits for the reply to `request`.
    pub fn receive_reply(&self, request: MessageId, timeout: Duration) -> Result<Vec<u8>, i32> {
        let deadline = Instant::now() + timeout;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if let Some(reply) = state.replies.remove(&request) {
                return Ok(reply);
            }
            if state.cancelled.contains(&request) {
                return Err(crate::casak::status::STATUS_CANCELLED);
            }
            if state.closed {
                return Err(STATUS_PORT_DISCONNECTED);
            }
            if !state.pending.contains(&request) {
                return Err(STATUS_REPLY_MESSAGE_MISMATCH);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(STATUS_TIMEOUT);
            }
            let (next, _) = self
                .inner
                .wake
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
        }
    }

    /// Cancels a request that has not been replied to.  A queued request is
    /// removed from the FIFO; a reply waiter is woken with
    /// `STATUS_CANCELLED`.
    pub fn cancel(&self, request: MessageId) -> Result<(), i32> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.pending.contains(&request) {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        state.pending.remove(&request);
        state.cancelled.insert(request);
        state.queue.retain(|message| message.id != request);
        drop(state);
        self.inner.wake.notify_all();
        Ok(())
    }

    /// Closes the port, drops queued messages and wakes every waiter.
    pub fn close(&self) -> u64 {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closed {
            return 0;
        }
        state.closed = true;
        let dropped = state.queue.len() as u64;
        state.queue.clear();
        state.dropped += dropped;
        state.pending.clear();
        drop(state);
        self.inner.wake.notify_all();
        dropped
    }

    pub fn is_closed(&self) -> bool {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .closed
    }

    pub fn pending_count(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .queue
            .len()
    }

    pub fn connection_count(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .connections
    }

    pub fn sent_count(&self) -> u64 {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sent
    }

    pub fn delivered_count(&self) -> u64 {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .delivered
    }

    pub fn replies_sent_count(&self) -> u64 {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .replies_sent
    }

    pub fn dropped_count(&self) -> u64 {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .dropped
    }
}

/// The ALPC port namespace.
#[derive(Debug)]
pub struct AlpcManager {
    ports: BTreeMap<String, AlpcPort>,
    next_port: u64,
}

impl AlpcManager {
    pub fn new() -> Self {
        Self {
            ports: BTreeMap::new(),
            next_port: 1,
        }
    }

    /// Creates a named server port.  Empty names and zero limits are invalid.
    pub fn create_port(
        &mut self,
        name: &str,
        max_queue: usize,
        max_message: usize,
    ) -> Result<AlpcPort, i32> {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.contains('\0') {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        if max_queue == 0 || max_message == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let key = trimmed.to_ascii_lowercase();
        if self.ports.contains_key(&key) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        let id = PortId(self.next_port);
        self.next_port += 1;
        let port = AlpcPort {
            id,
            inner: Arc::new(PortInner {
                state: Mutex::new(PortState {
                    name: trimmed.to_string(),
                    max_queue,
                    max_message,
                    queue: VecDeque::new(),
                    replies: BTreeMap::new(),
                    pending: BTreeSet::new(),
                    cancelled: BTreeSet::new(),
                    connections: 0,
                    next_message: 1,
                    closed: false,
                    sent: 0,
                    delivered: 0,
                    replies_sent: 0,
                    dropped: 0,
                }),
                wake: Condvar::new(),
            }),
        };
        self.ports.insert(key, port.clone());
        Ok(port)
    }

    /// Connects to a named port.  A missing name is
    /// `STATUS_OBJECT_NAME_NOT_FOUND`; a closed port is disconnected.
    pub fn connect(&mut self, name: &str) -> Result<AlpcPort, i32> {
        let key = name.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        let port = self
            .ports
            .get(&key)
            .cloned()
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
        if port.is_closed() {
            return Err(STATUS_PORT_DISCONNECTED);
        }
        {
            let mut state = port
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.connections += 1;
        }
        Ok(port)
    }

    /// Looks up a live port without connecting.
    pub fn port(&self, name: &str) -> Result<AlpcPort, i32> {
        self.ports
            .get(&name.trim().to_ascii_lowercase())
            .cloned()
            .ok_or(STATUS_OBJECT_NAME_NOT_FOUND)
    }

    pub fn port_count(&self) -> usize {
        self.ports.len()
    }

    /// Removes a closed port from the namespace.  Removing a live port fails
    /// with `STATUS_INVALID_HANDLE`.
    pub fn remove_port(&mut self, name: &str) -> Result<AlpcPort, i32> {
        let key = name.trim().to_ascii_lowercase();
        let port = self.ports.get(&key).cloned().ok_or(STATUS_INVALID_HANDLE)?;
        if !port.is_closed() {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.ports.remove(&key);
        Ok(port)
    }
}

impl Default for AlpcManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casak::status::STATUS_CANCELLED;

    fn server() -> (AlpcManager, AlpcPort) {
        let mut manager = AlpcManager::new();
        let port = manager
            .create_port("\\RPC Control\\CasaPort", 2, 8)
            .unwrap();
        (manager, port)
    }

    #[test]
    fn port_creation_and_connection_reject_invalid_names_and_limits() {
        assert_eq!(AlpcManager::default().port_count(), 0);
        let mut manager = AlpcManager::new();
        assert_eq!(
            manager.create_port("", 1, 1).err(),
            Some(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(
            manager.create_port("bad\0", 1, 1).err(),
            Some(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(
            manager.create_port("x", 0, 1).err(),
            Some(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            manager.create_port("x", 1, 0).err(),
            Some(STATUS_INVALID_PARAMETER)
        );
        let port = manager.create_port("Name", 2, 8).unwrap();
        assert_eq!(port.name(), "Name");
        assert_eq!(port.id(), PortId(1));
        assert_eq!(
            manager.create_port("name", 2, 8).err(),
            Some(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(manager.port_count(), 1);
        let connected = manager.connect("NAME").unwrap();
        assert_eq!(connected.id(), port.id());
        assert_eq!(port.connection_count(), 1);
        assert_eq!(manager.connect("").err(), Some(STATUS_OBJECT_NAME_INVALID));
        assert_eq!(
            manager.connect("missing").err(),
            Some(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(manager.port("name").unwrap().id(), port.id());
        assert_eq!(
            manager.port("missing").err(),
            Some(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            manager.remove_port("name").err(),
            Some(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            manager.remove_port("missing").err(),
            Some(STATUS_INVALID_HANDLE)
        );
        assert_eq!(port.close(), 0);
        assert_eq!(port.close(), 0);
        assert!(port.is_closed());
        assert_eq!(
            manager.connect("name").err(),
            Some(STATUS_PORT_DISCONNECTED)
        );
        manager.remove_port("name").unwrap();
        assert_eq!(manager.port_count(), 0);
    }

    #[test]
    fn send_receive_queue_limits_and_message_lengths_are_exact() {
        let (mut manager, port) = server();
        assert_eq!(
            port.send(vec![0; 9], false).err(),
            Some(STATUS_PORT_MESSAGE_TOO_LONG)
        );
        let first = port.send(vec![1], false).unwrap();
        assert_eq!(MessageId(1), first);
        port.send(vec![2], false).unwrap();
        assert_eq!(
            port.send(vec![3], false).err(),
            Some(STATUS_PORT_CONNECTION_REFUSED)
        );
        assert_eq!(port.pending_count(), 2);
        assert_eq!(port.sent_count(), 2);
        let message = port.receive(Duration::ZERO).unwrap();
        assert_eq!(message.id, first);
        assert_eq!(message.payload, vec![1]);
        assert!(!message.expects_reply);
        assert_eq!(port.delivered_count(), 1);
        let second = port.receive(Duration::ZERO).unwrap();
        assert_eq!(second.payload, vec![2]);
        assert_eq!(
            port.receive(Duration::from_millis(1)).err(),
            Some(STATUS_TIMEOUT)
        );
        let _client = manager.connect("\\rpc control\\casaport").unwrap();
        port.send(vec![5], false).unwrap();
        port.close();
        assert_eq!(port.dropped_count(), 1);
        assert_eq!(
            port.send(vec![4], false).err(),
            Some(STATUS_PORT_DISCONNECTED)
        );
        assert_eq!(
            port.receive(Duration::ZERO).err(),
            Some(STATUS_PORT_DISCONNECTED)
        );
    }

    #[test]
    fn reply_receive_reply_and_cancel_semantics_are_exact() {
        let (_manager, port) = server();
        let no_reply = port.send(vec![1], false).unwrap();
        assert_eq!(
            port.reply(no_reply, vec![9]).err(),
            Some(STATUS_REPLY_MESSAGE_MISMATCH)
        );
        port.receive(Duration::ZERO).unwrap();
        let request = port.send(vec![2], true).unwrap();
        assert_eq!(port.reply(request, vec![7, 7]), Ok(()));
        port.receive(Duration::ZERO).unwrap();
        assert_eq!(port.replies_sent_count(), 1);
        assert_eq!(
            port.reply(request, vec![8]).err(),
            Some(STATUS_REPLY_MESSAGE_MISMATCH)
        );
        assert_eq!(
            port.receive_reply(request, Duration::ZERO).unwrap(),
            vec![7, 7]
        );
        assert_eq!(
            port.receive_reply(request, Duration::ZERO).err(),
            Some(STATUS_REPLY_MESSAGE_MISMATCH)
        );
        let canceled = port.send(vec![3], true).unwrap();
        assert_eq!(port.cancel(canceled), Ok(()));
        assert_eq!(
            port.cancel(canceled).err(),
            Some(STATUS_OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            port.receive_reply(canceled, Duration::ZERO).err(),
            Some(STATUS_CANCELLED)
        );
        assert_eq!(
            port.reply(canceled, vec![1]).err(),
            Some(STATUS_REPLY_MESSAGE_MISMATCH)
        );
        let queued = port.send(vec![4], true).unwrap();
        port.cancel(queued).unwrap();
        assert_eq!(port.receive(Duration::ZERO).err(), Some(STATUS_TIMEOUT));
        let long_reply = port.send(vec![5], true).unwrap();
        assert_eq!(
            port.reply(long_reply, vec![0; 9]).err(),
            Some(STATUS_PORT_MESSAGE_TOO_LONG)
        );
        port.close();
        assert_eq!(
            port.reply(long_reply, vec![1]).err(),
            Some(STATUS_PORT_DISCONNECTED)
        );
    }

    #[test]
    fn blocking_receive_wakes_on_send_and_times_out() {
        let (_manager, port) = server();
        let waiter = port.clone();
        let thread = std::thread::spawn(move || waiter.receive(Duration::from_secs(2)));
        std::thread::sleep(Duration::from_millis(20));
        port.send(vec![1], false).unwrap();
        let message = thread.join().unwrap().unwrap();
        assert_eq!(message.payload, vec![1]);

        let waiter = port.clone();
        let thread = std::thread::spawn(move || waiter.receive(Duration::from_millis(5)));
        assert_eq!(thread.join().unwrap().err(), Some(STATUS_TIMEOUT));
    }

    #[test]
    fn reply_waiter_wakes_on_reply_cancel_and_close() {
        let (_manager, port) = server();
        let request = port.send(vec![1], true).unwrap();
        let waiter = port.clone();
        let thread =
            std::thread::spawn(move || waiter.receive_reply(request, Duration::from_secs(2)));
        std::thread::sleep(Duration::from_millis(20));
        port.reply(request, vec![4]).unwrap();
        assert_eq!(thread.join().unwrap().unwrap(), vec![4]);

        let canceled = port.send(vec![2], true).unwrap();
        let waiter = port.clone();
        let thread =
            std::thread::spawn(move || waiter.receive_reply(canceled, Duration::from_secs(2)));
        std::thread::sleep(Duration::from_millis(20));
        port.cancel(canceled).unwrap();
        assert_eq!(thread.join().unwrap().err(), Some(STATUS_CANCELLED));

        let closed = port.send(vec![3], true).unwrap();
        let waiter = port.clone();
        let thread =
            std::thread::spawn(move || waiter.receive_reply(closed, Duration::from_secs(2)));
        std::thread::sleep(Duration::from_millis(20));
        port.close();
        assert_eq!(thread.join().unwrap().err(), Some(STATUS_PORT_DISCONNECTED));
    }

    #[test]
    fn receive_reply_times_out_while_still_pending() {
        let (_manager, port) = server();
        let request = port.send(vec![1], true).unwrap();
        assert_eq!(
            port.receive_reply(request, Duration::from_millis(5)).err(),
            Some(STATUS_TIMEOUT)
        );
        assert_eq!(
            port.receive_reply(MessageId(404), Duration::ZERO).err(),
            Some(STATUS_REPLY_MESSAGE_MISMATCH)
        );
    }
}
