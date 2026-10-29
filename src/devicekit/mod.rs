//! Host-device transports used by [`crate::device_proxy`].
//!
//! [`iokit`] is the no-entitlement in-process IOKit user-client transport over
//! the real HID/USB/serial/PCI/network/audio bridges.  [`loopback`] is the
//! virtual CasaK device-tree transport whose implementation is a real
//! in-process device, not a success stub.

pub mod iokit;
pub mod loopback;
