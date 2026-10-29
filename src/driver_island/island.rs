//! Public island handles (`DriverIsland`, `IslandDevice`).

use super::*;

/// A device exposed by the island and backed by a CasaK device object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IslandDevice {
    /// Full guest path (`\Device\<name>`), or an empty string for a nameless
    /// device.
    pub name: String,
    /// Guest `PDEVICE_OBJECT` pointer handed to the driver.
    pub guest_pointer: u64,
    /// Whether `IoDeleteDevice` removed it.
    pub deleted: bool,
}

/// A loaded driver island with its real entry execution result.
pub struct DriverIsland {
    pub(crate) inner: Rc<RefCell<IslandState>>,
}

impl std::fmt::Debug for DriverIsland {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.inner.borrow();
        formatter
            .debug_struct("DriverIsland")
            .field("driver_name", &state.driver_name)
            .field("entry_rva", &format_args!("{:#x}", state.entry_rva))
            .field("status", &state.status)
            .field("loaded", &state.loaded)
            .finish()
    }
}
