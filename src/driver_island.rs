//! Sandboxed kernel driver island.
//!
//! This module executes a real, relocated PE driver image's `DriverEntry`
//! through the guest CPU runtime.  The image is mapped into the canonical
//! guest address space, its imports are patched against a real kernel API shim
//! table backed by CasaK objects, and a real guest `DRIVER_OBJECT` is handed
//! to the entry point.  The shims mutate real CasaK driver/device objects,
//! tagged pool blocks and IRPs, and `DbgPrint` is recorded in the runtime
//! trace plus the island's own log.
//!
//! The island executes native PE64 and PE32 images through the runtime's
//! x64/x86 guest paths.  Import and delay-import entries must be covered by
//! the shim table, and guest execution goes through the runtime's existing
//! [`PeHostRuntime::execute_guest_callback`] entry.  Nothing about the entry
//! call is synthesized — the bytes execute.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::casak::alpc::{AlpcManager, AlpcPort};
use crate::casak::diagnostics::{
    DiagnosticsManager, EventDescriptor, EventLevel, ProviderGuid, ProviderId,
};
use crate::casak::exec::{PoolBlock, PoolTag, TaggedPool};
use crate::casak::executive::Executive;
use crate::casak::interrupt::{ConnectRequest, DisconnectOutcome, InterruptManager};
use crate::casak::io::{
    DeviceExtension, DeviceFlags, IoManager, IrpId, IrpMajorFunction, IrpParameterBlock,
    STATUS_CANCELLED, STATUS_INVALID_PARAMETER, StackParameters,
};
use crate::casak::object::{
    ObjectId, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_ADDRESS, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};
use crate::casak::process::{ProcessId, ProcessManager, ThreadId};
use crate::casak::status::STATUS_OBJECT_TYPE_MISMATCH;
use crate::casak::threads::{SystemThreadHandle, SystemThreadManager};
use crate::cpu::{CpuState, GuestArch, MemoryImage, Register};
use crate::driver_image::{ImportRef, ImportReport, KernelApiSet, LoadedDriver, load_driver_image};
use crate::error::{AppError, AppResult};
use crate::ge::{FileAccess, RegistryView, ShareMode, StoredRegistryValue};
use crate::reason::ReasonCode;
use crate::runtime::{HostThunk, PeHostRuntime};
use crate::trace::TraceEvent;
use crate::vm::{VmProtection, VmRegionKind, VmState};
use crate::win32::CreationDisposition;

#[cfg(test)]
mod tests;

mod constants;
mod device_tree;
mod driver_object;
mod guest_memory;
mod io_manager;
mod irp;
mod island;
mod kernel;
mod kmdf;
mod loader;
mod pnp_power;
mod registry;
mod shims;
mod state;
mod threads;
mod types;

pub use self::island::{DriverIsland, IslandDevice};
pub use self::shims::DriverShim;

#[allow(unused_imports)]
pub(crate) use self::constants::*;
#[allow(unused_imports)]
pub(crate) use self::device_tree::*;
#[allow(unused_imports)]
pub(crate) use self::driver_object::*;
#[allow(unused_imports)]
pub(crate) use self::guest_memory::*;
#[allow(unused_imports)]
pub(crate) use self::io_manager::*;
#[allow(unused_imports)]
pub(crate) use self::irp::*;
#[allow(unused_imports)]
pub(crate) use self::island::*;
#[allow(unused_imports)]
pub(crate) use self::kernel::*;
#[allow(unused_imports)]
pub(crate) use self::kmdf::*;
#[allow(unused_imports)]
pub(crate) use self::loader::*;
#[allow(unused_imports)]
pub(crate) use self::pnp_power::*;
#[allow(unused_imports)]
pub(crate) use self::registry::*;
#[allow(unused_imports)]
pub(crate) use self::shims::*;
#[allow(unused_imports)]
pub(crate) use self::state::*;
#[allow(unused_imports)]
pub(crate) use self::threads::*;
#[allow(unused_imports)]
pub(crate) use self::types::*;
