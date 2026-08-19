//! Thin compatibility shim: the Steam milestone core moved to
//! [`crate::workloads::steam`].
//!
//! Kept so existing callers (`crate::steam_milestones::*`) keep compiling
//! and the generic runtime (pe_runtime, win32, cef_bridge, real_audio) can
//! reach the milestone types WITHOUT importing the workload module directly.
//! The workload-agnostic runtime code never uses the observer; only the
//! runner (the workload host) attaches it.

pub use crate::workloads::steam::*;
