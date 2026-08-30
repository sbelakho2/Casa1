//! Runtime dispatch tree: the split dispatch modules for the guest API
//! surfaces.  The Nt*/Rtl* native-API dispatch arms live in
//! [`ntdll`](self::ntdll); they build on the canonical layers
//! ([`crate::ntdll`], the canonical VM, the live object/handle namespace,
//! the guest scheduler) and are wired into the main `dispatch_import` match
//! in `crate::runtime`.

pub(crate) mod com;
pub(crate) mod ntdll;
