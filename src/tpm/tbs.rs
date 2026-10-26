//! Windows TBS (`tbs.dll`) facing adapter.
//!
//! The adapter mirrors the three exports a guest needs:
//!
//! - `Tbsi_Context_Create` → [`TbsAdapter::tbsi_context_create`]
//! - `Tbsip_Submit_Command` → [`TbsAdapter::tbsip_submit_command`]
//! - `Tbsip_Context_Close` → [`TbsAdapter::tbsip_context_close`]
//!
//! Every method returns a `TBS_RESULT` / [`TbsError`] with the exact public
//! TBS error code, so the root runtime can wire these to host thunks without
//! translating errors itself.  The root owns the actual export-table and
//! `HostThunk` registration; this module only exposes the callable surface.

use std::collections::BTreeMap;
use std::path::Path;

use super::Tpm;
use super::constants::{MAX_COMMAND_SIZE, TPM_RC_SIZE};
use super::persist::PersistError;
use super::wire::Header;

/// `TBS_SUCCESS`
pub const TBS_SUCCESS: u32 = 0x0000_0000;
/// `TBS_E_INTERNAL_ERROR`
pub const TBS_E_INTERNAL_ERROR: u32 = 0x8028_4001;
/// `TBS_E_BAD_PARAMETER`
pub const TBS_E_BAD_PARAMETER: u32 = 0x8028_4002;
/// `TBS_E_INVALID_OUTPUT_POINTER`
pub const TBS_E_INVALID_OUTPUT_POINTER: u32 = 0x8028_4003;
/// `TBS_E_INVALID_CONTEXT`
pub const TBS_E_INVALID_CONTEXT: u32 = 0x8028_4004;
/// `TBS_E_INSUFFICIENT_BUFFER`
pub const TBS_E_INSUFFICIENT_BUFFER: u32 = 0x8028_4005;
/// `TBS_E_IOERROR`
pub const TBS_E_IOERROR: u32 = 0x8028_4006;
/// `TBS_E_INVALID_CONTEXT_PARAM`
pub const TBS_E_INVALID_CONTEXT_PARAM: u32 = 0x8028_4007;
/// `TBS_E_SERVICE_NOT_RUNNING`
pub const TBS_E_SERVICE_NOT_RUNNING: u32 = 0x8028_4008;
/// `TBS_E_TOO_MANY_TBS_CONTEXTS`
pub const TBS_E_TOO_MANY_TBS_CONTEXTS: u32 = 0x8028_4009;
/// `TBS_E_TOO_MANY_RESOURCES`
pub const TBS_E_TOO_MANY_RESOURCES: u32 = 0x8028_400A;
/// `TBS_E_BUFFER_TOO_LARGE`
pub const TBS_E_BUFFER_TOO_LARGE: u32 = 0x8028_400E;
/// `TBS_E_TPM_NOT_FOUND`
pub const TBS_E_TPM_NOT_FOUND: u32 = 0x8028_400F;
/// `TBS_E_ACCESS_DENIED`
pub const TBS_E_ACCESS_DENIED: u32 = 0x8028_4012;

/// `TBS_CONTEXT_VERSION_ONE`
pub const TBS_CONTEXT_VERSION_ONE: u32 = 1;
/// `TBS_CONTEXT_VERSION_TWO`
pub const TBS_CONTEXT_VERSION_TWO: u32 = 2;

const MAX_TBS_CONTEXTS: usize = 16;

/// `TBS_CONTEXT_PARAMS` / `TBS_CONTEXT_PARAMS2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TbsContextParams {
    pub version: u32,
    /// Only valid for version two; version one must pass zero.
    pub flags: u32,
}

impl TbsContextParams {
    pub fn v1() -> Self {
        Self {
            version: TBS_CONTEXT_VERSION_ONE,
            flags: 0,
        }
    }

    pub fn v2(flags: u32) -> Self {
        Self {
            version: TBS_CONTEXT_VERSION_TWO,
            flags,
        }
    }
}

/// `TBS_COMMAND_PRIORITY` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TbsPriority {
    Normal,
    High,
    System,
    Maximum,
}

impl TbsPriority {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            100 => Some(Self::Normal),
            200 => Some(Self::High),
            300 => Some(Self::System),
            0x8000_0000 => Some(Self::Maximum),
            _ => None,
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            Self::Normal => 100,
            Self::High => 200,
            Self::System => 300,
            Self::Maximum => 0x8000_0000,
        }
    }
}

/// A TBS failure carrying its exact `TBS_RESULT` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TbsError {
    Internal,
    BadParameter,
    InvalidOutputPointer,
    InvalidContext,
    InsufficientBuffer,
    Io,
    InvalidContextParam,
    ServiceNotRunning,
    TooManyContexts,
    TooManyResources,
    BufferTooLarge,
    TpmNotFound,
    AccessDenied,
}

impl TbsError {
    pub fn code(self) -> u32 {
        match self {
            Self::Internal => TBS_E_INTERNAL_ERROR,
            Self::BadParameter => TBS_E_BAD_PARAMETER,
            Self::InvalidOutputPointer => TBS_E_INVALID_OUTPUT_POINTER,
            Self::InvalidContext => TBS_E_INVALID_CONTEXT,
            Self::InsufficientBuffer => TBS_E_INSUFFICIENT_BUFFER,
            Self::Io => TBS_E_IOERROR,
            Self::InvalidContextParam => TBS_E_INVALID_CONTEXT_PARAM,
            Self::ServiceNotRunning => TBS_E_SERVICE_NOT_RUNNING,
            Self::TooManyContexts => TBS_E_TOO_MANY_TBS_CONTEXTS,
            Self::TooManyResources => TBS_E_TOO_MANY_RESOURCES,
            Self::BufferTooLarge => TBS_E_BUFFER_TOO_LARGE,
            Self::TpmNotFound => TBS_E_TPM_NOT_FOUND,
            Self::AccessDenied => TBS_E_ACCESS_DENIED,
        }
    }
}

impl std::fmt::Display for TbsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TBS error 0x{:08X}", self.code())
    }
}

impl std::error::Error for TbsError {}

/// TBS context state.  Locality is supplied per submit call, mirroring
/// `Tbsip_Submit_Command`.
#[derive(Debug, Clone, Copy)]
struct ContextState {
    _reserved: (),
}

/// TBS-facing adapter around a [`Tpm`].
pub struct TbsAdapter {
    tpm: Tpm,
    contexts: BTreeMap<u64, ContextState>,
    next_context: u64,
}

impl TbsAdapter {
    pub fn new(tpm: Tpm) -> Self {
        Self {
            tpm,
            contexts: BTreeMap::new(),
            next_context: 1,
        }
    }

    /// Open the TPM for a game environment and wrap it in a TBS adapter.
    pub fn open_environment(root: &Path) -> Result<Self, TbsError> {
        let tpm = Tpm::open_environment(root).map_err(map_open_error)?;
        Ok(Self::new(tpm))
    }

    pub fn tpm(&self) -> &Tpm {
        &self.tpm
    }

    pub fn tpm_mut(&mut self) -> &mut Tpm {
        &mut self.tpm
    }

    /// `Tbsi_Context_Create` typed form.
    pub fn context_create(&mut self, params: &TbsContextParams) -> Result<u64, TbsError> {
        if params.version != TBS_CONTEXT_VERSION_ONE && params.version != TBS_CONTEXT_VERSION_TWO {
            return Err(TbsError::InvalidContextParam);
        }
        if params.version == TBS_CONTEXT_VERSION_ONE && params.flags != 0 {
            return Err(TbsError::InvalidContextParam);
        }
        if self.contexts.len() >= MAX_TBS_CONTEXTS {
            return Err(TbsError::TooManyContexts);
        }
        let handle = self.next_context;
        self.next_context = self.next_context.wrapping_add(1).max(1);
        self.contexts.insert(handle, ContextState { _reserved: () });
        Ok(handle)
    }

    /// `Tbsip_Context_Close` typed form.
    pub fn context_close(&mut self, context: u64) -> Result<(), TbsError> {
        self.contexts
            .remove(&context)
            .map(|_| ())
            .ok_or(TbsError::InvalidContext)
    }

    /// `Tbsip_Submit_Command` typed form.  Returns the response length; the
    /// TPM response (including any `TPM_RC_*` error) is in `response`.
    pub fn submit_command(
        &mut self,
        context: u64,
        locality: u8,
        priority: TbsPriority,
        command: &[u8],
        response: &mut [u8],
    ) -> Result<usize, TbsError> {
        self.submit_validated(context, locality, priority.as_u32(), command, response)
    }

    fn execute_validated(
        &mut self,
        context: u64,
        locality: u8,
        priority: u32,
        command: &[u8],
    ) -> Result<Vec<u8>, TbsError> {
        if !self.contexts.contains_key(&context) {
            return Err(TbsError::InvalidContext);
        }
        if locality > 4 {
            return Err(TbsError::BadParameter);
        }
        if TbsPriority::from_u32(priority).is_none() {
            return Err(TbsError::BadParameter);
        }
        if command.len() > MAX_COMMAND_SIZE {
            return Err(TbsError::BufferTooLarge);
        }
        if Header::parse(command).is_err() {
            return Err(TbsError::BadParameter);
        }
        self.tpm
            .execute(command, locality)
            .map_err(map_persist_error)
    }

    fn submit_validated(
        &mut self,
        context: u64,
        locality: u8,
        priority: u32,
        command: &[u8],
        response: &mut [u8],
    ) -> Result<usize, TbsError> {
        let response_bytes = self.execute_validated(context, locality, priority, command)?;
        if response.len() < response_bytes.len() {
            return Err(TbsError::InsufficientBuffer);
        }
        response[..response_bytes.len()].copy_from_slice(&response_bytes);
        Ok(response_bytes.len())
    }

    /// Raw `Tbsi_Context_Create` ABI: returns `TBS_RESULT` and writes the
    /// context handle through `out`.
    pub fn tbsi_context_create(&mut self, params: &TbsContextParams, out: &mut u64) -> u32 {
        match self.context_create(params) {
            Ok(handle) => {
                *out = handle;
                TBS_SUCCESS
            }
            Err(error) => error.code(),
        }
    }

    /// Raw `Tbsip_Context_Close` ABI.
    pub fn tbsip_context_close(&mut self, context: u64) -> u32 {
        match self.context_close(context) {
            Ok(()) => TBS_SUCCESS,
            Err(error) => error.code(),
        }
    }

    /// Raw `Tbsip_Submit_Command` ABI.
    ///
    /// `response_size` is in/out: on success it receives the number of bytes
    /// written; on `TBS_E_INSUFFICIENT_BUFFER` it receives the required size.
    pub fn tbsip_submit_command(
        &mut self,
        context: u64,
        locality: u8,
        priority: u32,
        command: &[u8],
        response: &mut [u8],
        response_size: &mut u32,
    ) -> u32 {
        let capacity = (*response_size as usize).min(response.len());
        match self.execute_validated(context, locality, priority, command) {
            Ok(bytes) => {
                if capacity < bytes.len() {
                    *response_size = bytes.len() as u32;
                    return TBS_E_INSUFFICIENT_BUFFER;
                }
                response[..bytes.len()].copy_from_slice(&bytes);
                *response_size = bytes.len() as u32;
                TBS_SUCCESS
            }
            Err(error) => error.code(),
        }
    }
}

fn map_persist_error(error: PersistError) -> TbsError {
    match error {
        PersistError::Io(_) => TbsError::Io,
        PersistError::Corrupt(_) => TbsError::Internal,
    }
}

fn map_open_error(error: super::TpmError) -> TbsError {
    match error {
        super::TpmError::Persist(error) => map_persist_error(error),
    }
}

/// The TPM response code carried by a complete response buffer, or
/// `TPM_RC_SIZE` when the buffer is too short to contain one.
pub fn response_code(response: &[u8]) -> u32 {
    if response.len() < 10 {
        return TPM_RC_SIZE;
    }
    u32::from_be_bytes([response[6], response[7], response[8], response[9]])
}
