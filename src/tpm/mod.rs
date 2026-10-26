//! Software TPM 2.0 for Windows TBS.
//!
//! This module implements a TPM 2.0 command engine, per-game-environment
//! persistent state, real RSA/ECDSA primitives, and a TBS-facing adapter.
//! It owns no host state outside the environment directory it is opened with;
//! there is no Keychain dependency.
//!
//! Entry points:
//! - [`Tpm`] — command engine (`execute`) and persistent state.
//! - [`tbs::TbsAdapter`] — context create/submit/close with TBS error codes,
//!   ready for the root runtime to connect to `Tbs.dll` exports.
//!
//! The runtime dispatch hook (a `Tbs.dll` export table entry and matching
//! `HostThunk` variants) is intentionally *not* wired here; shared dispatch
//! files are owned by the root integration.

pub mod constants;
mod crypto;
mod engine;
mod persist;
mod session;
mod state;
pub mod tbs;
mod wire;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use rand::RngCore;

use constants::{
    MAX_SESSIONS, MAX_TRANSIENT_OBJECTS, SESSION_HANDLE_BASE, SESSION_HANDLE_LAST,
    TPM_RC_INSUFFICIENT, TRANSIENT_HANDLE_BASE, TRANSIENT_HANDLE_LAST,
};
use persist::{PersistError, PersistedState, environment_state_path};
use state::{KeyMaterial, Object, PublicArea, Session, SessionMaterial};

/// Errors that escape the TPM command response (I/O and open failures).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmError {
    Persist(PersistError),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Persist(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for TpmError {}

impl From<PersistError> for TpmError {
    fn from(error: PersistError) -> Self {
        Self::Persist(error)
    }
}

/// A software TPM instance bound to one game environment.
pub struct Tpm {
    pub(crate) state: PersistedState,
    pub(crate) started: bool,
    pub(crate) objects: BTreeMap<u32, Object>,
    pub(crate) sessions: BTreeMap<u32, Session>,
    pub(crate) next_object: u32,
    pub(crate) next_session: u32,
    persist_path: Option<PathBuf>,
}

impl fmt::Debug for Tpm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tpm")
            .field("started", &self.started)
            .field("objects", &self.objects.len())
            .field("sessions", &self.sessions.len())
            .field("nv_indices", &self.state.nv.len())
            .field("persist_path", &self.persist_path)
            .finish()
    }
}

impl Default for Tpm {
    fn default() -> Self {
        Self::new()
    }
}

fn next_session_handle(candidate: u32) -> u32 {
    if candidate >= SESSION_HANDLE_LAST {
        SESSION_HANDLE_BASE
    } else {
        candidate + 1
    }
}

impl Tpm {
    /// Create an in-memory TPM seeded from host entropy.
    pub fn new() -> Self {
        let mut entropy = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        Self::from_state(PersistedState::fresh(entropy), None)
    }

    /// Create an in-memory TPM with deterministic entropy (tests and
    /// reproducible environments).  The value is used only to derive the
    /// persisted hierarchy seeds.
    pub fn new_with_seed(seed: [u8; 32]) -> Self {
        Self::from_state(PersistedState::fresh(seed), None)
    }

    /// Open (or create) the TPM state file at `path`.
    ///
    /// A missing file yields a fresh TPM.  A present but corrupt file is
    /// rejected with the exact [`persist::Corruption`] reason and is never
    /// reset or overwritten.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, TpmError> {
        let path = path.into();
        match persist::load(&path)? {
            Some(state) => Ok(Self::from_state(state, Some(path))),
            None => {
                let mut entropy = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut entropy);
                Ok(Self::from_state(PersistedState::fresh(entropy), Some(path)))
            }
        }
    }

    /// Open the state belonging to a game-environment root (`root/tpm2/state.bin`).
    pub fn open_environment(root: &Path) -> Result<Self, TpmError> {
        Self::open(environment_state_path(root))
    }

    fn from_state(state: PersistedState, persist_path: Option<PathBuf>) -> Self {
        Self {
            state,
            started: false,
            objects: BTreeMap::new(),
            sessions: BTreeMap::new(),
            next_object: TRANSIENT_HANDLE_BASE,
            next_session: SESSION_HANDLE_BASE,
            persist_path,
        }
    }

    /// Submit one TPM command.  TPM-level failures are encoded in the returned
    /// response buffer; only persistence failures escape as `Err`.
    pub fn execute(&mut self, command: &[u8], locality: u8) -> Result<Vec<u8>, PersistError> {
        engine::execute(self, command, locality)
    }

    /// Persist the current state atomically (no-op for in-memory instances).
    pub fn save(&self) -> Result<(), PersistError> {
        self.persist()
    }

    pub(crate) fn persist(&self) -> Result<(), PersistError> {
        match &self.persist_path {
            Some(path) => persist::save(path, &self.state),
            None => Ok(()),
        }
    }

    pub fn state_path(&self) -> Option<&Path> {
        self.persist_path.as_deref()
    }

    pub fn is_started(&self) -> bool {
        self.started
    }

    pub fn pcr(&self, index: usize) -> Option<[u8; 32]> {
        self.state.pcrs.get(index).copied()
    }

    pub fn pcr_update_counter(&self) -> u32 {
        self.state.pcr_update_counter
    }

    pub fn hierarchy_auth(&self, hierarchy: state::Hierarchy) -> &[u8] {
        hierarchy.auth(&self.state)
    }

    pub fn transient_handles(&self) -> Vec<u32> {
        self.objects.keys().copied().collect()
    }

    pub fn session_handles(&self) -> Vec<u32> {
        self.sessions.keys().copied().collect()
    }

    pub fn nv_indices(&self) -> Vec<u32> {
        self.state.nv.iter().map(|entry| entry.index).collect()
    }

    pub fn session_material(&self, handle: u32) -> Option<SessionMaterial> {
        self.sessions.get(&handle).map(|session| SessionMaterial {
            handle: session.handle,
            nonce_tpm: session.nonce_tpm,
            session_key: session.session_key,
        })
    }

    pub(crate) fn random_bytes(&mut self, count: usize) -> Vec<u8> {
        self.state.drbg.generate(count)
    }

    pub(crate) fn insert_object(
        &mut self,
        public: PublicArea,
        auth: Vec<u8>,
        key: KeyMaterial,
        child_seed: [u8; 32],
    ) -> Result<u32, u32> {
        if self.objects.len() >= MAX_TRANSIENT_OBJECTS {
            return Err(TPM_RC_INSUFFICIENT);
        }
        let handle = self.allocate_transient();
        let name = public.name();
        self.objects.insert(
            handle,
            Object {
                public,
                name,
                auth,
                key,
                child_seed,
            },
        );
        Ok(handle)
    }

    fn allocate_transient(&mut self) -> u32 {
        let mut candidate = self.next_object.max(TRANSIENT_HANDLE_BASE);
        loop {
            if !self.objects.contains_key(&candidate) {
                self.next_object = if candidate == TRANSIENT_HANDLE_LAST {
                    TRANSIENT_HANDLE_BASE
                } else {
                    candidate + 1
                };
                return candidate;
            }
            candidate = if candidate == TRANSIENT_HANDLE_LAST {
                TRANSIENT_HANDLE_BASE
            } else {
                candidate + 1
            };
        }
    }

    pub(crate) fn insert_session(
        &mut self,
        nonce_tpm: [u8; 32],
        session_key: [u8; 32],
        auth_hash: u16,
        bound_entity: u32,
    ) -> Result<u32, u32> {
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(TPM_RC_INSUFFICIENT);
        }
        let mut candidate = self.next_session.max(SESSION_HANDLE_BASE);
        loop {
            if !self.sessions.contains_key(&candidate) {
                self.next_session = next_session_handle(candidate);
                self.sessions.insert(
                    candidate,
                    Session {
                        handle: candidate,
                        nonce_tpm,
                        session_key,
                        auth_hash,
                        bound_entity,
                    },
                );
                return Ok(candidate);
            }
            candidate = next_session_handle(candidate);
        }
    }
}

/// Public constants re-exported for callers that build raw TPM commands.
pub use constants::{
    MAX_COMMAND_SIZE, MAX_DIGEST_SIZE, MAX_NV_SIZE, PCR_COUNT, TPM_RC_SUCCESS, TPM_RS_PW,
    TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS,
};

pub use persist::{Corruption, PersistError as StateError};
pub use state::Hierarchy;
pub use tbs::{
    TBS_CONTEXT_VERSION_ONE, TBS_CONTEXT_VERSION_TWO, TBS_SUCCESS, TbsAdapter, TbsContextParams,
    TbsError, TbsPriority,
};
