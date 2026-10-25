//! Security reference monitor: SIDs, tokens, impersonation and DACL
//! evaluation for object opens.
//!
//! Evaluation is fail-closed: an absent DACL denies every request, matched
//! deny ACEs override allows, restricted tokens must satisfy both SID sets,
//! and a token below an object's required integrity level is denied unless it
//! holds `SeTcbPrivilege`.

use std::collections::BTreeSet;

use crate::casak::object::{DELETE, GENERIC_WRITE, READ_CONTROL, WRITE_DAC};
use crate::casak::status::{
    STATUS_ACCESS_DENIED, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_SID,
    STATUS_PRIVILEGE_NOT_HELD,
};

/// A security identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sid {
    authority: u64,
    subauthorities: Vec<u32>,
}

impl Sid {
    /// Builds a SID.  A SID with neither an authority nor subauthorities is
    /// invalid and fails closed.
    pub fn new(authority: u64, subauthorities: impl Into<Vec<u32>>) -> Result<Self, i32> {
        let subauthorities = subauthorities.into();
        if authority == 0 && subauthorities.is_empty() {
            return Err(STATUS_INVALID_SID);
        }
        Ok(Self {
            authority,
            subauthorities,
        })
    }

    pub fn authority(&self) -> u64 {
        self.authority
    }

    pub fn subauthorities(&self) -> &[u32] {
        &self.subauthorities
    }

    /// `S-1-1-0` (Everyone).
    pub fn world() -> Self {
        Self::new(1, vec![0]).expect("world SID is valid")
    }

    /// `S-1-5-18` (Local System).
    pub fn local_system() -> Self {
        Self::new(5, vec![18]).expect("system SID is valid")
    }

    /// `S-1-5-11` (Authenticated Users).
    pub fn authenticated_users() -> Self {
        Self::new(5, vec![11]).expect("authenticated SID is valid")
    }

    /// `S-1-5-32-544` (Administrators).
    pub fn administrators() -> Self {
        Self::new(5, vec![32, 544]).expect("administrators SID is valid")
    }

    /// `S-1-5-32-545` (Users).
    pub fn users() -> Self {
        Self::new(5, vec![32, 545]).expect("users SID is valid")
    }
}

/// Integrity levels, ordered from lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    High,
    System,
}

/// A token privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Privilege {
    SeDebugPrivilege,
    SeBackupPrivilege,
    SeRestorePrivilege,
    SeShutdownPrivilege,
    SeTcbPrivilege,
}

/// Token impersonation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImpersonationLevel {
    Anonymous,
    Identification,
    Impersonation,
    Delegation,
}

/// Monotonic token identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TokenId(pub u64);

/// An access token owned by the reference monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub id: TokenId,
    pub user: Sid,
    pub groups: BTreeSet<Sid>,
    pub privileges: BTreeSet<Privilege>,
    pub integrity: IntegrityLevel,
    pub elevated: bool,
    pub impersonation: Option<ImpersonationLevel>,
    pub restricted: BTreeSet<Sid>,
}

/// One discretionary access-control entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub allow: bool,
    pub sid: Sid,
    pub mask: u32,
}

/// An ordered DACL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Acl {
    aces: Vec<Ace>,
}

impl Acl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_allow(&mut self, sid: Sid, mask: u32) {
        self.aces.push(Ace {
            allow: true,
            sid,
            mask,
        });
    }

    pub fn push_deny(&mut self, sid: Sid, mask: u32) {
        self.aces.push(Ace {
            allow: false,
            sid,
            mask,
        });
    }

    pub fn entries(&self) -> &[Ace] {
        &self.aces
    }
}

/// A security descriptor.  `None` DACL means "deny all".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptor {
    pub owner: Sid,
    pub dacl: Option<Acl>,
    pub integrity: Option<IntegrityLevel>,
}

impl SecurityDescriptor {
    pub fn new(owner: Sid) -> Self {
        Self {
            owner,
            dacl: None,
            integrity: None,
        }
    }

    pub fn with_dacl(owner: Sid, dacl: Acl) -> Self {
        Self {
            owner,
            dacl: Some(dacl),
            integrity: None,
        }
    }

    pub fn require_integrity(mut self, level: IntegrityLevel) -> Self {
        self.integrity = Some(level);
        self
    }
}

/// The security reference monitor.
#[derive(Debug)]
pub struct SecurityMonitor {
    tokens: std::collections::BTreeMap<TokenId, Token>,
    next_token: u64,
    impersonation: Vec<TokenId>,
}

impl SecurityMonitor {
    pub fn new() -> Self {
        Self {
            tokens: std::collections::BTreeMap::new(),
            next_token: 1,
            impersonation: Vec::new(),
        }
    }

    /// Creates a token.  At most 64 tokens are accepted per monitor.
    pub fn create_token(
        &mut self,
        user: Sid,
        groups: impl IntoIterator<Item = Sid>,
        privileges: impl IntoIterator<Item = Privilege>,
        integrity: IntegrityLevel,
    ) -> Result<TokenId, i32> {
        if self.tokens.len() >= 64 {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let id = TokenId(self.next_token);
        self.next_token += 1;
        self.tokens.insert(
            id,
            Token {
                id,
                user,
                groups: groups.into_iter().collect(),
                privileges: privileges.into_iter().collect(),
                integrity,
                elevated: false,
                impersonation: None,
                restricted: BTreeSet::new(),
            },
        );
        Ok(id)
    }

    /// Creates a restricted token that must satisfy both the normal and
    /// restricted SID checks.
    pub fn create_restricted_token(
        &mut self,
        user: Sid,
        groups: impl IntoIterator<Item = Sid>,
        restricted: impl IntoIterator<Item = Sid>,
    ) -> Result<TokenId, i32> {
        let id = self.create_token(user, groups, [], IntegrityLevel::Medium)?;
        if let Some(token) = self.tokens.get_mut(&id) {
            token.restricted = restricted.into_iter().collect();
        }
        Ok(id)
    }

    pub fn delete_token(&mut self, token: TokenId) -> Result<(), i32> {
        self.tokens
            .remove(&token)
            .map(|_| ())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn query_token(&self, token: TokenId) -> Result<&Token, i32> {
        self.tokens.get(&token).ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    /// Marks a token elevated.
    pub fn elevate(&mut self, token: TokenId) -> Result<(), i32> {
        let record = self.tokens.get_mut(&token).ok_or(STATUS_INVALID_HANDLE)?;
        record.elevated = true;
        Ok(())
    }

    /// Sets the impersonation level stored on a token.
    pub fn set_impersonation_level(
        &mut self,
        token: TokenId,
        level: ImpersonationLevel,
    ) -> Result<(), i32> {
        let record = self.tokens.get_mut(&token).ok_or(STATUS_INVALID_HANDLE)?;
        record.impersonation = Some(level);
        Ok(())
    }

    /// Begins impersonation.  Impersonation is LIFO.
    pub fn impersonate(&mut self, token: TokenId) -> Result<(), i32> {
        if !self.tokens.contains_key(&token) {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.impersonation.push(token);
        Ok(())
    }

    /// Ends the current impersonation.
    pub fn revert(&mut self) -> Result<TokenId, i32> {
        self.impersonation.pop().ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn current_token(&self) -> Option<TokenId> {
        self.impersonation.last().copied()
    }

    /// Fails unless the token holds `privilege`.
    pub fn require_privilege(&self, token: TokenId, privilege: Privilege) -> Result<(), i32> {
        let record = self.query_token(token)?;
        if record.privileges.contains(&privilege) {
            Ok(())
        } else {
            Err(STATUS_PRIVILEGE_NOT_HELD)
        }
    }

    /// Evaluates a DACL for `desired` access.  The token's own user and group
    /// SIDs participate, plus an implicit owner grant, the required integrity
    /// level, and (for restricted tokens) a second evaluation over the
    /// restricted SIDs.
    pub fn check_access(
        &self,
        token: TokenId,
        descriptor: &SecurityDescriptor,
        desired: u32,
    ) -> Result<(), i32> {
        let record = self.query_token(token)?;
        if descriptor
            .integrity
            .is_some_and(|required| record.integrity < required)
            && !record.privileges.contains(&Privilege::SeTcbPrivilege)
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        if record.impersonation == Some(ImpersonationLevel::Identification)
            && desired & (WRITE_DAC | DELETE | GENERIC_WRITE) != 0
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        if desired == 0 {
            return Ok(());
        }
        let dacl = descriptor.dacl.as_ref().ok_or(STATUS_ACCESS_DENIED)?;
        let mut effective = desired;
        if record.user == descriptor.owner {
            effective &= !(READ_CONTROL | WRITE_DAC);
        }
        if effective == 0 {
            return Ok(());
        }
        let normal = evaluate_acl(
            dacl,
            std::iter::once(&record.user).chain(record.groups.iter()),
            effective,
        );
        if !normal {
            return Err(STATUS_ACCESS_DENIED);
        }
        if !record.restricted.is_empty() {
            let restricted = evaluate_acl(dacl, record.restricted.iter(), effective);
            if !restricted {
                return Err(STATUS_ACCESS_DENIED);
            }
        }
        Ok(())
    }
}

fn evaluate_acl<'a>(dacl: &Acl, sids: impl Iterator<Item = &'a Sid>, desired: u32) -> bool {
    let sids: Vec<&Sid> = sids.collect();
    let denied: u32 = dacl
        .aces
        .iter()
        .filter(|ace| !ace.allow && sids.iter().any(|sid| **sid == ace.sid))
        .fold(0, |mask, ace| mask | ace.mask);
    if desired & denied != 0 {
        return false;
    }
    let allowed: u32 = dacl
        .aces
        .iter()
        .filter(|ace| ace.allow && sids.iter().any(|sid| **sid == ace.sid))
        .fold(0, |mask, ace| mask | ace.mask);
    desired & !allowed == 0
}

impl Default for SecurityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casak::object::{GENERIC_READ, READ_CONTROL, WRITE_DAC};

    fn monitor_with_user(user: Sid) -> (SecurityMonitor, TokenId) {
        let mut monitor = SecurityMonitor::new();
        let token = monitor
            .create_token(
                user,
                [Sid::users()],
                [Privilege::SeShutdownPrivilege],
                IntegrityLevel::Medium,
            )
            .unwrap();
        (monitor, token)
    }

    #[test]
    fn sid_construction_rejects_an_empty_identity() {
        assert_eq!(SecurityMonitor::default().token_count(), 0);
        assert_eq!(Sid::new(0, Vec::<u32>::new()), Err(STATUS_INVALID_SID));
        let sid = Sid::new(5, vec![32, 544]).unwrap();
        assert_eq!(sid.authority(), 5);
        assert_eq!(sid.subauthorities(), &[32, 544]);
    }

    #[test]
    fn missing_dacl_and_matched_deny_aces_fail_closed() {
        let (monitor, token) = monitor_with_user(Sid::users());
        let owner = Sid::local_system();
        let descriptor = SecurityDescriptor::new(owner.clone());
        assert_eq!(
            monitor.check_access(token, &descriptor, READ_CONTROL),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(monitor.check_access(token, &descriptor, 0), Ok(()));

        let mut acl = Acl::new();
        acl.push_allow(Sid::users(), GENERIC_READ);
        acl.push_deny(Sid::users(), GENERIC_READ);
        let descriptor = SecurityDescriptor::with_dacl(owner, acl.clone());
        assert_eq!(
            monitor.check_access(token, &descriptor, GENERIC_READ),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(acl.entries().len(), 2);
    }

    #[test]
    fn allow_aces_cover_user_groups_and_owner_implicit_rights() {
        let user = Sid::new(1, vec![1000]).unwrap();
        let (monitor, token) = monitor_with_user(user.clone());
        let mut acl = Acl::new();
        acl.push_allow(Sid::users(), GENERIC_READ);
        let descriptor = SecurityDescriptor::with_dacl(Sid::local_system(), acl.clone());
        assert_eq!(
            monitor.check_access(token, &descriptor, GENERIC_READ),
            Ok(())
        );
        assert_eq!(
            monitor.check_access(token, &descriptor, GENERIC_WRITE),
            Err(STATUS_ACCESS_DENIED)
        );
        let owned = SecurityDescriptor::with_dacl(user, Acl::new());
        assert_eq!(
            monitor.check_access(token, &owned, READ_CONTROL | WRITE_DAC),
            Ok(())
        );
        let mut unmatched = Acl::new();
        unmatched.push_allow(Sid::administrators(), GENERIC_READ);
        let denied = SecurityDescriptor::with_dacl(Sid::world(), unmatched);
        assert_eq!(
            monitor.check_access(token, &denied, GENERIC_READ),
            Err(STATUS_ACCESS_DENIED)
        );
    }

    #[test]
    fn restricted_tokens_must_satisfy_both_sid_sets() {
        let user = Sid::new(1, vec![1000]).unwrap();
        let restricted_sid = Sid::new(1, vec![2000]).unwrap();
        let mut monitor = SecurityMonitor::new();
        let token = monitor
            .create_restricted_token(user.clone(), [Sid::users()], [restricted_sid.clone()])
            .unwrap();
        let mut acl = Acl::new();
        acl.push_allow(user, GENERIC_READ);
        let descriptor = SecurityDescriptor::with_dacl(Sid::local_system(), acl.clone());
        assert_eq!(
            monitor.check_access(token, &descriptor, GENERIC_READ),
            Err(STATUS_ACCESS_DENIED)
        );
        acl.push_allow(restricted_sid, GENERIC_READ);
        let descriptor = SecurityDescriptor::with_dacl(Sid::local_system(), acl);
        assert_eq!(
            monitor.check_access(token, &descriptor, GENERIC_READ),
            Ok(())
        );
    }

    #[test]
    fn integrity_and_identification_impersonation_deny_writes() {
        let user = Sid::users();
        let (mut monitor, token) = monitor_with_user(user.clone());
        let mut acl = Acl::new();
        acl.push_allow(user.clone(), GENERIC_READ | GENERIC_WRITE);
        let descriptor = SecurityDescriptor::with_dacl(Sid::local_system(), acl.clone())
            .require_integrity(IntegrityLevel::High);
        assert_eq!(
            monitor.check_access(token, &descriptor, GENERIC_READ),
            Err(STATUS_ACCESS_DENIED)
        );
        let tcb = monitor
            .create_token(
                user.clone(),
                [Sid::users()],
                [Privilege::SeTcbPrivilege],
                IntegrityLevel::Low,
            )
            .unwrap();
        assert_eq!(monitor.check_access(tcb, &descriptor, GENERIC_READ), Ok(()));
        let token_for_impersonation = monitor
            .create_token(user, [Sid::users()], [], IntegrityLevel::System)
            .unwrap();
        monitor
            .set_impersonation_level(token_for_impersonation, ImpersonationLevel::Identification)
            .unwrap();
        let descriptor = SecurityDescriptor::with_dacl(Sid::local_system(), acl);
        assert_eq!(
            monitor.check_access(token_for_impersonation, &descriptor, GENERIC_WRITE),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            monitor.check_access(token_for_impersonation, &descriptor, GENERIC_READ),
            Ok(())
        );
    }

    #[test]
    fn token_lifecycle_and_privileges_reject_invalid_handles() {
        let mut monitor = SecurityMonitor::new();
        let token = monitor
            .create_token(
                Sid::users(),
                [Sid::authenticated_users()],
                [Privilege::SeDebugPrivilege],
                IntegrityLevel::Medium,
            )
            .unwrap();
        assert_eq!(monitor.token_count(), 1);
        assert!(monitor.query_token(token).unwrap().elevated == false);
        assert_eq!(monitor.elevate(token), Ok(()));
        assert!(monitor.query_token(token).unwrap().elevated);
        assert_eq!(
            monitor.require_privilege(token, Privilege::SeDebugPrivilege),
            Ok(())
        );
        assert_eq!(
            monitor.require_privilege(token, Privilege::SeBackupPrivilege),
            Err(STATUS_PRIVILEGE_NOT_HELD)
        );
        assert_eq!(
            monitor.require_privilege(TokenId(404), Privilege::SeDebugPrivilege),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(monitor.current_token(), None);
        assert_eq!(monitor.revert(), Err(STATUS_INVALID_HANDLE));
        assert_eq!(monitor.impersonate(token), Ok(()));
        assert_eq!(monitor.current_token(), Some(token));
        assert_eq!(
            monitor.impersonate(TokenId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(monitor.revert(), Ok(token));
        assert_eq!(
            monitor.set_impersonation_level(token, ImpersonationLevel::Impersonation),
            Ok(())
        );
        assert_eq!(
            monitor.set_impersonation_level(TokenId(404), ImpersonationLevel::Impersonation),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(monitor.elevate(TokenId(404)), Err(STATUS_INVALID_HANDLE));
        assert_eq!(
            monitor.delete_token(TokenId(404)),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(monitor.delete_token(token), Ok(()));
        assert_eq!(monitor.query_token(token), Err(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn token_pool_exhaustion_is_exact() {
        let mut monitor = SecurityMonitor::new();
        for _ in 0..64 {
            monitor
                .create_token(Sid::users(), [], [], IntegrityLevel::Medium)
                .unwrap();
        }
        assert_eq!(
            monitor.create_token(Sid::users(), [], [], IntegrityLevel::Medium),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(
            monitor.create_restricted_token(Sid::users(), [], []),
            Err(STATUS_INSUFFICIENT_RESOURCES)
        );
        assert_eq!(monitor.token_count(), 64);
    }

    #[test]
    fn well_known_sids_are_stable_and_missing_dacl_fails_closed() {
        assert_eq!(Sid::world(), Sid::new(1, vec![0]).unwrap());
        assert_eq!(Sid::local_system(), Sid::new(5, vec![18]).unwrap());
        assert_eq!(Sid::administrators(), Sid::new(5, vec![32, 544]).unwrap());
        assert_eq!(Sid::users(), Sid::new(5, vec![32, 545]).unwrap());
        let descriptor =
            SecurityDescriptor::new(Sid::users()).require_integrity(IntegrityLevel::Low);
        assert_eq!(descriptor.integrity, Some(IntegrityLevel::Low));
        let mut acl = Acl::new();
        acl.push_allow(Sid::world(), 1);
        acl.push_deny(Sid::world(), 2);
        assert_eq!(acl.entries()[0].allow, true);
        assert_eq!(acl.entries()[1].allow, false);
        let mut monitor = SecurityMonitor::new();
        let token = monitor
            .create_token(
                Sid::world(),
                [Sid::authenticated_users()],
                [],
                IntegrityLevel::Low,
            )
            .unwrap();
        let denied = SecurityDescriptor::new(Sid::administrators())
            .require_integrity(IntegrityLevel::System);
        assert_eq!(
            monitor.check_access(token, &denied, READ_CONTROL),
            Err(STATUS_ACCESS_DENIED)
        );
    }
}
