//! The lifecycle of a per-user install (C4, M5-D5, M5-D6, M5-D9): pure transitions over
//! [`InstallState`] for the first install, an apply, the health confirmation, start attempts, a
//! rollback and the delivery of lifecycle events, plus the set of versions garbage collection
//! keeps.
//!
//! Each transition takes the record loaded under the install's lock and returns the record to
//! commit; nothing here touches a file, a process or the time. Floors are copied untouched (a
//! commit refuses a lowered floor anyway), unknown top-level members are kept, and only a token's
//! SHA-256 is ever recorded. Every write refuses a machine-scope record
//! ([`LifecycleError::MachineScope`]): the privileged engine owns those, and nothing here reads a
//! root or a floor from a counters record (M4-SEC-obs1).

use std::collections::BTreeSet;

use crate::digest::Sha256Digest;
use crate::error::LifecycleError;
use crate::policy::INSTALL_ID_BYTES;
use crate::state::{
    CurrentRef, Health, InstallState, Lifecycle, LifecycleEvent, MAX_BAD_VERSIONS,
    MAX_LIFECYCLE_EVENTS, PendingRef, PreviousRef, Scope,
};
use crate::version::Version;

/// Unconfirmed unsupervised starts of a pending version before the next one rolls back (M5-D5).
pub const MAX_ATTEMPTS: u64 = 3;

/// What a confirming start presented (M5-D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCheck {
    /// The SHA-256 of the token found in the environment.
    Presented(Sha256Digest),
    /// No token in the environment.
    Absent,
}

/// The result of [`confirm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmOutcome {
    /// The pending version is now confirmed healthy.
    Confirmed,
    /// Nothing to confirm for this version: nothing is pending, or another version is. The
    /// record is unchanged.
    NothingPending,
}

/// The result of [`count_attempt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The start is counted; this many unconfirmed starts so far.
    Counted(u64),
    /// This start would be one above [`MAX_ATTEMPTS`]: the caller rolls back ([`rollback`]). The
    /// record is unchanged.
    RollBack,
}

/// Text equality: two versions of equal precedence but different build metadata are different
/// trees, so a version is matched by its text, not its precedence.
fn same(a: &Version, b: &Version) -> bool {
    a == b && a.to_string() == b.to_string()
}

fn user_only(s: &InstallState) -> Result<(), LifecycleError> {
    match s.scope {
        Scope::User => Ok(()),
        Scope::Machine => Err(LifecycleError::MachineScope),
    }
}

/// Constant-time equality of two digests: every byte is compared whatever the first difference.
fn digest_eq(a: &Sha256Digest, b: &Sha256Digest) -> bool {
    let diff = a
        .as_bytes()
        .iter()
        .zip(b.as_bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    core::hint::black_box(diff) == 0
}

/// `events` with every event for `version` removed.
fn without_events_for(lifecycle: Option<Lifecycle>, version: &Version) -> Vec<LifecycleEvent> {
    lifecycle
        .map(|l| l.events)
        .unwrap_or_default()
        .into_iter()
        .filter(|e| !same(e.recipient(), version))
        .collect()
}

/// `events` as the record member: `None` when empty, else the newest
/// [`MAX_LIFECYCLE_EVENTS`].
fn lifecycle_of(mut events: Vec<LifecycleEvent>) -> Option<Lifecycle> {
    if events.is_empty() {
        return None;
    }
    if events.len() > MAX_LIFECYCLE_EVENTS {
        events.drain(..events.len() - MAX_LIFECYCLE_EVENTS);
    }
    Some(Lifecycle { events })
}

/// The first install of `version` (its manifest issued at `issued`) into a record with no
/// current version (M5-D8): `current` is set, the install id is `install_id`, a staged entry
/// that is not newer than `version` is cleared with its `staged_issued`, and the events
/// `installed` and `first_run` are queued for `version`.
///
/// A record that already has a current version is [`LifecycleError::AlreadyInstalled`].
pub fn install_first(
    s: &InstallState,
    version: Version,
    issued: u64,
    install_id: [u8; INSTALL_ID_BYTES],
) -> Result<InstallState, LifecycleError> {
    user_only(s)?;
    if s.current.is_some() {
        return Err(LifecycleError::AlreadyInstalled);
    }
    let mut out = s.next();
    if out.staged.as_ref().is_some_and(|st| st.version <= version) {
        out.staged = None;
        out.staged_issued = None;
    }
    out.current = Some(CurrentRef {
        version: version.clone(),
        issued,
    });
    out.previous = None;
    out.pending = None;
    out.health = None;
    out.install_id = install_id;
    // A first install has no earlier version to deliver to.
    out.lifecycle = lifecycle_of(vec![
        LifecycleEvent::Installed {
            version: version.clone(),
        },
        LifecycleEvent::FirstRun { version },
    ]);
    Ok(out)
}

/// Applies the staged `version` (C4): the old current becomes `previous`, `version` becomes
/// current with the staged manifest's `issued` (so the floor time of FORMAT.md 11.3 is the
/// running release's), and it is pending its health check with `token_sha256` recorded for its
/// supervised start. `staged` and `staged_issued` are cleared, and the events `updated` and
/// `first_run` are queued for `version`; queued events for any other version are dropped.
///
/// Requires a current version, no pending one, fewer than [`MAX_BAD_VERSIONS`] bad versions (so
/// the rollback that may follow can always be committed), a usable staged entry (FORMAT.md 12.7:
/// newer than current, not bad, the record's target; the tree on disk is the caller's check)
/// whose version is `version`, and a `staged_issued` bound to it.
pub fn apply(
    s: &InstallState,
    version: &Version,
    token_sha256: Sha256Digest,
) -> Result<InstallState, LifecycleError> {
    user_only(s)?;
    let current = s.current.as_ref().ok_or(LifecycleError::NotInstalled)?;
    if s.pending.is_some() {
        return Err(LifecycleError::PendingExists);
    }
    if s.bad.len() >= MAX_BAD_VERSIONS {
        return Err(LifecycleError::BadFull);
    }
    let staged = s.staged.as_ref().ok_or(LifecycleError::NothingStaged)?;
    let usable = staged.version > current.version
        && !s.bad.contains(&staged.version)
        && staged.target == s.target;
    if !usable {
        return Err(LifecycleError::NothingStaged);
    }
    if !same(&staged.version, version) {
        return Err(LifecycleError::StagedVersionMismatch);
    }
    let issued = s
        .staged_issued_bound()
        .ok_or(LifecycleError::StagedIssuedUnbound)?;
    let from = current.version.clone();
    let mut out = s.next();
    out.previous = Some(PreviousRef {
        version: from.clone(),
    });
    out.current = Some(CurrentRef {
        version: version.clone(),
        issued,
    });
    out.pending = Some(PendingRef {
        version: version.clone(),
        attempts: 0,
    });
    out.health = Some(Health {
        version: version.clone(),
        token_sha256,
    });
    out.staged = None;
    out.staged_issued = None;
    let mut events: Vec<LifecycleEvent> = s
        .lifecycle
        .clone()
        .map(|l| l.events)
        .unwrap_or_default()
        .into_iter()
        .filter(|e| same(e.recipient(), version))
        .collect();
    events.push(LifecycleEvent::Updated {
        from,
        to: version.clone(),
    });
    events.push(LifecycleEvent::FirstRun {
        version: version.clone(),
    });
    out.lifecycle = lifecycle_of(events);
    Ok(out)
}

/// A start of version `own` confirms its health (M5-D5, per user).
///
/// When `own` is not the pending version (or nothing is pending) the outcome is
/// [`ConfirmOutcome::NothingPending`] and the record is returned unchanged: an older instance
/// never confirms a newer version. Otherwise a presented token must match the recorded digest
/// (compared in constant time; [`LifecycleError::TokenMismatch`] with no change when it does not,
/// or when no digest is recorded for that version), and a start with no token confirms. A
/// confirmation clears `pending` and `health`.
pub fn confirm(
    s: &InstallState,
    own: &Version,
    token: TokenCheck,
) -> Result<(InstallState, ConfirmOutcome), LifecycleError> {
    user_only(s)?;
    let Some(pending) = s.pending.as_ref().filter(|p| same(&p.version, own)) else {
        return Ok((s.clone(), ConfirmOutcome::NothingPending));
    };
    if let TokenCheck::Presented(presented) = token {
        let matches = s
            .health
            .as_ref()
            .filter(|h| same(&h.version, &pending.version))
            .is_some_and(|h| digest_eq(&h.token_sha256, &presented));
        if !matches {
            return Err(LifecycleError::TokenMismatch);
        }
    }
    let mut out = s.next();
    out.pending = None;
    out.health = None;
    Ok((out, ConfirmOutcome::Confirmed))
}

/// An unsupervised start of version `own`, pending its health check, counts one attempt
/// (M5-D5): [`AttemptOutcome::Counted`] with the new count, or [`AttemptOutcome::RollBack`] (the
/// record unchanged) when the count would go above [`MAX_ATTEMPTS`].
///
/// `own` must be the pending version ([`LifecycleError::NotPending`] otherwise).
pub fn count_attempt(
    s: &InstallState,
    own: &Version,
) -> Result<(InstallState, AttemptOutcome), LifecycleError> {
    user_only(s)?;
    let pending = s
        .pending
        .as_ref()
        .filter(|p| same(&p.version, own))
        .ok_or(LifecycleError::NotPending)?;
    let attempts = pending.attempts.saturating_add(1);
    if attempts > MAX_ATTEMPTS {
        return Ok((s.clone(), AttemptOutcome::RollBack));
    }
    let mut out = s.next();
    if let Some(p) = out.pending.as_mut() {
        p.attempts = attempts;
    }
    Ok((out, AttemptOutcome::Counted(attempts)))
}

/// Rolls the pending version `bad_version` back to the previous one (C4): `current` becomes the
/// previous version with the rolled-back release's `issued` kept (the floor time never
/// decreases), `previous`, `pending` and `health` are cleared, `bad_version` joins `bad` (kept
/// sorted), and its queued events are dropped. A staged entry of `bad_version` is cleared with
/// its `staged_issued`.
///
/// Requires `bad_version` pending and a previous version. `bad` already holding
/// [`MAX_BAD_VERSIONS`] other versions (only an older writer can get there, since [`apply`]
/// refuses a full list) still rolls back, without marking: a crashing version is never left
/// current because the list is full.
pub fn rollback(s: &InstallState, bad_version: &Version) -> Result<InstallState, LifecycleError> {
    user_only(s)?;
    if !s
        .pending
        .as_ref()
        .is_some_and(|p| same(&p.version, bad_version))
    {
        return Err(LifecycleError::NotPending);
    }
    let previous = s.previous.as_ref().ok_or(LifecycleError::NoPrevious)?;
    let current = s.current.as_ref().ok_or(LifecycleError::NotInstalled)?;
    let mut out = s.next();
    out.current = Some(CurrentRef {
        version: previous.version.clone(),
        issued: current.issued,
    });
    out.previous = None;
    out.pending = None;
    out.health = None;
    if let Err(at) = out.bad.binary_search(bad_version)
        && out.bad.len() < MAX_BAD_VERSIONS
    {
        out.bad.insert(at, bad_version.clone());
    }
    if out
        .staged
        .as_ref()
        .is_some_and(|st| same(&st.version, bad_version))
    {
        out.staged = None;
        out.staged_issued = None;
    }
    out.lifecycle = lifecycle_of(without_events_for(s.lifecycle.clone(), bad_version));
    Ok(out)
}

/// The events queued for version `own`, oldest first, and the record with them removed
/// (M5-D6: delivered at most once, so the caller commits the record before returning them).
/// No event for `own` leaves the record unchanged.
pub fn deliver_events(
    s: &InstallState,
    own: &Version,
) -> Result<(InstallState, Vec<LifecycleEvent>), LifecycleError> {
    user_only(s)?;
    let events = s.lifecycle.as_ref().map_or(&[][..], |l| &l.events[..]);
    let (mine, rest): (Vec<LifecycleEvent>, Vec<LifecycleEvent>) = events
        .iter()
        .cloned()
        .partition(|e| same(e.recipient(), own));
    if mine.is_empty() {
        return Ok((s.clone(), mine));
    }
    let mut out = s.next();
    out.lifecycle = lifecycle_of(rest);
    Ok((out, mine))
}

/// The versions garbage collection keeps (M5-D9): current, previous, pending and staged. The set
/// orders by precedence, so a directory whose version has the same precedence as a kept one is
/// kept too (erring on keeping).
pub fn gc_keep(s: &InstallState) -> BTreeSet<Version> {
    s.current
        .iter()
        .map(|c| c.version.clone())
        .chain(s.previous.iter().map(|p| p.version.clone()))
        .chain(s.pending.iter().map(|p| p.version.clone()))
        .chain(s.staged.iter().map(|st| st.version.clone()))
        .collect()
}
