//! The app-facing lifecycle calls (C4, M5-D5, M5-D6): [`startup`] at every start,
//! [`confirm_healthy`] once the app works, and [`apply_and_restart`] to hand a staged version to
//! the runtime and exit.
//!
//! Each call works on the [`Installation`] of the running executable; the `_for` forms take one
//! explicitly (another platform, a test). Every state change is a core transition committed under
//! the install's lock, which a call retries for up to its platform's busy wait (2 s by default)
//! before [`Error::Busy`]. They block the calling thread, so an async app calls them off its
//! executor's threads (or at start, before it runs one). No call shows a path, a URL or the
//! health token in an error.

use std::ffi::OsString;
use std::fmt;

use lunepack_core::state::{InstallState, Loaded, UserScope};
use lunepack_core::{
    AttemptOutcome, ConfirmOutcome, FileKind, IntegrationRequest, LifecycleEvent, ProcessId, Scope,
    SpawnSpec, TokenCheck, UserLayout, Version, reconcile_current,
};

use crate::Error;
use crate::installation::{HEALTH_TOKEN_VAR, Installation, lock_state, same_version};

/// What the app does after [`startup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupAction {
    /// Go on starting.
    Continue,
    /// Exit now: this version was rolled back and the previous one has been started in its
    /// place.
    Exit,
}

/// What [`startup`] found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Startup {
    /// Lifecycle events for this version, oldest first, each delivered once (M5-D6).
    pub events: Vec<LifecycleEvent>,
    /// Whether to go on.
    pub action: StartupAction,
    /// Whether this version still waits for [`confirm_healthy`].
    pub pending: bool,
}

impl Startup {
    fn go_on(events: Vec<LifecycleEvent>, pending: bool) -> Startup {
        Startup {
            events,
            action: StartupAction::Continue,
            pending,
        }
    }
}

/// Options of [`apply_and_restart`].
#[derive(Clone, Default)]
pub struct ApplyOptions {
    /// The version the app expects to be staged; another one is [`Error::UnexpectedVersion`].
    pub expect_version: Option<Version>,
    /// The process the runtime waits for before it applies (default: this process).
    pub wait_for: Option<ProcessId>,
    /// The arguments the new version is started with.
    pub restart_args: Vec<OsString>,
}

impl fmt::Debug for ApplyOptions {
    /// Shows the number of restart arguments, not their values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplyOptions")
            .field("expect_version", &self.expect_version)
            .field("wait_for", &self.wait_for)
            .field("restart_args", &self.restart_args.len())
            .finish()
    }
}

/// The runtime was started to apply this version once the waited-for process exits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyScheduled {
    version: Version,
}

impl ApplyScheduled {
    /// The version that will be applied.
    pub fn version(&self) -> &Version {
        &self.version
    }
}

/// The health token this process was started with.
enum Token {
    Absent,
    WellFormed([u8; 32]),
    Malformed,
}

fn read_token(token: Option<&OsString>) -> Token {
    let Some(token) = token else {
        return Token::Absent;
    };
    let Some(text) = token.to_str() else {
        return Token::Malformed;
    };
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return Token::Malformed;
    }
    let mut raw = [0u8; 32];
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        match (digit(pair[0]), digit(pair[1])) {
            (Some(hi), Some(lo)) => raw[i] = (hi << 4) | lo,
            _ => return Token::Malformed,
        }
    }
    Token::WellFormed(raw)
}

/// The install's state store.
fn store_of(inst: &Installation, layout: &UserLayout) -> UserScope {
    UserScope {
        dir: layout.state_dir(),
        app_id: inst.app_id().clone(),
    }
}

/// Commits `next` when it differs from the loaded `record`; returns the record now in force.
fn commit_if_changed(
    inst: &Installation,
    store: &UserScope,
    loaded: &Loaded<InstallState>,
    record: &InstallState,
    next: InstallState,
) -> Result<InstallState, Error> {
    if &next == record {
        return Ok(next);
    }
    let p = &inst.platform;
    Ok(store.commit(&*p.fs, loaded, &next, &*p.hasher)?)
}

fn reconcile(inst: &Installation, layout: &UserLayout, record: &InstallState) -> Result<(), Error> {
    reconcile_current(&*inst.platform.fs, layout.root(), record)
        .map_err(|e| Error::from(lunepack_core::Error::Layout(e)))
}

fn is_pending(record: &InstallState, own: &Version) -> bool {
    record
        .pending
        .as_ref()
        .is_some_and(|p| same_version(&p.version, own))
}

/// The start of the running app: [`startup_for`] its own installation with its own arguments.
pub fn startup() -> Result<Startup, Error> {
    let inst = Installation::from_current_exe()?;
    startup_for(&inst, std::env::args_os().skip(1).collect())
}

/// The start of `inst`'s version, which was started with `args` (M5-D5, M5-D6). Under the lock:
///
/// 1. the `current` link is reconciled with the record;
/// 2. when this version is pending its health check, a start that carries a well-formed health
///    token is supervised and counts nothing; any other start counts an attempt, and the one
///    after the third rolls back: the previous version becomes current again, the desktop
///    integration follows it (best effort), the previous entry is started detached with `args`
///    and no health token, and the result says [`StartupAction::Exit`] (also when that relaunch
///    fails: the rollback is committed). A previous version whose tree or config cannot be
///    opened is [`Error::RollbackUnavailable`] with nothing committed;
/// 3. the events queued for this version are delivered, marked so in the same commit.
///
/// A tree that is not installed, or an install with no current version yet, continues with no
/// events.
pub fn startup_for(inst: &Installation, args: Vec<OsString>) -> Result<Startup, Error> {
    let Some(layout) = inst.layout() else {
        return Ok(Startup::go_on(Vec::new(), false));
    };
    let p = &inst.platform;
    let own = inst.tree_version();
    let store = store_of(inst, layout);
    let guard = lock_state(p, &layout.state_dir())?;
    let loaded = store.load(&*p.fs, &*p.hasher)?;
    let Some(record) = loaded.record.clone() else {
        return Ok(Startup::go_on(Vec::new(), false));
    };
    if record.current.is_none() {
        return Ok(Startup::go_on(Vec::new(), false));
    }
    reconcile(inst, layout, &record)?;

    let mut next = record.clone();
    if is_pending(&record, own)
        && !matches!(read_token(p.health_token.as_ref()), Token::WellFormed(_))
    {
        let (counted, outcome) = lunepack_core::count_attempt(&record, own)?;
        match outcome {
            AttemptOutcome::Counted(_) => next = counted,
            AttemptOutcome::RollBack => {
                let previous = roll_back(inst, layout, &store, &loaded, &record)?;
                drop(guard);
                // The rollback is committed: a relaunch that fails cannot undo it, and this
                // version must still exit. The next start of the previous version recovers.
                let _ = p.process.spawn_detached(&SpawnSpec {
                    program: previous.entry_path(),
                    args,
                    env_set: Vec::new(),
                    env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
                });
                return Ok(Startup {
                    events: Vec::new(),
                    action: StartupAction::Exit,
                    pending: false,
                });
            }
        }
    }
    let (delivered, events) = lunepack_core::deliver_events(&next, own)?;
    let now = commit_if_changed(inst, &store, &loaded, &record, delivered)?;
    drop(guard);
    Ok(Startup::go_on(events, is_pending(&now, own)))
}

/// Rolls `inst`'s pending version back under the held lock. The previous version's installation
/// is opened first: when its tree or config is missing or invalid there is nothing to roll back
/// to, and the call is [`Error::RollbackUnavailable`] with nothing committed (the record stays
/// pending, as the runtime's applier leaves it). Then it commits the rollback, reconciles
/// `current`, and refreshes the desktop integration from the previous version's config (the bad
/// version's command link names as `stale_bins`). Returns the previous version's installation.
///
/// Everything after the commit is best effort: the record already names the previous version,
/// the entries point through `current`, and the previous version's own start (or the next apply
/// or install) reconciles and refreshes them again.
fn roll_back(
    inst: &Installation,
    layout: &UserLayout,
    store: &UserScope,
    loaded: &Loaded<InstallState>,
    record: &InstallState,
) -> Result<Installation, Error> {
    let p = &inst.platform;
    let own = inst.tree_version();
    let previous = record
        .previous
        .as_ref()
        .ok_or(Error::RollbackUnavailable)
        .and_then(|prev| {
            inst.version_installation(&prev.version)
                .map_err(|_| Error::RollbackUnavailable)
        })?;
    let next = lunepack_core::rollback(record, own)?;
    let committed = store.commit(&*p.fs, loaded, &next, &*p.hasher)?;
    let _ = reconcile(inst, layout, &committed);
    let stale_bins = match (&inst.meta().bin, &previous.meta().bin) {
        (Some(bad), keep) if keep.as_ref() != Some(bad) => vec![bad.clone()],
        _ => Vec::new(),
    };
    let request = IntegrationRequest {
        app_id: inst.app_id().clone(),
        install_root: layout.root().to_path_buf(),
        meta: previous.meta().clone(),
        stale_bins,
    };
    let _ = p.integration.apply(Scope::User, &request);
    Ok(previous)
}

/// The running app confirms its health: [`confirm_for`] its own installation.
pub fn confirm_healthy() -> Result<ConfirmOutcome, Error> {
    let inst = Installation::from_current_exe()?;
    confirm_for(&inst)
}

/// `inst`'s version confirms its health (M5-D5). The health token is read first: a token that is
/// set but not 64 lowercase hex digits is [`Error::TokenMismatch`]. Then, under the lock, the
/// core's `confirm` decides: a matching token, or no token at all (per-user installs only),
/// confirms a pending version; a token that does not match is [`Error::TokenMismatch`] and
/// changes nothing. A tree that is not installed, or a version that is not pending, is
/// [`ConfirmOutcome::NothingPending`].
pub fn confirm_for(inst: &Installation) -> Result<ConfirmOutcome, Error> {
    let p = &inst.platform;
    let check = match read_token(p.health_token.as_ref()) {
        Token::Absent => TokenCheck::Absent,
        Token::WellFormed(raw) => TokenCheck::Presented(p.hasher.sha256(&raw)),
        Token::Malformed => return Err(Error::TokenMismatch),
    };
    let Some(layout) = inst.layout() else {
        return Ok(ConfirmOutcome::NothingPending);
    };
    let store = store_of(inst, layout);
    let guard = lock_state(p, &layout.state_dir())?;
    let loaded = store.load(&*p.fs, &*p.hasher)?;
    let Some(record) = loaded.record.clone() else {
        return Ok(ConfirmOutcome::NothingPending);
    };
    let (next, outcome) = lunepack_core::confirm(&record, inst.tree_version(), check)?;
    if outcome == ConfirmOutcome::Confirmed {
        store.commit(&*p.fs, &loaded, &next, &*p.hasher)?;
    }
    drop(guard);
    Ok(outcome)
}

/// The running app hands its staged version to the runtime: [`apply_and_restart_for`] its own
/// installation.
pub fn apply_and_restart(options: ApplyOptions) -> Result<ApplyScheduled, Error> {
    let inst = Installation::from_current_exe()?;
    apply_and_restart_for(&inst, options)
}

/// Starts `inst`'s own runtime, detached, to apply the staged version once the waited-for process
/// (by default this one) has exited:
/// `lunepack-runtime apply --wait-pid <pid> --wait-start <ticks> --version <v> -- <restart args>`,
/// with no health token in its environment. The caller exits next.
///
/// The staged version is read again (C9): none, one that is not usable (FORMAT.md 12.7), a tree
/// that is not a real directory, or a staged entry without its bound `staged_issued` is
/// [`Error::NothingStaged`]. A staged version other than `options.expect_version` is
/// [`Error::UnexpectedVersion`]; a staged version is always newer than the current one.
pub fn apply_and_restart_for(
    inst: &Installation,
    options: ApplyOptions,
) -> Result<ApplyScheduled, Error> {
    let version = staged_version(inst)?;
    if let Some(expected) = &options.expect_version
        && !same_version(expected, &version)
    {
        return Err(Error::UnexpectedVersion);
    }
    let p = &inst.platform;
    let wait = match options.wait_for {
        Some(id) => id,
        None => p.process.current()?,
    };
    let mut args: Vec<OsString> = [
        "apply".to_owned(),
        "--wait-pid".to_owned(),
        wait.pid.to_string(),
        "--wait-start".to_owned(),
        wait.start_ticks.to_string(),
        "--version".to_owned(),
        version.to_string(),
        "--".to_owned(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    args.extend(options.restart_args);
    p.process.spawn_detached(&SpawnSpec {
        program: inst.runtime_path(),
        args,
        env_set: Vec::new(),
        env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
    })?;
    Ok(ApplyScheduled { version })
}

/// The usable staged version of `inst`'s install, with its tree in place and `staged_issued`
/// bound; [`Error::NothingStaged`] otherwise. Takes no lock (as `Updater::staged`).
fn staged_version(inst: &Installation) -> Result<Version, Error> {
    let layout = inst.layout().ok_or(Error::NothingStaged)?;
    let p = &inst.platform;
    let loaded = store_of(inst, layout).load(&*p.fs, &*p.hasher)?;
    let record = loaded.record.ok_or(Error::NothingStaged)?;
    let (Some(current), Some(staged)) = (&record.current, &record.staged) else {
        return Err(Error::NothingStaged);
    };
    let usable = staged.version > current.version
        && !record.bad.contains(&staged.version)
        && staged.target == record.target
        && record.staged_issued_bound().is_some();
    if !usable {
        return Err(Error::NothingStaged);
    }
    let tree = layout.versions_dir().join(&staged.tree);
    let real_dir = match p.fs.symlink_metadata(&tree) {
        Ok(meta) => meta.is_some_and(|m| m.kind == FileKind::Dir),
        Err(e) if e.kind == lunepack_core::FsErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    if !real_dir {
        return Err(Error::NothingStaged);
    }
    Ok(staged.version.clone())
}
