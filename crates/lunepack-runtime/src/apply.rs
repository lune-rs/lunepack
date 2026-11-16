//! The `apply` mode (C4, M5-D5, M5-D9): wait for the app to exit, commit the staged version,
//! launch it with a health token, supervise it, and roll it back when it fails; then collect old
//! trees.
//!
//! The install lock is held only in short windows, so the launched app's own `startup()` and
//! `confirm_healthy()` can commit in between:
//!
//! 1. **commit**: the staged version is checked and applied, `current` reconciled and the desktop
//!    integration refreshed from the new version's own config;
//! 2. **decision**: once supervision sees the record change or the child fail, the outcome is
//!    decided again on a record loaded under the lock (confirmed, rolled back by this run,
//!    rolled back elsewhere); a rollback also ends the own child and refreshes the integration
//!    from the previous version's config;
//! 3. **gc**, after the previous version was relaunched (detached, without the token).
//!
//! An apply that fails after the wait (window 1 refuses: no usable config, nothing staged, a held
//! lock, a disk or state error) changes nothing and starts the version that exited again, detached
//! and without the token, so the app comes back; the exit code is the failure. It does not when the
//! record moved on (a version pending, or another current): another applier or a rollback
//! elsewhere has started the app already.
//!
//! The process waited for is only waited for; the only process ever signalled is the own child.
//! Every per-version fact (entry, health timeout, install metadata) comes from that version's own
//! config at `R/versions/<v>/lunepack-update.json`, never from this runtime's tree (M5-D17). The
//! token is in the child's environment only: never in argv, an event, the log or an exit path.

use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use lunepack::{
    Child, ExitKind, FileKind, HEALTH_TOKEN_VAR, Installation, IntegrationRequest, LockGuard,
    Phase, Sha256Digest, SpawnSpec, UserLayout, Version, WaitOutcome,
};
use lunepack_core::state::{InstallState, Scope, UserScope};

use crate::events::{Event, Events, Reason, Warning};
use crate::gc::gc;
use crate::modes::{Adapters, ApplyArgs, Kind};

/// The mode's name in events.
pub const COMMAND: &str = "apply";
/// Longest wait for the process to exit before the apply gives up with nothing changed.
pub const WAIT_MAX: Duration = Duration::from_secs(10 * 60);
/// How long a lock window retries a held install lock.
pub const LOCK_WAIT: Duration = Duration::from_secs(30);
/// The first pause between two tries of a held lock; it doubles up to [`LOCK_POLL_MAX`].
const LOCK_POLL_MIN: Duration = Duration::from_millis(100);
const LOCK_POLL_MAX: Duration = Duration::from_secs(1);
/// How often supervision looks at the record and the child.
pub const SUPERVISE_POLL: Duration = Duration::from_millis(100);
/// How long the own child gets to exit after SIGTERM before it is killed.
pub const TERMINATE_GRACE: Duration = Duration::from_secs(5);
/// The bounds of a config's health timeout (FORMAT.md 13).
const HEALTH_TIMEOUT_SECS: std::ops::RangeInclusive<u64> = 5..=3600;

/// Takes `<state dir>/lock`, retrying a held lock for up to `total` (backoff 100 ms .. 1 s);
/// [`lunepack::Error::Busy`] after that.
pub fn lock_retry(
    ad: &Adapters,
    state_dir: &Path,
    total: Duration,
) -> Result<Box<dyn LockGuard>, lunepack::Error> {
    ad.fs.create_dir_all(state_dir)?;
    let path = state_dir.join("lock");
    let deadline = Instant::now() + total;
    let mut pause = LOCK_POLL_MIN;
    loop {
        if let Some(guard) = ad.fs.try_lock(&path)? {
            return Ok(guard);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(lunepack::Error::Busy);
        }
        std::thread::sleep(pause.min(deadline - now));
        pause = (pause * 2).min(LOCK_POLL_MAX);
    }
}

fn kind_of(e: impl Into<lunepack::Error>) -> Kind {
    Kind::of(&e.into())
}

/// Text equality of two versions (as the facade and the core compare them).
fn same(a: &Version, b: &Version) -> bool {
    a == b && a.to_string() == b.to_string()
}

/// 64 lowercase hex digits.
fn hex(raw: &[u8; 32]) -> OsString {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in raw {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    OsString::from(out)
}

/// The command-link names `outgoing` used that `incoming` no longer does.
fn stale_bins(outgoing: Option<&Installation>, incoming: &Installation) -> Vec<String> {
    match outgoing.and_then(|o| o.meta().bin.clone()) {
        Some(bin) if incoming.meta().bin.as_ref() != Some(&bin) => vec![bin],
        _ => Vec::new(),
    }
}

/// Refreshes the desktop integration from `to`'s metadata (best effort: a failure is a warning,
/// because the entries point through `current` and the next apply or install refreshes them).
fn refresh_integration(
    ad: &Adapters,
    layout: &UserLayout,
    from: Option<&Installation>,
    to: &Installation,
    events: &Events,
) {
    let request = IntegrationRequest {
        app_id: to.app_id().clone(),
        install_root: layout.root().to_path_buf(),
        meta: to.meta().clone(),
        stale_bins: stale_bins(from, to),
    };
    match ad.integration.apply(Scope::User, &request) {
        Ok(report) if report.kept.is_empty() => {}
        Ok(_) => events.emit(&Event::warning(
            Warning::IntegrationKept,
            Some(to.tree_version()),
        )),
        Err(_) => events.emit(&Event::warning(
            Warning::IntegrationFailed,
            Some(to.tree_version()),
        )),
    }
}

fn reconcile(ad: &Adapters, layout: &UserLayout, record: &InstallState, events: &Events) {
    if lunepack_core::reconcile_current(&*ad.fs, layout.root(), record).is_err() {
        events.emit(&Event::warning(Warning::ReconcileFailed, None));
    }
}

/// Whether `record` still has `v` pending under this run's token.
fn ours(record: &InstallState, v: &Version, token_sha256: &Sha256Digest) -> bool {
    record.pending.as_ref().is_some_and(|p| same(&p.version, v))
        && record
            .health
            .as_ref()
            .is_some_and(|h| same(&h.version, v) && h.token_sha256 == *token_sha256)
}

/// What window 1 committed.
struct Applied {
    /// The raw token; only its hex form leaves this module, in the child's environment.
    token: [u8; 32],
    token_sha256: Sha256Digest,
    /// The applied version's installation (its own config).
    new: Installation,
}

/// Why window 1 committed nothing.
struct Refused {
    kind: Kind,
    /// [`nothing_moved_on`] for the record window 1 loaded under the lock, when it got that far:
    /// the relaunch is decided on the state the refusal was decided on (F17).
    unmoved: Option<bool>,
}

impl Refused {
    fn unread(kind: Kind) -> Self {
        Self {
            kind,
            unmoved: None,
        }
    }
}

/// Window 1: checks and commits the apply of `v`, reconciles `current` and refreshes the
/// integration. Nothing is changed when it fails.
fn commit_apply(
    ad: &Adapters,
    inst: &Installation,
    layout: &UserLayout,
    v: &Version,
    events: &Events,
) -> Result<Applied, Refused> {
    let store = store_of(inst, layout);
    let guard =
        lock_retry(ad, &layout.state_dir(), LOCK_WAIT).map_err(|e| Refused::unread(kind_of(e)))?;
    let loaded = store
        .load(&*ad.fs, &*ad.hasher)
        .map_err(|e| Refused::unread(kind_of(e)))?;
    let Some(record) = loaded.record.clone() else {
        return Err(Refused::unread(Kind::NotInstalled));
    };
    let unmoved = nothing_moved_on(&record, inst.tree_version());
    let refused = |kind| Refused {
        kind,
        unmoved: Some(unmoved),
    };
    let current = record
        .current
        .as_ref()
        .ok_or_else(|| refused(Kind::NotInstalled))?;
    let staged_is_v = record.staged.as_ref().is_some_and(|s| same(&s.version, v));
    if !staged_is_v {
        return Err(refused(Kind::NothingStaged));
    }
    let tree_is_dir = matches!(
        ad.fs.symlink_metadata(&layout.version_dir(v)),
        Ok(Some(meta)) if meta.kind == FileKind::Dir
    );
    if !tree_is_dir {
        return Err(refused(Kind::NothingStaged));
    }
    // The new version's own config decides its entry, timeout and integration; without a usable
    // one nothing is committed.
    let new = inst
        .version_installation(v)
        .map_err(|e| refused(Kind::of(&e)))?;
    // The outgoing version's config only names command links to retire.
    let outgoing = inst.version_installation(&current.version).ok();

    let mut token = [0u8; 32];
    ad.rng.fill(&mut token).map_err(|e| refused(kind_of(e)))?;
    let token_sha256 = ad.hasher.sha256(&token);
    let next = lunepack_core::apply(&record, v, token_sha256).map_err(|e| refused(kind_of(e)))?;
    let committed = store
        .commit(&*ad.fs, &loaded, &next, &*ad.hasher)
        .map_err(|e| refused(kind_of(e)))?;
    reconcile(ad, layout, &committed, events);
    refresh_integration(ad, layout, outgoing.as_ref(), &new, events);
    drop(guard);
    events.emit(&Event::phase(Phase::Apply, Some(v)));
    Ok(Applied {
        token,
        token_sha256,
        new,
    })
}

fn store_of(inst: &Installation, layout: &UserLayout) -> UserScope {
    UserScope {
        dir: layout.state_dir(),
        app_id: inst.app_id().clone(),
    }
}

/// What supervision saw.
enum Watch {
    /// The record no longer has the version pending under this run's token.
    Changed,
    /// The version failed.
    Failed(Reason),
}

/// Watches the record (without the lock) and the child until the record changes, the child
/// fails, or `timeout` runs out. An exit with status 0 is not a failure: a launcher may have
/// handed off to another process of the same version, which may still confirm.
fn supervise(
    ad: &Adapters,
    store: &UserScope,
    v: &Version,
    token_sha256: &Sha256Digest,
    child: &mut dyn Child,
    deadline: Instant,
) -> Watch {
    loop {
        let changed = match store.load(&*ad.fs, &*ad.hasher) {
            Ok(loaded) => !loaded
                .record
                .as_ref()
                .is_some_and(|r| ours(r, v, token_sha256)),
            // Unreadable now: keep watching; the decision is made under the lock anyway.
            Err(_) => false,
        };
        if changed {
            return Watch::Changed;
        }
        match child.try_wait() {
            Ok(Some(ExitKind::Failure(_) | ExitKind::Signal(_))) => {
                return Watch::Failed(Reason::Crashed);
            }
            Ok(Some(ExitKind::Success) | None) | Err(_) => {}
        }
        let now = Instant::now();
        if now >= deadline {
            return Watch::Failed(Reason::Timeout);
        }
        std::thread::sleep(SUPERVISE_POLL.min(deadline - now));
    }
}

/// The outcome decided under the lock.
enum Decided {
    /// `v` is current and confirmed.
    Confirmed,
    /// Still pending under this run's token (supervision goes on).
    StillOurs,
    /// Something else decided: another start rolled `v` back.
    Superseded,
}

/// Window 2 (no failure seen): decides on the record loaded under the lock.
fn decide(
    ad: &Adapters,
    inst: &Installation,
    layout: &UserLayout,
    v: &Version,
    token_sha256: &Sha256Digest,
) -> Result<Decided, Kind> {
    let store = store_of(inst, layout);
    let guard = lock_retry(ad, &layout.state_dir(), LOCK_WAIT).map_err(kind_of)?;
    let loaded = store.load(&*ad.fs, &*ad.hasher).map_err(kind_of)?;
    drop(guard);
    let record = loaded.record.ok_or(Kind::NotInstalled)?;
    Ok(classify(&record, v, token_sha256))
}

fn classify(record: &InstallState, v: &Version, token_sha256: &Sha256Digest) -> Decided {
    if ours(record, v, token_sha256) {
        return Decided::StillOurs;
    }
    let confirmed = record.current.as_ref().is_some_and(|c| same(&c.version, v))
        && record.pending.is_none()
        && !record.bad.iter().any(|b| same(b, v));
    if confirmed {
        Decided::Confirmed
    } else {
        Decided::Superseded
    }
}

/// What window 2 did on a failure.
enum RolledBack {
    /// Committed; the previous version's installation, to relaunch.
    Done(Box<Installation>),
    /// The version is no longer pending under this run's token: decided elsewhere.
    NotOurs(Decided),
    /// The previous tree or its config is missing: nothing was changed and the version stays
    /// pending.
    Unavailable,
}

/// Window 2 on a failure: re-checks under the lock, ends the own child, commits the rollback,
/// reconciles `current` and refreshes the integration from the previous version's config.
fn roll_back(
    ad: &Adapters,
    inst: &Installation,
    layout: &UserLayout,
    applied: &Applied,
    child: Option<&mut Box<dyn Child>>,
    events: &Events,
) -> Result<RolledBack, Kind> {
    let v = applied.new.tree_version();
    let store = store_of(inst, layout);
    let guard = lock_retry(ad, &layout.state_dir(), LOCK_WAIT).map_err(kind_of)?;
    let loaded = store.load(&*ad.fs, &*ad.hasher).map_err(kind_of)?;
    let record = loaded.record.clone().ok_or(Kind::NotInstalled)?;
    if !ours(&record, v, &applied.token_sha256) {
        drop(guard);
        return Ok(RolledBack::NotOurs(classify(
            &record,
            v,
            &applied.token_sha256,
        )));
    }
    let previous = match record
        .previous
        .as_ref()
        .map(|p| inst.version_installation(&p.version))
    {
        Some(Ok(previous)) => previous,
        _ => {
            drop(guard);
            return Ok(RolledBack::Unavailable);
        }
    };
    if let Some(child) = child {
        // The own child only; a child that already ended is not signalled.
        let _ = child.terminate(TERMINATE_GRACE);
    }
    let next = lunepack_core::rollback(&record, v).map_err(kind_of)?;
    let committed = store
        .commit(&*ad.fs, &loaded, &next, &*ad.hasher)
        .map_err(kind_of)?;
    reconcile(ad, layout, &committed, events);
    refresh_integration(ad, layout, Some(&applied.new), &previous, events);
    drop(guard);
    Ok(RolledBack::Done(Box::new(previous)))
}

/// After an apply that changed nothing: starts the version that just exited again, detached, with
/// the restart arguments and without the health token (best effort; a failure is a warning).
///
/// Only when the record shows that nothing moved on (F17): no version pending, and the current
/// version is this runtime's own tree's, the version that just exited. Another applier that
/// applied the version first (a second app instance, or `apply-and-restart` called twice) has
/// launched it already, and a rollback elsewhere has relaunched the previous version; starting
/// one more instance would run it twice and, unsupervised, count a start against a pending
/// version. `unmoved` is that judgement on the record window 1 loaded under the lock; when it did
/// not get that far, the record is read here, and when it cannot be read the own tree is started
/// (M5-D18). The entry comes from the version's own config, else from this runtime's own tree.
fn relaunch_current(
    ad: &Adapters,
    inst: &Installation,
    layout: &UserLayout,
    unmoved: Option<bool>,
    restart: &[OsString],
    events: &Events,
) {
    let unmoved = unmoved.or_else(|| {
        store_of(inst, layout)
            .load(&*ad.fs, &*ad.hasher)
            .ok()
            .and_then(|loaded| loaded.record)
            .map(|record| nothing_moved_on(&record, inst.tree_version()))
    });
    if unmoved == Some(false) {
        return;
    }
    let own = inst.version_installation(inst.tree_version()).ok();
    let (entry, version) = match &own {
        Some(own) => (own.entry_path(), own.tree_version()),
        None => (inst.entry_path(), inst.tree_version()),
    };
    let relaunch = SpawnSpec {
        program: entry,
        args: restart.to_vec(),
        env_set: Vec::new(),
        env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
    };
    if ad.process.spawn_detached(&relaunch).is_err() {
        events.emit(&Event::warning(Warning::RelaunchFailed, Some(version)));
    }
}

/// Whether `record` is where the app that exited for this apply left it: nothing pending, and
/// `exited` current.
fn nothing_moved_on(record: &InstallState, exited: &Version) -> bool {
    record.pending.is_none()
        && record
            .current
            .as_ref()
            .is_some_and(|c| same(&c.version, exited))
}

/// The outcome of [`run_apply`] before it is reported.
enum End {
    Confirmed,
    RolledBack,
    Superseded,
    Unavailable,
    Failed(Kind),
}

/// Runs the `apply` mode for `inst` (the runtime's own installation, the outgoing version) and
/// reports the outcome as the final event. Returns the exit kind.
pub fn run_apply(ad: &Adapters, inst: &Installation, args: &ApplyArgs, events: &Events) -> Kind {
    let end = apply_inner(ad, inst, args, events);
    let tree_version = Some(inst.tree_version().clone());
    let version = Some(args.version.clone());
    let (kind, outcome) = match end {
        End::Confirmed => (Kind::Ok, "confirmed"),
        End::RolledBack => (Kind::RolledBack, "rolled_back"),
        End::Superseded => (Kind::RolledBack, "rolled_back_elsewhere"),
        End::Unavailable => (Kind::RollbackUnavailable, ""),
        End::Failed(kind) => (kind, ""),
    };
    if outcome.is_empty() {
        events.emit(&Event::Error {
            command: COMMAND,
            tree_version,
            kind: kind.name(),
            exit_code: kind.code(),
        });
    } else {
        events.emit(&Event::Result {
            command: COMMAND,
            tree_version,
            outcome,
            version,
        });
    }
    kind
}

fn apply_inner(ad: &Adapters, inst: &Installation, args: &ApplyArgs, events: &Events) -> End {
    let Some(layout) = inst.layout().cloned() else {
        return End::Failed(Kind::NotInstalled);
    };
    let v = &args.version;
    let me = ad.process.current().ok();

    events.emit(&Event::phase(Phase::Wait, Some(v)));
    match ad.process.wait_exit(&args.wait, WAIT_MAX) {
        Ok(WaitOutcome::Exited) => {}
        Ok(WaitOutcome::TimedOut) => return End::Failed(Kind::WaitTimeout),
        Err(e) => return End::Failed(kind_of(e)),
    }

    let applied = match commit_apply(ad, inst, &layout, v, events) {
        Ok(applied) => applied,
        Err(Refused { kind, unmoved }) => {
            // The app has exited for this apply; nothing was committed, so it starts again as
            // the version it was, unless the record moved on (F10, F17). The failure stays the
            // exit kind.
            relaunch_current(ad, inst, &layout, unmoved, &args.restart, events);
            return End::Failed(kind);
        }
    };

    // Launch, never through a shell: the new tree's entry from its own config.
    events.emit(&Event::phase(Phase::Launch, Some(v)));
    let spec = SpawnSpec {
        program: applied.new.entry_path(),
        args: args.restart.clone(),
        env_set: vec![(OsString::from(HEALTH_TOKEN_VAR), hex(&applied.token))],
        env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
    };
    let mut child = ad.process.spawn_child(&spec).ok();
    drop(spec);

    let timeout_secs = applied
        .new
        .config()
        .health_timeout_secs
        .clamp(*HEALTH_TIMEOUT_SECS.start(), *HEALTH_TIMEOUT_SECS.end());
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let store = store_of(inst, &layout);
    events.emit(&Event::phase(Phase::Confirm, Some(v)));

    let end = loop {
        let reason = match child.as_mut() {
            None => Reason::SpawnFailed,
            Some(c) => match supervise(ad, &store, v, &applied.token_sha256, &mut **c, deadline) {
                Watch::Failed(reason) => reason,
                Watch::Changed => match decide(ad, inst, &layout, v, &applied.token_sha256) {
                    Ok(Decided::Confirmed) => break End::Confirmed,
                    Ok(Decided::Superseded) => break End::Superseded,
                    Ok(Decided::StillOurs) => continue,
                    Err(kind) => break End::Failed(kind),
                },
            },
        };
        match roll_back(ad, inst, &layout, &applied, child.as_mut(), events) {
            Ok(RolledBack::Done(previous)) => {
                events.emit(&Event::Phase {
                    phase: Phase::Rollback,
                    version: Some(v.clone()),
                    reason: Some(reason),
                });
                let relaunch = SpawnSpec {
                    program: previous.entry_path(),
                    args: args.restart.clone(),
                    env_set: Vec::new(),
                    env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
                };
                if ad.process.spawn_detached(&relaunch).is_err() {
                    events.emit(&Event::warning(
                        Warning::RelaunchFailed,
                        Some(previous.tree_version()),
                    ));
                }
                break End::RolledBack;
            }
            Ok(RolledBack::NotOurs(Decided::Confirmed)) => break End::Confirmed,
            Ok(RolledBack::NotOurs(_)) => break End::Superseded,
            Ok(RolledBack::Unavailable) => {
                events.emit(&Event::warning(Warning::RollbackUnavailable, Some(v)));
                break End::Unavailable;
            }
            Err(kind) => break End::Failed(kind),
        }
    };
    if matches!(end, End::Superseded) {
        events.emit(&Event::warning(Warning::Superseded, Some(v)));
    }
    // GC once the outcome is decided and any relaunch has happened.
    if !matches!(end, End::Failed(_)) {
        gc(ad, inst, me, events);
    }
    end
}
