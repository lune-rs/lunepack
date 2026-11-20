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
//! An apply that fails after the wait (window 1 refuses: no usable config, nothing staged, the
//! version that exited still pending its health check, a held lock, a disk or state error) changes
//! nothing and starts the version that exited again, detached and without the token, so the app
//! comes back; the exit code is the failure. It does not when the record moved on (another version
//! current or pending, or the version to apply marked bad): another applier or a rollback elsewhere
//! has started the app already.
//!
//! The process waited for is only waited for; the only process ever signalled is the own child.
//! Every per-version fact (entry, health timeout, install metadata) comes from that version's own
//! config at `R/versions/<v>/lunepack-update.json`, never from this runtime's tree (M5-D17). The
//! token is in the child's environment only: never in argv, an event, the log or an exit path.
//!
//! With a UI (M6), the update window follows the events and never holds the operation up: the
//! outcome is decided, any relaunch done and old trees collected before the window hears of it.
//! On success the window closes; after a rollback (the previous version already started) or a
//! failure it shows a prompt the user dismisses, and a UI lost there changes nothing.

use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use lunepack::{
    Child, ChildStdio, ExitKind, FileKind, HEALTH_TOKEN_VAR, Installation, IntegrationRequest,
    LockGuard, Phase, Sha256Digest, SpawnSpec, UserLayout, Version, WaitOutcome,
};
use lunepack_core::state::{InstallState, Scope, UserScope};
use lunepack_core::{LayoutError, Projection, RelPath};

use lunepack_core::ui::{ChoiceValue, Outcome, PromptKind, StepItem};

use crate::events::{Event, Events, Reason, Warning};
use crate::gc::gc;
use crate::modes::{Adapters, ApplyArgs, Kind};
use crate::ui_host::UiHost;

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

/// Whether the install keeps its live tree in a bundle outside its root (macOS, M8-D1).
fn is_bundle(layout: &UserLayout) -> bool {
    layout.scheme().projection == Projection::Bundle
}

/// The live bundle `B` of a bundle install, `None` for the other layouts.
fn live_bundle(ad: &Adapters, layout: &UserLayout) -> Option<std::path::PathBuf> {
    if is_bundle(layout) {
        layout.bundle_path(&*ad.fs).ok().flatten()
    } else {
        None
    }
}

/// The entry that starts `version` once it is current (M8-D1): under the bundle layout the live
/// bundle's, because the version's staging tree is moved into the bundle by the reconcile that
/// follows the commit; elsewhere the version's own tree's.
fn live_entry(
    ad: &Adapters,
    layout: &UserLayout,
    version: &Installation,
    tree_entry: std::path::PathBuf,
    entry: &RelPath,
) -> std::path::PathBuf {
    match live_bundle(ad, layout) {
        Some(bundle) => entry.components().fold(bundle, |dir, part| dir.join(part)),
        None => {
            let _ = version;
            tree_entry
        }
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
        // Under the bundle layout the integration is rooted at the live bundle (M8-D12).
        install_root: live_bundle(ad, layout).unwrap_or_else(|| layout.root().to_path_buf()),
        version: to.tree_version().clone(),
        meta: to.meta().clone(),
        previous: from.map(|f| f.meta().clone()),
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

/// Projects `record` onto the disk (`current`, or the bundle swap). A failure is a warning, and
/// is returned so the bundle layout, where the new version cannot start without it, can stop.
fn reconcile(
    ad: &Adapters,
    layout: &UserLayout,
    record: &InstallState,
    events: &Events,
) -> Result<(), LayoutError> {
    let result = layout.reconcile(&*ad.fs, record);
    if result.is_err() {
        events.emit(&Event::warning(Warning::ReconcileFailed, None));
    }
    result
}

/// The kind of a failed reconcile (a refused place is exit 28, anything else a failed disk).
fn layout_kind(e: LayoutError) -> Kind {
    Kind::of(&lunepack_core::Error::Layout(e).into())
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
    let unmoved = nothing_moved_on(&record, inst.tree_version(), v);
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
    // macOS (M8-D4): the bundle's place is judged before anything is committed, so a refused
    // place is exit 28 with the install as it was.
    if is_bundle(layout) {
        let bundle = layout
            .bundle_path(&*ad.fs)
            .map_err(|e| refused(layout_kind(e)))?
            .ok_or_else(|| refused(Kind::NotInstalled))?;
        lunepack_core::check_place(&*ad.fs, layout, &bundle)
            .map_err(|e| refused(layout_kind(e)))?;
    }

    let mut token = [0u8; 32];
    ad.rng.fill(&mut token).map_err(|e| refused(kind_of(e)))?;
    let token_sha256 = ad.hasher.sha256(&token);
    let next = lunepack_core::apply(&record, v, token_sha256).map_err(|e| refused(kind_of(e)))?;
    let committed = store
        .commit(&*ad.fs, &loaded, &next, &*ad.hasher)
        .map_err(|e| refused(kind_of(e)))?;
    // Under the bundle layout the new version starts from the bundle, so a reconcile that did not
    // put it there stops the apply: the record names it, and the next start or apply finishes
    // the swap (never undone). The app that exited is started again by the caller.
    if let Err(e) = reconcile(ad, layout, &committed, events)
        && is_bundle(layout)
    {
        return Err(refused(layout_kind(e)));
    }
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
/// handed off to another process of the same version, which may still confirm. Nor is an exit
/// whose status is unknown (a background launch, M8-D13): the deadline decides, so an app started
/// that way that crashes before it confirms is rolled back at the deadline, not at once.
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
            Ok(Some(ExitKind::Success | ExitKind::Unknown) | None) | Err(_) => {}
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
    if let Err(e) = reconcile(ad, layout, &committed, events)
        && is_bundle(layout)
    {
        // The rollback is committed but the bundle still holds the failed version: nothing is
        // relaunched from it, and the next start or apply finishes the swap.
        drop(guard);
        return Err(layout_kind(e));
    }
    refresh_integration(ad, layout, Some(&applied.new), &previous, events);
    drop(guard);
    Ok(RolledBack::Done(Box::new(previous)))
}

/// After an apply that changed nothing: starts the version that just exited again, detached, with
/// the restart arguments and without the health token (best effort; a failure is a warning).
///
/// Only when the record shows that nothing moved on (F17, F19, F21): the current version is this
/// runtime's own tree's, the version that just exited, no other version is pending, and
/// `applying` (the version this applier was started for) is not bad. Another applier that applied
/// the version first (a second app instance, or `apply-and-restart` called twice) has launched it
/// already, or, when it failed, rolled it back and started the version that exited again; and a
/// rollback elsewhere has relaunched the previous version; starting one more instance would run
/// it twice and, unsupervised, count a start against a pending version. The version that exited
/// may itself still be pending (it asked for the update before it confirmed): it is started again,
/// and that start counts as an unconfirmed one. `unmoved` is that judgement on the record window 1
/// loaded under the lock; when it did not get that far, the record is read here, and when it
/// cannot be read the own tree is started (M5-D18). The entry comes from the version's own
/// config, else from this runtime's own tree.
fn relaunch_current(
    ad: &Adapters,
    inst: &Installation,
    layout: &UserLayout,
    applying: &Version,
    unmoved: Option<bool>,
    args: &ApplyArgs,
    events: &Events,
) {
    let unmoved = unmoved.or_else(|| {
        store_of(inst, layout)
            .load(&*ad.fs, &*ad.hasher)
            .ok()
            .and_then(|loaded| loaded.record)
            .map(|record| nothing_moved_on(&record, inst.tree_version(), applying))
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
        args: args.restart.clone(),
        env_set: Vec::new(),
        env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
        stdio: ChildStdio::Null,
    };
    if start_unsupervised(ad, &relaunch, args.background).is_err() {
        events.emit(&Event::warning(Warning::RelaunchFailed, Some(version)));
    }
}

/// Starts a version nobody supervises (a relaunch, the start after a rollback): detached, or with
/// `--background` through the background start (M8-D13), whose handle is dropped at once. Dropping
/// it never ends the app: it only stops watching it.
fn start_unsupervised(ad: &Adapters, spec: &SpawnSpec, background: bool) -> Result<(), ()> {
    if background {
        ad.process
            .spawn_app_background(spec)
            .map(drop)
            .map_err(drop)
    } else {
        ad.process.spawn_detached(spec).map_err(drop)
    }
}

/// Whether `record` is where the app that exited for this apply left it: `exited` current, no
/// other version pending, and `applying` (the version this applier was started for) not bad.
/// `exited` may itself be pending (F19): it was started for its health check and exited before it
/// confirmed, so the core refused the apply; that is not a move. Another applier's commit makes
/// its version current, and a rollback elsewhere of `exited` makes the previous version current:
/// both are moves. So is `applying` bad (F21): `apply_and_restart_for` does not schedule a bad
/// staged version and the core does not apply one, so it is bad here only when another run
/// applied it after this applier was scheduled and rolled it back, and both rollback paths (the
/// applier's and the app's own startup) start the previous version after their commit. `bad` is
/// a set by precedence, as the core keeps it and the scheduling check reads it, so membership is
/// by precedence here too.
fn nothing_moved_on(record: &InstallState, exited: &Version, applying: &Version) -> bool {
    record
        .current
        .as_ref()
        .is_some_and(|c| same(&c.version, exited))
        && record
            .pending
            .as_ref()
            .is_none_or(|p| same(&p.version, exited))
        && !record.bad.contains(applying)
}

/// The outcome of [`run_apply`] before it is reported.
enum End {
    Confirmed,
    /// Rolled back to this version, which was started again.
    RolledBack(Version),
    Superseded,
    Unavailable,
    Failed(Kind),
}

/// Runs the `apply` mode for `inst` (the runtime's own installation, the outgoing version) and
/// reports the outcome as the final event, then in `ui`. Returns the exit kind.
pub fn run_apply(
    ad: &Adapters,
    inst: &Installation,
    args: &ApplyArgs,
    events: &Events,
    ui: &UiHost,
) -> Kind {
    let end = apply_inner(ad, inst, args, events);
    let kind = report(inst, args, &end, events);
    // The window hears of the outcome only now: the operation never waits for it.
    match &end {
        End::Confirmed => {
            ui.steps(&[StepItem::Confirm]);
            ui.outcome(Outcome::Updated);
        }
        End::RolledBack(previous) => {
            ui.steps(&[StepItem::Rollback]);
            ui.outcome(Outcome::RolledBack {
                from: args.version.to_string(),
                to: previous.to_string(),
            });
            let _: ChoiceValue = ui.prompt(PromptKind::RolledBack, events, &mut |_| {});
        }
        End::Superseded | End::Unavailable | End::Failed(_) => {
            ui.outcome(Outcome::Failed {
                code: u32::from(kind.code()),
            });
            let _: ChoiceValue = ui.prompt(PromptKind::Failed, events, &mut |_| {});
        }
    }
    kind
}

/// Emits the final event of `end`; its exit kind.
fn report(inst: &Installation, args: &ApplyArgs, end: &End, events: &Events) -> Kind {
    let tree_version = Some(inst.tree_version().clone());
    let version = Some(args.version.clone());
    let (kind, outcome) = match end {
        End::Confirmed => (Kind::Ok, "confirmed"),
        End::RolledBack(_) => (Kind::RolledBack, "rolled_back"),
        End::Superseded => (Kind::RolledBack, "rolled_back_elsewhere"),
        End::Unavailable => (Kind::RollbackUnavailable, ""),
        End::Failed(kind) => (*kind, ""),
    };
    if outcome.is_empty() {
        events.emit(&Event::Error {
            command: COMMAND,
            tree_version,
            kind: kind.name(),
            exit_code: kind.code(),
            reason: kind.reason(),
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

    // A bundle the user moved since this app started is followed under the lock before anything
    // is committed (M8-D17), so the new version is placed in the bundle the user kept and not at
    // the path it was moved from. A move that cannot be followed is a stray copy: nothing is
    // applied through the old pointer and the app that exited comes back where it is.
    let followed = if inst.moved() {
        match lunepack::follow_move(inst) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Kind::NotInstalled),
            Err(e) => Err(Kind::of(&e)),
        }
    } else {
        Ok(())
    };
    if let Err(kind) = followed {
        relaunch_current(ad, inst, &layout, v, None, args, events);
        return End::Failed(kind);
    }

    let applied = match commit_apply(ad, inst, &layout, v, events) {
        Ok(applied) => applied,
        Err(Refused { kind, unmoved }) => {
            // The app has exited for this apply; nothing was committed, so it starts again as
            // the version it was, unless the record moved on (F10, F17, F19, F21). The failure
            // stays the exit kind.
            relaunch_current(ad, inst, &layout, v, unmoved, args, events);
            return End::Failed(kind);
        }
    };

    // Launch, never through a shell: the new tree's entry from its own config.
    events.emit(&Event::phase(Phase::Launch, Some(v)));
    let spec = SpawnSpec {
        program: live_entry(
            ad,
            &layout,
            &applied.new,
            applied.new.entry_path(),
            &applied.new.meta().entry,
        ),
        args: args.restart.clone(),
        env_set: vec![(OsString::from(HEALTH_TOKEN_VAR), hex(&applied.token))],
        env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
        stdio: ChildStdio::Null,
    };
    // `--background` (M8-D13): started without coming to the front; its exit status is then not
    // observable, and supervision leaves that case to the deadline.
    let mut child = if args.background {
        ad.process.spawn_app_background(&spec).ok()
    } else {
        ad.process.spawn_child(&spec).ok()
    };
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
                    program: live_entry(
                        ad,
                        &layout,
                        &previous,
                        previous.entry_path(),
                        &previous.meta().entry,
                    ),
                    args: args.restart.clone(),
                    env_set: Vec::new(),
                    env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
                    stdio: ChildStdio::Null,
                };
                if start_unsupervised(ad, &relaunch, args.background).is_err() {
                    events.emit(&Event::warning(
                        Warning::RelaunchFailed,
                        Some(previous.tree_version()),
                    ));
                }
                break End::RolledBack(previous.tree_version().clone());
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

#[cfg(test)]
mod tests {
    use lunepack::{Sha256Digest, Target, Version};
    use lunepack_core::TokenCheck;
    use lunepack_core::state::{InstallState, PendingRef, Scope, StagedRef};

    use super::nothing_moved_on;

    const TARGET: Target = Target::LinuxX86_64;
    const INSTALL_ID: [u8; 16] = [3; 16];

    fn v(text: &str) -> Version {
        Version::parse(text).expect("version")
    }

    fn empty() -> InstallState {
        let app = lunepack_testkit::sample_update_config().app_id;
        InstallState::new(1, app, Scope::User, INSTALL_ID, TARGET)
    }

    /// `record` with `staged` staged (bound).
    fn staging(record: &InstallState, staged: &str) -> InstallState {
        let digest = Sha256Digest::from_bytes([1; 32]);
        record.set_staged(Some((StagedRef::new(v(staged), TARGET, digest), 20)))
    }

    /// `current` installed and confirmed, `staged` staged.
    fn installed(current: &str, staged: &str) -> InstallState {
        staging(&empty().install(v(current), 10, TARGET, INSTALL_ID), staged)
    }

    /// `to` applied over `from` by the core's transition: pending its health check.
    fn applied(from: &str, to: &str) -> InstallState {
        let token = Sha256Digest::from_bytes([7; 32]);
        lunepack_core::apply(&installed(from, to), &v(to), token).expect("apply")
    }

    /// `to` applied over `from` and rolled back by the core's transitions: `from` current again,
    /// nothing pending, `to` bad.
    fn rolled_back(from: &str, to: &str) -> InstallState {
        lunepack_core::rollback(&applied(from, to), &v(to)).expect("rollback")
    }

    /// Every record shape the applier of 1.1.0 from 1.0.0's tree can find when its commit window
    /// refuses. A move is another version current or pending (F17, F19), or 1.1.0 bad (F21).
    #[test]
    fn another_version_current_or_pending_or_the_version_to_apply_bad_is_a_move() {
        let exited = v("1.0.0");
        let applying = v("1.1.0");
        // Where the app left it (a refusal commits nothing): 1.0.0 current, confirmed.
        assert!(nothing_moved_on(
            &installed("1.0.0", "1.1.0"),
            &exited,
            &applying
        ));
        // F19: 1.0.0 itself still pending (it asked for the update before it confirmed, so the
        // core refused), before and after an unconfirmed start was counted.
        let pending_self = staging(&applied("0.9.0", "1.0.0"), "1.1.0");
        assert!(nothing_moved_on(&pending_self, &exited, &applying));
        let (counted, _) = lunepack_core::count_attempt(&pending_self, &exited).expect("count");
        assert!(nothing_moved_on(&counted, &exited, &applying));
        // F17: another applier applied 1.1.0 first, pending and then confirmed.
        let other = applied("1.0.0", "1.1.0");
        assert!(!nothing_moved_on(&other, &exited, &applying));
        let (confirmed, _) =
            lunepack_core::confirm(&other, &v("1.1.0"), TokenCheck::Absent).expect("confirm");
        assert!(!nothing_moved_on(&confirmed, &exited, &applying));
        // F17: 1.0.0 was rolled back elsewhere; 0.9.0 is current again.
        let rolled_back_self = lunepack_core::rollback(&pending_self, &exited).expect("rollback");
        assert!(!nothing_moved_on(&rolled_back_self, &exited, &applying));
        // F21: another applier applied 1.1.0, it failed, and its rollback started 1.0.0 again:
        // 1.0.0 current and nothing pending, as the app left it, but 1.1.0 is bad.
        let failed_elsewhere = rolled_back("1.0.0", "1.1.0");
        assert!(failed_elsewhere.pending.is_none() && failed_elsewhere.staged.is_none());
        assert!(!nothing_moved_on(&failed_elsewhere, &exited, &applying));
        // `bad` is a set by precedence (as the core keeps it): another build of 1.1.0 rolled back
        // is a move too.
        let other_build = rolled_back("1.0.0", "1.1.0+b");
        assert!(!nothing_moved_on(&other_build, &exited, &applying));
        // Not a move: an earlier update that was rolled back (another version bad), with 1.1.0
        // staged since; and the same beside 1.0.0 itself still pending (F19).
        let earlier_bad = staging(&rolled_back("1.0.0", "1.0.5"), "1.1.0");
        assert!(nothing_moved_on(&earlier_bad, &exited, &applying));
        let token = Sha256Digest::from_bytes([7; 32]);
        let pending_after_bad = lunepack_core::apply(
            &staging(&rolled_back("0.9.0", "0.9.5"), "1.0.0"),
            &exited,
            token,
        )
        .expect("apply");
        let pending_after_bad = staging(&pending_after_bad, "1.1.0");
        assert!(nothing_moved_on(&pending_after_bad, &exited, &applying));
        // No current version.
        assert!(!nothing_moved_on(
            &staging(&empty(), "1.1.0"),
            &exited,
            &applying
        ));
        // A shape no core transition writes (pending is always the current version): another
        // version pending beside 1.0.0 current.
        let mut odd = installed("1.0.0", "1.1.0");
        odd.pending = Some(PendingRef {
            version: v("1.1.0"),
            attempts: 0,
        });
        assert!(!nothing_moved_on(&odd, &exited, &applying));
        // Versions match by text: the same precedence with other build metadata is another tree.
        assert!(!nothing_moved_on(
            &installed("1.0.0+b", "1.1.0"),
            &exited,
            &applying
        ));
    }

    // ---- the bundle layout (macOS, M8) ---------------------------------------------------------

    use std::io::Write as _;
    use std::path::PathBuf;
    use std::sync::Arc;

    use lunepack::{Fs, Installation, Platform};
    use lunepack_core::state::UserScope;
    use lunepack_core::{LayoutScheme, UserLayout, set_bundle_pointer, write_bundle_identity};
    use lunepack_testkit::{
        FakeCodec, FakeHasher, FakeIntegration, FakeProcess, FakeRng, FakeVerifier, MemFs,
        MemPlace, abs_path, sample_update_config,
    };

    use super::{commit_apply, live_entry, roll_back};
    use crate::events::Events;
    use crate::modes::{Adapters, Kind, Place};

    struct Mac {
        fs: MemFs,
        process: FakeProcess,
        integration: FakeIntegration,
        ad: Adapters,
    }

    fn home() -> PathBuf {
        abs_path("/Users/u")
    }

    fn data_home() -> PathBuf {
        home().join("Library").join("Application Support")
    }

    fn bundle() -> PathBuf {
        home().join("Applications").join("Hello.app")
    }

    fn app_layout() -> UserLayout {
        UserLayout::from_root(
            data_home().join(sample_update_config().app_id.as_str()),
            LayoutScheme::MACOS,
        )
    }

    fn mac_config(v: &str) -> lunepack::UpdateConfig {
        let mut c = sample_update_config();
        c.version = Version::parse(v).expect("version");
        c.target = Target::MacosAarch64;
        c.install.entry = lunepack::RelPath::parse("Contents/MacOS/hello").expect("entry");
        c.install.autostart = false;
        c
    }

    fn put(fs: &MemFs, path: PathBuf, bytes: &[u8]) {
        fs.create_dir_all(path.parent().expect("parent"))
            .expect("dirs");
        let mut f = fs.create_new(&path).expect("create");
        f.write_all(bytes).expect("write");
        f.sync().expect("sync");
    }

    fn put_bundle(fs: &MemFs, tree: &std::path::Path, v: &str) {
        put(
            fs,
            tree.join("Contents/Resources/lunepack-update.json"),
            &mac_config(v).to_bytes().expect("bytes"),
        );
        put(fs, tree.join("Contents/MacOS/hello"), v.as_bytes());
    }

    fn version_in(fs: &MemFs, tree: &std::path::Path) -> Option<String> {
        let bytes = fs
            .read_capped(
                &tree.join("Contents/Resources/lunepack-update.json"),
                1 << 16,
            )
            .ok()?;
        Some(
            lunepack::UpdateConfig::parse(&bytes)
                .ok()?
                .version
                .to_string(),
        )
    }

    /// 1.0.0 live in the bundle, 1.1.0 staged in `versions`.
    fn mac() -> Mac {
        let fs = MemFs::new();
        let process = FakeProcess::new("/unused");
        let integration = FakeIntegration::new();
        let layout = app_layout();
        for dir in [
            layout.versions_dir(),
            layout.state_dir(),
            home().join("Applications"),
        ] {
            fs.create_dir_all(&dir).expect("dirs");
        }
        put_bundle(&fs, &bundle(), "1.0.0");
        put_bundle(&fs, &layout.version_dir(&v("1.1.0")), "1.1.0");
        set_bundle_pointer(&fs, &layout, &bundle()).expect("pointer");
        write_bundle_identity(&fs, &layout, &bundle()).expect("identity");
        let app = sample_update_config().app_id;
        let record = InstallState::new(
            1,
            app.clone(),
            Scope::User,
            INSTALL_ID,
            Target::MacosAarch64,
        )
        .install(v("1.0.0"), 10, Target::MacosAarch64, INSTALL_ID)
        .set_staged(Some((
            lunepack_core::state::StagedRef::new(
                v("1.1.0"),
                Target::MacosAarch64,
                Sha256Digest::from_bytes([1; 32]),
            ),
            20,
        )));
        let store = UserScope {
            dir: layout.state_dir(),
            app_id: app,
        };
        let loaded = store.load(&fs, &FakeHasher).expect("load");
        store
            .commit(&fs, &loaded, &record, &FakeHasher)
            .expect("commit");
        let fs_arc: Arc<MemFs> = Arc::new(fs.clone());
        let platform = Platform::native()
            .with_fs(Arc::clone(&fs_arc) as Arc<dyn Fs>)
            .with_hasher(Arc::new(FakeHasher))
            .with_verifier(Arc::new(FakeVerifier))
            .with_process(Arc::new(process.clone()))
            .with_integration(Arc::new(integration.clone()))
            .with_rng(Arc::new(FakeRng::new(4)))
            .with_health_token(None)
            .with_data_home(data_home())
            .with_home(home())
            .with_layout_scheme(LayoutScheme::MACOS);
        let ad = Adapters {
            fs: fs_arc,
            hasher: Arc::new(FakeHasher),
            verifier: Arc::new(FakeVerifier),
            codec: Arc::new(FakeCodec::new()),
            process: Arc::new(process.clone()),
            integration: Arc::new(integration.clone()),
            rng: Arc::new(FakeRng::new(4)),
            platform,
        };
        Mac {
            fs,
            process,
            integration,
            ad,
        }
    }

    impl Mac {
        fn open(&self) -> Installation {
            Installation::from_exe_with(
                &bundle().join("Contents/MacOS/hello"),
                self.ad.platform.clone(),
            )
            .expect("installation")
        }
    }

    #[test]
    fn a_bundle_apply_commits_swaps_and_launches_from_the_live_bundle() {
        let mac = mac();
        let inst = mac.open();
        let layout = inst.layout().cloned().expect("layout");
        let events = Events::new(None, None);
        let applied = commit_apply(&mac.ad, &inst, &layout, &v("1.1.0"), &events)
            .map_err(|r| r.kind)
            .expect("apply");
        // The record names 1.1.0; the bundle holds it and 1.0.0 is parked.
        assert_eq!(version_in(&mac.fs, &bundle()).as_deref(), Some("1.1.0"));
        assert_eq!(
            version_in(&mac.fs, &layout.version_dir(&v("1.0.0"))).as_deref(),
            Some("1.0.0")
        );
        assert!(
            mac.fs
                .symlink_metadata(&layout.version_dir(&v("1.1.0")))
                .expect("lstat")
                .is_none()
        );
        // The entry that starts it is the bundle's, not the staging tree's (which is gone).
        let entry = live_entry(
            &mac.ad,
            &layout,
            &applied.new,
            applied.new.entry_path(),
            &applied.new.meta().entry,
        );
        assert_eq!(entry, bundle().join("Contents/MacOS/hello"));
        assert!(applied.new.entry_path().starts_with(layout.versions_dir()));
        // The desktop integration is rooted at the bundle.
        let call = mac.integration.calls().pop().expect("integration call");
        assert_eq!(call.install_root, bundle());
        assert!(mac.process.spawns().is_empty());
    }

    #[test]
    fn a_bundle_apply_in_a_place_lunepack_does_not_update_commits_nothing() {
        for (what, expected, edit) in [
            (
                "another volume",
                Place::OtherVolume,
                Box::new(|m: &mut MemPlace| m.device = 9) as Box<dyn Fn(&mut MemPlace)>,
            ),
            (
                "not writable",
                Place::NotWritable,
                Box::new(|m: &mut MemPlace| m.writable = false),
            ),
            (
                "not owned",
                Place::NotOwned,
                Box::new(|m: &mut MemPlace| m.owned_by_caller = false),
            ),
        ] {
            let mac = mac();
            let inst = mac.open();
            let layout = inst.layout().cloned().expect("layout");
            let before = mac_record(&mac, &layout);
            let mut facts = MemPlace::default();
            edit(&mut facts);
            // The Applications folder (and so the bundle in it, for `not owned`) is the place.
            mac.fs.set_place(&home().join("Applications"), facts);
            let events = Events::new(None, None);
            let got = commit_apply(&mac.ad, &inst, &layout, &v("1.1.0"), &events);
            assert_eq!(
                got.err().map(|r| r.kind),
                Some(Kind::UnsupportedLocation(expected)),
                "{what}"
            );
            assert_eq!(mac_record(&mac, &layout), before, "{what}: committed");
            assert_eq!(
                version_in(&mac.fs, &bundle()).as_deref(),
                Some("1.0.0"),
                "{what}"
            );
            assert_eq!(
                version_in(&mac.fs, &layout.version_dir(&v("1.1.0"))).as_deref(),
                Some("1.1.0"),
                "{what}: moved"
            );
        }
    }

    fn mac_record(mac: &Mac, layout: &UserLayout) -> InstallState {
        UserScope {
            dir: layout.state_dir(),
            app_id: sample_update_config().app_id,
        }
        .load(&mac.fs, &FakeHasher)
        .expect("load")
        .record
        .expect("record")
    }

    #[test]
    fn a_bundle_rollback_puts_the_previous_version_back_in_the_bundle() {
        let mac = mac();
        let inst = mac.open();
        let layout = inst.layout().cloned().expect("layout");
        let events = Events::new(None, None);
        let applied = commit_apply(&mac.ad, &inst, &layout, &v("1.1.0"), &events)
            .map_err(|r| r.kind)
            .expect("apply");
        let done = roll_back(&mac.ad, &inst, &layout, &applied, None, &events).expect("rollback");
        let super::RolledBack::Done(previous) = done else {
            panic!("the rollback was not done");
        };
        assert_eq!(previous.tree_version(), &v("1.0.0"));
        assert_eq!(version_in(&mac.fs, &bundle()).as_deref(), Some("1.0.0"));
        assert_eq!(
            version_in(&mac.fs, &layout.version_dir(&v("1.1.0"))).as_deref(),
            Some("1.1.0"),
            "the failed version is parked"
        );
        // Its entry, once the swap is done, is the bundle's.
        let entry = live_entry(
            &mac.ad,
            &layout,
            &previous,
            previous.entry_path(),
            &previous.meta().entry,
        );
        assert_eq!(entry, bundle().join("Contents/MacOS/hello"));
        let rec = mac_record(&mac, &layout);
        assert_eq!(rec.current.expect("current").version, v("1.0.0"));
        assert!(rec.bad.contains(&v("1.1.0")));
    }

    /// GC under the bundle layout touches `R/versions` only: the live bundle, the slots and the
    /// pointer stay, an unreferenced version tree goes, and one a process still runs from stays
    /// (an old instance that the swap moved into `versions/<O>`, probe 7 of the plan).
    #[test]
    fn gc_collects_unreferenced_trees_in_versions_and_keeps_one_in_use() {
        for in_use in [true, false] {
            let mac = mac();
            let inst = mac.open();
            let layout = inst.layout().cloned().expect("layout");
            let old = layout.version_dir(&v("0.8.0"));
            put_bundle(&mac.fs, &old, "0.8.0");
            // A slot holding a tree and the pointer, which GC must never touch.
            put_bundle(&mac.fs, &layout.swap_slot(), "0.7.0");
            mac.process.script_in_use(in_use);
            let events = Events::new(None, None);
            let report = crate::gc::gc(&mac.ad, &inst, None, &events);
            let still = version_in(&mac.fs, &old).is_some();
            assert_eq!(still, in_use, "in use = {in_use}");
            assert_eq!(report.removed.is_empty(), in_use);
            assert_eq!(report.kept.contains(&v("0.8.0")), in_use);
            assert_eq!(version_in(&mac.fs, &bundle()).as_deref(), Some("1.0.0"));
            assert!(
                version_in(&mac.fs, &layout.swap_slot()).is_some(),
                "the slot"
            );
            assert!(
                version_in(&mac.fs, &layout.version_dir(&v("1.1.0"))).is_some(),
                "the staged tree is kept"
            );
            assert!(layout.bundle_path(&mac.fs).expect("pointer").is_some());
            // Every tree it asked about is a direct child of `versions`.
            for (tree, _) in mac.process.in_use_calls() {
                assert_eq!(tree.parent(), Some(layout.versions_dir().as_path()));
            }
        }
    }

    // ---- the background start (M8-D13) ---------------------------------------------------------

    use std::ffi::OsString;
    use std::time::{Duration, Instant};

    use lunepack::HEALTH_TOKEN_VAR;
    use lunepack_core::{ExitKind, Process, ProcessId};
    use lunepack_testkit::ChildScript;

    use super::{Decided, Watch, apply_inner, decide, store_of, supervise};
    use crate::events::Reason;
    use crate::modes::ApplyArgs;

    /// The apply of `version` with `--background` or not; the wait target has exited already.
    fn apply_args(version: &str, background: bool) -> ApplyArgs {
        ApplyArgs {
            wait: ProcessId {
                pid: 999,
                start_ticks: 9,
            },
            version: v(version),
            restart: vec![OsString::from("--after")],
            no_ui: true,
            background,
        }
    }

    /// Which start each spawn of the fake was: `bg`, `child` or `detached`.
    fn starts(mac: &Mac) -> Vec<&'static str> {
        mac.process
            .spawns()
            .iter()
            .map(|s| match (s.detached, s.background) {
                (true, _) => "detached",
                (false, true) => "bg",
                (false, false) => "child",
            })
            .collect()
    }

    #[test]
    fn the_new_version_and_the_rollback_start_use_the_background_start_when_asked() {
        for (background, want) in [(true, ["bg", "bg"]), (false, ["child", "detached"])] {
            let mac = mac();
            let inst = mac.open();
            // The new version crashes at once: rolled back, the previous version started again.
            mac.process
                .script_child(ChildScript::exits(0, ExitKind::Failure(1)));
            let events = Events::new(None, None);
            let end = apply_inner(&mac.ad, &inst, &apply_args("1.1.0", background), &events);
            assert!(
                matches!(&end, super::End::RolledBack(p) if p == &v("1.0.0")),
                "background {background}"
            );
            assert_eq!(starts(&mac), want, "background {background}");
            let spawns = mac.process.spawns();
            // Both from the live bundle; the token only in the new version's environment, and
            // never as an argument.
            for s in &spawns {
                assert_eq!(s.program, bundle().join("Contents/MacOS/hello"));
                assert_eq!(s.args, vec![OsString::from("--after")]);
            }
            assert!(spawns[0].env_set.iter().any(|(k, _)| k == HEALTH_TOKEN_VAR));
            assert!(spawns[1].env_set.is_empty());
        }
    }

    #[test]
    fn the_relaunch_after_a_refused_apply_uses_the_background_start_when_asked() {
        for (background, want) in [(true, "bg"), (false, "detached")] {
            let mac = mac();
            let inst = mac.open();
            let events = Events::new(None, None);
            // 1.2.0 is not staged: nothing is committed and 1.0.0 starts again.
            let end = apply_inner(&mac.ad, &inst, &apply_args("1.2.0", background), &events);
            assert!(matches!(end, super::End::Failed(Kind::NothingStaged)));
            assert_eq!(starts(&mac), [want], "background {background}");
            let spawn = &mac.process.spawns()[0];
            assert!(spawn.env_set.is_empty());
            assert_eq!(spawn.env_remove, vec![OsString::from(HEALTH_TOKEN_VAR)]);
        }
    }

    #[test]
    fn an_unknown_exit_is_left_to_the_deadline_and_to_the_record() {
        let mac = mac();
        let inst = mac.open();
        let layout = inst.layout().cloned().expect("layout");
        let events = Events::new(None, None);
        let applied = commit_apply(&mac.ad, &inst, &layout, &v("1.1.0"), &events)
            .map_err(|r| r.kind)
            .expect("apply");
        let store = store_of(&inst, &layout);
        let spec = lunepack_core::SpawnSpec::new(bundle().join("Contents/MacOS/hello"));

        // Gone before it confirmed, status unknown: not a crash; the deadline decides.
        mac.process
            .script_child(ChildScript::exits(0, ExitKind::Unknown));
        let mut child = mac.process.spawn_app_background(&spec).expect("start");
        let started = Instant::now();
        let watch = supervise(
            &mac.ad,
            &store,
            &v("1.1.0"),
            &applied.token_sha256,
            child.as_mut(),
            started + Duration::from_millis(400),
        );
        assert!(matches!(watch, Watch::Failed(Reason::Timeout)));
        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "not at once"
        );

        // Gone after it confirmed: the record decides, a success.
        let rec = mac_record(&mac, &layout);
        let (confirmed, _) = lunepack_core::confirm(
            &rec,
            &v("1.1.0"),
            lunepack_core::TokenCheck::Presented(applied.token_sha256),
        )
        .expect("confirm");
        let loaded = store.load(&mac.fs, &FakeHasher).expect("load");
        store
            .commit(&mac.fs, &loaded, &confirmed, &FakeHasher)
            .expect("commit");
        mac.process
            .script_child(ChildScript::exits(0, ExitKind::Unknown));
        let mut child = mac.process.spawn_app_background(&spec).expect("start");
        let watch = supervise(
            &mac.ad,
            &store,
            &v("1.1.0"),
            &applied.token_sha256,
            child.as_mut(),
            Instant::now() + Duration::from_secs(30),
        );
        assert!(matches!(watch, Watch::Changed));
        assert!(matches!(
            decide(&mac.ad, &inst, &layout, &v("1.1.0"), &applied.token_sha256),
            Ok(Decided::Confirmed)
        ));
    }
}
