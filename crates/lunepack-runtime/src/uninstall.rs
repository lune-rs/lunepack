//! The `uninstall` mode (M5-D10): removes a per-user install, run from one of its own trees.
//!
//! The install root `R` comes from this runtime's own resolved path (`R/versions/<v>/…`), never
//! from an argument, the state or an environment variable beyond the two the layout is defined
//! by (`HOME`, `XDG_DATA_HOME`). Before anything is removed, `R` must be:
//!
//! - exactly `<data home>/<app id>`, the derivation of M5-D2 in this environment;
//! - a real directory (not a symlink) whose canonical path is itself;
//! - holding, under its lock, an install record of this app id.
//!
//! Any mismatch refuses with nothing deleted. Once `R` is the derived one, what an earlier
//! uninstall cut off before its end left beside it (tombstones of this app id, F18) is removed.
//! With the lock held, a process other than this one that runs from `R` (its executable, working
//! directory, mapped or open files) refuses. Then the desktop integration is removed (only what
//! carries lunepack's marker, or a command link into `R/current/`; anything else is kept and
//! reported), `R` is renamed to a fresh tombstone beside it, `.<app id>.removing-<random>`, and the
//! tombstone is removed without following a symlink: a link inside a tree is removed, never what
//! it points to. A cut-off run so leaves `R` whole (rerun the uninstall) or gone (a reinstall works,
//! and the next install or uninstall removes the tombstone), never half removed.
//!
//! Windows (M7-D5): a running image cannot be deleted, so `uninstall` started inside `R` is phase
//! 1 of a hand-off ([`hand_off`]): it derives `R` from its own path and checks it as above, copies
//! itself (and a regular-file `lunepack-ui.exe` beside it) into a new
//! `%TEMP%\lunepack-uninstall-<16 hex>` directory with a marker naming the app id, starts the copy
//! detached as phase 2 (`uninstall --install-root <R> --wait-pid <pid> --wait-start <start>`) and
//! exits 0; it never deletes. Phase 2 is accepted only from such a directory ([`hand_off_copy`]),
//! waits up to [`HAND_OFF_WAIT`] for phase 1, validates the root it was given again
//! ([`hand_off_installation`]: a real canonical directory, not a reparse point, whose canonical
//! parent is the data home and that holds a record of the marker's app id; its name is never
//! checked) and then runs the uninstall above unchanged.
//!
//! macOS (M8-D5, M8-D15): a bundle install is the live bundle `B` outside `R`, `R` and the
//! LaunchAgent. `B` is this runtime's own tree and must be exactly what `R/bundle` names; `B` and
//! then `R` each leave their path in one rename to a tombstone beside them and are removed, and the
//! LaunchAgent goes last, when its `Label` is ours ([`uninstall_bundle`]).
//!
//! A machine install (M10 step 18, Windows) is removed by the engine, in an elevated process; this
//! runtime only asks and reports. Anything that runs from inside `R` makes the engine's removal
//! guard refuse, so the run the user started (from a version tree in `R`) first hands off to a copy
//! of itself under `%TEMP%` exactly as above ([`machine_hand_off`], validated against the machine
//! home and the machine record), and that copy asks in the window, has the runtime of the current
//! version inside `R` run the elevated `machine-uninstall` ([`crate::machine::uninstall`]), reports
//! what the elevated side relays and, when the install is gone, removes this user's own home. The
//! homes of other users are left.
//!
//! With a UI (M6), the confirm prompt comes before anything else: `cancel` there, or the UI lost
//! there, ends the mode with `cancelled` and nothing changed (M6-D5). The UI process, started from
//! the tree being removed, is the one process besides this one the in-use scan excludes (by pid
//! and start time). After the outcome the done prompt lists the integration items kept; `reveal`
//! opens the folder of one of them (M6-D10, `xdg-open` without a shell), which changes nothing.

use std::path::Path;

use lunepack::{
    FileKind, Installation, IntegrationItem, IntegrationRequest, Phase, ProcessId, Version,
};
use lunepack_core::layout::{Projection, TOMBSTONE_RANDOM_BYTES, UserLayout};
use lunepack_core::state::{Scope, UserScope};
use lunepack_core::ui::{ChoiceValue, Outcome, PromptKind, StepItem};

use crate::apply::{LOCK_WAIT, lock_retry};
use crate::events::{Event, Events, Warning};
use crate::machine::{self, Host};
use crate::modes::{Adapters, Kind};
use crate::ui_host::{self, UiHost};

/// The mode's name in events.
pub const COMMAND: &str = "uninstall";
/// The result's outcome when everything lunepack wrote is gone.
pub const OUTCOME: &str = "uninstalled";
/// The result's outcome when an integration item that is not lunepack's was kept.
pub const OUTCOME_LEFTOVERS: &str = "uninstalled_with_leftovers";

/// An integration item kept, with the command-link name it was checked under.
type Kept = (IntegrationItem, Option<String>);

/// Runs the `uninstall` mode for `inst` (the installation this runtime belongs to), with
/// `data_home` the environment's per-user data home (canonical), and its prompts in `ui`.
/// Returns the exit kind and the final event.
pub fn run_uninstall(
    ad: &Adapters,
    inst: &Installation,
    data_home: &Path,
    events: &Events,
    ui: &UiHost,
) -> (Kind, Event) {
    if ui.prompt(PromptKind::Confirm, events, &mut |_| {}) != ChoiceValue::Proceed {
        ui.outcome(Outcome::Cancelled);
        return report(inst, Err(Kind::Cancelled));
    }
    let result = uninstall(ad, inst, data_home, events, ui.child_id());
    match &result {
        Ok(kept) => {
            ui.steps(&[StepItem::Integrate, StepItem::Remove]);
            let paths = ui_host::leftovers(leftover_paths(inst, kept));
            ui.outcome(Outcome::Uninstalled {
                leftovers: paths.clone(),
            });
            ui.prompt(PromptKind::Done, events, &mut |index| {
                if let Some(path) = paths.get(index as usize) {
                    reveal(ad, Path::new(path));
                }
            });
        }
        Err(kind) => {
            ui.outcome(Outcome::UninstallFailed {
                code: u32::from(kind.code()),
            });
            ui.prompt(PromptKind::Failed, events, &mut |_| {});
        }
    }
    report(inst, result.map(|kept| !kept.is_empty()))
}

/// [`run_uninstall`] for a machine install (the copy outside `R`): the confirm prompt, the
/// elevated removal through `host` and the outcome in `ui`; the user's own home goes when the
/// install is gone. `silent`: a standard user is not asked for administrator rights (30).
pub fn run_machine_uninstall(
    ad: &Adapters,
    host: Option<&Host<'_>>,
    inst: &Installation,
    silent: bool,
    events: &Events,
    ui: &UiHost,
) -> (Kind, Event) {
    if ui.prompt(PromptKind::Confirm, events, &mut |_| {}) != ChoiceValue::Proceed {
        ui.outcome(Outcome::Cancelled);
        return report(inst, Err(Kind::Cancelled));
    }
    let result = machine_uninstall(ad, host, inst, silent, events);
    match &result {
        Ok(()) => {
            ui.steps(&[StepItem::Integrate, StepItem::Remove]);
            ui.outcome(Outcome::Uninstalled {
                leftovers: Vec::new(),
            });
            ui.prompt(PromptKind::Done, events, &mut |_| {});
        }
        Err(kind) => {
            ui.outcome(Outcome::UninstallFailed {
                code: u32::from(kind.code()),
            });
            ui.prompt(PromptKind::Failed, events, &mut |_| {});
        }
    }
    report(inst, result.map(|()| false))
}

/// The elevated removal of the machine install `inst` is a version of, then this user's home.
fn machine_uninstall(
    ad: &Adapters,
    host: Option<&Host<'_>>,
    inst: &Installation,
    silent: bool,
    events: &Events,
) -> Result<(), Kind> {
    let host = host.ok_or(Kind::Unsupported)?;
    let target = machine::target_of(&*ad.fs, &*ad.hasher, inst).ok_or(Kind::NotInstalled)?;
    let home = target
        .root
        .parent()
        .ok_or(Kind::InstallMismatch)?
        .to_path_buf();
    events.emit(&Event::phase(Phase::Uninstall, Some(inst.tree_version())));
    machine::uninstall(host, &*ad.fs, &*ad.hasher, &home, &target, silent, events)?;
    // This user's counters, cache and log; the homes of other users are theirs. Best effort: the
    // install is gone either way.
    if let Some(user_home) = inst.user_home() {
        let _ = ad.fs.remove_dir_all_nofollow(user_home);
    }
    Ok(())
}

fn report(inst: &Installation, result: Result<bool, Kind>) -> (Kind, Event) {
    let tree_version = Some(inst.tree_version().clone());
    match result {
        Ok(leftovers) => (
            Kind::Ok,
            Event::Result {
                command: COMMAND,
                tree_version,
                outcome: if leftovers {
                    OUTCOME_LEFTOVERS
                } else {
                    OUTCOME
                },
                version: None,
            },
        ),
        Err(kind) => (
            kind,
            Event::Error {
                command: COMMAND,
                tree_version,
                kind: kind.name(),
                exit_code: kind.code(),
                reason: kind.reason(),
            },
        ),
    }
}

/// Whether `root` is a real directory whose canonical path is itself.
fn real_canonical_dir(ad: &Adapters, root: &Path) -> bool {
    let real = matches!(
        ad.fs.symlink_metadata(root),
        Ok(Some(meta)) if meta.kind == FileKind::Dir
    );
    real && std::fs::canonicalize(root).is_ok_and(|c| c == root)
}

/// The paths of the kept integration items, as the UI shows them (Linux: the desktop entry under
/// the applications directory, the command link under the bin directory).
#[cfg(target_os = "linux")]
fn leftover_paths(inst: &Installation, kept: &[Kept]) -> Vec<String> {
    let Ok(dirs) = lunepack_os_linux::xdg_dirs(&lunepack_os_linux::XdgEnv::from_process()) else {
        return Vec::new();
    };
    kept.iter()
        .filter_map(|(item, bin)| match item {
            IntegrationItem::DesktopEntry => Some(
                dirs.applications()
                    .join(format!("{}.desktop", inst.app_id().as_str())),
            ),
            IntegrationItem::BinLink => bin.as_ref().map(|b| dirs.bin().join(b)),
            _ => None,
        })
        .filter_map(|p| p.to_str().map(str::to_owned))
        .collect()
}

/// macOS: the LaunchAgent kept (a foreign file at its name), under the canonical `HOME`.
#[cfg(target_os = "macos")]
fn leftover_paths(inst: &Installation, kept: &[Kept]) -> Vec<String> {
    let Some(home) = std::env::var_os("HOME").and_then(|h| std::fs::canonicalize(h).ok()) else {
        return Vec::new();
    };
    kept.iter()
        .filter(|(item, _)| *item == IntegrationItem::Autostart)
        .map(|_| {
            home.join("Library/LaunchAgents")
                .join(format!("{}.lunepack.plist", inst.app_id().as_str()))
        })
        .filter_map(|p| p.to_str().map(str::to_owned))
        .collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn leftover_paths(_inst: &Installation, _kept: &[Kept]) -> Vec<String> {
    Vec::new()
}

/// Opens the folder holding `path` with the desktop's opener (M6-D10): `xdg-open <dir>`, found on
/// `PATH` (absolute entries only), started detached without a shell. Best effort; other platforms
/// open nothing until their milestones.
#[cfg(target_os = "linux")]
fn reveal(ad: &Adapters, path: &Path) {
    let Some(dir) = path.parent() else {
        return;
    };
    let Some(opener) = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .filter(|d| d.is_absolute())
            .map(|d| d.join("xdg-open"))
            .find(|p| p.is_file())
    }) else {
        return;
    };
    let mut spec = lunepack::SpawnSpec::new(opener);
    spec.args = vec![dir.as_os_str().to_owned()];
    spec.env_remove = vec![std::ffi::OsString::from(lunepack::HEALTH_TOKEN_VAR)];
    let _ = ad.process.spawn_detached(&spec);
}

/// macOS: `/usr/bin/open <dir>` (Finder), started detached without a shell. Best effort.
#[cfg(target_os = "macos")]
fn reveal(ad: &Adapters, path: &Path) {
    let Some(dir) = path.parent() else {
        return;
    };
    let mut spec = lunepack::SpawnSpec::new(std::path::PathBuf::from("/usr/bin/open"));
    spec.args = vec![dir.as_os_str().to_owned()];
    spec.env_remove = vec![std::ffi::OsString::from(lunepack::HEALTH_TOKEN_VAR)];
    let _ = ad.process.spawn_detached(&spec);
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn reveal(_ad: &Adapters, _path: &Path) {}

/// Removes everything; the integration items kept. `ui` is the UI process this run started, which
/// the in-use scan does not count.
fn uninstall(
    ad: &Adapters,
    inst: &Installation,
    data_home: &Path,
    events: &Events,
    ui: Option<ProcessId>,
) -> Result<Vec<Kept>, Kind> {
    let layout = inst.layout().ok_or(Kind::NotInstalled)?;
    if layout.scheme().projection == Projection::Bundle {
        return uninstall_bundle(ad, inst, layout, data_home, events, ui);
    }
    let root = layout.root();
    // M5-D10, M7-D16: the root this runtime stands in must be one this environment's data home
    // holds under the layout's scheme (`<data home>/<app id>` under XDG).
    if !lunepack_core::root_valid_for_uninstall(
        &*ad.fs,
        data_home,
        root,
        inst.app_id(),
        layout.scheme(),
    ) || !real_canonical_dir(ad, root)
    {
        return Err(Kind::InstallMismatch);
    }
    // Best effort: a tombstone is never `R`, so one that stays changes nothing here.
    let _ = lunepack_core::remove_tombstones(&*ad.fs, data_home, inst.app_id());

    let guard = lock_retry(ad, &layout.state_dir(), LOCK_WAIT).map_err(|e| Kind::of(&e))?;
    let store = UserScope {
        dir: layout.state_dir(),
        app_id: inst.app_id().clone(),
    };
    let loaded = store
        .load(&*ad.fs, &*ad.hasher)
        .map_err(|e| Kind::of(&e.into()))?;
    let record = loaded.record.ok_or(Kind::NotInstalled)?;
    if &record.app_id != inst.app_id() {
        return Err(Kind::InstallMismatch);
    }
    // Checked again under the lock, right before anything is removed.
    if !real_canonical_dir(ad, root) {
        return Err(Kind::InstallMismatch);
    }

    let me: ProcessId = ad.process.current().map_err(|e| Kind::of(&e.into()))?;
    let mut exclude = vec![me];
    exclude.extend(ui);
    match ad.process.tree_in_use(root, &exclude) {
        Ok(false) => {}
        Ok(true) => return Err(Kind::InUse),
        Err(e) => return Err(Kind::of(&e.into())),
    }
    events.emit(&Event::phase(Phase::Uninstall, Some(inst.tree_version())));

    // The integration as this tree's config and the current version's config declare it (they
    // differ when this runtime is not the current version's).
    let mut owners: Vec<Installation> = vec![inst.clone()];
    if let Some(current) = record.current.as_ref().map(|c| &c.version)
        && !same(current, inst.tree_version())
        && let Ok(other) = inst.version_installation(current)
    {
        owners.push(other);
    }
    let mut kept: Vec<Kept> = Vec::new();
    for owner in &owners {
        let request = IntegrationRequest {
            app_id: inst.app_id().clone(),
            install_root: root.to_path_buf(),
            version: owner.tree_version().clone(),
            meta: owner.meta().clone(),
            previous: None,
            stale_bins: Vec::new(),
        };
        let report = ad
            .integration
            .remove(Scope::User, &request)
            .map_err(|e| Kind::of(&e.into()))?;
        kept.extend(
            report
                .kept
                .into_iter()
                .map(|item| (item, owner.meta().bin.clone())),
        );
    }
    if !kept.is_empty() {
        events.emit(&Event::warning(Warning::IntegrationKept, None));
    }

    // `R` leaves its path in one rename (F18), under the lock (on Windows right after it, M7-D21
    // below); the tombstone is beside it in the data home, so on the same filesystem. Its removal
    // can then be cut off without leaving a half-removed `R`.
    let mut random = [0u8; TOMBSTONE_RANDOM_BYTES];
    ad.rng.fill(&mut random).map_err(|e| Kind::of(&e.into()))?;
    let tombstone = data_home.join(lunepack_core::tombstone_name(inst.app_id(), &random));
    // M7-D21: on Windows a directory with an open file under it cannot be renamed, and the lock is
    // a file in `R`, so the lock is released right before the rename (after the record check, the
    // in-use scan and the integration removal). Every lunepack operation holds that lock file open,
    // so the rename succeeds only while none runs; one that locks after it finds no `R` there. A
    // failed rename returns the error with nothing deleted.
    #[cfg(windows)]
    drop(guard);
    ad.fs
        .rename(root, &tombstone)
        .map_err(|e| Kind::of(&e.into()))?;
    let _ = ad.fs.sync_dir(data_home);
    let removed = ad.fs.remove_dir_all_nofollow(&tombstone);
    #[cfg(not(windows))]
    drop(guard);
    // A failure is one only while the tombstone is still there (another run's tombstone cleanup
    // may have removed it under this one).
    if let Err(e) = removed
        && !matches!(ad.fs.symlink_metadata(&tombstone), Ok(None))
    {
        return Err(Kind::of(&e.into()));
    }
    let _ = ad.fs.sync_dir(data_home);
    Ok(kept)
}

/// The uninstall of a macOS bundle install (M8-D5, M8-D15): the live bundle `B` (outside `R`),
/// the install root `R` and the LaunchAgent. The running tree's place was judged when `inst` was
/// found (M8-D4: translocated or read-only is exit 28 before this). Then, before anything is
/// removed:
///
/// - `B` is this runtime's own tree (canonical) and exactly what `R/bundle` names, a real
///   directory whose canonical path is itself; a moved bundle not yet followed, or an old
///   instance in `R/versions`, is `install_mismatch` (26);
/// - `R` passes the same rules as on Linux ([`lunepack_core::root_valid_for_uninstall`],
///   `<data home>/<app id>`, real and canonical) and holds, under its lock, a record of this app id;
/// - `B`'s place passes [`lunepack_core::check_place`] (exit 28 otherwise);
/// - no process other than this one and its UI runs from `B` or from `R` (its version trees
///   included): `in_use` (25).
///
/// Once `B` and `R` are known to be the install's, this app id's tombstones in their parents (the
/// apps folder and the data home) are removed (M5-D10's rule). Under the lock, `B` leaves its path
/// in one rename to a tombstone in its own folder and is removed, then `R` the same way in the data
/// home: a cut-off run leaves each whole or gone, and `R` without `B` is an orphaned install
/// (M8-D16) that an installer rerun installs anew. Last, the LaunchAgent goes when its `Label` is
/// ours; a foreign one is kept and reported. This runtime and its UI may run from `B`: their files
/// are unlinked, and the run ends with its final object.
fn uninstall_bundle(
    ad: &Adapters,
    inst: &Installation,
    layout: &UserLayout,
    data_home: &Path,
    events: &Events,
    ui: Option<ProcessId>,
) -> Result<Vec<Kept>, Kind> {
    let fs = &*ad.fs;
    let root = layout.root();
    let bundle = inst.tree_root();
    let app_id = inst.app_id();
    let valid = || {
        lunepack_core::root_valid_for_uninstall(fs, data_home, root, app_id, layout.scheme())
            && real_canonical_dir(ad, root)
            && is_live_bundle(ad, inst, layout)
    };
    if !valid() {
        return Err(Kind::InstallMismatch);
    }
    let apps = bundle.parent().ok_or(Kind::InstallMismatch)?;
    // Best effort: a tombstone is never `B` or `R`, so one that stays changes nothing here.
    let _ = lunepack_core::remove_tombstones(fs, data_home, app_id);
    let _ = lunepack_core::remove_tombstones(fs, apps, app_id);

    let guard = lock_retry(ad, &layout.state_dir(), LOCK_WAIT).map_err(|e| Kind::of(&e))?;
    let store = UserScope {
        dir: layout.state_dir(),
        app_id: app_id.clone(),
    };
    let loaded = store
        .load(fs, &*ad.hasher)
        .map_err(|e| Kind::of(&e.into()))?;
    let record = loaded.record.ok_or(Kind::NotInstalled)?;
    if &record.app_id != app_id {
        return Err(Kind::InstallMismatch);
    }
    // Checked again under the lock, right before anything is removed.
    if !valid() {
        return Err(Kind::InstallMismatch);
    }
    lunepack_core::check_place(fs, layout, bundle)
        .map_err(|e| Kind::of(&lunepack_core::Error::Layout(e).into()))?;

    let me: ProcessId = ad.process.current().map_err(|e| Kind::of(&e.into()))?;
    let mut exclude = vec![me];
    exclude.extend(ui);
    for tree in [bundle, root] {
        match ad.process.tree_in_use(tree, &exclude) {
            Ok(false) => {}
            Ok(true) => return Err(Kind::InUse),
            Err(e) => return Err(Kind::of(&e.into())),
        }
    }
    events.emit(&Event::phase(Phase::Uninstall, Some(inst.tree_version())));

    // `B`, then `R`, each out of its path in one rename. A failed rename returns with what is
    // left whole; once `B` is gone, `R` follows even if `B`'s tombstone could not be emptied
    // (its error is returned at the end), so the install is never left half gone.
    let mut first = remove_whole(ad, bundle, apps, app_id)?;
    let removed = remove_whole(ad, root, data_home, app_id);
    drop(guard);
    if let Some(kind) = removed? {
        first.get_or_insert(kind);
    }

    // The LaunchAgent, only when its `Label` is ours (M8-D12); its request names `B`.
    let request = IntegrationRequest {
        app_id: app_id.clone(),
        install_root: bundle.to_path_buf(),
        version: inst.tree_version().clone(),
        meta: inst.meta().clone(),
        previous: None,
        stale_bins: Vec::new(),
    };
    let report = ad
        .integration
        .remove(Scope::User, &request)
        .map_err(|e| Kind::of(&e.into()))?;
    if let Some(kind) = first {
        return Err(kind);
    }
    let kept: Vec<Kept> = report.kept.into_iter().map(|item| (item, None)).collect();
    if !kept.is_empty() {
        events.emit(&Event::warning(Warning::IntegrationKept, None));
    }
    Ok(kept)
}

/// Whether `inst`'s tree is the live bundle: not a moved bundle, exactly `R/bundle`'s target, and
/// a real directory whose canonical path is itself.
fn is_live_bundle(ad: &Adapters, inst: &Installation, layout: &UserLayout) -> bool {
    let bundle = inst.tree_root();
    !inst.moved()
        && matches!(layout.bundle_path(&*ad.fs), Ok(Some(b)) if b == bundle)
        && real_canonical_dir(ad, bundle)
}

/// Moves `dir` out of its path in one rename, to a fresh tombstone of `app_id` in `parent` (its
/// own folder, so the same filesystem), then removes the tombstone without following a symlink.
/// `Err` when `dir` is still there; `Ok(Some(kind))` when it is gone but its tombstone could not
/// be removed whole (the next uninstall removes it).
fn remove_whole(
    ad: &Adapters,
    dir: &Path,
    parent: &Path,
    app_id: &lunepack::AppId,
) -> Result<Option<Kind>, Kind> {
    let mut random = [0u8; TOMBSTONE_RANDOM_BYTES];
    ad.rng.fill(&mut random).map_err(|e| Kind::of(&e.into()))?;
    let tombstone = parent.join(lunepack_core::tombstone_name(app_id, &random));
    ad.fs
        .rename(dir, &tombstone)
        .map_err(|e| Kind::of(&e.into()))?;
    let _ = ad.fs.sync_dir(parent);
    let removed = ad.fs.remove_dir_all_nofollow(&tombstone);
    let _ = ad.fs.sync_dir(parent);
    // A failure is one only while the tombstone is still there.
    Ok(match removed {
        Err(e) if !matches!(ad.fs.symlink_metadata(&tombstone), Ok(None)) => {
            Some(Kind::of(&e.into()))
        }
        _ => None,
    })
}

/// Text equality of two versions.
fn same(a: &Version, b: &Version) -> bool {
    a == b && a.to_string() == b.to_string()
}

/// How long phase 2 waits for phase 1 to exit before it goes on (the in-use check then decides).
#[cfg(windows)]
pub const HAND_OFF_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The file name of the runtime's copy in the hand-off directory.
#[cfg(windows)]
const COPY_FILE: &str = "lunepack-runtime.exe";

/// Phase 1 of the Windows uninstall (M7-D5): `inst` is the installed tree this runtime runs from;
/// its `R` is checked as the uninstall checks it, then this runtime (and the UI beside it, when it
/// is a regular file) is copied into a fresh hand-off directory under `temp`, created new with its
/// marker, and the copy is started detached as phase 2. Nothing is deleted under `R`; this process
/// keeps no handle into `R` (no log; its working directory moves to the copy's).
#[cfg(windows)]
pub fn hand_off(
    ad: &Adapters,
    inst: &Installation,
    data_home: &Path,
    temp: &Path,
    silent: bool,
) -> Result<(), Kind> {
    let layout = inst.layout().ok_or(Kind::NotInstalled)?;
    let root = layout.root();
    if !lunepack_core::root_valid_for_uninstall(
        &*ad.fs,
        data_home,
        root,
        inst.app_id(),
        layout.scheme(),
    ) || !real_canonical_dir(ad, root)
    {
        return Err(Kind::InstallMismatch);
    }
    hand_off_copy_and_start(ad, inst.app_id().as_str(), root, temp, silent)
}

/// Phase 1 for a machine install (M10 step 18): the same hand-off, with `R` validated against the
/// machine home `home` and the machine record (the install is `inst`, found as one). Nothing is
/// deleted, and nothing elevated is started: the copy asks first.
#[cfg(windows)]
pub fn machine_hand_off(
    ad: &Adapters,
    inst: &Installation,
    home: &Path,
    temp: &Path,
    silent: bool,
) -> Result<(), Kind> {
    let layout = inst.machine_layout().ok_or(Kind::NotInstalled)?;
    let root = layout.root();
    if !lunepack_core::root_valid_for_uninstall(
        &*ad.fs,
        home,
        root,
        inst.app_id(),
        lunepack_core::LayoutScheme::WINDOWS,
    ) || !real_canonical_dir(ad, root)
    {
        return Err(Kind::InstallMismatch);
    }
    hand_off_copy_and_start(ad, inst.app_id().as_str(), root, temp, silent)
}

/// The rest of phase 1: this runtime (and the UI beside it, when it is a regular file) is copied
/// into a fresh hand-off directory under `temp`, created new with its marker, and the copy is
/// started detached as phase 2.
#[cfg(windows)]
fn hand_off_copy_and_start(
    ad: &Adapters,
    app_id: &str,
    root: &Path,
    temp: &Path,
    silent: bool,
) -> Result<(), Kind> {
    use crate::tempdirs::{self, Marker};

    let exe = ad.process.current_exe().map_err(|e| Kind::of(&e.into()))?;
    let me = ad.process.current().map_err(|e| Kind::of(&e.into()))?;
    let marker = Marker {
        app_id: app_id.to_owned(),
        owner: me,
    };
    let dir = tempdirs::create(&*ad.fs, &*ad.rng, temp, tempdirs::UNINSTALL_PREFIX, &marker)
        .map_err(|_| Kind::Fs)?;
    let started = (|| {
        let copy = dir.join(COPY_FILE);
        copy_new(&exe, &copy).map_err(|_| Kind::Fs)?;
        let ui = exe.with_file_name(ui_host::UI_FILE);
        if matches!(ad.fs.symlink_metadata(&ui), Ok(Some(m)) if m.kind == FileKind::File) {
            // Best effort: without its UI, phase 2 runs headless.
            let _ = copy_new(&ui, &dir.join(ui_host::UI_FILE));
        }
        // Phase 2 inherits this directory, not one inside `R`.
        std::env::set_current_dir(&dir).map_err(|_| Kind::Fs)?;
        let mut spec = lunepack::SpawnSpec::new(copy);
        spec.args = vec![
            "uninstall".into(),
            "--install-root".into(),
            root.as_os_str().to_owned(),
            "--wait-pid".into(),
            me.pid.to_string().into(),
            "--wait-start".into(),
            me.start_ticks.to_string().into(),
        ];
        if silent {
            spec.args.push("--silent".into());
        }
        spec.env_remove = vec![std::ffi::OsString::from(lunepack::HEALTH_TOKEN_VAR)];
        ad.process
            .spawn_detached(&spec)
            .map_err(|e| Kind::of(&e.into()))
    })();
    if started.is_err() {
        let _ = std::env::set_current_dir(temp);
        let _ = ad.fs.remove_dir_all_nofollow(&dir);
    }
    started
}

/// Copies the regular file `from` to the new file `to` (create-new, never an existing path).
#[cfg(windows)]
fn copy_new(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut src = std::fs::File::open(from)?;
    let mut dst = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)?;
    std::io::copy(&mut src, &mut dst)?;
    dst.sync_all()
}

/// Phase 2's own-directory rule (M7-D5): this runtime runs from directly inside a real directory
/// named `lunepack-uninstall-<16 lowercase hex>` directly under `temp` (both canonical), holding a
/// marker. `None` anywhere else: the caller refuses with a usage error before any action.
#[cfg(windows)]
pub fn hand_off_copy(
    ad: &Adapters,
    temp: &Path,
) -> Option<(std::path::PathBuf, crate::tempdirs::Marker)> {
    use crate::tempdirs;

    let exe = ad.process.current_exe().ok()?;
    let dir = exe.parent()?;
    let name = dir.file_name()?.to_str()?;
    if !tempdirs::is_dir_name(name, tempdirs::UNINSTALL_PREFIX) || dir.parent() != Some(temp) {
        return None;
    }
    if !matches!(ad.fs.symlink_metadata(dir), Ok(Some(m)) if m.kind == FileKind::Dir) {
        return None;
    }
    let marker = tempdirs::read_marker(&*ad.fs, dir)?;
    Some((dir.to_path_buf(), marker))
}

/// Phase 2's installation (M7-D5, M7-D16): `given` must be a real directory (not a reparse
/// point) whose canonical path is a real directory, with the canonical data home as its parent,
/// holding a record of `app_id`; the installation is the record's current version's tree there.
/// `R`'s name is never checked. Any mismatch is `install_mismatch`, with nothing changed.
#[cfg(windows)]
pub fn hand_off_installation(
    ad: &Adapters,
    data_home: &Path,
    given: &Path,
    app_id: &str,
) -> Result<Installation, Kind> {
    use lunepack::{AppId, UpdateConfig, UserLayout};
    use lunepack_core::update_config::{MAX_UPDATE_CONFIG_BYTES, runtime_file};

    let is_dir =
        |p: &Path| matches!(ad.fs.symlink_metadata(p), Ok(Some(m)) if m.kind == FileKind::Dir);
    let app = AppId::parse(app_id).map_err(|_| Kind::InstallMismatch)?;
    if !is_dir(given) {
        return Err(Kind::InstallMismatch);
    }
    let root = std::fs::canonicalize(given).map_err(|_| Kind::InstallMismatch)?;
    let scheme = ad.platform.layout_scheme();
    if !is_dir(&root)
        || !lunepack_core::root_valid_for_uninstall(&*ad.fs, data_home, &root, &app, scheme)
    {
        return Err(Kind::InstallMismatch);
    }
    let layout = UserLayout::from_root(root.clone(), scheme);
    let store = UserScope {
        dir: layout.state_dir(),
        app_id: app.clone(),
    };
    let record = match store.load(&*ad.fs, &*ad.hasher) {
        Ok(loaded) => loaded.record.ok_or(Kind::InstallMismatch)?,
        Err(_) => return Err(Kind::InstallMismatch),
    };
    if record.app_id != app {
        return Err(Kind::InstallMismatch);
    }
    let current = record.current.ok_or(Kind::NotInstalled)?.version;
    // The current version's runtime, beside its entry: the tree's config names both.
    let config_path = layout.version_config_path(&current);
    if !matches!(ad.fs.symlink_metadata(&config_path), Ok(Some(m)) if m.kind == FileKind::File) {
        return Err(Kind::UpdateConfig);
    }
    let bytes = ad
        .fs
        .read_capped(&config_path, MAX_UPDATE_CONFIG_BYTES)
        .map_err(|_| Kind::UpdateConfig)?;
    let config = UpdateConfig::parse(&bytes).map_err(|_| Kind::UpdateConfig)?;
    let mut runtime = layout.version_dir(&current);
    for part in config.install.entry.components() {
        runtime.push(part);
    }
    runtime.set_file_name(runtime_file(config.target));
    let inst = Installation::from_exe_with(
        &runtime,
        ad.platform.clone().with_data_home(data_home.to_path_buf()),
    )
    .map_err(|e| Kind::of(&e))?;
    match inst.layout() {
        Some(l) if l.root() == root && inst.app_id() == &app => Ok(inst),
        _ => Err(Kind::InstallMismatch),
    }
}

/// Phase 2's installation for a machine install (M10 step 18): `given` must be a real directory
/// whose canonical path is a real directory with the canonical machine home `home` as its parent
/// ([`lunepack_core::root_valid_for_uninstall`] under the Windows scheme), holding a machine record
/// of `app_id`; the installation is the record's current version's tree there, and it must be found
/// as that machine install. Any mismatch is `install_mismatch`, with nothing changed.
#[cfg(windows)]
pub fn hand_off_machine_installation(
    ad: &Adapters,
    home: &Path,
    given: &Path,
    app_id: &str,
) -> Result<Installation, Kind> {
    use lunepack::{AppId, UpdateConfig};
    use lunepack_core::state::MachineStore;
    use lunepack_core::update_config::{MAX_UPDATE_CONFIG_BYTES, runtime_file};
    use lunepack_core::{LayoutScheme, MachineLayout};

    let is_dir =
        |p: &Path| matches!(ad.fs.symlink_metadata(p), Ok(Some(m)) if m.kind == FileKind::Dir);
    let app = AppId::parse(app_id).map_err(|_| Kind::InstallMismatch)?;
    if !is_dir(given) {
        return Err(Kind::InstallMismatch);
    }
    let root = std::fs::canonicalize(given).map_err(|_| Kind::InstallMismatch)?;
    if !is_dir(&root)
        || !lunepack_core::root_valid_for_uninstall(
            &*ad.fs,
            home,
            &root,
            &app,
            LayoutScheme::WINDOWS,
        )
    {
        return Err(Kind::InstallMismatch);
    }
    let layout = MachineLayout::new(&root);
    let store = MachineStore {
        dir: layout.state_dir(),
        app_id: app.clone(),
    };
    let record = match store.load(&*ad.fs, &*ad.hasher) {
        Ok(loaded) => loaded.record.ok_or(Kind::InstallMismatch)?,
        Err(_) => return Err(Kind::InstallMismatch),
    };
    if record.app_id != app {
        return Err(Kind::InstallMismatch);
    }
    let current = record.current.ok_or(Kind::NotInstalled)?.version;
    let tree = layout.version_dir(&current);
    let mut config_path = tree.clone();
    for part in LayoutScheme::WINDOWS.config.split('/') {
        config_path.push(part);
    }
    if !matches!(ad.fs.symlink_metadata(&config_path), Ok(Some(m)) if m.kind == FileKind::File) {
        return Err(Kind::UpdateConfig);
    }
    let bytes = ad
        .fs
        .read_capped(&config_path, MAX_UPDATE_CONFIG_BYTES)
        .map_err(|_| Kind::UpdateConfig)?;
    let config = UpdateConfig::parse(&bytes).map_err(|_| Kind::UpdateConfig)?;
    let mut runtime = tree;
    for part in config.install.entry.components() {
        runtime.push(part);
    }
    runtime.set_file_name(runtime_file(config.target));
    let inst =
        Installation::from_exe_with(&runtime, ad.platform.clone()).map_err(|e| Kind::of(&e))?;
    match inst.machine_layout() {
        Some(l) if l.root() == root && inst.app_id() == &app => Ok(inst),
        _ => Err(Kind::InstallMismatch),
    }
}
