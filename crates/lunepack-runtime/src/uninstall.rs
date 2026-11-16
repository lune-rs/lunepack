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

use std::path::Path;

use lunepack::{FileKind, Installation, IntegrationRequest, Phase, ProcessId, Version};
use lunepack_core::layout::TOMBSTONE_RANDOM_BYTES;
use lunepack_core::state::{Scope, UserScope};

use crate::apply::{LOCK_WAIT, lock_retry};
use crate::events::{Event, Events, Warning};
use crate::modes::{Adapters, Kind};

/// The mode's name in events.
pub const COMMAND: &str = "uninstall";
/// The result's outcome when everything lunepack wrote is gone.
pub const OUTCOME: &str = "uninstalled";
/// The result's outcome when an integration item that is not lunepack's was kept.
pub const OUTCOME_LEFTOVERS: &str = "uninstalled_with_leftovers";

/// Runs the `uninstall` mode for `inst` (the installation this runtime belongs to), with
/// `data_home` the environment's per-user data home (canonical). Returns the exit kind and the
/// final event.
pub fn run_uninstall(
    ad: &Adapters,
    inst: &Installation,
    data_home: &Path,
    events: &Events,
) -> (Kind, Event) {
    let tree_version = Some(inst.tree_version().clone());
    match uninstall(ad, inst, data_home, events) {
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

/// Removes everything; `Ok(true)` when an integration item was kept.
fn uninstall(
    ad: &Adapters,
    inst: &Installation,
    data_home: &Path,
    events: &Events,
) -> Result<bool, Kind> {
    let layout = inst.layout().ok_or(Kind::NotInstalled)?;
    let root = layout.root();
    // M5-D10: the root this runtime stands in must be the one this environment derives.
    if root != data_home.join(inst.app_id().as_str()) || !real_canonical_dir(ad, root) {
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
    match ad.process.tree_in_use(root, &[me]) {
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
    let mut leftovers = false;
    for owner in &owners {
        let request = IntegrationRequest {
            app_id: inst.app_id().clone(),
            install_root: root.to_path_buf(),
            meta: owner.meta().clone(),
            stale_bins: Vec::new(),
        };
        let report = ad
            .integration
            .remove(Scope::User, &request)
            .map_err(|e| Kind::of(&e.into()))?;
        leftovers |= !report.kept.is_empty();
    }
    if leftovers {
        events.emit(&Event::warning(Warning::IntegrationKept, None));
    }

    // `R` leaves its path in one rename (F18), under the lock; the tombstone is beside it in the
    // data home, so on the same filesystem. Its removal can then be cut off without leaving a
    // half-removed `R`.
    let mut random = [0u8; TOMBSTONE_RANDOM_BYTES];
    ad.rng.fill(&mut random).map_err(|e| Kind::of(&e.into()))?;
    let tombstone = data_home.join(lunepack_core::tombstone_name(inst.app_id(), &random));
    ad.fs
        .rename(root, &tombstone)
        .map_err(|e| Kind::of(&e.into()))?;
    let _ = ad.fs.sync_dir(data_home);
    let removed = ad.fs.remove_dir_all_nofollow(&tombstone);
    drop(guard);
    // A failure is one only while the tombstone is still there (another run's tombstone cleanup
    // may have removed it under this one).
    if let Err(e) = removed
        && !matches!(ad.fs.symlink_metadata(&tombstone), Ok(None))
    {
        return Err(Kind::of(&e.into()));
    }
    let _ = ad.fs.sync_dir(data_home);
    Ok(leftovers)
}

/// Text equality of two versions.
fn same(a: &Version, b: &Version) -> bool {
    a == b && a.to_string() == b.to_string()
}
