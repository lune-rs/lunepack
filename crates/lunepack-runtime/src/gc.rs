//! Garbage collection of version trees (M5-D9), run after an apply's outcome is decided, never
//! before the relaunch. A machine install is not collected here: its service collects.
//!
//! Under the install's lock it keeps `gc_keep` of the record (current, previous, pending and
//! staged) and removes only direct children of the layout's versions directory (`R/versions`,
//! `R\app` under the Windows scheme; on Windows also the launcher stub's leftover copies in `R`)
//! that are real directories (not
//! followed when a symlink) whose name is a version's canonical text, that are not kept, and
//! that no other process uses (`Process::tree_in_use`, this process excluded). Every error keeps
//! the tree: a failed check, a failed removal, an unreadable directory.

use std::time::Duration;

use lunepack::{FileKind, Installation, ProcessId, Version};
use lunepack_core::gc_keep;
use lunepack_core::state::UserScope;

use crate::apply::lock_retry;
use crate::events::{Event, Events, Warning};
use crate::modes::Adapters;

/// How long GC waits for the install lock before it skips this run.
pub const GC_LOCK_WAIT: Duration = Duration::from_secs(10);

/// What a GC run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Versions whose trees were removed.
    pub removed: Vec<Version>,
    /// Versions whose trees were kept because they are in use or an operation failed.
    pub kept: Vec<Version>,
}

/// Collects `inst`'s install. `me` is excluded from the in-use check.
pub fn gc(ad: &Adapters, inst: &Installation, me: Option<ProcessId>, events: &Events) -> GcReport {
    let mut report = GcReport::default();
    // A machine install's trees are the service's to collect, after a confirm (M10 step 6): this
    // runtime does nothing there, whatever the layout it could build (M10 step 18).
    if inst.is_machine() {
        return report;
    }
    let Some(layout) = inst.layout() else {
        return report;
    };
    let Ok(guard) = lock_retry(ad, &layout.state_dir(), GC_LOCK_WAIT) else {
        events.emit(&Event::warning(Warning::GcBusy, None));
        return report;
    };
    let store = UserScope {
        dir: layout.state_dir(),
        app_id: inst.app_id().clone(),
    };
    let record = match store.load(&*ad.fs, &*ad.hasher) {
        Ok(loaded) => loaded.record,
        Err(_) => None,
    };
    // No readable record: nothing is known to be unused.
    let Some(record) = record else {
        drop(guard);
        return report;
    };
    // Windows: the launcher stub's transient copies beside it in `R` (M7-D8); only exact leftover
    // names, never a running copy, never `app` or `.lunepack`.
    #[cfg(windows)]
    let _ = lunepack_os_windows::remove_stub_leftovers(layout.root());
    let keep = gc_keep(&record);
    let versions = layout.versions_dir();
    let Ok(entries) = ad.fs.list_dir(&versions) else {
        drop(guard);
        return report;
    };
    let exclude: Vec<ProcessId> = me.into_iter().collect();
    for entry in entries {
        let Some(name) = entry.name.to_str() else {
            continue;
        };
        let Ok(version) = Version::parse(name) else {
            continue;
        };
        // Only a name that is the version's canonical text is a version tree.
        if version.to_string() != name || entry.kind != FileKind::Dir || keep.contains(&version) {
            continue;
        }
        let tree = versions.join(name);
        // Checked again right before the removal, not followed.
        let real_dir = matches!(
            ad.fs.symlink_metadata(&tree),
            Ok(Some(meta)) if meta.kind == FileKind::Dir
        );
        if !real_dir {
            continue;
        }
        match ad.process.tree_in_use(&tree, &exclude) {
            Ok(false) => {}
            Ok(true) => {
                events.emit(&Event::warning(Warning::GcInUse, Some(&version)));
                report.kept.push(version);
                continue;
            }
            Err(_) => {
                events.emit(&Event::warning(Warning::GcKept, Some(&version)));
                report.kept.push(version);
                continue;
            }
        }
        match ad.fs.remove_dir_all_nofollow(&tree) {
            Ok(()) => report.removed.push(version),
            Err(_) => {
                events.emit(&Event::warning(Warning::GcKept, Some(&version)));
                report.kept.push(version);
            }
        }
    }
    let _ = ad.fs.sync_dir(&versions);
    drop(guard);
    report
}
