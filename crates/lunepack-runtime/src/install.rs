//! The `install` mode (M5-D8): the first install of the app from a bootstrap tree, headless.
//!
//! The bootstrap is any verified copy of a version tree outside the install (M6's installer
//! extracts one). Its own update config names the root, feed and channel; the install root is
//! `R = <data home>/<app id>` (M5-D2, the data home worked out by the composition root). The
//! facade's [`Updater::install`](lunepack::Updater::install) does the work: the integration
//! preflight before the first write, the record created or resumed (a record with no current
//! version is a run that was cut off), the newest release of the channel staged with the
//! bootstrap's matching files reused, then the commit, `current` and the integration.
//!
//! This mode refuses a bootstrap that lies under `R` (an installed tree runs `apply`, not
//! `install`), an `R` that exists but is not a real directory, and an existing `R` that is not
//! empty and holds neither this app's record nor only what a cut-off run leaves (S2). It never
//! launches the app.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use lunepack::{DownloadOptions, FileKind, Installation, Phase, Progress, UserLayout};
use lunepack_core::state::UserScope;

use crate::events::{Event, Events};
use crate::modes::{Adapters, Kind};

/// The mode's name in events.
pub const COMMAND: &str = "install";
/// The result's outcome.
pub const OUTCOME: &str = "installed";
/// The install lock's file name in the state directory.
const LOCK_FILE: &str = "lock";
/// How often the progress forwarder looks whether the install ended.
const FORWARD_POLL: Duration = Duration::from_millis(50);

/// Runs the `install` mode from `boot`, the bootstrap tree this runtime belongs to (its platform
/// carries the data home). Returns the exit kind and the final event.
pub fn run_install(ad: &Adapters, boot: &Installation, events: &Events) -> (Kind, Event) {
    let tree_version = Some(boot.tree_version().clone());
    match install(ad, boot, events) {
        Ok(version) => (
            Kind::Ok,
            Event::Result {
                command: COMMAND,
                tree_version,
                outcome: OUTCOME,
                version: Some(version),
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

/// Whether the existing directory `root` may be taken over as the install root (S2): it is
/// empty, or `root/state` holds a record of this app id, or it holds only what a run cut off
/// before its first record leaves (a `state` directory with the lock and record files). Anything
/// else (an app's own user data from before lunepack, another packaging's directory, a shared
/// directory) is [`Kind::InstallMismatch`]: uninstall would remove `R` whole, so `R` must hold
/// nothing lunepack did not make. Nothing is written here.
fn adoptable(ad: &Adapters, boot: &Installation, root: &Path) -> Result<(), Kind> {
    let entries = ad.fs.list_dir(root).map_err(kind_of)?;
    if entries.is_empty() {
        return Ok(());
    }
    let state = UserLayout::from_root(root.to_path_buf()).state_dir();
    let state_is_dir = entries
        .iter()
        .any(|e| Some(e.name.as_os_str()) == state.file_name() && e.kind == FileKind::Dir);
    if !state_is_dir {
        return Err(Kind::InstallMismatch);
    }
    let store = UserScope {
        dir: state.clone(),
        app_id: boot.app_id().clone(),
    };
    if store
        .load(&*ad.fs, &*ad.hasher)
        .map_err(kind_of)?
        .record
        .is_some()
    {
        return Ok(());
    }
    let only_state = entries.len() == 1;
    let state_entries = ad.fs.list_dir(&state).map_err(kind_of)?;
    let only_ours = state_entries.iter().all(|e| {
        e.kind == FileKind::File
            && e.name
                .to_str()
                .is_some_and(|n| n == LOCK_FILE || is_record_name(n))
    });
    if only_state && only_ours {
        Ok(())
    } else {
        Err(Kind::InstallMismatch)
    }
}

/// A record file name of the state store, `<20 digits>.rec` (FORMAT.md 12.4).
fn is_record_name(name: &str) -> bool {
    name.strip_suffix(".rec")
        .is_some_and(|digits| digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
}

fn kind_of(e: impl Into<lunepack::Error>) -> Kind {
    Kind::of(&e.into())
}

fn install(ad: &Adapters, boot: &Installation, events: &Events) -> Result<lunepack::Version, Kind> {
    // An installed tree (one under some `R/versions`) is not a bootstrap.
    if boot.is_installed() {
        return Err(Kind::AlreadyInstalled);
    }
    let root = boot.install_root().map_err(|e| Kind::of(&e))?;
    // A bootstrap anywhere under `R` could be removed or replaced by the install itself.
    if boot.tree_root().starts_with(&root) {
        return Err(Kind::AlreadyInstalled);
    }
    // `R` is created by the install, or is a real directory a cut-off run left.
    match ad.fs.symlink_metadata(&root) {
        Ok(None) => {}
        Ok(Some(meta)) if meta.kind == FileKind::Dir => adoptable(ad, boot, &root)?,
        Ok(Some(_)) => return Err(Kind::InstallMismatch),
        Err(e) if e.kind == lunepack::FsErrorKind::NotFound => {}
        Err(e) => return Err(Kind::of(&e.into())),
    }

    let updater = boot
        .updater_builder()
        .and_then(lunepack::UpdaterBuilder::build)
        .map_err(|e| Kind::of(&e))?;
    events.emit(&Event::phase(Phase::Install, Some(boot.tree_version())));

    // Progress arrives on the polling thread; a scoped forwarder hands it to the sinks.
    let (tx, rx) = mpsc::channel::<Progress>();
    let done = AtomicBool::new(false);
    let result = std::thread::scope(|scope| {
        let done = &done;
        scope.spawn(move || {
            loop {
                match rx.recv_timeout(FORWARD_POLL) {
                    Ok(progress) => events.emit(&Event::Progress(progress)),
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) if done.load(Ordering::Acquire) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        });
        let options = DownloadOptions {
            progress: Some(Box::new(move |p: &Progress| {
                let _ = tx.send(p.clone());
            })),
            cancel: None,
        };
        let result = lunepack::block_on(updater.install(options));
        done.store(true, Ordering::Release);
        result
    });
    let installed = result.map_err(|e| Kind::of(&e))?;
    Ok(installed.version().clone())
}
