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
//! `install`). The facade refuses an `R` that exists and is not lunepack's (not a real directory,
//! or not empty and holding neither this app's record nor only what a cut-off run leaves; S2),
//! which this mode reports as `install_mismatch`. It never launches the app.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use lunepack::{DownloadOptions, Installation, Phase, Progress};

use crate::events::{Event, Events};
use crate::modes::Kind;

/// The mode's name in events.
pub const COMMAND: &str = "install";
/// The result's outcome.
pub const OUTCOME: &str = "installed";
/// How often the progress forwarder looks whether the install ended.
const FORWARD_POLL: Duration = Duration::from_millis(50);

/// Runs the `install` mode from `boot`, the bootstrap tree this runtime belongs to (its platform
/// carries the data home). Returns the exit kind and the final event.
pub fn run_install(boot: &Installation, events: &Events) -> (Kind, Event) {
    let tree_version = Some(boot.tree_version().clone());
    match install(boot, events) {
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

fn install(boot: &Installation, events: &Events) -> Result<lunepack::Version, Kind> {
    // An installed tree (one under some `R/versions`) is not a bootstrap.
    if boot.is_installed() {
        return Err(Kind::AlreadyInstalled);
    }
    let root = boot.install_root().map_err(|e| Kind::of(&e))?;
    // A bootstrap anywhere under `R` could be removed or replaced by the install itself.
    if boot.tree_root().starts_with(&root) {
        return Err(Kind::AlreadyInstalled);
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
