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
//! which this mode reports as `install_mismatch`.
//!
//! With a UI (M6), the welcome prompt comes before anything else: `cancel` there, or the UI lost
//! there, ends the mode with `cancelled` and nothing changed (M6-D5). After the outcome comes the
//! done prompt, whose `finish{launch:true}` starts the installed app (detached, without a health
//! token, the only action a choice after the outcome takes), or the failed prompt, whose `retry`
//! runs the install again. Headless (no UI, `--silent`), every prompt takes its default: proceed,
//! and the app is not launched.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use std::ffi::OsString;

use lunepack::{
    ChildStdio, DownloadOptions, HEALTH_TOKEN_VAR, Installation, Phase, Progress, SpawnSpec,
    Version,
};
use lunepack_core::ui::{ChoiceValue, Outcome, PromptKind, StepItem};

use crate::events::{Event, Events, Warning};
use crate::modes::{Adapters, Kind};
use crate::ui_host::UiHost;

/// The mode's name in events.
pub const COMMAND: &str = "install";
/// The result's outcome.
pub const OUTCOME: &str = "installed";
/// How often the progress forwarder looks whether the install ended.
const FORWARD_POLL: Duration = Duration::from_millis(50);

/// Runs the `install` mode from `boot`, the bootstrap tree this runtime belongs to (its platform
/// carries the data home), with its prompts in `ui`. Returns the exit kind and the final event.
pub fn run_install(
    ad: &Adapters,
    boot: &Installation,
    events: &Events,
    ui: &UiHost,
) -> (Kind, Event) {
    if ui.prompt(PromptKind::Welcome, events, &mut |_| {}) != ChoiceValue::Proceed {
        ui.outcome(Outcome::Cancelled);
        return report(boot, Err(Kind::Cancelled));
    }
    loop {
        let result = install(boot, events);
        match &result {
            Ok(_) => {
                ui.steps(&[
                    StepItem::Verify,
                    StepItem::Stage,
                    StepItem::Commit,
                    StepItem::Integrate,
                ]);
                ui.outcome(Outcome::Installed);
            }
            Err(kind) => ui.outcome(Outcome::Failed {
                code: u32::from(kind.code()),
            }),
        }
        let kind = match &result {
            Ok(_) => PromptKind::Done,
            Err(_) => PromptKind::Failed,
        };
        match ui.prompt(kind, events, &mut |_| {}) {
            ChoiceValue::Retry => continue,
            ChoiceValue::Finish { launch: true } => {
                if let Ok(version) = &result {
                    launch(ad, boot, version, events);
                }
            }
            _ => {}
        }
        return report(boot, result);
    }
}

/// Starts the installed version's entry (from its own config), detached, with no arguments and
/// without a health token; a failure is a warning.
fn launch(ad: &Adapters, boot: &Installation, version: &Version, events: &Events) {
    let started = boot.install_layout().ok().and_then(|layout| {
        // The bundle layout (macOS) puts the installed version in the live bundle.
        let tree = match layout.bundle_path(&*ad.fs) {
            Ok(Some(bundle)) => bundle,
            _ => layout.version_dir(version),
        };
        let entry = boot
            .meta()
            .entry
            .components()
            .fold(tree, |dir, part| dir.join(part));
        let installed = Installation::from_exe_with(&entry, ad.platform.clone()).ok()?;
        let spec = SpawnSpec {
            program: installed.entry_path(),
            args: Vec::new(),
            env_set: Vec::new(),
            env_remove: vec![OsString::from(HEALTH_TOKEN_VAR)],
            stdio: ChildStdio::Null,
        };
        ad.process.spawn_detached(&spec).ok()
    });
    if started.is_none() {
        events.emit(&Event::warning(Warning::RelaunchFailed, Some(version)));
    }
}

fn report(boot: &Installation, result: Result<Version, Kind>) -> (Kind, Event) {
    let tree_version = Some(boot.tree_version().clone());
    match result {
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
                reason: kind.reason(),
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
