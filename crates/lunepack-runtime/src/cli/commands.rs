//! The app-facing commands (C4, D42): each a thin layer over the facade, so a Rust app and a
//! program that runs this binary get the same behaviour and the same errors. Nothing is decided
//! here: the facade's results are mapped to the closed objects of [`super::json`], and its errors
//! to a [`Kind`].

use lunepack::{
    ApplyOptions, CancelToken, CheckOptions, CheckOutcome, DownloadOptions, HEALTH_TOKEN_VAR,
    Installation, Platform, UiChoice, blocking,
};

use super::WaitTarget;
use super::args::{Command, Parsed};
use super::json::{Body, UpdateSummary};
use super::progress::Output;
use crate::modes::Kind;

/// The platform the commands run on: the runtime's adapters, with the health token of this
/// process's environment (an app's child inherits the one the supervisor gave it; the runtime
/// itself is not a supervised start).
pub fn platform(base: &Platform) -> Platform {
    base.clone()
        .with_health_token(std::env::var_os(HEALTH_TOKEN_VAR))
}

/// Runs `parsed` for the tree `inst`. Progress goes to `output`; `cancel` ends a long operation;
/// `wait` is the process `apply-and-restart` waits for (`None` for the other commands).
pub fn run(
    inst: &Installation,
    parsed: &Parsed,
    output: &Output,
    cancel: &CancelToken,
    wait: Option<WaitTarget>,
) -> Result<Body, Kind> {
    match parsed.command {
        Command::Check => check(inst, parsed, output, cancel),
        Command::Download => download(inst, parsed, output, cancel),
        Command::Startup => startup(inst, parsed),
        Command::Confirm => confirm(inst),
        Command::ApplyAndRestart => apply_and_restart(inst, parsed, wait),
    }
}

fn updater(inst: &Installation, parsed: &Parsed) -> Result<blocking::Updater, Kind> {
    // No network and no state before this: a tree that is not installed has nothing to check,
    // unless it is a macOS bundle the check may adopt (M8-D9).
    if !inst.is_installed() && !inst.adoptable() {
        return Err(Kind::NotInstalled);
    }
    let mut builder = inst.updater_builder().map_err(|e| Kind::of(&e))?;
    if let Some(channel) = &parsed.channel {
        builder = builder.channel(channel.clone());
    }
    let updater = builder.build().map_err(|e| Kind::of(&e))?;
    Ok(blocking::Updater::from(updater))
}

/// The check, with progress (only an adoption reports any, phase `adopt`).
fn checked(
    updater: &blocking::Updater,
    output: &Output,
    cancel: &CancelToken,
) -> Result<CheckOutcome, Kind> {
    let options = CheckOptions {
        progress: Some(output.callback()),
        cancel: None,
    };
    updater
        .check_with(options, cancel)
        .map_err(|e| Kind::of(&e))
}

fn check(
    inst: &Installation,
    parsed: &Parsed,
    output: &Output,
    cancel: &CancelToken,
) -> Result<Body, Kind> {
    let updater = updater(inst, parsed)?;
    let outcome = checked(&updater, output, cancel)?;
    Ok(Body::Check {
        update: outcome.update.map(|info| UpdateSummary {
            version: info.version().clone(),
            download_size_max: info.download_size_max(),
            time_checked: info.time_checked(),
        }),
        adopted: outcome.adopted,
    })
}

/// `download` runs its own check: it never takes an update description from its caller, and it
/// may be told the version the app expects (another one is an error, never a downgrade).
fn download(
    inst: &Installation,
    parsed: &Parsed,
    output: &Output,
    cancel: &CancelToken,
) -> Result<Body, Kind> {
    let updater = updater(inst, parsed)?;
    let Some(info) = checked(&updater, output, cancel)?.update else {
        return Ok(Body::Download(None));
    };
    if let Some(expected) = &parsed.expect_version
        && (expected != info.version() || expected.to_string() != info.version().to_string())
    {
        return Err(Kind::UnexpectedVersion);
    }
    let options = |output: &Output| DownloadOptions {
        progress: Some(output.callback()),
        cancel: None,
    };
    let downloaded = updater
        .download(&info, options(output), cancel)
        .map_err(|e| Kind::of(&e))?
        .with_options(options(output));
    let staged = updater
        .stage(downloaded, cancel)
        .map_err(|e| Kind::of(&e))?;
    Ok(Body::Download(Some(staged.version().clone())))
}

fn startup(inst: &Installation, parsed: &Parsed) -> Result<Body, Kind> {
    let started =
        lunepack::startup_for(inst, parsed.passed_args.clone()).map_err(|e| Kind::of(&e))?;
    Ok(Body::Startup {
        events: started.events,
        exit: started.action == lunepack::StartupAction::Exit,
        pending: started.pending,
    })
}

fn confirm(inst: &Installation) -> Result<Body, Kind> {
    let outcome = lunepack::confirm_for(inst).map_err(|e| Kind::of(&e))?;
    Ok(Body::Confirm(match outcome {
        lunepack::ConfirmOutcome::Confirmed => "confirmed",
        lunepack::ConfirmOutcome::NothingPending => "nothing_pending",
    }))
}

/// `apply-and-restart`: the facade starts this tree's runtime detached (`apply`, standard streams
/// null, a new session; with `--no-ui` the applier shows no update window), which waits for `wait`, applies the staged version and starts the new
/// tree's entry with the arguments after `--`. Nothing is started when the wait target is not a
/// running process, when nothing usable is staged, or when the staged version is not the one
/// `--expect-version` names. The target is only ever waited on.
fn apply_and_restart(
    inst: &Installation,
    parsed: &Parsed,
    wait: Option<WaitTarget>,
) -> Result<Body, Kind> {
    // Read at the start of the process (main.rs); a command without one is a wiring fault.
    let wait = wait.ok_or(Kind::Internal)??;
    let scheduled = lunepack::apply_and_restart_for(
        inst,
        ApplyOptions {
            expect_version: parsed.expect_version.clone(),
            wait_for: Some(wait),
            restart_args: parsed.passed_args.clone(),
            ui: if parsed.no_ui {
                UiChoice::Never
            } else {
                UiChoice::Auto
            },
        },
    )
    .map_err(|e| Kind::of(&e))?;
    Ok(Body::ApplyAndRestart(scheduled.version().clone()))
}
