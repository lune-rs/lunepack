//! The Rust app of the end-to-end suite (M5-D13), and a worked example of an app that updates
//! itself through the library.
//!
//! At every start it calls [`lunepack::startup`] first, then acts on a marker file in its own
//! tree, `e2e-flags` at the tree's root, one directive per line:
//!
//! - `crash-on-start`: exit 3 without confirming;
//! - `exit-without-confirm`: exit 0 without confirming;
//! - `slow-confirm <secs>`: sleep that long before confirming.
//!
//! Then it confirms its health. With `--update` it checks the feed, downloads and stages what it
//! finds and hands it to the runtime with [`lunepack::apply_and_restart`], passing
//! `--after-update` as the restart argument; with `--no-ui` as well, the applier shows no
//! window ([`lunepack::UiChoice::Never`]).
//!
//! The harness names two files in the environment. `LUNEPACK_E2E_OUT` gets one line per outcome,
//! `<tree version> <outcome>`: versions and outcomes only, so the suite can compare runs of
//! different apps. `LUNEPACK_E2E_DETAIL` gets facts that differ by app (the executable's real
//! path). Neither is written when its variable is unset.
//!
//! A failure prints nothing and writes `<version> error <stage>` to the outcome file.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use lunepack::{
    ApplyOptions, CancelToken, ConfirmOutcome, DownloadOptions, Installation, LifecycleEvent,
    StartupAction, blocking,
};

const OUT_VAR: &str = "LUNEPACK_E2E_OUT";
const DETAIL_VAR: &str = "LUNEPACK_E2E_DETAIL";
const FLAGS_FILE: &str = "e2e-flags";
const AFTER_UPDATE: &str = "--after-update";

/// Appends one line to the file `var` names (one `write`, so concurrent processes interleave
/// whole lines).
fn note(var: &str, line: &str) {
    let Some(path) = std::env::var_os(var) else {
        return;
    };
    let mut line = line.to_owned();
    line.push('\n');
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = file.write_all(line.as_bytes());
    }
}

/// What the marker file asks for.
#[derive(Default)]
struct Flags {
    crash: bool,
    exit_without_confirm: bool,
    slow_confirm: Option<u64>,
}

fn read_flags(tree: &Path) -> Flags {
    let mut flags = Flags::default();
    let Ok(text) = std::fs::read_to_string(tree.join(FLAGS_FILE)) else {
        return flags;
    };
    for line in text.lines() {
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some("crash-on-start"), None) => flags.crash = true,
            (Some("exit-without-confirm"), None) => flags.exit_without_confirm = true,
            (Some("slow-confirm"), Some(secs)) => flags.slow_confirm = secs.parse().ok(),
            _ => {}
        }
    }
    flags
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let started = lunepack::startup();
    let Ok(inst) = Installation::from_current_exe() else {
        note(OUT_VAR, "- error locate");
        return ExitCode::from(1);
    };
    let version = inst.tree_version().to_string();
    let out = |line: &str| note(OUT_VAR, &format!("{version} {line}"));
    let Ok(startup) = started else {
        out("error startup");
        return ExitCode::from(1);
    };
    if let Ok(exe) = std::env::current_exe() {
        note(DETAIL_VAR, &format!("{version} exe {}", exe.display()));
    }
    out("start");
    if args.iter().any(|a| a == AFTER_UPDATE) {
        out("arg after-update");
    }
    for event in &startup.events {
        match event {
            LifecycleEvent::Installed { .. } => out("event installed"),
            LifecycleEvent::FirstRun { .. } => out("event first_run"),
            LifecycleEvent::Updated { from, .. } => out(&format!("event updated {from}")),
        }
    }
    if startup.action == StartupAction::Exit {
        out("exit rolled-back");
        return ExitCode::SUCCESS;
    }

    let flags = read_flags(inst.tree_root());
    if flags.crash {
        out("crash");
        return ExitCode::from(3);
    }
    if flags.exit_without_confirm {
        out("exit-without-confirm");
        return ExitCode::SUCCESS;
    }
    if let Some(secs) = flags.slow_confirm {
        out("slow-confirm");
        std::thread::sleep(Duration::from_secs(secs));
    }
    match lunepack::confirm_healthy() {
        Ok(ConfirmOutcome::Confirmed) => out("confirmed"),
        Ok(ConfirmOutcome::NothingPending) => out("nothing-pending"),
        Err(lunepack::Error::TokenMismatch) => {
            out("error token-mismatch");
            return ExitCode::from(1);
        }
        Err(_) => {
            out("error confirm");
            return ExitCode::from(1);
        }
    }

    if args.iter().any(|a| a == "--update") {
        let no_ui = args.iter().any(|a| a == "--no-ui");
        return match update(&inst, no_ui) {
            Ok(line) => {
                out(&line);
                ExitCode::SUCCESS
            }
            Err(stage) => {
                out(&format!("error {stage}"));
                ExitCode::from(1)
            }
        };
    }
    ExitCode::SUCCESS
}

/// Check, download, stage and hand over. Returns the last outcome line; the earlier ones are
/// written on the way.
fn update(inst: &Installation, no_ui: bool) -> Result<String, &'static str> {
    let version = inst.tree_version().to_string();
    let out = |line: &str| note(OUT_VAR, &format!("{version} {line}"));
    let builder = inst.updater_builder().map_err(|_| "builder")?;
    let updater = blocking::Updater::from(builder.build().map_err(|_| "builder")?);
    let cancel = CancelToken::new();
    let Some(info) = updater.check(&cancel).map_err(|_| "check")? else {
        return Ok("check none".to_owned());
    };
    out(&format!("check {}", info.version()));
    let downloaded = updater
        .download(&info, DownloadOptions::default(), &cancel)
        .map_err(|_| "download")?;
    let staged = updater.stage(downloaded, &cancel).map_err(|_| "stage")?;
    out(&format!("staged {}", staged.version()));
    lunepack::apply_and_restart(ApplyOptions {
        expect_version: Some(staged.version().clone()),
        wait_for: None,
        restart_args: vec![OsString::from(AFTER_UPDATE)],
        ui: if no_ui {
            lunepack::UiChoice::Never
        } else {
            lunepack::UiChoice::Auto
        },
    })
    .map_err(|_| "apply")?;
    Ok("apply-scheduled".to_owned())
}
