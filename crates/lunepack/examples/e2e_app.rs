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
//! Then it confirms its health. Two arguments serve the Windows suite (`scripts/e2e-windows.ps1`):
//! `--hold <secs>` keeps the process alive that long (writing `hold` first), so a running image
//! can be replaced or collected around it, and `--check <n>` runs the sibling runtime's
//! `check --json` `n` times with default `std::process::Command` flags and writes `check-run
//! <exit code>` after each, to see that the runtime opens no console of its own; `--aumid`
//! writes `aumid <id>` with the process's explicit app user model id (Windows; `aumid none` when
//! it has none or off Windows), which the suite compares with the Start-menu shortcut's. With
//! `--update` it checks the feed, downloads and stages what it
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
    /// `hold <secs>`: stay alive that long after confirming (macOS rows read `ps` meanwhile).
    hold: Option<u64>,
}

fn read_flags(tree: &Path) -> Flags {
    let mut flags = Flags::default();
    // A macOS bundle keeps the marker under `Contents/Resources` (a file at the bundle's root
    // would break a signature's seal).
    let text = std::fs::read_to_string(tree.join(FLAGS_FILE))
        .or_else(|_| std::fs::read_to_string(tree.join("Contents/Resources").join(FLAGS_FILE)));
    let Ok(text) = text else {
        return flags;
    };
    for line in text.lines() {
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some("crash-on-start"), None) => flags.crash = true,
            (Some("exit-without-confirm"), None) => flags.exit_without_confirm = true,
            (Some("slow-confirm"), Some(secs)) => flags.slow_confirm = secs.parse().ok(),
            (Some("hold"), Some(secs)) => flags.hold = secs.parse().ok(),
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

    // The macOS rows compare this with `ps` (the token must never be in an argv): it is noted
    // only when the row asks for it, and goes to the detail file, never to the outcome file.
    if std::env::var_os("LUNEPACK_E2E_NOTE_TOKEN").is_some() {
        let token = std::env::var("LUNEPACK_HEALTH_TOKEN").unwrap_or_default();
        note(DETAIL_VAR, &format!("{version} token {token}"));
    }
    if let Some(secs) = flags.hold {
        out("hold");
        std::thread::sleep(Duration::from_secs(secs));
    }
    if let Some(secs) = arg_value(&args, "--hold") {
        out("hold");
        std::thread::sleep(Duration::from_secs(secs));
    }
    if args.iter().any(|a| a == "--aumid") {
        out(&format!("aumid {}", process_aumid()));
    }
    if let Some(runs) = arg_value(&args, "--check") {
        check_runs(&inst, runs, &out);
    }
    if args.iter().any(|a| a == "--update") {
        let no_ui = args.iter().any(|a| a == "--no-ui");
        let background = args.iter().any(|a| a == "--background");
        return match update(&inst, no_ui, background) {
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

/// This process's explicit app user model id (set by [`lunepack::startup`]), `none` when it has
/// none; `error` when the system cannot say.
#[cfg(windows)]
fn process_aumid() -> String {
    match lunepack_os_windows::process_aumid() {
        Ok(Some(id)) => id,
        Ok(None) => "none".to_owned(),
        Err(_) => "error".to_owned(),
    }
}

/// Only Windows has an app user model id.
#[cfg(not(windows))]
fn process_aumid() -> String {
    "none".to_owned()
}

/// The number that follows `flag` among `args`.
fn arg_value(args: &[OsString], flag: &str) -> Option<u64> {
    let at = args.iter().position(|a| a == flag)?;
    args.get(at + 1)?.to_str()?.parse().ok()
}

/// Runs the runtime beside the entry `runs` times with `check --json`, all default process flags
/// (so a runtime that was a console program would open a console of its own when this app has
/// none; the suite starts it with no console), and writes each exit code.
fn check_runs(inst: &Installation, runs: u64, out: &dyn Fn(&str)) {
    let name = if cfg!(windows) {
        "lunepack-runtime.exe"
    } else {
        "lunepack-runtime"
    };
    let Some(dir) = inst.entry_path().parent().map(Path::to_path_buf) else {
        out("error check-run");
        return;
    };
    // The control of the Windows suite's console check: a console program started the same way
    // by an app that has no console (a ping, a console program) gets a console host of its own, which the suite's sampler
    // must see (else it proves nothing about the runtime).
    #[cfg(windows)]
    let control = std::process::Command::new("ping.exe")
        .args(["-n", "4", "127.0.0.1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok();
    for _ in 0..runs {
        let code = std::process::Command::new(dir.join(name))
            .args(["check", "--json"])
            .output()
            .ok()
            .and_then(|output| output.status.code());
        out(&format!(
            "check-run {}",
            code.map_or_else(|| "none".to_owned(), |c| c.to_string())
        ));
    }
    #[cfg(windows)]
    if let Some(mut control) = control {
        let _ = control.wait();
    }
}

/// Check, download, stage and hand over. Returns the last outcome line; the earlier ones are
/// written on the way.
fn update(inst: &Installation, no_ui: bool, background: bool) -> Result<String, &'static str> {
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
        background,
    })
    .map_err(|_| "apply")?;
    Ok("apply-scheduled".to_owned())
}
