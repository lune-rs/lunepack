//! `lunepack-runtime`: the per-version runtime (C4). This file is its composition root: it wires
//! the core's traits to the default adapters and hands them to the mode the command line names.
//!
//! Modes: `apply` (internal; started detached by `lunepack::apply_and_restart`), `install` (from a
//! bootstrap tree) and `uninstall` (from the installed tree). `install` and `uninstall` are
//! headless: their events go to stderr and their final result or error is one JSON line on
//! stdout. A command line that does not follow the grammar prints one fixed line on stderr and
//! exits 2 before anything else happens. Nothing this binary prints holds a path, an argument
//! value, the health token or an error's own text (C4 Output).

// Off Linux the modes are compiled (and checked) but not wired.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod apply;
mod cli;
mod events;
mod gc;
mod install;
mod modes;
mod uninstall;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use events::{Event, Events, LogSink, StderrSink};
use modes::{Kind, Mode, USAGE_LINE};

/// How long the sinks get to write out what they hold before the process exits.
const SINK_DRAIN: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let mode = match modes::parse(&args) {
        Ok(mode) => mode,
        Err(modes::UsageError) => {
            // With `--json` before any `--`, even a refusal is an object on stdout (C4 Output).
            if cli::args::wants_json(&args) {
                println!("{}", cli::json::error_line(None, None, Kind::Usage));
            } else {
                eprintln!("{USAGE_LINE}");
            }
            return ExitCode::from(Kind::Usage.code());
        }
    };
    let kind = match mode {
        Mode::Apply(args) => run(|ad| {
            let inst = lunepack::Installation::from_current_exe_with(ad.platform.clone());
            let inst = match inst {
                Ok(inst) => inst,
                Err(e) => return fail(apply::COMMAND, Kind::of(&e)),
            };
            let events = events_for(ad, &inst);
            let kind = apply::run_apply(ad, &inst, &args, &events);
            events.finish(SINK_DRAIN);
            kind
        }),
        Mode::Command(parsed) => run(|ad| cli::execute(ad, &parsed)),
        // R is `<data home>/<app id>`, with the data home from this environment (M5-D2).
        Mode::Install => run(|ad| {
            let data_home = match data_home() {
                Ok(dir) => dir,
                Err(kind) => return headless_fail(install::COMMAND, kind),
            };
            let platform = ad.platform.clone().with_data_home(data_home);
            let boot = match lunepack::Installation::from_current_exe_with(platform) {
                Ok(boot) => boot,
                Err(e) => return headless_fail(install::COMMAND, Kind::of(&e)),
            };
            let events = stderr_events();
            let (kind, last) = install::run_install(ad, &boot, &events);
            conclude(events, &last);
            kind
        }),
        // The log lives in R, which this mode removes: events go to stderr.
        Mode::Uninstall => run(|ad| {
            let data_home = match data_home() {
                Ok(dir) => dir,
                Err(kind) => return headless_fail(uninstall::COMMAND, kind),
            };
            let inst = match lunepack::Installation::from_current_exe_with(ad.platform.clone()) {
                Ok(inst) => inst,
                Err(e) => return headless_fail(uninstall::COMMAND, Kind::of(&e)),
            };
            let events = stderr_events();
            let (kind, last) = uninstall::run_uninstall(ad, &inst, &data_home, &events);
            conclude(events, &last);
            kind
        }),
    };
    ExitCode::from(kind.code())
}

fn stderr_events() -> Events {
    Events::new(Some(Box::new(StderrSink)), None)
}

/// Ends a headless mode: `last` to the sinks, then as the one line on stdout.
fn conclude(events: Events, last: &Event) {
    events.emit(last);
    events.finish(SINK_DRAIN);
    let mut line = events::to_json_line(last);
    line.push('\n');
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
}

/// A headless mode that failed before its tree was known.
fn headless_fail(command: &'static str, kind: Kind) -> Kind {
    conclude(
        stderr_events(),
        &Event::Error {
            command,
            tree_version: None,
            kind: kind.name(),
            exit_code: kind.code(),
        },
    );
    kind
}

/// The per-user data home of this environment (`XDG_DATA_HOME`, else `$HOME/.local/share`),
/// canonical (M5-D2).
#[cfg(target_os = "linux")]
fn data_home() -> Result<PathBuf, Kind> {
    let dirs = lunepack_os_linux::xdg_dirs(&lunepack_os_linux::XdgEnv::from_process())
        .map_err(|e| Kind::of(&e.into()))?;
    Ok(dirs.data_home().to_path_buf())
}

#[cfg(not(target_os = "linux"))]
fn data_home() -> Result<PathBuf, Kind> {
    Err(Kind::Unsupported)
}

/// The events of a mode: to `R/logs/runtime.log` when the tree is installed, else to stderr
/// (M5-D15). No UI sink in M5.
fn events_for(ad: &modes::Adapters, inst: &lunepack::Installation) -> Events {
    match inst.layout() {
        Some(layout) => Events::new(
            Some(Box::new(LogSink::new(
                std::sync::Arc::clone(&ad.fs),
                layout.logs_dir(),
            ))),
            None,
        ),
        None => Events::new(Some(Box::new(StderrSink)), None),
    }
}

/// Reports a failure that happened before the install (and so the log) was known: one JSON
/// error line on stderr.
fn fail(command: &'static str, kind: Kind) -> Kind {
    let events = Events::new(Some(Box::new(StderrSink)), None);
    events.emit(&Event::Error {
        command,
        tree_version: None,
        kind: kind.name(),
        exit_code: kind.code(),
    });
    events.finish(SINK_DRAIN);
    kind
}

/// Runs `body` on the native adapters.
#[cfg(target_os = "linux")]
fn run(body: impl FnOnce(&modes::Adapters) -> Kind) -> Kind {
    use std::sync::Arc;

    let fs: Arc<dyn lunepack::Fs> = Arc::new(lunepack_fs::StdFs::new());
    let hasher: Arc<dyn lunepack::Hasher> = Arc::new(lunepack_crypto::Sha256Hasher);
    let process: Arc<dyn lunepack::Process> = Arc::new(lunepack_os_linux::LinuxProcess::new());
    let integration: Arc<dyn lunepack::OsIntegration> =
        Arc::new(lunepack_os_linux::XdgIntegration::from_process_env());
    let rng: Arc<dyn lunepack::Rng> = Arc::new(lunepack_crypto::OsRng);
    let platform = lunepack::Platform::native()
        .with_fs(Arc::clone(&fs))
        .with_hasher(Arc::clone(&hasher))
        .with_verifier(Arc::new(lunepack_crypto::Ed25519Verifier))
        .with_process(Arc::clone(&process))
        .with_integration(Arc::clone(&integration))
        .with_rng(Arc::clone(&rng))
        // The runtime is never a supervised start itself.
        .with_health_token(None);
    body(&modes::Adapters {
        fs,
        hasher,
        process,
        integration,
        rng,
        platform,
    })
}

/// Processes and the desktop integration have no adapter here yet (M7, M8).
#[cfg(not(target_os = "linux"))]
fn run(_body: impl FnOnce(&modes::Adapters) -> Kind) -> Kind {
    fail("runtime", Kind::Unsupported)
}
