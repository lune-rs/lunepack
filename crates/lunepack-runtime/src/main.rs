//! `lunepack-runtime`: the per-version runtime (C4). This file is its composition root: it wires
//! the core's traits to the default adapters and hands them to the mode the command line names.
//!
//! Modes in M5 step 8: `apply` (internal; started detached by `lunepack::apply_and_restart`).
//! A command line that does not follow the grammar prints one fixed line on stderr and exits 2
//! before anything else happens. Nothing this binary prints holds a path, an argument value, the
//! health token or an error's own text (C4 Output).

// Off Linux the modes are compiled (and checked) but not wired.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod apply;
mod events;
mod gc;
mod modes;

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
            eprintln!("{USAGE_LINE}");
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
    };
    ExitCode::from(kind.code())
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
