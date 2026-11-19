//! `lunepack-runtime`: the per-version runtime (C4). This file is its composition root: it wires
//! the core's traits to the default adapters and hands them to the mode the command line names.
//!
//! Modes: `apply` (internal; started detached by `lunepack::apply_and_restart`), `install` (from a
//! bootstrap tree) and `uninstall` (from the installed tree). Each starts the `lunepack-ui` process
//! beside it when it may (M6, [`ui_host`]); the UI only shows and asks, and without it the mode runs
//! headless. `install` and `uninstall` write their events to stderr and their final result or
//! error as one JSON line on stdout. A command line that does not follow the grammar prints one fixed line on stderr and
//! exits 2 before anything else happens. Nothing this binary prints holds a path, an argument
//! value, the health token or an error's own text (C4 Output).

// Off Linux the modes are compiled (and checked) but not wired.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
// A Windows-subsystem binary (M7-D6): no console window ever appears when an app starts it,
// whatever spawn flags the app's language uses. Piped stdio works because the parent passes the
// handles; typed in `cmd` it returns at once and prints nothing visible unless redirected.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod apply;
mod cli;
mod events;
mod gc;
mod install;
mod modes;
mod setup;
mod tempdirs;
mod ui_host;
mod uninstall;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use events::{Event, Events, LogSink, Sink, StderrSink};
use lunepack_core::ui::{AppCard, Details, Flow, MAX_LOCATION};
use modes::{Kind, Mode, USAGE_LINE};
use ui_host::UiHost;

/// How long the sinks get to write out what they hold before the process exits.
const SINK_DRAIN: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    // First, before any library load: only System32 from here on (M7-D10).
    #[cfg(windows)]
    lunepack_os_windows::harden_dll_search();
    // `apply-and-restart` waits for its parent by default (C4): named now, before anything else,
    // so the parent cannot have exited and had its pid reused by the time the target is read.
    let parent = initial_parent();
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    // A setup file (M6 step 7) is this runtime with a payload and a trailer at its end; that is
    // looked at before the command line, and a runtime without the trailer goes on unchanged.
    if let Some(kind) = setup_mode(&args) {
        return ExitCode::from(kind.code());
    }
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
            let ui = ui_for(
                ad,
                args.no_ui,
                Flow::Update,
                ui_host::card(
                    &inst.meta().name,
                    &args.version.to_string(),
                    Some(&inst.tree_version().to_string()),
                ),
                None,
            );
            let events = events_for(ad, &inst, ui.sink());
            ui.report(&events);
            let kind = apply::run_apply(ad, &inst, &args, &events, &ui);
            ui.close(&events);
            events.finish(SINK_DRAIN);
            kind
        }),
        Mode::Command(parsed) => {
            // A pid given on the command line is named (with its start time) at once, too.
            let wait = (parsed.command == cli::args::Command::ApplyAndRestart)
                .then(|| wait_target(parsed.wait_pid, parent));
            run(|ad| cli::execute(ad, &parsed, wait))
        }
        // R is `<data home>/<app id>`, with the data home from this environment (M5-D2).
        Mode::Install { silent } => run(|ad| {
            let data_home = match data_home() {
                Ok(dir) => dir,
                Err(kind) => return headless_fail(install::COMMAND, kind),
            };
            clear_temp_dirs(ad);
            let platform = ad.platform.clone().with_data_home(data_home);
            let boot = match lunepack::Installation::from_current_exe_with(platform) {
                Ok(boot) => boot,
                Err(e) => return headless_fail(install::COMMAND, Kind::of(&e)),
            };
            let ui = ui_for(
                ad,
                silent,
                Flow::Install,
                ui_host::card(&boot.meta().name, &boot.tree_version().to_string(), None),
                boot.install_root().ok(),
            );
            let events = Events::new(Some(Box::new(StderrSink)), ui.sink());
            ui.report(&events);
            let (kind, last) = install::run_install(ad, &boot, &events, &ui);
            let seen = ui.outcome_acknowledged();
            ui.close(&events);
            conclude(events, &last);
            notice(silent, seen, &boot.meta().name, Operation::Install, kind);
            kind
        }),
        // The log lives in R, which this mode removes: events go to stderr. On Windows this is
        // phase 1 of the hand-off (M7-D5).
        Mode::Uninstall { silent } => run(|ad| {
            let data_home = match data_home() {
                Ok(dir) => dir,
                Err(kind) => return headless_fail(uninstall::COMMAND, kind),
            };
            let inst = match lunepack::Installation::from_current_exe_with(ad.platform.clone()) {
                Ok(inst) => inst,
                Err(e) => return headless_fail(uninstall::COMMAND, Kind::of(&e)),
            };
            uninstall_mode(ad, &inst, &data_home, silent)
        }),
        // Windows: phase 2, from the uninstaller's own temp copy only; anywhere else a usage
        // error before any action (M7-D5).
        Mode::UninstallHandOff(args) => run(|ad| hand_off_phase_2(ad, &args)),
    };
    ExitCode::from(kind.code())
}

/// Windows: phase 1 of the hand-off; it prints nothing when phase 2 was started (M7-D5).
#[cfg(windows)]
fn uninstall_mode(
    ad: &modes::Adapters,
    inst: &lunepack::Installation,
    data_home: &std::path::Path,
    silent: bool,
) -> Kind {
    let Some(temp) = tempdirs::temp_home() else {
        return headless_fail(uninstall::COMMAND, Kind::Fs);
    };
    clear_temp_dirs(ad);
    match uninstall::hand_off(ad, inst, data_home, &temp, silent) {
        Ok(()) => Kind::Ok,
        Err(kind) => headless_fail(uninstall::COMMAND, kind),
    }
}

#[cfg(not(windows))]
fn uninstall_mode(
    ad: &modes::Adapters,
    inst: &lunepack::Installation,
    data_home: &std::path::Path,
    silent: bool,
) -> Kind {
    uninstall_flow(ad, inst, data_home, silent)
}

/// The uninstall of `inst` with its UI and its outcome (M5-D10, M6): the confirm prompt, the
/// removal, the done or failed prompt, the result line and a native notice where one is due.
fn uninstall_flow(
    ad: &modes::Adapters,
    inst: &lunepack::Installation,
    data_home: &std::path::Path,
    silent: bool,
) -> Kind {
    let ui = ui_for(
        ad,
        silent,
        Flow::Uninstall,
        ui_host::card(&inst.meta().name, &inst.tree_version().to_string(), None),
        inst.layout().map(|l| l.root().to_path_buf()),
    );
    let events = Events::new(Some(Box::new(StderrSink)), ui.sink());
    ui.report(&events);
    let (kind, last) = uninstall::run_uninstall(ad, inst, data_home, &events, &ui);
    let seen = ui.outcome_acknowledged();
    ui.close(&events);
    conclude(events, &last);
    notice(silent, seen, &inst.meta().name, Operation::Uninstall, kind);
    kind
}

/// Phase 2 of the Windows uninstall hand-off (M7-D5): the own-directory rule first (a usage error
/// before any action), then the wait for phase 1, the root's validation and the uninstall. The
/// UI's copy is removed after it exited; this runtime's copy and the marker stay for a later run's
/// cleanup.
#[cfg(windows)]
fn hand_off_phase_2(ad: &modes::Adapters, args: &modes::HandOffArgs) -> Kind {
    let Some((dir, marker)) =
        tempdirs::temp_home().and_then(|temp| uninstall::hand_off_copy(ad, &temp))
    else {
        eprintln!("{USAGE_LINE}");
        return Kind::Usage;
    };
    // Nothing of this process stays inside `R`.
    let _ = std::env::set_current_dir(&dir);
    // A timeout or an unreadable process is not an error here: the in-use check decides.
    let _ = ad.process.wait_exit(&args.wait, uninstall::HAND_OFF_WAIT);
    let data_home = match data_home() {
        Ok(dir) => dir,
        Err(kind) => return headless_fail(uninstall::COMMAND, kind),
    };
    let inst = match uninstall::hand_off_installation(
        ad,
        &data_home,
        &args.install_root,
        &marker.app_id,
    ) {
        Ok(inst) => inst,
        Err(kind) => return headless_fail(uninstall::COMMAND, kind),
    };
    let kind = uninstall_flow(ad, &inst, &data_home, args.silent);
    // The UI has exited (`close` waited for it): its copy goes, best effort.
    let ui_copy = dir.join(ui_host::UI_FILE);
    if matches!(ad.fs.symlink_metadata(&ui_copy), Ok(Some(m)) if m.kind == lunepack::FileKind::File)
    {
        let _ = ad.fs.remove_file(&ui_copy);
    }
    kind
}

/// `--install-root` exists only on Windows; the parser refuses it elsewhere.
#[cfg(not(windows))]
fn hand_off_phase_2(_ad: &modes::Adapters, _args: &modes::HandOffArgs) -> Kind {
    eprintln!("{USAGE_LINE}");
    Kind::Usage
}

/// Whether process `pid` started at `start` runs; a process that cannot be read counts as running.
#[cfg(any(target_os = "linux", windows))]
fn alive(pid: u32, start: u64) -> bool {
    #[cfg(target_os = "linux")]
    let found = lunepack_os_linux::LinuxProcess::new().process_id(pid);
    #[cfg(windows)]
    let found = lunepack_os_windows::WindowsProcess::new().process_id(pid);
    match found {
        Ok(Some(id)) => id.start_ticks == start,
        Ok(None) => false,
        Err(_) => true,
    }
}

/// Windows: removes earlier runs' stale directories under the temp dir (M7-D5, M7-D13): a
/// directory's owner must have exited and no process may run from it. Best effort.
#[cfg(windows)]
fn clear_temp_dirs(ad: &modes::Adapters) {
    let Some(temp) = tempdirs::temp_home() else {
        return;
    };
    let in_use = |dir: &std::path::Path| !matches!(ad.process.tree_in_use(dir, &[]), Ok(false));
    tempdirs::clear_stale(&*ad.fs, &temp, &alive, &in_use);
}

/// Linux keeps its setup UI under the app's cache, cleared by the setup itself (M6-D7).
#[cfg(not(windows))]
fn clear_temp_dirs(_ad: &modes::Adapters) {}

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

/// The interactive modes whose end may need a native notice.
#[derive(Clone, Copy)]
#[cfg_attr(not(windows), allow(dead_code))]
enum Operation {
    Install,
    Uninstall,
    /// A setup run that ended before it knew the app (no name to show): its title is fixed.
    Setup,
}

/// The title of a native notice for a setup run that failed before the app's name was verified.
#[cfg(any(target_os = "linux", windows))]
const SETUP_TITLE: &str = "Setup";

/// The fixed text of a native notice: the app's validated display name, what happened and the
/// closed result code (D36). Never a path, a value or an error's own text.
#[cfg_attr(not(windows), allow(dead_code))]
fn notice_text(name: &str, operation: Operation, kind: Kind) -> String {
    let (done, failed) = match operation {
        Operation::Install => ("was installed.", "could not be installed"),
        Operation::Uninstall => ("was uninstalled.", "could not be uninstalled"),
        Operation::Setup => ("finished.", "could not finish"),
    };
    if kind == Kind::Ok {
        format!("{name} {done}")
    } else {
        format!("{name} {failed} (code {}).", kind.code())
    }
}

/// Windows: an interactive install or uninstall that ended without a UI that showed its outcome
/// (no UI binary, one that failed to start or was lost) shows one native message box, because a
/// Windows-subsystem process has no console to say it on (D36, M7-D6). Only after the outcome
/// is committed; never under `--silent`, `--no-ui` or `LUNEPACK_NO_UI`, and never for a
/// cancellation the user chose. `seen`: the UI itself answered the prompt after the outcome.
#[cfg(windows)]
fn notice(quiet: bool, seen: bool, name: &str, operation: Operation, kind: Kind) {
    let env = |var: &str| std::env::var_os(var);
    if seen || kind == Kind::Cancelled || !ui_host::ui_wanted(quiet, &env) {
        return;
    }
    let level = if kind == Kind::Ok {
        lunepack_os_windows::MessageKind::Info
    } else {
        lunepack_os_windows::MessageKind::Error
    };
    let _ = lunepack_os_windows::message_box(name, &notice_text(name, operation, kind), level);
}

/// Other platforms print their outcome on the terminal; no native notice.
#[cfg(not(windows))]
fn notice(_quiet: bool, _seen: bool, _name: &str, _operation: Operation, _kind: Kind) {}

/// A path as the UI shows it: Windows' `\\?\X:\` prefix of a canonical path is dropped.
fn shown_path(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    if let Some(text) = path.to_str()
        && let Some(rest) = text.strip_prefix(r"\\?\")
        && rest.as_bytes().get(1) == Some(&b':')
    {
        return PathBuf::from(rest);
    }
    path
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

/// The per-user program files folder (M7-D2), canonical when it exists: the executable's path is
/// canonical too, so the parent of an install root compares equal to it (M7-D16).
#[cfg(windows)]
fn data_home() -> Result<PathBuf, Kind> {
    let dir = lunepack_os_windows::user_program_files().map_err(|_| Kind::Fs)?;
    Ok(std::fs::canonicalize(&dir).unwrap_or(dir))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn data_home() -> Result<PathBuf, Kind> {
    Err(Kind::Unsupported)
}

/// The parent process as this process started: its id, or why it cannot be waited for (pid 1,
/// gone, a zombie, unreadable: `process`).
#[cfg(target_os = "linux")]
fn initial_parent() -> cli::WaitTarget {
    use lunepack::Process as _;
    match lunepack_os_linux::LinuxProcess::new().parent() {
        Ok(Some(id)) => Ok(id),
        Ok(None) | Err(_) => Err(Kind::Process),
    }
}

#[cfg(windows)]
fn initial_parent() -> cli::WaitTarget {
    use lunepack::Process as _;
    match lunepack_os_windows::WindowsProcess::new().parent() {
        Ok(Some(id)) => Ok(id),
        Ok(None) | Err(_) => Err(Kind::Process),
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn initial_parent() -> cli::WaitTarget {
    Err(Kind::Unsupported)
}

/// The wait target of `apply-and-restart`: the process `--wait-pid` names, with its start time
/// read now (a pid with no running process is `process`), else the parent read at start.
#[cfg(target_os = "linux")]
fn wait_target(wait_pid: Option<u32>, parent: cli::WaitTarget) -> cli::WaitTarget {
    let Some(pid) = wait_pid else {
        return parent;
    };
    match lunepack_os_linux::LinuxProcess::new().process_id(pid) {
        Ok(Some(id)) => Ok(id),
        Ok(None) | Err(_) => Err(Kind::Process),
    }
}

#[cfg(windows)]
fn wait_target(wait_pid: Option<u32>, parent: cli::WaitTarget) -> cli::WaitTarget {
    let Some(pid) = wait_pid else {
        return parent;
    };
    match lunepack_os_windows::WindowsProcess::new().process_id(pid) {
        Ok(Some(id)) => Ok(id),
        Ok(None) | Err(_) => Err(Kind::Process),
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn wait_target(_wait_pid: Option<u32>, parent: cli::WaitTarget) -> cli::WaitTarget {
    parent
}

/// The events of a mode: to `R/logs/runtime.log` when the tree is installed, else to stderr
/// (M5-D15), and to the UI when there is one.
fn events_for(
    ad: &modes::Adapters,
    inst: &lunepack::Installation,
    ui: Option<Box<dyn Sink>>,
) -> Events {
    match inst.layout() {
        Some(layout) => Events::new(
            Some(Box::new(LogSink::new(
                std::sync::Arc::clone(&ad.fs),
                layout.logs_dir(),
            ))),
            ui,
        ),
        None => Events::new(Some(Box::new(StderrSink)), ui),
    }
}

/// The UI of a mode: started from beside this runtime's resolved executable when it may be
/// (never under `--silent` or `--no-ui`, `LUNEPACK_NO_UI`, or without a display), else headless.
/// `location` is the install root shown, when its text fits.
fn ui_for(
    ad: &modes::Adapters,
    quiet: bool,
    flow: Flow,
    app: AppCard,
    location: Option<PathBuf>,
) -> UiHost {
    let Ok(exe) = ad.process.current_exe() else {
        return UiHost::headless(flow);
    };
    let env = |name: &str| std::env::var_os(name);
    let details = Details {
        location: location
            .map(shown_path)
            .and_then(|p| p.to_str().map(str::to_owned))
            .and_then(|t| ui_host::within(t, MAX_LOCATION)),
        size_bytes: None,
    };
    UiHost::start(
        &ui_host::Start {
            process: std::sync::Arc::clone(&ad.process),
            fs: &*ad.fs,
            runtime_exe: &exe,
            env: &env,
            quiet,
        },
        flow,
        app,
        details,
    )
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

/// Setup mode (M6 step 7, M7): `None` when this executable carries no setup trailer (the ordinary
/// runtime), else the run's exit kind. A trailer that is malformed is `verify`; a command line
/// other than nothing or `--silent` (`/S` on Windows) is a usage error.
#[cfg(any(target_os = "linux", windows))]
fn setup_mode(args: &[std::ffi::OsString]) -> Option<Kind> {
    use lunepack::Process as _;

    #[cfg(target_os = "linux")]
    let process = lunepack_os_linux::LinuxProcess::new();
    #[cfg(windows)]
    let process = lunepack_os_windows::WindowsProcess::new();
    let exe = process.current_exe().ok()?;
    let found = match setup::detect(
        &lunepack_fs::StdFs::new(),
        &exe,
        &lunepack_crypto::Sha256Hasher,
        &lunepack_crypto::Ed25519Verifier,
    ) {
        setup::Detect::None => return None,
        setup::Detect::Malformed => {
            conclude(stderr_events(), &setup::failed(Kind::Verify, None));
            // The arguments are not validated here: a usage error is its own exit, so only
            // `--silent` or `/S` matters for the notice.
            let quiet = modes::parse_setup(args).unwrap_or(false);
            notice(quiet, false, SETUP_TITLE, Operation::Setup, Kind::Verify);
            return Some(Kind::Verify);
        }
        setup::Detect::Setup(found) => found,
    };
    let Ok(silent) = modes::parse_setup(args) else {
        eprintln!("{USAGE_LINE}");
        return Some(Kind::Usage);
    };
    Some(run(|ad| {
        let data_home = match data_home() {
            Ok(dir) => dir,
            Err(kind) => {
                let kind = headless_fail(setup::COMMAND, kind);
                notice(silent, false, SETUP_TITLE, Operation::Setup, kind);
                return kind;
            }
        };
        let env = |name: &str| std::env::var_os(name);
        let want_ui = ui_host::ui_wanted(silent, &env);
        let own = process.process_id(std::process::id()).ok().flatten();
        clear_temp_dirs(ad);
        let ui_home = setup::ui_home(&env);
        let prepared = match setup::prepare(
            ad,
            found,
            &data_home,
            ui_home.as_deref(),
            want_ui,
            own,
            &alive,
        ) {
            Ok(prepared) => prepared,
            Err(kind) => {
                let kind = headless_fail(setup::COMMAND, kind);
                notice(silent, false, SETUP_TITLE, Operation::Setup, kind);
                return kind;
            }
        };
        let (app, details) = setup::welcome(&prepared);
        let ui = match prepared.ui_dir() {
            // The UI was read out of the verified pack into this run's own directory (M6-D7); the
            // host starts it from there as it starts the one beside an installed runtime.
            Some(dir) => UiHost::start(
                &ui_host::Start {
                    process: std::sync::Arc::clone(&ad.process),
                    fs: &*ad.fs,
                    runtime_exe: &dir.join("lunepack-runtime"),
                    env: &env,
                    quiet: silent,
                },
                Flow::Install,
                app,
                details,
            ),
            None => UiHost::headless(Flow::Install),
        };
        let events = Events::new(Some(Box::new(StderrSink)), ui.sink());
        ui.report(&events);
        let (kind, last) = setup::run_setup(ad, &prepared, &events, &ui);
        let seen = ui.outcome_acknowledged();
        ui.close(&events);
        prepared.cleanup(&*ad.fs);
        conclude(events, &last);
        notice(silent, seen, prepared.name(), Operation::Install, kind);
        kind
    }))
}

/// Setup files are Linux and Windows only in this release (M8 takes macOS's).
#[cfg(not(any(target_os = "linux", windows)))]
fn setup_mode(_args: &[std::ffi::OsString]) -> Option<Kind> {
    None
}

/// Runs `body` on the native adapters.
#[cfg(any(target_os = "linux", windows))]
fn run(body: impl FnOnce(&modes::Adapters) -> Kind) -> Kind {
    use std::sync::Arc;

    let fs: Arc<dyn lunepack::Fs> = Arc::new(lunepack_fs::StdFs::new());
    let hasher: Arc<dyn lunepack::Hasher> = Arc::new(lunepack_crypto::Sha256Hasher);
    let (process, integration) = native_adapters();
    let rng: Arc<dyn lunepack::Rng> = Arc::new(lunepack_crypto::OsRng);
    let verifier: Arc<dyn lunepack::Verifier> = Arc::new(lunepack_crypto::Ed25519Verifier);
    let codec: Arc<dyn lunepack::Codec> = Arc::new(lunepack_codec_lzma::LzmaCodec);
    let platform = lunepack::Platform::native()
        .with_fs(Arc::clone(&fs))
        .with_hasher(Arc::clone(&hasher))
        .with_verifier(Arc::clone(&verifier))
        .with_process(Arc::clone(&process))
        .with_integration(Arc::clone(&integration))
        .with_rng(Arc::clone(&rng))
        // The runtime is never a supervised start itself.
        .with_health_token(None);
    body(&modes::Adapters {
        fs,
        hasher,
        verifier,
        codec,
        process,
        integration,
        rng,
        platform,
    })
}

/// The process and desktop-integration adapters of this OS.
#[cfg(target_os = "linux")]
fn native_adapters() -> (
    std::sync::Arc<dyn lunepack::Process>,
    std::sync::Arc<dyn lunepack::OsIntegration>,
) {
    (
        std::sync::Arc::new(lunepack_os_linux::LinuxProcess::new()),
        std::sync::Arc::new(lunepack_os_linux::XdgIntegration::from_process_env()),
    )
}

/// The process and desktop-integration adapters of this OS (per-user scope, M7).
#[cfg(windows)]
fn native_adapters() -> (
    std::sync::Arc<dyn lunepack::Process>,
    std::sync::Arc<dyn lunepack::OsIntegration>,
) {
    (
        std::sync::Arc::new(lunepack_os_windows::WindowsProcess::new()),
        std::sync::Arc::new(lunepack_os_windows::WindowsIntegration::current_user()),
    )
}

/// Processes and the desktop integration have no adapter here yet (M8).
#[cfg(not(any(target_os = "linux", windows)))]
fn run(_body: impl FnOnce(&modes::Adapters) -> Kind) -> Kind {
    fail("runtime", Kind::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The native notice's text is fixed: the name, what happened and the closed code.
    #[test]
    fn the_notice_text_names_the_app_the_result_and_the_code_only() {
        assert_eq!(
            notice_text("My App", Operation::Install, Kind::Ok),
            "My App was installed."
        );
        assert_eq!(
            notice_text("My App", Operation::Install, Kind::Fs),
            "My App could not be installed (code 9)."
        );
        assert_eq!(
            notice_text("Setup", Operation::Setup, Kind::Verify),
            "Setup could not finish (code 7)."
        );
        assert_eq!(
            notice_text("My App", Operation::Uninstall, Kind::Ok),
            "My App was uninstalled."
        );
        assert_eq!(
            notice_text("My App", Operation::Uninstall, Kind::InUse),
            "My App could not be uninstalled (code 25)."
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_canonical_path_is_shown_without_its_verbatim_prefix() {
        assert_eq!(
            shown_path(PathBuf::from(r"\\?\C:\Users\a b\Programs\App")),
            PathBuf::from(r"C:\Users\a b\Programs\App")
        );
        // A UNC path keeps its prefix.
        let unc = PathBuf::from(r"\\?\UNC\host\share\App");
        assert_eq!(shown_path(unc.clone()), unc);
    }
}
