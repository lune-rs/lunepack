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
mod machine;
mod modes;
mod relay;
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
            with_host(ad, |host| {
                // A machine install's policy can switch the update window off (M10-D12).
                let ui = ui_for(
                    ad,
                    args.no_ui || policy_quiet(host, &inst),
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
                let service = host.map(|h| apply::ServiceEnd {
                    connector: h.service,
                    policy: h.policy,
                });
                let kind = apply::run_apply(ad, service.as_ref(), &inst, &args, &events, &ui);
                ui.close(&events);
                events.finish(SINK_DRAIN);
                kind
            })
        }),
        Mode::Command(parsed) => {
            // A pid given on the command line is named (with its start time) at once, too.
            let wait = (parsed.command == cli::args::Command::ApplyAndRestart)
                .then(|| wait_target(parsed.wait_pid, parent));
            run(|ad| with_host(ad, |host| cli::execute(ad, host, &parsed, wait)))
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
        // The elevated modes of a machine install (Windows; the grammar has no such word
        // elsewhere). They build their own adapters and read no environment variable.
        Mode::MachineRepair(args) => machine_repair_mode(&args),
        Mode::MachineUninstall(phase) => machine_uninstall_mode(&phase),
        // macOS: the installer package's postinstall (M11-D8); anywhere else a usage error.
        Mode::MachinePkg => machine_pkg_mode(),
        // Linux and macOS (M11-D14): the elevated modes of a machine install, and the
        // unelevated uninstall's copy; Windows has its own words for these.
        Mode::MachineUnix(mode) => machine_unix_mode(mode),
        Mode::UninstallCopy { silent } => run(|ad| uninstall_copy_mode(ad, silent)),
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
    // An administrator's process never hands off through the user's temp folder, whose unelevated
    // processes could replace the copy or the UI beside it before it runs with the full token (S1,
    // M10-D19): it runs phase 1 itself, headless.
    if inst.is_machine() {
        use lunepack_core::Elevation as _;
        let standing = lunepack_os_windows::WindowsElevation.standing();
        if machine::uninstall_route(standing) == machine::UninstallRoute::InPlace {
            let Ok(sid) = lunepack_os_windows::current_user_sid() else {
                return headless_fail(uninstall::COMMAND, Kind::Process);
            };
            let kind = with_machine_base(|base, ops, process, exe| {
                machine::uninstall_in_place(base, ops, process, standing, &sid, exe)
            });
            return match kind {
                Kind::Ok => Kind::Ok,
                kind => headless_fail(uninstall::COMMAND, kind),
            };
        }
    }
    let Some(temp) = tempdirs::temp_home() else {
        return headless_fail(uninstall::COMMAND, Kind::Fs);
    };
    clear_temp_dirs(ad);
    // A machine install's removal asks and reports from a copy outside `R` too: the engine's
    // removal guard refuses while any process runs from `R` (M10 step 18).
    let handed = if inst.is_machine() {
        match machine::native::machine_home() {
            Some(home) => uninstall::machine_hand_off(ad, inst, &home, &temp, silent),
            None => Err(Kind::Fs),
        }
    } else {
        uninstall::hand_off(ad, inst, data_home, &temp, silent)
    };
    match handed {
        Ok(()) => Kind::Ok,
        Err(kind) => headless_fail(uninstall::COMMAND, kind),
    }
}

/// Linux, and macOS (the bundle `B`, the install root `R` and the LaunchAgent, M8-D5, M8-D15):
/// the uninstall of a per-user install runs in this process, from the installed tree. A machine
/// install (M11-D14) is removed by the engine in an administrator's process: this process's own
/// when it is one (headless, no UI, as an elevated process never shows one), else on Linux
/// through a copy of this runtime in the user's own home (outside `R`, so the engine's removal
/// guard finds none of our processes in it) that asks pkexec, and on macOS through the command
/// to run as an administrator (no prompt of our own, D38 (a)).
#[cfg(not(windows))]
fn uninstall_mode(
    ad: &modes::Adapters,
    inst: &lunepack::Installation,
    data_home: &std::path::Path,
    silent: bool,
) -> Kind {
    if !inst.is_machine() {
        return uninstall_flow(ad, None, inst, data_home, silent);
    }
    use lunepack_core::Elevation as _;
    if unix_elevation().standing() != lunepack_core::Standing::Standard {
        return uninstall_machine_in_place(ad, inst);
    }
    // A standard user's run that may not ask asks nothing and copies nothing.
    if silent {
        return headless_fail(uninstall::COMMAND, Kind::ElevationRequired);
    }
    if cfg!(target_os = "linux") {
        // Only a failure returns: the copy took this process's place.
        let kind = match uninstall::user_copy_hand_off(
            ad,
            inst,
            &machine::StdExec { keep_env: true },
            &enter_dir,
        ) {
            Ok(()) => Kind::Ok,
            Err(kind) => kind,
        };
        return headless_fail(uninstall::COMMAND, kind);
    }
    with_host(ad, |host| uninstall_flow(ad, host, inst, data_home, silent))
}

/// The pkexec of Linux, the standing-only elevation of macOS.
#[cfg(all(unix, target_os = "linux"))]
fn unix_elevation() -> lunepack_os_linux::PkexecElevation {
    lunepack_os_linux::PkexecElevation::new()
}

/// The pkexec of Linux, the standing-only elevation of macOS.
#[cfg(all(unix, target_os = "macos"))]
fn unix_elevation() -> lunepack_os_macos::MacElevation {
    lunepack_os_macos::MacElevation
}

#[cfg(all(not(windows), not(any(target_os = "linux", target_os = "macos"))))]
fn unix_elevation() -> UnsupportedElevation {
    UnsupportedElevation
}

/// An elevation for a system with no machine installs.
#[cfg(all(not(windows), not(any(target_os = "linux", target_os = "macos"))))]
struct UnsupportedElevation;

#[cfg(all(not(windows), not(any(target_os = "linux", target_os = "macos"))))]
impl lunepack_core::Elevation for UnsupportedElevation {
    fn standing(&self) -> lunepack_core::Standing {
        lunepack_core::Standing::Standard
    }

    fn run_elevated(
        &self,
        _exe: &std::path::Path,
        _args: &[String],
    ) -> Result<lunepack_core::Elevated, lunepack_core::ElevationError> {
        Err(lunepack_core::ElevationError::NoAgent)
    }
}

/// An administrator's `uninstall` of a machine install: phase 1 in this process, headless (S1,
/// D35): it copies the runtime into an admin-only folder of the machine home and becomes the copy,
/// which removes the install and prints the result. Only a failure returns.
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn uninstall_machine_in_place(ad: &modes::Adapters, inst: &lunepack::Installation) -> Kind {
    use lunepack_core::Elevation as _;

    let (Some(home), Ok(exe), Some(layout)) = (
        machine::native_unix::home(),
        ad.process.current_exe(),
        inst.machine_layout(),
    ) else {
        return headless_fail(uninstall::COMMAND, Kind::Fs);
    };
    let scheme = machine::native_unix::SCHEME;
    if let Err(kind) = machine::validated(
        &*ad.fs,
        &*ad.hasher,
        &home,
        scheme,
        layout.root(),
        inst.app_id(),
        &inst.meta().name,
    ) {
        return headless_fail(uninstall::COMMAND, kind);
    }
    let located = machine::Located {
        root: layout.root().to_path_buf(),
        app_id: inst.app_id().clone(),
        name: inst.meta().name.clone(),
        version: inst.tree_version().clone(),
    };
    let adapters = machine::native_unix::Adapters::new();
    let kind = machine::run_uninstall_start_unix(
        &adapters.base(&home),
        &machine::native_unix::NativeOps { enter: enter_dir },
        &machine::StdExec { keep_env: false },
        unix_elevation().standing(),
        &located,
        false,
        &exe,
    );
    headless_fail(uninstall::COMMAND, kind)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn uninstall_machine_in_place(_ad: &modes::Adapters, _inst: &lunepack::Installation) -> Kind {
    headless_fail(uninstall::COMMAND, Kind::Unsupported)
}

/// The uninstall of `inst` with its UI and its outcome (M5-D10, M6): the confirm prompt, the
/// removal, the done or failed prompt, the result line and a native notice where one is due.
fn uninstall_flow(
    ad: &modes::Adapters,
    host: Option<&machine::Host<'_>>,
    inst: &lunepack::Installation,
    data_home: &std::path::Path,
    silent: bool,
) -> Kind {
    // A machine install's policy makes every runtime mode headless, as `LUNEPACK_NO_UI` does.
    let quiet = silent || policy_quiet(host, inst);
    let location = match inst.machine_layout() {
        Some(machine) => Some(machine.root().to_path_buf()),
        None => inst.layout().map(|l| l.root().to_path_buf()),
    };
    let ui = ui_for(
        ad,
        quiet,
        Flow::Uninstall,
        ui_host::card(&inst.meta().name, &inst.tree_version().to_string(), None),
        location,
    );
    let events = Events::new(Some(Box::new(StderrSink)), ui.sink());
    ui.report(&events);
    let (kind, last) = if inst.is_machine() {
        uninstall::run_machine_uninstall(ad, host, inst, silent, &events, &ui)
    } else {
        uninstall::run_uninstall(ad, inst, data_home, &events, &ui)
    };
    let seen = ui.outcome_acknowledged();
    ui.close(&events);
    conclude(events, &last);
    notice(quiet, seen, &inst.meta().name, Operation::Uninstall, kind);
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
    // A root directly in the Program Files folder is a machine install's; anything else is a
    // per-user install's (the two homes never coincide).
    let machine_home = machine::native::machine_home().filter(|home| {
        args.install_root
            .parent()
            .is_some_and(|p| p == home.as_path())
    });
    let installed = match &machine_home {
        Some(home) => {
            uninstall::hand_off_machine_installation(ad, home, &args.install_root, &marker.app_id)
        }
        None => {
            uninstall::hand_off_installation(ad, &data_home, &args.install_root, &marker.app_id)
        }
    };
    let inst = match installed {
        Ok(inst) => inst,
        Err(kind) => return headless_fail(uninstall::COMMAND, kind),
    };
    let kind = with_host(ad, |host| {
        uninstall_flow(ad, host, &inst, &data_home, args.silent)
    });
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
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn alive(pid: u32, start: u64) -> bool {
    #[cfg(target_os = "linux")]
    let found = lunepack_os_linux::LinuxProcess::new().process_id(pid);
    #[cfg(windows)]
    let found = lunepack_os_windows::WindowsProcess::new().process_id(pid);
    #[cfg(target_os = "macos")]
    let found = lunepack_os_macos::MacProcess::new().process_id(pid);
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
    conclude_to(events, last, true);
}

/// [`conclude`], with the line on stdout only when `stdout` (a standard output that carries a
/// UI's frames, `--ui-stdio`, gets nothing else).
fn conclude_to(events: Events, last: &Event, stdout: bool) {
    events.emit(last);
    events.finish(SINK_DRAIN);
    if !stdout {
        return;
    }
    let mut line = events::to_json_line(last);
    line.push('\n');
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
}

/// The interactive modes whose end may need a native notice.
#[derive(Clone, Copy)]
#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
enum Operation {
    Install,
    Uninstall,
    /// A setup run that ended before it verified the app's name (a refused payload): its title
    /// is fixed. A setup refused after that (its root) is an `Install` notice with the name.
    Setup,
}

/// The title of a native notice for a setup run that failed before the app's name was verified.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
const SETUP_TITLE: &str = "Setup";

/// The fixed text of a native notice: the app's validated display name, what happened and the
/// closed result code (D36). Never a path, a value or an error's own text.
#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
fn notice_text(name: &str, operation: Operation, kind: Kind) -> String {
    let (done, failed) = match operation {
        Operation::Install => ("was installed.", "could not be installed"),
        Operation::Uninstall => ("was uninstalled.", "could not be uninstalled"),
        Operation::Setup => ("finished.", "could not finish"),
    };
    match (operation, kind) {
        (_, Kind::Ok) => format!("{name} {done}"),
        // M8-D4: a copy somewhere lunepack does not update is told where to go, whatever the mode.
        (_, Kind::UnsupportedLocation(_)) => {
            format!("Move {name} to your Applications folder and open it from there.")
        }
        // A setup rerun over the installed app repaired its integration; nothing failed.
        (Operation::Install, Kind::AlreadyInstalled) => format!("{name} is already installed."),
        _ => format!("{name} {failed} (code {}).", kind.code()),
    }
}

/// Whether a native notice reports a normal end (the information icon) rather than a failure.
#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
fn notice_is_info(operation: Operation, kind: Kind) -> bool {
    matches!(
        (operation, kind),
        (_, Kind::Ok) | (Operation::Install, Kind::AlreadyInstalled)
    )
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
    let level = if notice_is_info(operation, kind) {
        lunepack_os_windows::MessageKind::Info
    } else {
        lunepack_os_windows::MessageKind::Error
    };
    let _ = lunepack_os_windows::message_box(name, &notice_text(name, operation, kind), level);
}

/// macOS (M8-D11): the same rule as Windows: one native alert, through `osascript` with the fixed
/// script and the text as arguments only, after the outcome is committed; never under `--silent`,
/// `--no-ui` or `LUNEPACK_NO_UI`, never for a cancellation the user chose, and not when the UI
/// itself showed the outcome. The alert is bounded and its failure (no window server, no
/// `osascript`) changes nothing.
#[cfg(target_os = "macos")]
fn notice(quiet: bool, seen: bool, name: &str, operation: Operation, kind: Kind) {
    let env = |var: &str| std::env::var_os(var);
    if seen || kind == Kind::Cancelled || !ui_host::ui_wanted(quiet, &env) {
        return;
    }
    let level = if notice_is_info(operation, kind) {
        lunepack_os_macos::NoticeKind::Info
    } else {
        lunepack_os_macos::NoticeKind::Error
    };
    let _ = lunepack_os_macos::notice(name, &notice_text(name, operation, kind), level);
}

/// Other platforms print their outcome on the terminal; no native notice.
#[cfg(not(any(windows, target_os = "macos")))]
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
            reason: kind.reason(),
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

/// `$HOME/Library/Application Support`, canonical (M8-D1): the facade's own rule.
#[cfg(target_os = "macos")]
fn data_home() -> Result<PathBuf, Kind> {
    lunepack::Platform::native()
        .data_home_dir()
        .map_err(|e| Kind::of(&e))
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
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

#[cfg(target_os = "macos")]
fn initial_parent() -> cli::WaitTarget {
    use lunepack::Process as _;
    match lunepack_os_macos::MacProcess::new().parent() {
        Ok(Some(id)) => Ok(id),
        Ok(None) | Err(_) => Err(Kind::Process),
    }
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
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

#[cfg(target_os = "macos")]
fn wait_target(wait_pid: Option<u32>, parent: cli::WaitTarget) -> cli::WaitTarget {
    let Some(pid) = wait_pid else {
        return parent;
    };
    match lunepack_os_macos::MacProcess::new().process_id(pid) {
        Ok(Some(id)) => Ok(id),
        Ok(None) | Err(_) => Err(Kind::Process),
    }
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
fn wait_target(_wait_pid: Option<u32>, parent: cli::WaitTarget) -> cli::WaitTarget {
    parent
}

/// Runs `body` with what a machine install's modes hand their work to: the Windows adapters on
/// Windows, nothing elsewhere (there is no machine install elsewhere).
#[cfg(windows)]
fn with_host<T>(ad: &modes::Adapters, body: impl FnOnce(Option<&machine::Host<'_>>) -> T) -> T {
    let elevation = lunepack_os_windows::WindowsElevation;
    let ops = machine::native::NativeOps { enter: enter_dir };
    let pipes = machine::native::NativeConnector;
    let service = lunepack_os_windows::WindowsConnector::new();
    let policy = lunepack_os_windows::RegistryPolicy::new();
    let sid = lunepack_os_windows::current_user_sid().ok();
    body(Some(&machine::Host {
        elevation: &elevation,
        ops: &ops,
        pipes: &pipes,
        service: &service,
        policy: &policy,
        rng: &*ad.rng,
        sid: sid.as_deref(),
        relay: machine::Relay::Pipe,
    }))
}

/// The host of a machine install's modes on Linux and macOS (M11-D14): its elevation (pkexec on
/// Linux, none of our own on macOS), the engine's one-shot operations for a process that is an
/// administrator's already, the update service's socket and the policy file. Nothing is read
/// here; the child's events come back on its standard output.
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn with_host<T>(ad: &modes::Adapters, body: impl FnOnce(Option<&machine::Host<'_>>) -> T) -> T {
    let elevation = unix_elevation();
    let ops = machine::native_unix::NativeOps { enter: enter_dir };
    let service = machine_service();
    let policy = machine_policy();
    body(Some(&machine::Host {
        elevation: &elevation,
        ops: &ops,
        pipes: &machine::NoPipes,
        service: &service,
        policy: &policy,
        rng: &*ad.rng,
        sid: None,
        relay: machine::Relay::Stdout,
    }))
}

#[cfg(target_os = "linux")]
fn machine_service() -> lunepack_os_linux::UnixConnector {
    lunepack_os_linux::UnixConnector::new()
}

#[cfg(target_os = "macos")]
fn machine_service() -> lunepack_os_macos::UnixConnector {
    lunepack_os_macos::UnixConnector::new()
}

#[cfg(target_os = "linux")]
fn machine_policy() -> lunepack_os_linux::FilePolicy {
    lunepack_os_linux::FilePolicy::new()
}

#[cfg(target_os = "macos")]
fn machine_policy() -> lunepack_os_macos::FilePolicy {
    lunepack_os_macos::FilePolicy::new()
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn with_host<T>(_ad: &modes::Adapters, body: impl FnOnce(Option<&machine::Host<'_>>) -> T) -> T {
    body(None)
}

/// Whether an administrator's policy makes this machine install's runtime headless (`NoUpdateUi`,
/// M10-D12), as `LUNEPACK_NO_UI` does for every install.
fn policy_quiet(host: Option<&machine::Host<'_>>, inst: &lunepack::Installation) -> bool {
    host.is_some_and(|h| machine::no_update_ui(inst.is_machine(), h.policy, inst.app_id()))
}

/// Makes `dir` the working directory of this process.
#[cfg(any(windows, unix))]
fn enter_dir(dir: &std::path::Path) -> bool {
    std::env::set_current_dir(dir).is_ok()
}

/// The hidden `machine-repair` mode: the engine's `repair` in an elevated runtime inside `R`.
#[cfg(windows)]
fn machine_repair_mode(_args: &modes::MachineArgs) -> Kind {
    use lunepack::Process as _;
    use lunepack_core::Elevation as _;

    let process = lunepack_os_windows::WindowsProcess::new();
    let (Some(home), Ok(exe)) = (machine::native::machine_home(), process.current_exe()) else {
        return Kind::Fs;
    };
    let ops = machine::native::NativeOps { enter: enter_dir };
    machine::run_repair_mode(
        &ops,
        &lunepack_fs::StdFs::new(),
        &lunepack_crypto::Sha256Hasher,
        &home,
        lunepack_os_windows::WindowsElevation.standing(),
        &exe,
    )
}

/// The hidden `machine-uninstall` mode, either phase.
#[cfg(windows)]
fn machine_uninstall_mode(phase: &modes::MachineUninstall) -> Kind {
    use lunepack_core::Elevation as _;

    let standing = lunepack_os_windows::WindowsElevation.standing();
    with_machine_base(|base, ops, process, exe| match phase {
        modes::MachineUninstall::Start(args) => {
            machine::run_uninstall_start(base, ops, process, standing, args, exe)
        }
        modes::MachineUninstall::Second { wait } => machine::run_uninstall_second(
            base,
            ops,
            process,
            &machine::native::NativePipes,
            standing,
            wait,
            exe,
            machine::ACCEPT_WAIT,
        ),
    })
}

/// Runs `f` over the native adapters of the machine uninstall's phases: the machine home (the
/// Program Files known folder), this process's resolved executable, the filesystem, codec, hasher,
/// verifier, randomness and protection, and the operations that enter a folder. No environment
/// variable is read.
#[cfg(windows)]
fn with_machine_base(
    f: impl FnOnce(
        &machine::Base<'_>,
        &machine::native::NativeOps,
        &lunepack_os_windows::WindowsProcess,
        &std::path::Path,
    ) -> Kind,
) -> Kind {
    use lunepack::Process as _;

    let process = lunepack_os_windows::WindowsProcess::new();
    let (Some(home), Ok(exe)) = (machine::native::machine_home(), process.current_exe()) else {
        return Kind::Fs;
    };
    let (fs, codec, hasher, verifier, rng) = (
        lunepack_fs::StdFs::new(),
        lunepack_codec_lzma::LzmaCodec,
        lunepack_crypto::Sha256Hasher,
        lunepack_crypto::Ed25519Verifier,
        lunepack_crypto::OsRng,
    );
    let protect = lunepack_os_windows::WindowsProtect;
    let base = machine::Base {
        fs: &fs,
        codec: &codec,
        hasher: &hasher,
        verifier: &verifier,
        clock: &lunepack::SystemClock,
        rng: &rng,
        protect: &protect,
        home: &home,
    };
    let ops = machine::native::NativeOps { enter: enter_dir };
    f(&base, &ops, &process, &exe)
}

/// The hidden `machine-install --pkg` mode (macOS, M11-D8): the engine's first install from the
/// payload the installer package placed, run by its postinstall as root. It builds its few
/// adapters itself and reads no environment variable, no temporary directory, no working
/// directory and nothing of a user's profile. The result is the one JSON line on stdout and the
/// events on stderr, which Installer's log keeps; the exit code is what the package shows.
#[cfg(target_os = "macos")]
fn machine_pkg_mode() -> Kind {
    use lunepack_core::Elevation as _;

    // Only root's process goes further: nothing is looked at before that.
    let standing = lunepack_os_macos::MacElevation.standing();
    if standing == lunepack_core::Standing::Standard {
        eprintln!("{USAGE_LINE}");
        return Kind::Usage;
    }
    let (Ok(home), Ok(apps_dir), Ok(image)) = (
        machine::native_macos::machine_home(),
        machine::native_macos::apps_dir(),
        machine::native_macos::own_image(),
    ) else {
        return headless_fail(setup::COMMAND, Kind::Fs);
    };
    let adapters = machine::native_macos::Adapters::new();
    let installer = machine::native_macos::MacInstaller { apps_dir };
    let events = stderr_events();
    let kind = machine::run_pkg_mode(
        &machine::PkgRun {
            base: adapters.base(&home),
            stat: &machine::native_macos::MacStat,
            installer: &installer,
            repairer: &machine::native_macos::MacRepairer,
            standing,
            image: &image,
            kernel_path: &machine::native_macos::named,
            scheme: lunepack_core::MachineScheme::MACOS,
        },
        &events,
    );
    let last = match kind {
        Kind::Ok => Event::Result {
            command: setup::COMMAND,
            tree_version: None,
            outcome: setup::OUTCOME,
            version: None,
        },
        kind => setup::failed(kind, None),
    };
    conclude(events, &last);
    kind
}

#[cfg(not(target_os = "macos"))]
fn machine_pkg_mode() -> Kind {
    Kind::Usage
}

/// The hidden elevated modes of a machine install on Linux and macOS (M11-D14), started by pkexec
/// or by phase 1 of the uninstall. Each builds its few adapters itself and reads no environment
/// variable, no temporary directory and nothing of a user's profile; its inputs are its own image
/// (the root it stands in) and the machine record, its exit code is its result, and a standard
/// user's process is refused (usage) before anything is looked at.
#[cfg(all(unix, any(target_os = "linux", target_os = "macos")))]
fn machine_unix_mode(mode: modes::MachineUnix) -> Kind {
    use lunepack_core::Elevation as _;
    use modes::MachineUnix;

    let standing = unix_elevation().standing();
    if standing == lunepack_core::Standing::Standard {
        eprintln!("{USAGE_LINE}");
        return Kind::Usage;
    }
    let (Some(home), Some(exe)) = (machine::native_unix::home(), machine::native_unix::image())
    else {
        return Kind::Fs;
    };
    let scheme = machine::native_unix::SCHEME;
    let adapters = machine::native_unix::Adapters::new();
    let base = adapters.base(&home);
    let ops = machine::native_unix::NativeOps { enter: enter_dir };
    match mode {
        MachineUnix::Repair => {
            machine::run_repair_mode_in(&ops, base.fs, base.hasher, &home, standing, &exe, scheme)
        }
        MachineUnix::UninstallStart => {
            match machine::locate_in(base.fs, base.hasher, &home, &exe, scheme) {
                Ok(located) => machine::run_uninstall_start_unix(
                    &base,
                    &ops,
                    &machine::StdExec { keep_env: false },
                    standing,
                    &located,
                    true,
                    &exe,
                ),
                Err(kind) => kind,
            }
        }
        MachineUnix::UninstallSecond { relay: true } => machine::run_uninstall_second_relayed(
            &base,
            &ops,
            standing,
            scheme,
            Box::new(std::io::stdout()),
            &exe,
        ),
        MachineUnix::UninstallSecond { relay: false } => {
            let events = stderr_events();
            let kind =
                machine::run_uninstall_second_unix(&base, &ops, standing, scheme, &events, &exe);
            let last = match kind {
                Kind::Ok => Event::Result {
                    command: uninstall::COMMAND,
                    tree_version: None,
                    outcome: uninstall::OUTCOME,
                    version: None,
                },
                kind => Event::Error {
                    command: uninstall::COMMAND,
                    tree_version: None,
                    kind: kind.name(),
                    exit_code: kind.code(),
                    reason: kind.reason(),
                },
            };
            conclude(events, &last);
            kind
        }
    }
}

#[cfg(not(all(unix, any(target_os = "linux", target_os = "macos"))))]
fn machine_unix_mode(_mode: modes::MachineUnix) -> Kind {
    Kind::Usage
}

/// The hidden `uninstall --user-copy` mode (M11-D14, Linux): the unelevated uninstall of a machine
/// install, run from the copy of this runtime the user's own `uninstall` made in their home.
/// Anywhere else it is a usage error before any action.
#[cfg(target_os = "linux")]
fn uninstall_copy_mode(ad: &modes::Adapters, silent: bool) -> Kind {
    let (Ok(data_home), Ok(exe), Some(home)) = (
        data_home(),
        ad.process.current_exe(),
        machine::native_unix::home(),
    ) else {
        return headless_fail(uninstall::COMMAND, Kind::Fs);
    };
    let inst = match uninstall::user_copy_installation(
        ad,
        &exe,
        &data_home,
        &home,
        machine::native_unix::SCHEME,
    ) {
        Ok(inst) => inst,
        Err(Kind::Usage) => {
            eprintln!("{USAGE_LINE}");
            return Kind::Usage;
        }
        Err(kind) => return headless_fail(uninstall::COMMAND, kind),
    };
    let kind = with_host(ad, |host| {
        uninstall_flow(ad, host, &inst, &data_home, silent)
    });
    // The copy's folder is in this user's home, which a removal that succeeded took with it.
    uninstall::user_copy_cleanup(ad, &exe);
    kind
}

#[cfg(not(target_os = "linux"))]
fn uninstall_copy_mode(_ad: &modes::Adapters, _silent: bool) -> Kind {
    eprintln!("{USAGE_LINE}");
    Kind::Usage
}

/// The hidden modes exist on Windows only; the grammar refuses them elsewhere.
#[cfg(not(windows))]
fn machine_repair_mode(_args: &modes::MachineArgs) -> Kind {
    Kind::Usage
}

#[cfg(not(windows))]
fn machine_uninstall_mode(_phase: &modes::MachineUninstall) -> Kind {
    Kind::Usage
}

/// The events of a mode: to `R/logs/runtime.log` when the tree is installed, else to stderr
/// (M5-D15), and to the UI when there is one.
fn events_for(
    ad: &modes::Adapters,
    inst: &lunepack::Installation,
    ui: Option<Box<dyn Sink>>,
) -> Events {
    // A machine install's `R` is no place for this user to write: the log is in the user's home.
    let logs = match (inst.layout(), inst.user_home()) {
        (Some(layout), _) => Some(layout.logs_dir()),
        (None, Some(home)) if inst.is_machine() => Some(home.join("logs")),
        _ => None,
    };
    match logs {
        Some(dir) => Events::new(
            Some(Box::new(LogSink::new(std::sync::Arc::clone(&ad.fs), dir))),
            ui,
        ),
        None => Events::new(Some(Box::new(StderrSink)), ui),
    }
}

/// Whether this process holds the full token of a UAC elevation (M10-D15): such a process never
/// starts the UI (S1). Windows only; elsewhere there is no such token.
#[cfg(windows)]
fn uac_elevated() -> bool {
    use lunepack_core::Elevation as _;
    lunepack_os_windows::WindowsElevation.standing() == lunepack_core::Standing::UacElevated
}

#[cfg(not(windows))]
fn uac_elevated() -> bool {
    false
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
        all_users_location: None,
    };
    UiHost::start(
        &ui_host::Start {
            process: std::sync::Arc::clone(&ad.process),
            fs: &*ad.fs,
            runtime_exe: &exe,
            env: &env,
            quiet,
            elevated: uac_elevated(),
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
        reason: kind.reason(),
    });
    events.finish(SINK_DRAIN);
    kind
}

/// Setup mode (M6 step 7, M7, M11): `None` when this executable carries no setup trailer (the
/// ordinary runtime), else the run's exit kind. A trailer that is malformed is `verify`; a command
/// line other than `--silent` and `--all-users` once each, or exactly `machine-install --events
/// stdout`, is a usage error.
///
/// A process that runs as root reads the image it was started from through one open of
/// `/proc/self/exe` (not through a path that may name another file by the time it is opened), and
/// reads no environment variable and starts no window (M11-D9): it installs for all users in
/// this process (`--all-users`) or as the elevated copy of a setup an unelevated user started
/// (`machine-install --events stdout`, run by pkexec), and refuses anything else with one line.
#[cfg(target_os = "linux")]
fn setup_mode(args: &[std::ffi::OsString]) -> Option<Kind> {
    use lunepack::Process as _;

    let process = lunepack_os_linux::LinuxProcess::new();
    let root = lunepack_os_linux::effective_uid() == 0;
    let exe = if root {
        PathBuf::from("/proc/self/exe")
    } else {
        process.current_exe().ok()?
    };
    let found = match setup::detect(
        &lunepack_fs::StdFs::new(),
        &exe,
        &lunepack_crypto::Sha256Hasher,
        &lunepack_crypto::Ed25519Verifier,
    ) {
        setup::Detect::None => return None,
        setup::Detect::Malformed => {
            conclude(stderr_events(), &setup::failed(Kind::Verify, None));
            notice(
                unparsed_setup_quiet(args),
                false,
                SETUP_TITLE,
                Operation::Setup,
                Kind::Verify,
            );
            return Some(Kind::Verify);
        }
        setup::Detect::Setup(found) => found,
    };
    let Ok(command) = modes::parse_setup_command_unix(args) else {
        eprintln!("{USAGE_LINE}");
        return Some(Kind::Usage);
    };
    match command {
        // The elevated copy of a setup, started by pkexec: its events on its standard output, its
        // exit code its whole result. Not `run`: that reads the environment.
        modes::SetupCommand::MachineInstallStdout => {
            if !root {
                eprintln!("{USAGE_LINE}");
                return Some(Kind::Usage);
            }
            Some(linux_machine_install_mode(&found))
        }
        modes::SetupCommand::Run(run_args) if root => Some(linux_root_setup(found, run_args)),
        modes::SetupCommand::Run(run_args) => Some(run(|ad| {
            linux_user_setup(ad, &process, &exe, found, run_args)
        })),
        // The Windows form of the mode is no word of the Linux grammar.
        modes::SetupCommand::MachineInstall(_) => {
            eprintln!("{USAGE_LINE}");
            Some(Kind::Usage)
        }
    }
}

/// The hidden `machine-install --events stdout` mode: the engine's first install in the elevated
/// copy of the setup, from the one open of its own executed image, its progress on its standard
/// output. Its exit code is its whole result. It builds its few adapters itself and reads no
/// environment variable, no working directory and nothing of a user's profile.
#[cfg(target_os = "linux")]
fn linux_machine_install_mode(found: &setup::Found) -> Kind {
    use lunepack_core::Elevation as _;

    let Some(home) = machine::native_linux::machine_home() else {
        return Kind::Fs;
    };
    let adapters = machine::native_linux::Adapters::new();
    machine::run_stdout_mode(
        &adapters.base(&home),
        &machine::native_linux::LinuxInstaller,
        lunepack_os_linux::PkexecElevation::new().standing(),
        found,
        Box::new(std::io::stdout()),
    )
}

/// The fixed line a setup run as root without `--all-users` prints: it never shows a window as root.
#[cfg(target_os = "linux")]
const ROOT_SETUP_TEXT: &str = "This installer does not run as root. Start it as your own user and \
choose \"For all users\", or start it as root with --all-users.";

/// `--all-users` as root (`sudo <setup> --all-users`): the payload copied from the image, verified
/// there and installed in this process, with no window and no environment variable read. The
/// result is the one JSON line on stdout. Without `--all-users`, one line and exit 2.
#[cfg(target_os = "linux")]
fn linux_root_setup(found: setup::Found, args: modes::SetupArgs) -> Kind {
    if !args.all_users {
        eprintln!("{ROOT_SETUP_TEXT}");
        return Kind::Usage;
    }
    let version = found.trailer.version.clone();
    let events = stderr_events();
    let result = match machine::native_linux::machine_home() {
        Some(home) => {
            let adapters = machine::native_linux::Adapters::new();
            machine::install_all_own_image(
                &adapters.base(&home),
                &machine::native_linux::LinuxInstaller,
                &found,
                &events,
            )
            .map(|installed| installed.version)
        }
        None => Err(Kind::Fs),
    };
    let (kind, last) = match result {
        Ok(installed) => (
            Kind::Ok,
            Event::Result {
                command: setup::COMMAND,
                tree_version: Some(version),
                outcome: setup::OUTCOME,
                version: Some(installed),
            },
        ),
        Err(kind) => (kind, setup::failed(kind, Some(version))),
    };
    conclude(events, &last);
    kind
}

/// A setup run by a user without administrator rights: per user by default, for all users when the
/// release carries the update service and the user chooses it (the window's "For all users", or
/// `--all-users`), through pkexec ([`machine::hand_off_stdout`]) or, when nothing can ask, the
/// `sudo` command on a screen of its own (M11-D9). The per-user install and the all-users one
/// exclude each other (M10-D14).
#[cfg(target_os = "linux")]
fn linux_user_setup(
    ad: &modes::Adapters,
    process: &lunepack_os_linux::LinuxProcess,
    exe: &std::path::Path,
    found: setup::Found,
    run_args: modes::SetupArgs,
) -> Kind {
    use lunepack_core::{MachineOs, MachineScheme, Standing};

    let silent = run_args.silent;
    let data_home = match data_home() {
        Ok(dir) => dir,
        Err(kind) => {
            let kind = headless_fail(setup::COMMAND, kind);
            notice(silent, false, SETUP_TITLE, Operation::Setup, kind);
            return kind;
        }
    };
    let verified = match setup::verify(ad, found, setup::Binding::TrailerRoot) {
        Ok(verified) => verified,
        Err(refused) => {
            let kind = headless_fail(setup::COMMAND, refused.kind);
            notice(silent, false, SETUP_TITLE, Operation::Setup, kind);
            return kind;
        }
    };
    let name = verified.name().to_owned();
    let (offer, forced) = match machine::decide(
        Standing::Standard,
        run_args,
        verified.has_service_for(MachineOs::Linux),
        &|| {
            Ok(setup::user_install_exists(
                ad,
                &data_home,
                verified.app_id(),
                &name,
            ))
        },
    ) {
        machine::Decision::Exit(kind) => {
            let kind = headless_fail(setup::COMMAND, kind);
            notice(silent, false, &name, Operation::Install, kind);
            return kind;
        }
        machine::Decision::Window { offer, forced } => (offer, forced),
        // Only a process that holds a full token gets these.
        machine::Decision::Notice | machine::Decision::InProcess => {
            return headless_fail(setup::COMMAND, Kind::Usage);
        }
    };

    let env = |name: &str| std::env::var_os(name);
    let want_ui = ui_host::ui_wanted(silent, &env);
    let own = process.process_id(std::process::id()).ok().flatten();
    clear_temp_dirs(ad);
    let ui_home = setup::ui_home(&env);
    let prepared =
        match verified.into_prepared(ad, &data_home, ui_home.as_deref(), want_ui, own, &alive) {
            Ok(prepared) => prepared,
            Err(refused) => {
                let kind = headless_fail(setup::COMMAND, refused.kind);
                notice(
                    silent,
                    false,
                    refused.name.as_deref().unwrap_or(SETUP_TITLE),
                    Operation::Install,
                    kind,
                );
                return kind;
            }
        };
    // The all-users install needs the machine home and this setup's own path (what pkexec runs);
    // without them the choice is not offered (and a run that asked for it fails).
    let home = machine::native_linux::machine_home();
    let setup_path = std::fs::canonicalize(exe).ok();
    let elevation = lunepack_os_linux::PkexecElevation::new();
    let machine_ctx = match (&home, &setup_path) {
        (Some(home), Some(setup_path)) => Some(setup::Machine {
            home,
            scheme: MachineScheme::LINUX,
            transfer: setup::Transfer::Stdout(machine::StdoutHandOff {
                elevation: &elevation,
                setup: setup_path,
            }),
            offered: offer,
            forced,
        }),
        _ => None,
    };
    if machine_ctx.is_none() && forced {
        prepared.cleanup(&*ad.fs);
        return headless_fail(setup::COMMAND, Kind::Process);
    }
    let all_users_location = machine_ctx.as_ref().filter(|m| m.offered).and_then(|m| {
        shown_path(m.home.join(prepared.app_id().as_str()))
            .to_str()
            .map(str::to_owned)
    });
    let (app, details) = setup::welcome(&prepared, all_users_location);
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
                elevated: uac_elevated(),
            },
            Flow::Install,
            app,
            details,
        ),
        None => UiHost::headless(Flow::Install),
    };
    let events = Events::new(Some(Box::new(StderrSink)), ui.sink());
    ui.report(&events);
    let (kind, last) = setup::run_setup(ad, &prepared, &events, &ui, machine_ctx.as_ref());
    let seen = ui.outcome_acknowledged();
    ui.close(&events);
    prepared.cleanup(&*ad.fs);
    conclude(events, &last);
    notice(silent, seen, prepared.name(), Operation::Install, kind);
    kind
}

/// Setup mode on Windows (M10 step 16): the Linux flow plus the all-users install. `None` when this
/// executable carries no setup trailer. The payload is verified against the anchor the image
/// carries of its own payload, never against the trailer's root alone (M10-D4), before anything is
/// shown or written; then the run follows [`machine::route`]: the window with the all-users
/// choice, an all-users install in this process, the hidden elevated `machine-install` mode, or a
/// refusal. A process that holds a full administrator token never starts the UI (M10-D15).
#[cfg(windows)]
fn setup_mode(args: &[std::ffi::OsString]) -> Option<Kind> {
    use lunepack::Process as _;
    use lunepack_core::setup::{ANCHOR_RESOURCE_ID, SetupAnchor};

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
            notice(
                unparsed_setup_quiet(args),
                false,
                SETUP_TITLE,
                Operation::Setup,
                Kind::Verify,
            );
            return Some(Kind::Verify);
        }
        setup::Detect::Setup(found) => found,
    };
    let Ok(command) = modes::parse_setup_command(args) else {
        eprintln!("{USAGE_LINE}");
        return Some(Kind::Usage);
    };
    // Read from this process's own mapped image: what was started, whatever happens to the file.
    let anchor = lunepack_os_windows::own_resource(ANCHOR_RESOURCE_ID)
        .and_then(|bytes| SetupAnchor::parse(&bytes).ok());
    let elevation = lunepack_os_windows::WindowsElevation;
    match command {
        // No `run`: its platform reads the environment (the health token it then drops), and the
        // elevated copy reads none.
        modes::SetupCommand::MachineInstall(machine_args) => Some(machine_install_mode(
            &elevation,
            found,
            anchor.as_ref(),
            &machine_args,
        )),
        modes::SetupCommand::Run(run_args) => Some(run(|ad| {
            windows_setup(
                ad,
                &process,
                &elevation,
                &exe,
                found,
                anchor.as_ref(),
                run_args,
            )
        })),
    }
}

/// The hidden `machine-install` mode: the engine's first install in an elevated copy of the setup,
/// its progress into the pipe the unelevated setup reads. Its exit code is its whole result. It
/// builds its few adapters itself and reads no environment variable, no temporary directory and
/// nothing of a user's profile.
#[cfg(windows)]
fn machine_install_mode(
    elevation: &dyn lunepack_core::Elevation,
    found: setup::Found,
    anchor: Option<&lunepack_core::setup::SetupAnchor>,
    args: &modes::MachineArgs,
) -> Kind {
    let Some(home) = machine::native::machine_home() else {
        return Kind::Fs;
    };
    let (fs, codec, hasher, verifier, rng) = (
        lunepack_fs::StdFs::new(),
        lunepack_codec_lzma::LzmaCodec,
        lunepack_crypto::Sha256Hasher,
        lunepack_crypto::Ed25519Verifier,
        lunepack_crypto::OsRng,
    );
    let protect = lunepack_os_windows::WindowsProtect;
    let base = machine::Base {
        fs: &fs,
        codec: &codec,
        hasher: &hasher,
        verifier: &verifier,
        clock: &lunepack::SystemClock,
        rng: &rng,
        protect: &protect,
        home: &home,
    };
    machine::run_mode(
        &base,
        &machine::native::NativeInstaller,
        &machine::native::NativePipes,
        elevation.standing(),
        args,
        &found,
        anchor,
        machine::ACCEPT_WAIT,
    )
}

/// The refusal a Windows setup run ends with before it installs anything: the result on stdout and
/// stderr and, unless the process is elevated (which never shows a window), the native notice.
#[cfg(windows)]
fn setup_refused(kind: Kind, name: Option<&str>, silent: bool, elevated: bool) -> Kind {
    let kind = headless_fail(setup::COMMAND, kind);
    if !elevated {
        match name {
            Some(name) => notice(silent, false, name, Operation::Install, kind),
            None => notice(silent, false, SETUP_TITLE, Operation::Setup, kind),
        }
    }
    kind
}

/// The fixed text an elevated setup started without `--all-users` shows (nothing from the payload).
#[cfg(windows)]
const ELEVATED_SETUP_TEXT: &str = "This installer does not run with administrator rights. \
Start it normally and choose \"Install for all users\", or start it with --all-users from an \
administrator prompt.";

/// A Windows setup run after its payload's anchor was read.
#[cfg(windows)]
fn windows_setup(
    ad: &modes::Adapters,
    process: &lunepack_os_windows::WindowsProcess,
    elevation: &dyn lunepack_core::Elevation,
    exe: &std::path::Path,
    found: setup::Found,
    anchor: Option<&lunepack_core::setup::SetupAnchor>,
    run_args: modes::SetupArgs,
) -> Kind {
    let silent = run_args.silent;
    let standing = elevation.standing();
    let elevated = standing == lunepack_core::Standing::UacElevated;
    // Before anything is shown, looked up or written: the payload against the anchor.
    let verified = match setup::verify(ad, found, setup::Binding::Anchor(anchor)) {
        Ok(verified) => verified,
        Err(refused) => return setup_refused(refused.kind, None, silent, elevated),
    };
    let name = verified.name().to_owned();
    let (offer, forced) = match machine::decide(standing, run_args, verified.has_service(), &|| {
        let data_home = data_home()?;
        Ok(setup::user_install_exists(
            ad,
            &data_home,
            verified.app_id(),
            &name,
        ))
    }) {
        machine::Decision::Exit(kind) => return setup_refused(kind, Some(&name), silent, elevated),
        machine::Decision::Notice => {
            let _ = lunepack_os_windows::message_box(
                SETUP_TITLE,
                ELEVATED_SETUP_TEXT,
                lunepack_os_windows::MessageKind::Error,
            );
            eprintln!("{USAGE_LINE}");
            return Kind::Usage;
        }
        machine::Decision::InProcess => return install_all_users_here(ad, verified, anchor),
        machine::Decision::Window { offer, forced } => (offer, forced),
    };

    // The window (when one may be shown), per user by default.
    let data_home = match data_home() {
        Ok(dir) => dir,
        Err(kind) => return setup_refused(kind, Some(&name), silent, elevated),
    };
    let env = |name: &str| std::env::var_os(name);
    let want_ui = ui_host::ui_wanted(silent, &env);
    let own = process.process_id(std::process::id()).ok().flatten();
    clear_temp_dirs(ad);
    let ui_home = setup::ui_home(&env);
    let prepared =
        match verified.into_prepared(ad, &data_home, ui_home.as_deref(), want_ui, own, &alive) {
            Ok(prepared) => prepared,
            Err(refused) => {
                let kind = headless_fail(setup::COMMAND, refused.kind);
                notice(
                    silent,
                    false,
                    refused.name.as_deref().unwrap_or(SETUP_TITLE),
                    Operation::Install,
                    kind,
                );
                return kind;
            }
        };
    // The all-users install needs the machine home and this user's SID; without them the choice
    // is not offered (and a run that asked for it fails).
    let home = machine::native::machine_home();
    let sid = lunepack_os_windows::current_user_sid().ok();
    let connector = machine::native::NativeConnector;
    let machine_ctx = match (&home, &sid) {
        (Some(home), Some(sid)) => Some(setup::Machine {
            home,
            scheme: lunepack_core::MachineScheme::WINDOWS,
            transfer: setup::Transfer::Pipe(machine::HandOff {
                elevation,
                connector: &connector,
                rng: &*ad.rng,
                own_exe: exe,
                sid,
            }),
            offered: offer,
            forced,
        }),
        _ => None,
    };
    if machine_ctx.is_none() && forced {
        prepared.cleanup(&*ad.fs);
        return setup_refused(Kind::Process, Some(&name), silent, elevated);
    }
    let all_users_location = machine_ctx
        .as_ref()
        .filter(|m| m.offered)
        .and_then(|m| shown_path(m.home.join(&name)).to_str().map(str::to_owned));
    let (app, details) = setup::welcome(&prepared, all_users_location);
    let ui = match prepared.ui_dir() {
        Some(dir) => UiHost::start(
            &ui_host::Start {
                process: std::sync::Arc::clone(&ad.process),
                fs: &*ad.fs,
                runtime_exe: &dir.join("lunepack-runtime"),
                env: &env,
                quiet: silent,
                elevated,
            },
            Flow::Install,
            app,
            details,
        ),
        None => UiHost::headless(Flow::Install),
    };
    let events = Events::new(Some(Box::new(StderrSink)), ui.sink());
    ui.report(&events);
    let (kind, last) = setup::run_setup(ad, &prepared, &events, &ui, machine_ctx.as_ref());
    let seen = ui.outcome_acknowledged();
    ui.close(&events);
    prepared.cleanup(&*ad.fs);
    conclude(events, &last);
    notice(silent, seen, prepared.name(), Operation::Install, kind);
    kind
}

/// `--all-users` as an administrator: the payload copied, verified and installed in this process,
/// with no window. The result is the one JSON line on stdout.
#[cfg(windows)]
fn install_all_users_here(
    ad: &modes::Adapters,
    verified: setup::Verified,
    anchor: Option<&lunepack_core::setup::SetupAnchor>,
) -> Kind {
    let (Some(anchor), Some(home)) = (anchor, machine::native::machine_home()) else {
        return headless_fail(setup::COMMAND, Kind::Fs);
    };
    let protect = lunepack_os_windows::WindowsProtect;
    let base = machine::Base {
        fs: &*ad.fs,
        codec: &*ad.codec,
        hasher: &*ad.hasher,
        verifier: &*ad.verifier,
        clock: &lunepack::SystemClock,
        rng: &*ad.rng,
        protect: &protect,
        home: &home,
    };
    let events = stderr_events();
    let result = machine::install_all(
        &base,
        &machine::native::NativeInstaller,
        verified.found(),
        anchor,
        &events,
    );
    let version = verified.version().clone();
    let (kind, last) = match result {
        Ok(installed) => (
            Kind::Ok,
            Event::Result {
                command: setup::COMMAND,
                tree_version: Some(version),
                outcome: setup::OUTCOME,
                version: Some(installed.version),
            },
        ),
        Err(kind) => (kind, setup::failed(kind, Some(version))),
    };
    conclude(events, &last);
    kind
}

/// Whether a setup run that ends before its arguments were validated (a malformed setup file) is
/// quiet for the notice: anything but an empty command line. Arguments that do not parse mean a
/// command-line caller, as with a valid file (whose usage error shows no notice), so no modal box
/// may block it; a double-click passes none and still gets the notice (F14).
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
fn unparsed_setup_quiet(args: &[std::ffi::OsString]) -> bool {
    modes::parse_setup(args).unwrap_or(true)
}

/// The macOS installer (M8-D7, [`setup`]): `None` when this runtime is not the installer app's
/// (the ordinary runtime), else the run's exit kind. A payload file that is malformed is
/// `verify`; a command line other than nothing, `--silent` or `--ui-stdio` is a usage error.
///
/// With `--ui-stdio` the standard output carries the UI's frames and nothing else: the result
/// goes to the standard error stream only (where the events go too).
#[cfg(target_os = "macos")]
fn setup_mode(args: &[std::ffi::OsString]) -> Option<Kind> {
    use lunepack::Process as _;
    use setup::InstallerRun;

    let process = lunepack_os_macos::MacProcess::new();
    let exe = process.current_exe().ok()?;
    let how = setup::parse_installer(args);
    let ui_stdio = how == Ok(InstallerRun::UiStdio);
    let quiet = installer_quiet(how);
    let found = match setup::detect_installer(
        &lunepack_fs::StdFs::new(),
        &exe,
        &lunepack_crypto::Sha256Hasher,
        &lunepack_crypto::Ed25519Verifier,
    ) {
        setup::Detect::None => return None,
        setup::Detect::Malformed => {
            conclude_to(
                stderr_events(),
                &setup::failed(Kind::Verify, None),
                !ui_stdio,
            );
            notice(quiet, false, SETUP_TITLE, Operation::Setup, Kind::Verify);
            return Some(Kind::Verify);
        }
        setup::Detect::Setup(found) => found,
    };
    let Ok(how) = how else {
        eprintln!("{USAGE_LINE}");
        return Some(Kind::Usage);
    };
    Some(run(|ad| {
        let fail = |kind: Kind, name: Option<&str>| {
            conclude_to(stderr_events(), &setup::failed(kind, None), !ui_stdio);
            // A refused root comes after the payload was verified: the notice names the app.
            match name {
                Some(name) => notice(quiet, false, name, Operation::Install, kind),
                None => notice(quiet, false, SETUP_TITLE, Operation::Setup, kind),
            }
            kind
        };
        let data_home = match data_home() {
            Ok(dir) => dir,
            Err(kind) => return fail(kind, None),
        };
        // M8-D2: the live bundle goes in `~/Applications`; the data home is
        // `<canonical HOME>/Library/Application Support` (M8-D1).
        let Some(apps_dir) = data_home
            .parent()
            .and_then(std::path::Path::parent)
            .map(|home| home.join("Applications"))
        else {
            return fail(Kind::Fs, None);
        };
        // No UI is read out of the pack: the installer app carries it beside this runtime.
        let binding = setup::Binding::TrailerRoot;
        let prepared =
            match setup::prepare(ad, found, binding, &data_home, None, false, None, &alive) {
                Ok(prepared) => prepared.with_apps_dir(apps_dir),
                Err(refused) => return fail(refused.kind, refused.name.as_deref()),
            };
        // The all-users install is the installer package the app carries (M11-D8): offered when
        // the app has one, opened in Installer (never run by this process, which is never root).
        // An install of the app in the machine home stops a per-user one either way (M10-D14).
        let pkg = installer_package(ad, &exe);
        let machine_ctx = setup::Machine {
            home: std::path::Path::new(lunepack_core::layout::MACHINE_HOME_MACOS),
            scheme: lunepack_core::MachineScheme::MACOS,
            transfer: setup::Transfer::Package(machine::PackageHandOff {
                process: &*ad.process,
                pkg: pkg.as_deref(),
            }),
            offered: pkg.is_some(),
            forced: false,
        };
        let all_users_location = pkg
            .is_some()
            .then(|| machine::native_macos::APPS_DIR.to_owned());
        let (app, details) = setup::welcome(&prepared, all_users_location);
        let env = |name: &str| std::env::var_os(name);
        let ui = match how {
            InstallerRun::Silent => UiHost::headless(Flow::Install),
            InstallerRun::Ui => UiHost::start(
                &ui_host::Start {
                    process: std::sync::Arc::clone(&ad.process),
                    fs: &*ad.fs,
                    runtime_exe: &exe,
                    env: &env,
                    quiet: false,
                    elevated: uac_elevated(),
                },
                Flow::Install,
                app,
                details,
            ),
            InstallerRun::UiStdio => match (process.parent(), own_streams()) {
                (Ok(Some(parent)), Some((input, output))) => UiHost::over_parent(
                    ui_host::Bounds::default(),
                    std::sync::Arc::clone(&ad.process),
                    parent,
                    input,
                    output,
                    Flow::Install,
                    app,
                    details,
                ),
                // The parent is gone already, or the streams cannot be used: headless.
                _ => UiHost::headless(Flow::Install),
            },
        };
        let events = Events::new(Some(Box::new(StderrSink)), ui.sink());
        ui.report(&events);
        let (kind, last) = setup::run_setup(ad, &prepared, &events, &ui, Some(&machine_ctx));
        let seen = ui.outcome_acknowledged();
        ui.close(&events);
        conclude_to(events, &last, !ui_stdio);
        notice(quiet, seen, prepared.name(), Operation::Install, kind);
        kind
    }))
}

/// The installer package inside the installer app `exe` belongs to
/// (`<I>/Contents/Resources/lunepack-all-users.pkg`), canonical, when it is a regular file: the
/// app's own resource, never a path a caller gave.
#[cfg(target_os = "macos")]
fn installer_package(ad: &modes::Adapters, exe: &std::path::Path) -> Option<PathBuf> {
    let contents = exe.parent()?.parent()?;
    let pkg = contents.join("Resources").join(ALL_USERS_PKG);
    match ad.fs.symlink_metadata(&pkg) {
        Ok(Some(meta)) if meta.kind == lunepack::FileKind::File => std::fs::canonicalize(&pkg).ok(),
        _ => None,
    }
}

/// The installer package's file name in the installer app's resources (the packager's constant).
#[cfg(target_os = "macos")]
const ALL_USERS_PKG: &str = "lunepack-all-users.pkg";

/// Whether a macOS installer run is quiet for the notice (F14): only a run a person started may
/// get one, which is no argument (a double-click on the installer's runtime) or the installer
/// app's own UI (`--ui-stdio`, which a double-click on the app starts). `--silent` and a command
/// line that does not parse are a command-line caller.
#[cfg(target_os = "macos")]
fn installer_quiet(how: Result<setup::InstallerRun, modes::UsageError>) -> bool {
    !matches!(
        how,
        Ok(setup::InstallerRun::Ui | setup::InstallerRun::UiStdio)
    )
}

/// This process's standard input and output as files of their own (duplicated descriptors, so
/// no lock of the standard library's handles is held while a frame is written), for a UI that is
/// the parent (`--ui-stdio`).
#[cfg(target_os = "macos")]
fn own_streams() -> Option<(
    Box<dyn std::io::Read + Send>,
    Box<dyn std::io::Write + Send>,
)> {
    use std::os::fd::AsFd as _;
    let input = std::io::stdin().as_fd().try_clone_to_owned().ok()?;
    let output = std::io::stdout().as_fd().try_clone_to_owned().ok()?;
    Some((
        Box::new(std::fs::File::from(input)),
        Box::new(std::fs::File::from(output)),
    ))
}

/// Setup files are Linux, Windows and macOS only.
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
fn setup_mode(_args: &[std::ffi::OsString]) -> Option<Kind> {
    None
}

/// Runs `body` on the native adapters.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
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

/// The process and desktop-integration adapters of this OS (per-user scope, M8).
#[cfg(target_os = "macos")]
fn native_adapters() -> (
    std::sync::Arc<dyn lunepack::Process>,
    std::sync::Arc<dyn lunepack::OsIntegration>,
) {
    (
        std::sync::Arc::new(lunepack_os_macos::MacProcess::new()),
        std::sync::Arc::new(lunepack_os_macos::MacIntegration::from_process_env()),
    )
}

/// Processes and the desktop integration have no adapter on this OS.
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
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

    /// A copy in a place lunepack does not update is told to move (M8-D4), with no code or reason.
    #[test]
    fn an_unsupported_location_tells_the_user_to_move_the_app() {
        for operation in [Operation::Install, Operation::Uninstall, Operation::Setup] {
            for place in [
                modes::Place::Translocated,
                modes::Place::ReadOnly,
                modes::Place::NotOwned,
            ] {
                assert_eq!(
                    notice_text("My App", operation, Kind::UnsupportedLocation(place)),
                    "Move My App to your Applications folder and open it from there."
                );
                assert!(!notice_is_info(operation, Kind::UnsupportedLocation(place)));
            }
        }
    }

    /// A malformed setup file is checked before its arguments: only an empty command line (a
    /// double-click) may get the modal notice; anything else is a command-line caller (F14).
    #[test]
    fn a_setup_with_unparsed_arguments_shows_a_notice_only_for_an_empty_command_line() {
        let os = |a: &[&str]| a.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        assert!(!unparsed_setup_quiet(&os(&[])));
        assert!(unparsed_setup_quiet(&os(&["--silent"])));
        for args in [
            &["--no-such-option"][..],
            &["/quiet"],
            &["/VERYSILENT"],
            &["/qn"],
            &["install"],
            &["--silent", "--silent"],
            &["--no-ui"],
        ] {
            assert!(unparsed_setup_quiet(&os(args)), "{args:?}");
        }
    }

    /// A setup rerun over the installed app (exit 23) is a normal end, not a failed install.
    #[test]
    fn an_already_installed_app_is_reported_as_installed_with_the_information_icon() {
        assert_eq!(
            notice_text("My App", Operation::Install, Kind::AlreadyInstalled),
            "My App is already installed."
        );
        assert!(notice_is_info(Operation::Install, Kind::AlreadyInstalled));
        assert!(notice_is_info(Operation::Install, Kind::Ok));
        assert!(notice_is_info(Operation::Uninstall, Kind::Ok));
        assert!(!notice_is_info(Operation::Install, Kind::Fs));
        assert!(!notice_is_info(Operation::Setup, Kind::Verify));
        assert!(!notice_is_info(
            Operation::Uninstall,
            Kind::AlreadyInstalled
        ));
    }

    /// macOS (F14): the installer's notice only for a double-click (no argument) or its own UI.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_installer_shows_a_notice_only_for_a_double_click_or_its_own_ui() {
        let os = |a: &[&str]| a.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        assert!(!installer_quiet(setup::parse_installer(&os(&[]))));
        assert!(!installer_quiet(setup::parse_installer(&os(&[
            "--ui-stdio"
        ]))));
        for args in [
            &["--silent"][..],
            &["--no-such-option"],
            &["/S"],
            &["install"],
            &["--ui-stdio", "--silent"],
            &["--ui-stdio", "--ui-stdio"],
            &["--ui-stdio=1"],
        ] {
            assert!(
                installer_quiet(setup::parse_installer(&os(args))),
                "{args:?}"
            );
        }
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
