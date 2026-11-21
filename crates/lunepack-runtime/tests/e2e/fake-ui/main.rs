//! A stand-in `lunepack-ui` for the end-to-end suite (M6 step 11): a small ELF that speaks the
//! engine's frame protocol with no window, so a release can carry it (`pack --ui` only takes an
//! executable image) and the suite can start it, kill it and count its starts without a GPU.
//!
//! It is started as the real UI is (`lunepack-ui --engine`, frames on standard input and output)
//! and is told what to do through the environment the runtime passes on:
//!
//! - `LUNEPACK_E2E_UI_DIR`: a directory it notes its life in, one file per kind and one line per
//!   event: `ui-spawns` (one line per start), `ui-hello` (the flow and the app's name) and
//!   `ui-prompts` (the kind of each prompt). Nothing is noted when it is unset.
//! - `LUNEPACK_E2E_UI_MODE`: `proceed` (the default) says hello, answers every `Ping` and takes
//!   the choice that lets the operation go on (proceed at the welcome and confirm screens, finish
//!   without launching, close, acknowledge); `die` does the same until the operation reports
//!   progress, a finished step or its outcome, and then aborts the process (SIGABRT);
//!   `all-users` is `proceed`, except that at the welcome screen it answers `ProceedAllUsers`
//!   when the hello offered the all-users install (and plain `Proceed` when it did not);
//!   `all-users-die` is `all-users` followed by `die` (the per-machine suite's hand-off whose
//!   window is lost mid-install).
//!
//! On Windows it is a GUI-subsystem program with the build's hardening (the runtime's `build.rs`
//! links examples too), because `pack --ui` holds a `windows-*` UI to the runtime's own image
//! rules (subsystem, `DependentLoadFlags`, manifest, no static `advapi32`).

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use lunepack_core::ui::{self, ChoiceValue, EngineMsg, Flow, PromptKind, UiMsg};

const DIR_VAR: &str = "LUNEPACK_E2E_UI_DIR";
const MODE_VAR: &str = "LUNEPACK_E2E_UI_MODE";

fn note(name: &str, text: &str) {
    let Some(dir) = std::env::var_os(DIR_VAR) else {
        return;
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(Path::new(&dir).join(name))
    {
        let _ = file.write_all(text.as_bytes());
    }
}

/// The choice that lets the operation go on.
fn choice(kind: PromptKind, flow: Option<Flow>, all_users: bool) -> ChoiceValue {
    match kind {
        PromptKind::Welcome if all_users => ChoiceValue::ProceedAllUsers,
        PromptKind::Welcome | PromptKind::Confirm => ChoiceValue::Proceed,
        PromptKind::Done if flow == Some(Flow::Uninstall) => ChoiceValue::Close,
        PromptKind::Done => ChoiceValue::Finish { launch: false },
        PromptKind::Failed => ChoiceValue::Close,
        PromptKind::RolledBack => ChoiceValue::Acknowledge,
    }
}

fn main() -> ExitCode {
    #[cfg(windows)]
    lunepack_os_windows::harden_dll_search();
    let args: Vec<_> = std::env::args_os().collect();
    // The macOS installer app's main executable (M8-D7): started with no argument as
    // `<I>/Contents/MacOS/lunepack-ui`, it starts the runtime beside it with `--ui-stdio` and
    // serves the frames over that child's pipes (the parent's role of the real UI).
    #[cfg(unix)]
    if args.len() == 1
        && let Some(runtime) = installer_runtime()
    {
        return as_installer_parent(&runtime);
    }
    if args.get(1).map(std::ffi::OsString::as_os_str) != Some("--engine".as_ref())
        || args.len() != 2
    {
        eprintln!("usage: e2e_fake_ui --engine");
        return ExitCode::from(2);
    }
    let mode = Mode::from_env();
    note("ui-spawns", "start\n");
    serve(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        mode,
    )
}

/// The runtime beside this executable when it is `lunepack-ui` in `Contents/MacOS`.
#[cfg(unix)]
fn installer_runtime() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    if exe.file_name()? != "lunepack-ui" {
        return None;
    }
    let dir = exe.parent()?;
    (dir.file_name()? == "MacOS").then(|| dir.join("lunepack-runtime"))
}

/// Runs the runtime with `--ui-stdio` and answers its frames; returns when the runtime ends.
#[cfg(unix)]
fn as_installer_parent(runtime: &Path) -> ExitCode {
    use std::process::{Command, Stdio};
    let mode = Mode::from_env();
    note("ui-spawns", "start\n");
    let Ok(mut child) = Command::new(runtime)
        .arg("--ui-stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    else {
        return ExitCode::from(1);
    };
    let (Some(mut to_child), Some(mut from_child)) = (child.stdin.take(), child.stdout.take())
    else {
        return ExitCode::from(1);
    };
    serve(&mut from_child, &mut to_child, mode);
    drop(to_child);
    match child.wait() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    }
}

/// What the stand-in does, from `LUNEPACK_E2E_UI_MODE`.
#[derive(Clone, Copy)]
struct Mode {
    /// Abort once the operation reports progress, a step or its outcome.
    die: bool,
    /// Answer the all-users choice at the welcome screen when it is offered.
    all_users: bool,
}

impl Mode {
    fn from_env() -> Mode {
        let mode = std::env::var(MODE_VAR).ok();
        Mode {
            die: matches!(mode.as_deref(), Some("die" | "all-users-die")),
            all_users: matches!(mode.as_deref(), Some("all-users" | "all-users-die")),
        }
    }
}

/// Answers the engine's frames from `input` on `out` until the engine closes.
fn serve(input: &mut impl std::io::Read, out: &mut impl std::io::Write, mode: Mode) -> ExitCode {
    let die = mode.die;
    let mut flow = None;
    let mut offered = false;
    loop {
        let Ok(msg) = ui::read_frame::<_, EngineMsg>(input) else {
            return ExitCode::SUCCESS;
        };
        let reply = match msg {
            EngineMsg::Hello {
                build_id,
                flow: shown,
                app,
                details,
            } => {
                flow = Some(shown);
                offered = shown == Flow::Install && details.all_users_location.is_some();
                note("ui-hello", &format!("{shown:?} {}\n", app.name));
                Some(UiMsg::Hello { build_id })
            }
            EngineMsg::Ping { n } => Some(UiMsg::Pong { n }),
            EngineMsg::Prompt { id, kind } => {
                note("ui-prompts", &format!("{kind:?}\n"));
                Some(UiMsg::Choice {
                    id,
                    value: choice(kind, flow, mode.all_users && offered),
                })
            }
            EngineMsg::Progress { .. } | EngineMsg::Step { .. } | EngineMsg::Outcome(_) if die => {
                die_abruptly();
            }
            EngineMsg::Close => return ExitCode::SUCCESS,
            _ => None,
        };
        if let Some(reply) = reply
            && ui::write_frame(out, &reply).is_err()
        {
            return ExitCode::SUCCESS;
        }
    }
}

/// Ends this process the way a crashed UI looks to the runtime (its pipes close, no exit status of
/// its own), without a crash report: on macOS an abort would raise the system's "quit unexpectedly"
/// dialog on the screen of whoever runs the suite, so the process kills itself with SIGKILL, which
/// writes no report. Elsewhere it aborts (SIGABRT), as the Linux rows have always done.
fn die_abruptly() -> ! {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", &std::process::id().to_string()])
            .status();
        // `kill` could not run: leave with a plain exit status (no signal, no report).
        std::process::exit(137);
    }
    #[cfg(not(target_os = "macos"))]
    std::process::abort()
}
