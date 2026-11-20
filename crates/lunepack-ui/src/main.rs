//! `lunepack-ui`: the separate process that shows the install, update and uninstall screens
//! (M6). It is spawned by the runtime, talks to it over stdio frames and never decides anything:
//! the engine validates every choice, and the UI's failure never changes an outcome.
//!
//! The event loop runs on the main thread. A reader thread decodes the frames on standard input
//! and posts them to the loop; a writer thread sends the answers on standard output, which carries
//! nothing else. The exit codes are typed (`channel::Exit`): 0 closed, 10 no display, 11 no
//! adapter, 12 protocol error, 13 engine gone, 14 build-id mismatch; 2 is a usage error.
//!
//! macOS installer (M8-D7): in `Install <name>.app` this binary is the main executable, so a
//! double-click starts it with no argument. When its resolved path is
//! `<I>/Contents/MacOS/lunepack-ui` and both `<I>/Contents/MacOS/lunepack-runtime` and
//! `<I>/Contents/Resources/lunepack-setup.payload` are regular files ([`installer_engine`]), it
//! starts that runtime, and only it, with the one argument `--ui-stdio`, and talks to it over the
//! child's pipes exactly as it would over its own standard streams. The engine decides
//! everything and finishes without the UI if the UI goes; the UI never stops the engine. Anything
//! else keeps the `--engine`-only grammar.

#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod channel;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use lunepack_ui_luneui::lune_ui::motion::MotionTier;
use lunepack_ui_luneui::winit::event_loop::EventLoop;

use channel::{Exit, UserEvent};

const USAGE: &str =
    "usage: lunepack-ui --engine (started by the lunepack runtime; frames on stdin and stdout)";

/// Whether `args` (after the program name) are exactly `--engine`.
fn is_engine_mode(args: &[OsString]) -> bool {
    matches!(args, [only] if only == "--engine")
}

/// The installer's runtime, beside this binary in an installer app (M8-D7): `exe` (this binary's
/// resolved path) is `<I>/Contents/MacOS/lunepack-ui`, and `<I>/Contents/MacOS/lunepack-runtime`
/// and `<I>/Contents/Resources/lunepack-setup.payload` are regular files, not links. The path is
/// built from `exe` alone; nothing from the command line or the environment goes into it.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn installer_engine(exe: &Path) -> Option<PathBuf> {
    let named = |path: Option<&Path>, name: &str| {
        path.and_then(Path::file_name)
            .is_some_and(|n| n == std::ffi::OsStr::new(name))
    };
    let macos_dir = exe.parent();
    let contents = macos_dir.and_then(Path::parent);
    if !named(Some(exe), "lunepack-ui")
        || !named(macos_dir, "MacOS")
        || !named(contents, "Contents")
    {
        return None;
    }
    let installer = contents?.parent()?;
    let is_file = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file());
    let engine = macos_dir?.join(ENGINE_FILE);
    let payload = lunepack_core::update_config::MACOS_INSTALLER_PAYLOAD
        .split('/')
        .fold(installer.to_path_buf(), |dir, name| dir.join(name));
    (is_file(&engine) && is_file(&payload)).then_some(engine)
}

/// The installer's runtime's file name, beside this binary.
const ENGINE_FILE: &str = "lunepack-runtime";
/// The one argument the installer's runtime is started with.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const UI_STDIO_ARG: &str = "--ui-stdio";
/// The variable that carries a supervised start's health token; never passed on.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const HEALTH_TOKEN_VAR: &str = "LUNEPACK_HEALTH_TOKEN";

/// Starts the installer's runtime `engine` with its standard input and output piped to this
/// process (standard error inherited) and runs the UI over those pipes. The runtime is not
/// waited for and never stopped: when the UI ends first, the runtime finishes without it.
#[cfg(target_os = "macos")]
fn run_installer(engine: &Path) -> Exit {
    let child = std::process::Command::new(engine)
        .arg(UI_STDIO_ARG)
        .env_remove(HEALTH_TOKEN_VAR)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn();
    let Ok(mut child) = child else {
        return Exit::EngineGone;
    };
    let (Some(to_engine), Some(from_engine)) = (child.stdin.take(), child.stdout.take()) else {
        return Exit::EngineGone;
    };
    run(from_engine, to_engine)
}

/// The OS's reduce-motion setting as a motion tier: reduced only when the OS says so; unknown
/// is the full tier.
fn motion_tier() -> MotionTier {
    #[cfg(windows)]
    let reduced = lunepack_os_windows::prefers_reduced_motion();
    #[cfg(target_os = "macos")]
    let reduced = lunepack_os_macos::prefers_reduced_motion();
    #[cfg(target_os = "linux")]
    let reduced = lunepack_os_linux::prefers_reduced_motion();
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    let reduced: Option<bool> = None;
    if reduced == Some(true) {
        MotionTier::Reduced
    } else {
        MotionTier::Full
    }
}

fn main() -> ExitCode {
    // First, before any library load: only System32 from here on (M7-D10).
    #[cfg(windows)]
    lunepack_os_windows::harden_dll_search();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    #[cfg(target_os = "macos")]
    if args.is_empty()
        && let Some(engine) = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .ok()
            .and_then(|exe| installer_engine(&exe))
    {
        return ExitCode::from(run_installer(&engine).code());
    }
    if !is_engine_mode(&args) {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    ExitCode::from(run(std::io::stdin(), std::io::stdout()).code())
}

/// The UI over the engine's frames on `input`, answering on `output`.
fn run(input: impl Read + Send + 'static, output: impl Write + Send + 'static) -> Exit {
    let event_loop = match EventLoop::<UserEvent>::with_user_event().build() {
        Ok(l) => l,
        Err(_) => return Exit::NoDisplay,
    };
    let proxy = event_loop.create_proxy();
    let reader_proxy = event_loop.create_proxy();
    if channel::spawn_reader(input, move |ev| reader_proxy.send_event(ev).is_ok()).is_err() {
        return Exit::EngineGone;
    }
    let writer_proxy = event_loop.create_proxy();
    let Ok(writer) = channel::spawn_writer(output, move || {
        let _ = writer_proxy.send_event(UserEvent::Ended(Exit::EngineGone));
    }) else {
        return Exit::EngineGone;
    };
    let mut app = app::App::new(proxy, writer, motion_tier());
    match event_loop.run_app(&mut app) {
        Ok(()) => app.exit(),
        Err(_) => Exit::NoDisplay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn only_a_lone_engine_flag_starts_the_ui() {
        assert!(is_engine_mode(&args(&["--engine"])));
        assert!(!is_engine_mode(&args(&[])));
        assert!(!is_engine_mode(&args(&["--engine", "x"])));
        assert!(!is_engine_mode(&args(&["--demo"])));
        assert!(!is_engine_mode(&args(&["--engine=1"])));
    }

    /// An installer app laid out under a temporary directory; returns the UI's path in it.
    fn installer(dir: &Path, engine: bool, payload: bool) -> PathBuf {
        let macos = dir.join("Install App.app/Contents/MacOS");
        let resources = dir.join("Install App.app/Contents/Resources");
        std::fs::create_dir_all(&macos).unwrap();
        std::fs::create_dir_all(&resources).unwrap();
        std::fs::write(macos.join("lunepack-ui"), b"ui").unwrap();
        if engine {
            std::fs::write(macos.join("lunepack-runtime"), b"runtime").unwrap();
        }
        if payload {
            std::fs::write(resources.join("lunepack-setup.payload"), b"payload").unwrap();
        }
        macos.join("lunepack-ui")
    }

    #[test]
    fn the_installer_engine_is_the_runtime_beside_the_ui_and_nothing_else() {
        let tmp = std::env::temp_dir().join(format!("lp-ui-installer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let ui = installer(&tmp.join("good"), true, true);
        assert_eq!(
            installer_engine(&ui),
            Some(ui.parent().unwrap().join("lunepack-runtime"))
        );
        // Either sibling missing: not an installer.
        assert_eq!(
            installer_engine(&installer(&tmp.join("a"), false, true)),
            None
        );
        assert_eq!(
            installer_engine(&installer(&tmp.join("b"), true, false)),
            None
        );
        // Another name or place of the UI itself.
        let renamed = ui.with_file_name("other-ui");
        std::fs::copy(&ui, &renamed).unwrap();
        assert_eq!(installer_engine(&renamed), None);
        let loose = tmp.join("good/Install App.app/Contents/lunepack-ui");
        std::fs::copy(&ui, &loose).unwrap();
        assert_eq!(installer_engine(&loose), None);
        // A link in the runtime's place is not the runtime.
        #[cfg(unix)]
        {
            let ui = installer(&tmp.join("link"), false, true);
            std::os::unix::fs::symlink(
                tmp.join("good/Install App.app/Contents/MacOS/lunepack-runtime"),
                ui.parent().unwrap().join("lunepack-runtime"),
            )
            .unwrap();
            assert_eq!(installer_engine(&ui), None);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn the_motion_tier_is_one_of_the_two_the_os_can_ask_for() {
        assert!(matches!(
            motion_tier(),
            MotionTier::Full | MotionTier::Reduced
        ));
    }
}
