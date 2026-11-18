//! `lunepack-ui`: the separate process that shows the install, update and uninstall screens
//! (M6). It is spawned by the runtime, talks to it over stdio frames and never decides anything:
//! the engine validates every choice, and the UI's failure never changes an outcome.
//!
//! The event loop runs on the main thread. A reader thread decodes the frames on standard input
//! and posts them to the loop; a writer thread sends the answers on standard output, which carries
//! nothing else. The exit codes are typed (`channel::Exit`): 0 closed, 10 no display, 11 no
//! adapter, 12 protocol error, 13 engine gone, 14 build-id mismatch; 2 is a usage error.

#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod channel;

use std::ffi::OsString;
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
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if !is_engine_mode(&args) {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    ExitCode::from(run().code())
}

fn run() -> Exit {
    let event_loop = match EventLoop::<UserEvent>::with_user_event().build() {
        Ok(l) => l,
        Err(_) => return Exit::NoDisplay,
    };
    let proxy = event_loop.create_proxy();
    let reader_proxy = event_loop.create_proxy();
    if channel::spawn_reader(std::io::stdin(), move |ev| {
        reader_proxy.send_event(ev).is_ok()
    })
    .is_err()
    {
        return Exit::EngineGone;
    }
    let writer_proxy = event_loop.create_proxy();
    let Ok(writer) = channel::spawn_writer(std::io::stdout(), move || {
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

    #[test]
    fn the_motion_tier_is_one_of_the_two_the_os_can_ask_for() {
        assert!(matches!(
            motion_tier(),
            MotionTier::Full | MotionTier::Reduced
        ));
    }
}
