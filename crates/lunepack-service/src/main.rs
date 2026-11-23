//! `lunepack-service`: the per-machine update service. See the library's docs.

use std::ffi::OsString;
use std::process::ExitCode;

use lunepack_service::args;
use lunepack_service::exit;

fn main() -> ExitCode {
    // First, before any library load: only System32 from here on (M7-D10).
    #[cfg(windows)]
    lunepack_os_windows::harden_dll_search();
    // The service stands as root: its unit says `UMask=0022` already, and a launchd daemon starts
    // with 022, but it takes no mask from anywhere else either (M11-D7).
    #[cfg(target_os = "linux")]
    lunepack_os_linux::set_root_umask();
    #[cfg(target_os = "macos")]
    lunepack_os_macos::set_root_umask();
    // The one place the command line is read.
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mode = match args::parse(&argv) {
        Ok(mode) => mode,
        Err(args::UsageError) => {
            eprintln!("usage: lunepack-service [--self-test]");
            return ExitCode::from(exit::USAGE);
        }
    };
    run(mode)
}

#[cfg(windows)]
fn run(mode: args::Mode) -> ExitCode {
    ExitCode::from(lunepack_service::host::run(mode))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run(mode: args::Mode) -> ExitCode {
    ExitCode::from(lunepack_service::host_unix::run(mode))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn run(mode: args::Mode) -> ExitCode {
    let _ = mode;
    println!("lunepack-service: this system has no update service host yet");
    ExitCode::from(exit::USAGE)
}
