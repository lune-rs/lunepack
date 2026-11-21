//! `lunepack-service`: the per-machine update service. See the library's docs.

use std::ffi::OsString;
use std::process::ExitCode;

use lunepack_service::args;
use lunepack_service::exit;

fn main() -> ExitCode {
    // First, before any library load: only System32 from here on (M7-D10).
    lunepack_os_windows::harden_dll_search();
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

#[cfg(not(windows))]
fn run(mode: args::Mode) -> ExitCode {
    // The Linux and macOS hosts come with M11.
    let _ = mode;
    println!("lunepack-service: this system has no update service host yet");
    ExitCode::from(exit::USAGE)
}
