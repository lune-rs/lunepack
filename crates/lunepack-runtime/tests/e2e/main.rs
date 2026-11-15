//! The end-to-end suite of the Linux runtime (M5-D13): the real `lunepack` command line packs and
//! signs releases, a loopback server (or a directory) serves them, and an installed app updates
//! itself through the real static runtime, confirms its health or is rolled back, and is
//! uninstalled. Rows are in [`scenarios`]; the helpers that drive and read the binaries are in
//! [`lab`].
//!
//! `scripts/e2e.sh` builds what this needs and runs it in a container. It is not part of the
//! gate: without its environment the binary prints SKIP and exits 0, and with
//! `LUNEPACK_E2E_REQUIRE=1` (CI) a skip is a failure. With its environment it refuses to run on
//! anything but Linux, and outside a container or CI, so a developer's own home and desktop are
//! never touched (every child runs with a temporary `HOME` all the same).
//!
//! Environment: `LUNEPACK_E2E_RUNTIME` (the static runtime), `LUNEPACK_E2E_CLI` (`lunepack`),
//! `LUNEPACK_E2E_APP` (the Rust example app, `e2e_app`).

#[cfg(target_os = "linux")]
mod lab;
#[cfg(target_os = "linux")]
mod scenarios;

use std::path::PathBuf;
use std::process::ExitCode;

const RUNTIME_VAR: &str = "LUNEPACK_E2E_RUNTIME";
const CLI_VAR: &str = "LUNEPACK_E2E_CLI";
const APP_VAR: &str = "LUNEPACK_E2E_APP";
const REQUIRE_VAR: &str = "LUNEPACK_E2E_REQUIRE";

fn main() -> ExitCode {
    let paths: Vec<Option<PathBuf>> = [RUNTIME_VAR, CLI_VAR, APP_VAR]
        .iter()
        .map(|var| std::env::var_os(var).map(PathBuf::from))
        .collect();
    let [Some(runtime), Some(cli), Some(app)] = &paths[..] else {
        if std::env::var(REQUIRE_VAR).is_ok_and(|v| v == "1") {
            eprintln!("e2e: FAIL: {REQUIRE_VAR}=1, but the build environment is not set");
            return ExitCode::FAILURE;
        }
        println!(
            "e2e: SKIP (run scripts/e2e.sh: it builds the runtime, the command line and the app)"
        );
        return ExitCode::SUCCESS;
    };
    run(runtime, cli, app)
}

#[cfg(not(target_os = "linux"))]
fn run(_: &PathBuf, _: &PathBuf, _: &PathBuf) -> ExitCode {
    eprintln!(
        "e2e: refusing to run: the suite is Linux only (scripts/e2e.sh runs it in a container)"
    );
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn run(runtime: &PathBuf, cli: &PathBuf, app: &PathBuf) -> ExitCode {
    use std::path::Path;

    let in_container = Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || std::env::var_os("CI").is_some();
    if !in_container {
        eprintln!(
            "e2e: refusing to run outside a container or CI (scripts/e2e.sh runs it in Docker)"
        );
        return ExitCode::FAILURE;
    }
    for path in [runtime, cli, app] {
        if !path.is_file() {
            eprintln!("e2e: FAIL: a binary named in the environment is not a file");
            return ExitCode::FAILURE;
        }
    }
    let Some(name) = app.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        eprintln!("e2e: FAIL: the app has no file name");
        return ExitCode::FAILURE;
    };
    let bins = lab::Binaries {
        runtime: runtime.clone(),
        cli: cli.clone(),
    };
    let app = lab::App {
        binary: app.clone(),
        name,
    };
    eprintln!("e2e: {}", scenarios::validator_note());
    match scenarios::run_table(&bins, &app) {
        Ok(log) => {
            println!("e2e: outcome log ({} lines)", log.len());
            for line in &log {
                println!("{line}");
            }
            println!("e2e: PASS");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("e2e: FAIL: {why}");
            ExitCode::FAILURE
        }
    }
}
