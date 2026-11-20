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
//! The scenario table runs twice, once with the Rust example app (`e2e_app`, which updates itself
//! through the library) and once with the shell app (`shell-app/app.sh`, which drives the
//! runtime's command line only); the two normalised outcome logs must be equal. The extra
//! command-line tests (hard kill, nothing staged, planted secrets) are in [`cli_extra`]. The UI
//! scenarios (M6 step 11: a setup file, a UI that is absent, killed or cannot start) are in [`ui`]:
//! a table run with both apps like the first, then extras run once.
//!
//! Environment: `LUNEPACK_E2E_RUNTIME` (the static runtime), `LUNEPACK_E2E_CLI` (`lunepack`),
//! `LUNEPACK_E2E_APP` (the Rust example app), `LUNEPACK_E2E_SHELL_APP` (the shell app),
//! `LUNEPACK_E2E_FAKE_UI` (the stand-in UI, `tests/e2e/fake-ui`) and `LUNEPACK_E2E_UI` (the real
//! `lunepack-ui`).

#[cfg(target_os = "linux")]
mod cli_extra;
#[cfg(target_os = "linux")]
mod lab;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod scenarios;
#[cfg(target_os = "linux")]
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

const RUNTIME_VAR: &str = "LUNEPACK_E2E_RUNTIME";
const CLI_VAR: &str = "LUNEPACK_E2E_CLI";
const APP_VAR: &str = "LUNEPACK_E2E_APP";
const SHELL_APP_VAR: &str = "LUNEPACK_E2E_SHELL_APP";
const FAKE_UI_VAR: &str = "LUNEPACK_E2E_FAKE_UI";
const UI_VAR: &str = "LUNEPACK_E2E_UI";
const REQUIRE_VAR: &str = "LUNEPACK_E2E_REQUIRE";

fn main() -> ExitCode {
    let paths: Vec<Option<PathBuf>> = [
        RUNTIME_VAR,
        CLI_VAR,
        APP_VAR,
        SHELL_APP_VAR,
        FAKE_UI_VAR,
        UI_VAR,
    ]
    .iter()
    .map(|var| std::env::var_os(var).map(PathBuf::from))
    .collect();
    let [
        Some(runtime),
        Some(cli),
        Some(app),
        Some(shell),
        Some(fake_ui),
        Some(real_ui),
    ] = &paths[..]
    else {
        if std::env::var(REQUIRE_VAR).is_ok_and(|v| v == "1") {
            eprintln!("e2e: FAIL: {REQUIRE_VAR}=1, but the build environment is not set");
            return ExitCode::FAILURE;
        }
        println!(
            "e2e: SKIP (run scripts/e2e.sh: it builds the runtime, the command line and the apps)"
        );
        return ExitCode::SUCCESS;
    };
    run(&Paths {
        runtime,
        cli,
        app,
        shell,
        fake_ui,
        real_ui,
    })
}

/// The files the environment names (only the Linux and macOS builds read them).
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
struct Paths<'a> {
    runtime: &'a PathBuf,
    cli: &'a PathBuf,
    app: &'a PathBuf,
    shell: &'a PathBuf,
    fake_ui: &'a PathBuf,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    real_ui: &'a PathBuf,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn run(_: &Paths<'_>) -> ExitCode {
    eprintln!(
        "e2e: refusing to run: the suite is Linux (scripts/e2e.sh) or macOS (scripts/e2e-macos.sh) only"
    );
    ExitCode::FAILURE
}

/// The macOS suite (M8 step 10): `scripts/e2e-macos.sh` makes the temporary root and sets `HOME`
/// and `LUNEPACK_E2E_ROOT`; the rows are in [`macos`].
#[cfg(target_os = "macos")]
fn run(paths: &Paths<'_>) -> ExitCode {
    for path in [
        paths.runtime,
        paths.cli,
        paths.app,
        paths.shell,
        paths.fake_ui,
    ] {
        if !path.is_file() {
            eprintln!("e2e: FAIL: a binary named in the environment is not a file");
            return ExitCode::FAILURE;
        }
    }
    if std::env::var_os("LUNEPACK_E2E_ROOT").is_none() {
        eprintln!("e2e: refusing to run without LUNEPACK_E2E_ROOT (scripts/e2e-macos.sh sets it)");
        return ExitCode::FAILURE;
    }
    let bins = macos::Bins {
        runtime: paths.runtime.clone(),
        cli: paths.cli.clone(),
        app: paths.app.clone(),
        shell_app: paths.shell.clone(),
        fake_ui: paths.fake_ui.clone(),
    };
    let ci = std::env::var("LUNEPACK_E2E_CI").is_ok_and(|v| v == "1");
    match macos::run_all(&bins, ci) {
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

#[cfg(target_os = "linux")]
fn run(paths: &Paths<'_>) -> ExitCode {
    use std::path::Path;

    let Paths {
        runtime,
        cli,
        app,
        shell,
        fake_ui,
        real_ui,
    } = paths;

    let in_container = Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || std::env::var_os("CI").is_some();
    if !in_container {
        eprintln!(
            "e2e: refusing to run outside a container or CI (scripts/e2e.sh runs it in Docker)"
        );
        return ExitCode::FAILURE;
    }
    for path in [runtime, cli, app, shell, fake_ui, real_ui] {
        if !path.is_file() {
            eprintln!("e2e: FAIL: a binary named in the environment is not a file");
            return ExitCode::FAILURE;
        }
    }
    let bins = lab::Binaries {
        runtime: (*runtime).clone(),
        cli: (*cli).clone(),
        fake_ui: (*fake_ui).clone(),
        real_ui: (*real_ui).clone(),
    };
    let (Some(rust_app), Some(shell_app)) = (named_app(app), named_app(shell)) else {
        eprintln!("e2e: FAIL: an app has no file name");
        return ExitCode::FAILURE;
    };
    eprintln!("e2e: {}", scenarios::validator_note());

    eprintln!("e2e: table 1 of 2: the Rust app ({})", rust_app.name);
    let rust_log = match scenarios::run_table(&bins, &rust_app) {
        Ok(log) => log,
        Err(why) => {
            eprintln!("e2e: FAIL: {why}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("e2e: table 2 of 2: the shell app ({})", shell_app.name);
    let shell_log = match scenarios::run_table(&bins, &shell_app) {
        Ok(log) => log,
        Err(why) => {
            eprintln!("e2e: FAIL: the shell app: {why}");
            return ExitCode::FAILURE;
        }
    };
    if !same_logs(&rust_log, &shell_log) {
        return ExitCode::FAILURE;
    }

    eprintln!("e2e: ui table: the Rust app ({})", rust_app.name);
    let rust_ui_log = match ui::run_table(&bins, &rust_app) {
        Ok(log) => log,
        Err(why) => {
            eprintln!("e2e: FAIL: {why}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("e2e: ui table: the shell app ({})", shell_app.name);
    let shell_ui_log = match ui::run_table(&bins, &shell_app) {
        Ok(log) => log,
        Err(why) => {
            eprintln!("e2e: FAIL: the shell app: {why}");
            return ExitCode::FAILURE;
        }
    };
    if !same_logs(&rust_ui_log, &shell_ui_log) {
        return ExitCode::FAILURE;
    }
    let rust_log: Vec<String> = rust_log.into_iter().chain(rust_ui_log).collect();

    if let Err(why) = cli_extra::run_all(&bins, &rust_app) {
        eprintln!("e2e: FAIL: {why}");
        return ExitCode::FAILURE;
    }
    if let Err(why) = ui::run_extras(&bins, &rust_app) {
        eprintln!("e2e: FAIL: {why}");
        return ExitCode::FAILURE;
    }

    println!(
        "e2e: outcome log ({} lines, equal for both apps)",
        rust_log.len()
    );
    for line in &rust_log {
        println!("{line}");
    }
    println!("e2e: PASS");
    ExitCode::SUCCESS
}

/// Whether the two apps' outcome logs are equal; prints the first difference when not.
#[cfg(target_os = "linux")]
fn same_logs(rust_log: &[String], shell_log: &[String]) -> bool {
    if rust_log == shell_log {
        return true;
    }
    eprintln!("e2e: FAIL: the two apps' outcome logs differ");
    let at = rust_log
        .iter()
        .zip(shell_log)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| rust_log.len().min(shell_log.len()));
    eprintln!(
        "  first difference at line {at}:\n    rust:  {:?}\n    shell: {:?}",
        rust_log.get(at),
        shell_log.get(at)
    );
    false
}

#[cfg(target_os = "linux")]
fn named_app(binary: &std::path::Path) -> Option<lab::App> {
    let name = binary.file_name()?.to_string_lossy().into_owned();
    Some(lab::App {
        binary: binary.to_owned(),
        name,
    })
}
