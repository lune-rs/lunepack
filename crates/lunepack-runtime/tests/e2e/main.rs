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
//! a table run with both apps like the first, then extras run once. A third app, the .NET
//! example (M13 step 7), is a folder of about 190 files; it runs the rows of
//! [`scenarios::FOLDER_APP_ROWS`] and its log must equal the shell app's log cut to those rows.
//!
//! Environment: `LUNEPACK_E2E_RUNTIME` (the static runtime), `LUNEPACK_E2E_CLI` (`lunepack`),
//! `LUNEPACK_E2E_APP` (the Rust example app), `LUNEPACK_E2E_SHELL_APP` (the shell app),
//! `LUNEPACK_E2E_FAKE_UI` (the stand-in UI, `tests/e2e/fake-ui`) and `LUNEPACK_E2E_UI` (the real
//! `lunepack-ui`). On macOS `LUNEPACK_E2E_DOTNET_BUNDLE` names the example's app bundle instead.
//! `LUNEPACK_E2E_DOTNET_APP` names the published folder of the .NET example (its
//! entry is `Example`; `scripts/build-example-dotnet.sh` makes it); with `LUNEPACK_E2E_REQUIRE=1`
//! it must be set, and `LUNEPACK_E2E_DOTNET=0` is the one opt-out (the suite prints `SKIPPED`).

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
#[cfg(target_os = "linux")]
const DOTNET_APP_VAR: &str = "LUNEPACK_E2E_DOTNET_APP";
#[cfg(target_os = "linux")]
const DOTNET_VAR: &str = "LUNEPACK_E2E_DOTNET";
/// The .NET example's entry in its folder (the assembly name of `examples/dotnet`).
#[cfg(target_os = "linux")]
const DOTNET_ENTRY: &str = "Example";

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

/// The .NET example's app bundle of the macOS suite (M13 step 8): `LUNEPACK_E2E_DOTNET_BUNDLE` names
/// the `.app` that `scripts/build-example-dotnet.sh --macos-bundle` made. `Ok(None)` when its row
/// is skipped: by name (`LUNEPACK_E2E_DOTNET=0`) or, without `LUNEPACK_E2E_REQUIRE=1`, because no
/// bundle was given; either way the suite says `SKIPPED` once. An error when the row is required
/// and the bundle is not usable.
#[cfg(target_os = "macos")]
fn dotnet_bundle() -> Result<Option<PathBuf>, String> {
    const BUNDLE_VAR: &str = "LUNEPACK_E2E_DOTNET_BUNDLE";
    const DOTNET_VAR: &str = "LUNEPACK_E2E_DOTNET";
    if std::env::var(DOTNET_VAR).is_ok_and(|v| v == "0") {
        eprintln!("e2e: SKIPPED: the .NET row ({DOTNET_VAR}=0)");
        return Ok(None);
    }
    let required = std::env::var(REQUIRE_VAR).is_ok_and(|v| v == "1");
    let Some(bundle) = std::env::var_os(BUNDLE_VAR).map(PathBuf::from) else {
        if required {
            return Err(format!(
                "{REQUIRE_VAR}=1, but {BUNDLE_VAR} is not set ({DOTNET_VAR}=0 skips the .NET row)"
            ));
        }
        eprintln!("e2e: SKIPPED: the .NET row ({BUNDLE_VAR} is not set)");
        return Ok(None);
    };
    if !bundle.join("Contents/MacOS/Example").is_file()
        || !bundle.join("Contents/Info.plist").is_file()
    {
        return Err(format!(
            "{BUNDLE_VAR} does not name the example's bundle (Contents/Info.plist, Contents/MacOS/Example)"
        ));
    }
    Ok(Some(bundle))
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
        dotnet_bundle: match dotnet_bundle() {
            Ok(bundle) => bundle,
            Err(why) => {
                eprintln!("e2e: FAIL: {why}");
                return ExitCode::FAILURE;
            }
        },
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
    let dotnet = match dotnet_app() {
        Ok(app) => app,
        Err(why) => {
            eprintln!("e2e: FAIL: {why}");
            return ExitCode::FAILURE;
        }
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
    if !same_logs("rust", &rust_log, "shell", &shell_log) {
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
    if !same_logs("rust", &rust_ui_log, "shell", &shell_ui_log) {
        return ExitCode::FAILURE;
    }
    let rust_log: Vec<String> = rust_log.into_iter().chain(rust_ui_log).collect();

    if let Some(dotnet_app) = &dotnet {
        eprintln!(
            "e2e: folder table: the .NET app ({}), rows {:?}",
            dotnet_app.name,
            scenarios::FOLDER_APP_ROWS
        );
        let started = std::time::Instant::now();
        let dotnet_log = match scenarios::run_folder_table(&bins, dotnet_app) {
            Ok(log) => log,
            Err(why) => {
                eprintln!("e2e: FAIL: the .NET app: {why}");
                return ExitCode::FAILURE;
            }
        };
        eprintln!(
            "e2e: the .NET rows took {:.0}s",
            started.elapsed().as_secs_f32()
        );
        let shell_rows = scenarios::filter_log(&shell_log, scenarios::FOLDER_APP_ROWS);
        if !same_logs(".NET", &dotnet_log, "shell", &shell_rows) {
            return ExitCode::FAILURE;
        }
    }

    if let Err(why) = cli_extra::run_all(&bins, &rust_app) {
        eprintln!("e2e: FAIL: {why}");
        return ExitCode::FAILURE;
    }
    if let Err(why) = ui::run_extras(&bins, &rust_app) {
        eprintln!("e2e: FAIL: {why}");
        return ExitCode::FAILURE;
    }

    println!(
        "e2e: outcome log ({} lines, equal for both apps{})",
        rust_log.len(),
        if dotnet.is_some() {
            "; the .NET app's rows equal the shell app's"
        } else {
            ""
        }
    );
    for line in &rust_log {
        println!("{line}");
    }
    println!("e2e: PASS");
    ExitCode::SUCCESS
}

/// Whether the two outcome logs are equal; prints the first difference when not.
#[cfg(target_os = "linux")]
fn same_logs(a_name: &str, a: &[String], b_name: &str, b: &[String]) -> bool {
    if a == b {
        return true;
    }
    eprintln!("e2e: FAIL: the outcome logs of {a_name} and {b_name} differ");
    let at = a
        .iter()
        .zip(b)
        .position(|(x, y)| x != y)
        .unwrap_or_else(|| a.len().min(b.len()));
    eprintln!(
        "  first difference at line {at}:\n    {a_name}: {:?}\n    {b_name}: {:?}",
        a.get(at),
        b.get(at)
    );
    false
}

/// The .NET example as an app of the lab, from the environment. `Ok(None)` when its rows are
/// skipped: by name (`LUNEPACK_E2E_DOTNET=0`) or, without `LUNEPACK_E2E_REQUIRE=1`, because no
/// folder was given; either way the suite says `SKIPPED` once. An error when the rows are required
/// and the folder is not usable.
#[cfg(target_os = "linux")]
fn dotnet_app() -> Result<Option<lab::App>, String> {
    if std::env::var(DOTNET_VAR).is_ok_and(|v| v == "0") {
        eprintln!("e2e: SKIPPED: the .NET rows ({DOTNET_VAR}=0)");
        return Ok(None);
    }
    let required = std::env::var(REQUIRE_VAR).is_ok_and(|v| v == "1");
    let Some(folder) = std::env::var_os(DOTNET_APP_VAR).map(PathBuf::from) else {
        if required {
            return Err(format!(
                "{REQUIRE_VAR}=1, but {DOTNET_APP_VAR} is not set ({DOTNET_VAR}=0 skips the .NET rows)"
            ));
        }
        eprintln!("e2e: SKIPPED: the .NET rows ({DOTNET_APP_VAR} is not set)");
        return Ok(None);
    };
    if !folder.join(DOTNET_ENTRY).is_file() {
        return Err(format!(
            "{DOTNET_APP_VAR} does not name a folder with the entry {DOTNET_ENTRY}"
        ));
    }
    Ok(Some(lab::App {
        binary: folder,
        name: DOTNET_ENTRY.to_owned(),
        folder: true,
    }))
}

#[cfg(target_os = "linux")]
fn named_app(binary: &std::path::Path) -> Option<lab::App> {
    let name = binary.file_name()?.to_string_lossy().into_owned();
    Some(lab::App {
        binary: binary.to_owned(),
        name,
        folder: false,
    })
}
