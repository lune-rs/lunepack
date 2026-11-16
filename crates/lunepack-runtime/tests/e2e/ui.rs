//! The UI scenarios of the end-to-end suite (M6 step 11): a setup file installs offline, an update
//! and an uninstall run with a UI process beside the runtime, and the UI is absent, killed or
//! unable to start without changing what the operation leaves behind. No scenario needs a GPU or a
//! display: the UI is either the stand-in of `tests/e2e/fake-ui`, which speaks the frame protocol
//! with no window, or the real `lunepack-ui` pointed at an X display that nothing serves.
//!
//! - rows 9 to 12 are a table like [`crate::scenarios`]'s, run with both apps on one lab, so the
//!   outcome logs are compared: (a) a setup file `--silent`, (d) an update whose UI is killed
//!   mid-apply, (e) `apply-and-restart --no-ui` and (f) an uninstall with a live UI. The outcome
//!   lines are the headless rows' own ([`check_installed`], [`expect_confirmed_update`]), so
//!   "the same outcome as without a UI" is one definition and not a copy;
//! - the extras run once, with the Rust app: (b) a setup file with no display, (c) one whose UI is
//!   killed mid-install, (g) one with the real `lunepack-ui` and a `DISPLAY` that nothing serves.
//!
//! A UI is started only when the runtime wants one, so each scenario that must start none counts
//! the stand-in's starts (a file it appends to, `ui-spawns`) and each scenario that must start one
//! checks the count is one. The runtime logs a UI that was never wanted nowhere (its stop reasons
//! are for a UI that was started), so "no UI" is the empty count with the controls beside it.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use crate::lab::{APP_ID, App, Binaries, Captured, FeedKind, Lab, RUNTIME_FILE, Release, Ui};
use crate::scenarios::{
    Row, check_installed, expect_confirmed_update, run_rows, uninstall_and_check, update_from_link,
};

const U1: Release = Release {
    ui: Ui::Fake,
    ..Release::plain("1.0.0")
};
const U2: Release = Release {
    ui: Ui::Fake,
    ..Release::plain("2.0.0")
};
const U3: Release = Release {
    ui: Ui::Fake,
    ..Release::plain("3.0.0")
};
const U1_REAL: Release = Release {
    ui: Ui::Real,
    ..Release::plain("1.0.0")
};

/// Rows 9 to 12, on one lab with an `http:` feed.
pub const UI_ROWS: &[Row] = &[
    Row {
        id: 9,
        name: "install through a setup file, --silent",
        run: row_setup_silent,
    },
    Row {
        id: 10,
        name: "update to 2.0.0 with the UI killed mid-apply",
        run: row_update_ui_killed,
    },
    Row {
        id: 11,
        name: "update to 3.0.0 with apply-and-restart --no-ui",
        run: row_update_no_ui,
    },
    Row {
        id: 12,
        name: "uninstall with a live UI",
        run: row_uninstall_with_ui,
    },
];

/// Runs the UI rows on a fresh lab. Returns the normalised outcome log, or the failure.
pub fn run_table(bins: &Binaries, app: &App) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    let mut lab = Lab::new(bins, app, FeedKind::Http);
    run_rows(&mut lab, UI_ROWS, &mut log)?;
    Ok(log)
}

// ---- helpers -------------------------------------------------------------------------------------

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The setup ended with exit 0 and the result line of an install. A failure shows the run's own
/// output (result and warning objects, which hold no path or secret).
fn assert_setup_installed(run: &Captured) {
    let stdout = text(&run.stdout);
    assert!(
        run.code == 0
            && stdout.contains("\"command\":\"setup\"")
            && stdout.contains("\"outcome\":\"installed\""),
        "the setup did not install: exit {}, stdout {stdout:?}, stderr {:?}",
        run.code,
        text(&run.stderr)
    );
}

/// The `ui_stopped` warnings among a setup's stderr lines.
fn ui_stopped_lines(run: &Captured) -> Vec<String> {
    text(&run.stderr)
        .lines()
        .filter(|l| l.contains("\"code\":\"ui_stopped\""))
        .map(str::to_owned)
        .collect()
}

/// The setup removed the directory it ran the UI from (M6-D7): none is left under the cache.
fn assert_no_setup_ui_dir(lab: &Lab) {
    let cache = lab.home.join(".cache").join(APP_ID);
    let left: Vec<String> = std::fs::read_dir(&cache)
        .map(|dir| {
            dir.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("setup-ui-"))
                .collect()
        })
        .unwrap_or_default();
    assert!(left.is_empty(), "the setup left a UI directory: {left:?}");
}

// ---- the table -----------------------------------------------------------------------------------

/// (a) A setup file installs `--silent` with no network and no UI, though a display and a UI are
/// there.
fn row_setup_silent(lab: &mut Lab) -> Vec<String> {
    lab.publish(&U1);
    lab.fake_ui_env("proceed", true);
    let setup = lab.build_setup(U1.version);
    let run = lab.run_cmd(&setup, &["--silent"], None);
    assert_setup_installed(&run);
    assert!(
        lab.requests().is_empty(),
        "the setup used the network to install"
    );
    assert!(
        lab.ui_notes("ui-spawns").is_empty(),
        "--silent started a UI"
    );
    assert_no_setup_ui_dir(lab);
    check_installed(lab, &U1)
}

/// (d) The UI of the applier dies when the update reports its first step; the update still ends as
/// the headless one does (the same lines and state), and the log says the UI stopped.
fn row_update_ui_killed(lab: &mut Lab) -> Vec<String> {
    lab.publish(&U2);
    lab.fake_ui_env("die", true);
    update_from_link(lab);
    let lines = expect_confirmed_update(lab, &U2, "1.0.0");
    assert_eq!(
        lab.ui_notes("ui-spawns").len(),
        1,
        "the applier started the UI once"
    );
    let log = lab.runtime_log();
    assert!(
        log.lines()
            .any(|l| l.contains("\"code\":\"ui_stopped\"") && l.contains("\"reason\":\"exited\"")),
        "the runtime log has no ui_stopped (exited): {log}"
    );
    lines
}

/// (e) `apply-and-restart --no-ui` (through the app's `--no-ui`) starts no UI, with a display and
/// a UI that would answer.
fn row_update_no_ui(lab: &mut Lab) -> Vec<String> {
    lab.publish(&U3);
    lab.fake_ui_env("proceed", true);
    let status = lab.run_app(&lab.bin_link(), &["--update", "--no-ui"]);
    assert!(
        status.success(),
        "the --update --no-ui run failed: {status}"
    );
    let lines = expect_confirmed_update(lab, &U3, "2.0.0");
    assert!(lab.ui_notes("ui-spawns").is_empty(), "--no-ui started a UI");
    lines
}

/// (f) An uninstall with a live UI, started from the tree being removed: the UI is asked to
/// confirm and told how it ended, and the uninstall ends as the headless one does.
fn row_uninstall_with_ui(lab: &mut Lab) -> Vec<String> {
    lab.fake_ui_env("proceed", true);
    let runtime = lab.root.join("versions/3.0.0/bin").join(RUNTIME_FILE);
    let lines = uninstall_and_check(lab, &runtime);
    assert_eq!(
        lab.ui_notes("ui-spawns").len(),
        1,
        "the uninstall started the UI once"
    );
    assert_eq!(
        lab.ui_notes("ui-hello"),
        ["Uninstall Lunepack E2E"],
        "the UI's flow and app"
    );
    assert_eq!(
        lab.ui_notes("ui-prompts"),
        ["Confirm", "Done"],
        "the UI's prompts"
    );
    lines
}

// ---- the extras ----------------------------------------------------------------------------------

/// A test of this file: it panics when an expectation fails.
type Test = fn(&Binaries, &App);

const TESTS: &[(&str, Test)] = &[
    ("(b) setup file with no display", setup_no_display),
    ("(c) setup file, UI killed mid-install", setup_ui_killed),
    (
        "(g) setup file, the real UI and a DISPLAY nothing serves",
        setup_real_ui_without_server,
    ),
];

/// Runs every extra, stopping at the first failure.
pub fn run_extras(bins: &Binaries, app: &App) -> Result<(), String> {
    for (name, test) in TESTS {
        eprintln!("e2e: ui: {name}");
        let started = Instant::now();
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| test(bins, app))) {
            let why = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "a panic".to_owned());
            return Err(format!("ui test `{name}` failed: {why}"));
        }
        eprintln!("e2e: ui ok ({:.1}s)", started.elapsed().as_secs_f32());
    }
    Ok(())
}

/// (b) With neither `DISPLAY` nor `WAYLAND_DISPLAY` set the setup starts no UI (and does not
/// even unpack one) and installs as `--silent` does. The controls are (c) and (d), which start the
/// same UI the moment a display is set.
fn setup_no_display(bins: &Binaries, app: &App) {
    let mut lab = Lab::new(bins, app, FeedKind::Http);
    lab.publish(&U1);
    lab.fake_ui_env("proceed", false);
    let setup = lab.build_setup(U1.version);
    let run = lab.run_cmd(&setup, &[], None);
    assert_setup_installed(&run);
    assert!(
        lab.ui_notes("ui-spawns").is_empty(),
        "a UI was started with no display"
    );
    assert!(
        ui_stopped_lines(&run).is_empty(),
        "a UI that was never wanted was reported stopped"
    );
    assert_no_setup_ui_dir(&lab);
    check_installed(&lab, &U1);
}

/// (c) The UI of the setup dies when the install reports its first step: the outcome is (a)'s.
fn setup_ui_killed(bins: &Binaries, app: &App) {
    let mut lab = Lab::new(bins, app, FeedKind::Http);
    lab.publish(&U1);
    lab.fake_ui_env("die", true);
    let setup = lab.build_setup(U1.version);
    let run = lab.run_cmd(&setup, &[], None);
    assert_setup_installed(&run);
    assert_eq!(
        lab.ui_notes("ui-spawns").len(),
        1,
        "the setup started the UI once"
    );
    assert_eq!(
        lab.ui_notes("ui-prompts"),
        ["Welcome"],
        "the UI was asked to proceed and died before the done screen"
    );
    let stopped = ui_stopped_lines(&run);
    assert!(
        stopped.len() == 1 && stopped[0].contains("\"reason\":\"exited\""),
        "expected one ui_stopped (exited), got {stopped:?}"
    );
    assert_no_setup_ui_dir(&lab);
    assert!(
        lab.requests().is_empty(),
        "the setup used the network to install"
    );
    check_installed(&lab, &U1);
}

/// (g) The real `lunepack-ui` is unpacked and started with `DISPLAY` set while no X server runs: it
/// exits with its typed code 10 (no display), the runtime logs `ui_stopped` (exited, code 10) and
/// the install completes headless. That warning is also the proof the UI was started: a UI that
/// never started has no exit code.
fn setup_real_ui_without_server(bins: &Binaries, app: &App) {
    let mut lab = Lab::new(bins, app, FeedKind::Http);
    lab.publish(&U1_REAL);
    lab.set_var("DISPLAY", ":99");
    let setup = lab.build_setup(U1_REAL.version);
    let run = lab.run_cmd(&setup, &[], None);
    assert_setup_installed(&run);
    let stopped = ui_stopped_lines(&run);
    assert!(
        stopped.len() == 1
            && stopped[0].contains("\"reason\":\"exited\"")
            && stopped[0].contains("\"ui_exit_code\":10"),
        "expected one ui_stopped (exited, code 10), got {stopped:?}"
    );
    assert_no_setup_ui_dir(&lab);
    check_installed(&lab, &U1_REAL);
}
