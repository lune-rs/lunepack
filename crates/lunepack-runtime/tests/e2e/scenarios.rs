//! The scenario table of the end-to-end suite (M5-D13): one list of rows, each an action and the
//! state it must leave behind (the record, the trees, the `current` link, the desktop entry, the
//! command link and the outcome lines). The table is data, so the suite can run it again with
//! another app (the shell app of M5 step 14) and compare the outcome logs.
//!
//! Rows 1 to 7 share one lab on the loopback `http:` feed; row 8 runs rows 1 and 2 again on a
//! fresh lab over a `file:` feed. Every outcome line is `<tree version> <outcome>`, written by the
//! app under test, so the log holds versions and outcomes only.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command;
use std::time::Instant;

use crate::lab::{
    App, Binaries, FeedKind, Lab, RUNTIME_FILE, RecordView, Release, TARGET, delta_content,
    desktop_file_validates, have_desktop_file_validate, kill9, runtime_apply_pids,
};

/// One row of the table.
#[derive(Clone, Copy)]
pub struct Row {
    pub id: u8,
    pub name: &'static str,
    /// Runs the row on `lab` (panicking when an expectation fails) and returns its normalised
    /// outcome lines.
    pub run: fn(&mut Lab) -> Vec<String>,
}

/// Rows 1 to 7: one install, four updates, the attempt counter and the uninstall.
pub const HTTP_ROWS: &[Row] = &[
    Row {
        id: 1,
        name: "install over the loopback http feed",
        run: row_install,
    },
    Row {
        id: 2,
        name: "update to 2.0.0 with confirm",
        run: row_update_confirmed,
    },
    Row {
        id: 3,
        name: "update to 3.0.0, which crashes: supervised rollback",
        run: row_crash_rolls_back,
    },
    Row {
        id: 4,
        name: "update to 4.0.0, whose entry moved",
        run: row_moved_entry,
    },
    Row {
        id: 5,
        name: "slow confirm beyond the timeout: rollback",
        run: row_slow_confirm,
    },
    Row {
        id: 6,
        name: "attempt counter after the supervisor was killed",
        run: row_attempt_counter,
    },
    Row {
        id: 7,
        name: "uninstall leaves a foreign file",
        run: row_uninstall,
    },
];

/// Row 8: rows 1 and 2 again over a `file:` feed.
pub const FILE_ROWS: &[Row] = &[Row {
    id: 8,
    name: "install and update over the file feed",
    run: row_file_feed,
}];

/// Row 9: the published releases say `publisher_check = "enforce"` (M9-D6); Linux has no OS code
/// signature, so the check does not apply and the update goes through as in row 2.
pub const ENFORCE_ROWS: &[Row] = &[Row {
    id: 9,
    name: "publisher_check = enforce: install and update proceed (not applicable on Linux)",
    run: row_enforce_update,
}];

/// Rows 10 to 12 (M12 step 7): an update that fetches a changed file as a delta patch, and the two
/// ways the patch is not available (the installed file is not the base; the delta file is not
/// served). Each runs on a fresh lab, so each installs 1.0.0 itself.
pub const DELTA_ROWS: &[Row] = &[
    Row {
        id: 10,
        name: "update by delta: the changed file arrives as a patch",
        run: row_delta_update,
    },
    Row {
        id: 11,
        name: "delta fallback: the installed base file changed by one byte",
        run: row_delta_base_changed,
    },
    Row {
        id: 12,
        name: "delta fallback: the delta file is not served",
        run: row_delta_missing,
    },
];

/// The size of `share/delta.bin` of the delta rows' releases.
const DELTA_BYTES: usize = 256 << 10;
const D1: Release = Release {
    delta_bytes: DELTA_BYTES,
    ..Release::plain("1.0.0")
};
const D2: Release = Release {
    delta_bytes: DELTA_BYTES,
    delta_tweak: 0x5A,
    ..Release::plain("1.1.0")
};

const V1: Release = Release::plain("1.0.0");
const V2: Release = Release::plain("2.0.0");
const V3: Release = Release {
    flags: &["crash-on-start"],
    ..Release::plain("3.0.0")
};
const V4: Release = Release {
    moved_entry: true,
    ..Release::plain("4.0.0")
};
/// Sleeps 60 s before confirming, under a 5 s health timeout (the least the config allows).
const V5: Release = Release {
    flags: &["slow-confirm 60"],
    moved_entry: true,
    health_timeout_secs: 5,
    ..Release::plain("5.0.0")
};
/// Exits 0 without confirming, under a long timeout, so the supervisor is still waiting when the
/// scenario kills it.
const V6: Release = Release {
    flags: &["exit-without-confirm"],
    moved_entry: true,
    health_timeout_secs: 120,
    ..Release::plain("6.0.0")
};

/// The rows a folder app (the .NET example, about 190 files; the C example, the app and its
/// library) runs, by id. Together they cover each
/// stage of an app's life: the install (1); the update by `check`, `download` and
/// `apply-and-restart` with the new version's confirm (2); a version that crashes on start, rolled
/// back and marked bad (3); the fixed version (4); the uninstall (7, which runs from the tree row 4
/// left); and an update that arrives as a delta (10). Rows 5, 6, 8, 9, 11 and 12 test the runtime
/// (timeouts, the attempt counter, a file feed, a policy, the delta fallbacks), not the app, and the
/// two single-file apps already run them. The shell app's log, cut to these rows by [`filter_log`],
/// is what each folder app's log must equal.
pub const FOLDER_APP_ROWS: &[u8] = &[1, 2, 3, 4, 7, 10];

/// Runs the whole table on a fresh lab per feed kind, stopping at the first failing row.
/// Returns the normalised outcome log, or the failure.
pub fn run_table(bins: &Binaries, app: &App) -> Result<Vec<String>, String> {
    run_table_of(bins, app, None)
}

/// Runs the rows of [`FOLDER_APP_ROWS`] and no others, in the table's order, each group in the lab
/// it has in [`run_table`].
pub fn run_folder_table(bins: &Binaries, app: &App) -> Result<Vec<String>, String> {
    run_table_of(bins, app, Some(FOLDER_APP_ROWS))
}

/// The lines of `log` that belong to the rows `ids` (a row's lines follow its `# row N` line).
pub fn filter_log(log: &[String], ids: &[u8]) -> Vec<String> {
    let mut keep = false;
    let mut out = Vec::new();
    for line in log {
        if let Some(n) = line.strip_prefix("# row ") {
            keep = n.parse::<u8>().is_ok_and(|n| ids.contains(&n));
        }
        if keep {
            out.push(line.clone());
        }
    }
    out
}

fn run_table_of(bins: &Binaries, app: &App, only: Option<&[u8]>) -> Result<Vec<String>, String> {
    let picked = |rows: &[Row]| -> Vec<Row> {
        rows.iter()
            .filter(|row| only.is_none_or(|ids| ids.contains(&row.id)))
            .copied()
            .collect()
    };
    let mut log = Vec::new();
    for (kind, rows) in [(FeedKind::Http, HTTP_ROWS), (FeedKind::File, FILE_ROWS)] {
        let rows = picked(rows);
        if !rows.is_empty() {
            let mut lab = Lab::new(bins, app, kind);
            run_rows(&mut lab, &rows, &mut log)?;
        }
    }
    let rows = picked(ENFORCE_ROWS);
    if !rows.is_empty() {
        let mut lab = Lab::new(bins, app, FeedKind::Http);
        lab.set_publisher_check("enforce");
        run_rows(&mut lab, &rows, &mut log)?;
    }
    for row in picked(DELTA_ROWS) {
        let mut lab = Lab::new(bins, app, FeedKind::Http);
        run_rows(&mut lab, std::slice::from_ref(&row), &mut log)?;
    }
    Ok(log)
}

/// Runs `rows` in order on `lab`, appending each row's outcome lines (under a `# row N` line) to
/// `log`; stops at the first row that panics, naming it and the lab's state.
pub fn run_rows(lab: &mut Lab, rows: &[Row], log: &mut Vec<String>) -> Result<(), String> {
    for row in rows {
        eprintln!("e2e: row {}: {}", row.id, row.name);
        let started = Instant::now();
        match catch_unwind(AssertUnwindSafe(|| (row.run)(lab))) {
            Ok(lines) => {
                log.push(format!("# row {}", row.id));
                log.extend(lines);
                eprintln!(
                    "e2e: row {} ok ({:.1}s)",
                    row.id,
                    started.elapsed().as_secs_f32()
                );
            }
            Err(payload) => {
                let why = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                    .unwrap_or_else(|| "a panic".to_owned());
                return Err(format!(
                    "row {} failed: {why}\n{}",
                    row.id,
                    lab.diagnostics()
                ));
            }
        }
    }
    Ok(())
}

pub fn record(current: &str, previous: Option<&str>, bad: &[&str], events: usize) -> RecordView {
    RecordView {
        current: Some(current.to_owned()),
        previous: previous.map(str::to_owned),
        pending: None,
        staged: None,
        bad: bad.iter().map(|s| (*s).to_owned()).collect(),
        events,
    }
}

/// The desktop entry and the command link match an entry at `entry` (M5-D2, M5-D10).
pub fn assert_integration(lab: &Lab, entry: &str) {
    let desktop = lab.desktop_file();
    assert_eq!(
        std::fs::read_to_string(&desktop).expect("the desktop entry"),
        lab.expected_desktop(entry),
        "the desktop entry"
    );
    assert!(
        desktop_file_validates(&desktop),
        "desktop-file-validate refused the entry"
    );
    assert_eq!(
        lab.bin_target(),
        Some(format!("{}/current/{entry}", lab.root.display())),
        "the command link"
    );
}

pub fn assert_current_link(lab: &Lab, version: &str) {
    assert_eq!(
        lab.current_link().as_deref(),
        Some(format!("versions/{version}").as_str()),
        "R/current"
    );
}

/// Every line of the runtime log is a schema-1 object.
pub fn assert_log_is_schema_1(lab: &Lab) {
    let log = lab.runtime_log();
    assert!(!log.is_empty(), "the runtime wrote no log");
    for line in log.lines() {
        assert!(
            line.starts_with("{\"schema\":1,"),
            "a log line is not schema 1"
        );
    }
}

/// Runs the app through the command link with `--update` and expects it to hand over.
pub fn update_from_link(lab: &Lab) {
    let status = lab.run_app(&lab.bin_link(), &["--update"]);
    assert!(status.success(), "the --update run failed: {status}");
}

/// Runs the app through the command link with no arguments.
pub fn start_from_link(lab: &Lab) {
    let status = lab.run_app(&lab.bin_link(), &[]);
    assert!(status.success(), "the app failed: {status}");
}

fn row_install(lab: &mut Lab) -> Vec<String> {
    install_release(lab, &V1)
}

/// Publishes `release` (1.0.0) and installs it through the runtime's install mode; returns the
/// outcome lines of [`check_installed`].
fn install_release(lab: &mut Lab, release: &Release) -> Vec<String> {
    lab.publish(release);
    let boot = lab.bootstrap();
    let (code, stdout) = lab.run_runtime(&boot.join("bin").join(RUNTIME_FILE), "install");
    assert_eq!(code, 0, "install exited {code}: {stdout}");
    assert!(
        stdout.contains("\"outcome\":\"installed\""),
        "the install result line"
    );
    if lab.feed_kind() == FeedKind::Http {
        assert!(
            !lab.requests().is_empty(),
            "the loopback server saw no request"
        );
    }
    check_installed(lab, release)
}

/// What a first install of `release` (1.0.0) leaves behind, however it was made (the runtime's
/// install mode, or a setup file): the record, the trees, the links, the integration, and the
/// app's own lines over two starts through the command link. Returns those lines.
pub fn check_installed(lab: &Lab, release: &Release) -> Vec<String> {
    let mut want = record("1.0.0", None, &[], 2);
    want.staged = None;
    assert_eq!(lab.record(), Some(want), "the record after the install");
    assert_eq!(lab.versions(), ["1.0.0"]);
    assert_current_link(lab, "1.0.0");
    assert_integration(lab, &lab.entry_rel(release));

    // Two starts through the command link: the events come once.
    start_from_link(lab);
    start_from_link(lab);
    let lines = lab.expect_lines(&[
        "1.0.0 start",
        "1.0.0 event installed",
        "1.0.0 event first_run",
        "1.0.0 nothing-pending",
        "1.0.0 start",
        "1.0.0 nothing-pending",
    ]);
    assert_eq!(
        lab.record().map(|r| r.events),
        Some(0),
        "events are delivered once"
    );
    lines
}

fn row_update_confirmed(lab: &mut Lab) -> Vec<String> {
    lab.publish(&V2);
    update_from_link(lab);
    expect_confirmed_update(lab, &V2, "1.0.0")
}

/// The outcome lines of an update from `from` to `to` that the new version confirms, in the
/// order the apps write them.
fn confirmed_update_lines(from: &str, to: &str) -> Vec<String> {
    vec![
        format!("{from} start"),
        format!("{from} nothing-pending"),
        format!("{from} check {to}"),
        format!("{from} staged {to}"),
        format!("{from} apply-scheduled"),
        format!("{to} start"),
        format!("{to} arg after-update"),
        format!("{to} event updated {from}"),
        format!("{to} event first_run"),
        format!("{to} confirmed"),
    ]
}

/// Waits for the outcome lines of a confirmed update from `from` to `release` and checks what
/// it leaves behind: the record, the kept versions, the link and the integration. The one
/// definition of "the update's outcome", so a variant (a UI that dies, no UI) is compared with
/// the headless run line by line. Returns the lines.
pub fn expect_confirmed_update(lab: &Lab, release: &Release, from: &str) -> Vec<String> {
    let to = release.version;
    let want = confirmed_update_lines(from, to);
    let want: Vec<&str> = want.iter().map(String::as_str).collect();
    let lines = lab.expect_lines(&want);
    lab.wait_runtime_gone();
    assert_eq!(
        lab.record(),
        Some(record(to, Some(from), &[], 0)),
        "the record after the confirmed update"
    );
    // GC keeps the current and the previous version, and there is nothing older.
    assert_eq!(lab.versions(), [from, to]);
    assert_current_link(lab, to);
    assert_integration(lab, &lab.entry_rel(release));
    assert_log_is_schema_1(lab);
    lines
}

fn row_crash_rolls_back(lab: &mut Lab) -> Vec<String> {
    lab.publish(&V3);
    update_from_link(lab);
    let mut lines = lab.expect_lines(&[
        "2.0.0 start",
        "2.0.0 nothing-pending",
        "2.0.0 check 3.0.0",
        "2.0.0 staged 3.0.0",
        "2.0.0 apply-scheduled",
        "3.0.0 start",
        "3.0.0 arg after-update",
        "3.0.0 event updated 2.0.0",
        "3.0.0 event first_run",
        "3.0.0 crash",
        // The previous version is started again with the restart arguments, without the token.
        "2.0.0 start",
        "2.0.0 arg after-update",
        "2.0.0 nothing-pending",
    ]);
    lab.wait_runtime_gone();
    assert_eq!(
        lab.record(),
        Some(record("2.0.0", None, &["3.0.0"], 0)),
        "the record after the rollback"
    );
    // GC keeps only the current version once the rollback cleared the previous one.
    assert_eq!(lab.versions(), ["2.0.0"]);
    assert_current_link(lab, "2.0.0");
    assert_integration(lab, &lab.entry_rel(&V2));

    // The bad version is not offered again.
    update_from_link(lab);
    lines.extend(lab.expect_lines(&["2.0.0 start", "2.0.0 nothing-pending", "2.0.0 check none"]));
    lines
}

fn row_moved_entry(lab: &mut Lab) -> Vec<String> {
    lab.publish(&V4);
    update_from_link(lab);
    let mut lines = lab.expect_lines(&[
        "2.0.0 start",
        "2.0.0 nothing-pending",
        "2.0.0 check 4.0.0",
        "2.0.0 staged 4.0.0",
        "2.0.0 apply-scheduled",
        "4.0.0 start",
        "4.0.0 arg after-update",
        "4.0.0 event updated 2.0.0",
        "4.0.0 event first_run",
        "4.0.0 confirmed",
    ]);
    lab.wait_runtime_gone();
    assert_eq!(
        lab.record(),
        Some(record("4.0.0", Some("2.0.0"), &["3.0.0"], 0)),
        "the record after the move"
    );
    assert_eq!(lab.versions(), ["2.0.0", "4.0.0"]);
    assert_current_link(lab, "4.0.0");
    // The command link and the desktop entry follow the entry to the tree's root.
    let entry = lab.entry_rel(&V4);
    assert_eq!(entry, lab.app_name());
    assert_integration(lab, &entry);
    // The relaunch ran the new tree's entry.
    let ran = format!("4.0.0 exe {}/versions/4.0.0/{entry}", lab.root.display());
    assert!(
        lab.detail_lines().contains(&ran),
        "the relaunch did not run the moved entry"
    );

    // And the command link starts it.
    start_from_link(lab);
    lines.extend(lab.expect_lines(&["4.0.0 start", "4.0.0 nothing-pending"]));
    lines
}

fn row_slow_confirm(lab: &mut Lab) -> Vec<String> {
    lab.publish(&V5);
    update_from_link(lab);
    // The timeout (5 s) passes, the runtime ends the app and starts 4.0.0 again.
    let lines = lab.expect_lines(&[
        "4.0.0 start",
        "4.0.0 nothing-pending",
        "4.0.0 check 5.0.0",
        "4.0.0 staged 5.0.0",
        "4.0.0 apply-scheduled",
        "5.0.0 start",
        "5.0.0 arg after-update",
        "5.0.0 event updated 4.0.0",
        "5.0.0 event first_run",
        "5.0.0 slow-confirm",
        "4.0.0 start",
        "4.0.0 arg after-update",
        "4.0.0 nothing-pending",
    ]);
    lab.wait_runtime_gone();
    assert_eq!(
        lab.record(),
        Some(record("4.0.0", None, &["3.0.0", "5.0.0"], 0)),
        "the record after the timeout"
    );
    assert_eq!(lab.versions(), ["4.0.0"]);
    assert_current_link(lab, "4.0.0");
    lines
}

fn row_attempt_counter(lab: &mut Lab) -> Vec<String> {
    lab.publish(&V6);
    update_from_link(lab);
    let mut lines = lab.expect_lines(&[
        "4.0.0 start",
        "4.0.0 nothing-pending",
        "4.0.0 check 6.0.0",
        "4.0.0 staged 6.0.0",
        "4.0.0 apply-scheduled",
        "6.0.0 start",
        "6.0.0 arg after-update",
        "6.0.0 event updated 4.0.0",
        "6.0.0 event first_run",
        "6.0.0 exit-without-confirm",
    ]);
    // The app has exited without confirming; the supervisor keeps waiting. Kill it.
    let pids = runtime_apply_pids();
    assert_eq!(pids.len(), 1, "one runtime in apply mode");
    kill9(pids[0]);
    lab.wait_runtime_gone();
    let pending = RecordView {
        pending: Some(("6.0.0".to_owned(), 0)),
        ..record("6.0.0", Some("4.0.0"), &["3.0.0", "5.0.0"], 0)
    };
    assert_eq!(
        lab.record(),
        Some(pending.clone()),
        "pending, no attempt yet"
    );

    // Three unsupervised starts count one attempt each.
    for attempt in 1..=3u64 {
        start_from_link(lab);
        lines.extend(lab.expect_lines(&["6.0.0 start", "6.0.0 exit-without-confirm"]));
        let want = RecordView {
            pending: Some(("6.0.0".to_owned(), attempt)),
            ..pending.clone()
        };
        assert_eq!(lab.record(), Some(want), "attempt {attempt}");
    }
    // The fourth rolls back and starts 4.0.0 in its place; the two apps' lines race.
    start_from_link(lab);
    lines.extend(lab.expect_lines_unordered(&[
        "6.0.0 start",
        "6.0.0 exit rolled-back",
        "4.0.0 start",
        "4.0.0 nothing-pending",
    ]));
    assert_eq!(
        lab.record(),
        Some(record("4.0.0", None, &["3.0.0", "5.0.0", "6.0.0"], 0)),
        "the record after the fourth start"
    );
    assert_current_link(lab, "4.0.0");
    // Only the runtime collects trees: the bad version's stays until the next apply.
    assert_eq!(lab.versions(), ["4.0.0", "6.0.0"]);
    lines
}

fn row_uninstall(lab: &mut Lab) -> Vec<String> {
    uninstall_and_check(lab, &lab.root.join("versions/4.0.0").join(RUNTIME_FILE))
}

/// Uninstalls through the runtime at `runtime` and checks what is gone and what stays (a
/// foreign desktop entry and command are planted first, and the data home itself).
pub fn uninstall_and_check(lab: &Lab, runtime: &std::path::Path) -> Vec<String> {
    // Foreign files beside the install's own: another app's entry and command.
    let foreign_desktop = lab.data.join("applications/other.desktop");
    let foreign_bin = lab.home.join(".local/bin/other-tool");
    std::fs::write(
        &foreign_desktop,
        b"[Desktop Entry]\nType=Application\nName=Other\nExec=other\n",
    )
    .expect("plant a desktop entry");
    std::fs::write(&foreign_bin, b"#!/bin/sh\n").expect("plant a command");

    let (code, stdout) = lab.run_runtime(runtime, "uninstall");
    assert_eq!(code, 0, "uninstall exited {code}: {stdout}");
    assert!(
        stdout.contains("\"outcome\":\"uninstalled\""),
        "the uninstall result line: {stdout}"
    );

    assert!(!lab.root.exists(), "the install root is gone");
    assert!(
        std::fs::symlink_metadata(lab.desktop_file()).is_err(),
        "the desktop entry is gone"
    );
    assert!(
        std::fs::symlink_metadata(lab.bin_link()).is_err(),
        "the command link is gone"
    );
    assert_eq!(
        std::fs::read(&foreign_desktop).expect("foreign entry"),
        b"[Desktop Entry]\nType=Application\nName=Other\nExec=other\n"
    );
    assert_eq!(
        std::fs::read(&foreign_bin).expect("foreign command"),
        b"#!/bin/sh\n"
    );
    assert!(lab.data.exists(), "the data home itself stays");
    Vec::new()
}

fn row_file_feed(lab: &mut Lab) -> Vec<String> {
    let mut lines = row_install(lab);
    lines.extend(row_update_confirmed(lab));
    assert!(lab.requests().is_empty(), "a file feed makes no request");
    lines
}

/// Row 9: rows 1 and 2 again with `publisher_check = "enforce"` in every release (M9-D9: the
/// platform has no check, so the outcome is "not applicable" and the update is staged and applied
/// as without a policy), then a `download` from the updated tree. The policy really is in the
/// installed tree's configuration, nothing is marked bad, and the `download` result carries no
/// `publisher` member.
fn row_enforce_update(lab: &mut Lab) -> Vec<String> {
    let mut lines = row_install(lab);
    let config = std::fs::read_to_string(lab.root.join("versions/1.0.0/lunepack-update.json"))
        .expect("the installed tree's update configuration");
    let parsed = lunepack_core::UpdateConfig::parse(config.as_bytes())
        .expect("the installed update configuration parses");
    assert_eq!(
        parsed.publisher_check,
        lunepack_core::PublisherPolicy::Enforce,
        "the policy is written into the installed tree's configuration"
    );
    lines.extend(row_update_confirmed(lab));
    lab.publish(&Release::plain("2.1.0"));
    let runtime = lab.root.join("versions/2.0.0/bin").join(RUNTIME_FILE);
    let run = lab.run_cmd(&runtime, &["download", "--json"], None);
    assert_eq!(run.code, 0, "download under enforce exited {}", run.code);
    let last = run.last_line();
    assert!(
        last.contains("\"version\":\"2.1.0\",\"staged\":true"),
        "download stages 2.1.0: {last}"
    );
    assert!(
        !last.contains("publisher"),
        "no finding on a platform without a check: {last}"
    );
    let record = lab.record().expect("a record");
    assert!(record.bad.is_empty(), "nothing is marked bad");
    lines
}

/// The runtime of the installed 1.0.0 (the entry is under `bin/` in these releases).
fn installed_runtime_1_0_0(lab: &Lab) -> std::path::PathBuf {
    lab.root.join("versions/1.0.0/bin").join(RUNTIME_FILE)
}

/// The `source` of every `stage` progress line of `stdout` (the runtime's JSON Lines) that names
/// `path`. The runtime writes at most ten progress lines a second and a stage phase's last one, so
/// a small file's own line may not be among them: rows use this only as a consistency check
/// (every line that is there names the right source), never to demand a line.
fn file_sources(stdout: &[u8], path: &str) -> Vec<String> {
    let needle = format!("\"file\":{{\"path\":\"{path}\",");
    let mut sources = Vec::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        if line.starts_with("{\"schema\":1,\"type\":\"progress\",\"phase\":\"stage\"")
            && line.contains(&needle)
            && let Some(rest) = line.split("\"source\":\"").nth(1)
            && let Some(source) = rest.split('"').next()
        {
            sources.push(source.to_owned());
        }
    }
    sources
}

/// Every `(path, source)` of the `stage` progress lines of `stdout` that name a file (the same
/// lines [`file_sources`] reads, for every path).
fn stage_files(stdout: &[u8]) -> Vec<(String, String)> {
    let mut files = Vec::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        if line.starts_with("{\"schema\":1,\"type\":\"progress\",\"phase\":\"stage\"")
            && let Some(rest) = line.split("\"file\":{\"path\":\"").nth(1)
            && let Some(path) = rest.split('"').next()
            && let Some(rest) = rest.split("\"source\":\"").nth(1)
            && let Some(source) = rest.split('"').next()
        {
            files.push((path.to_owned(), source.to_owned()));
        }
    }
    files
}

/// The bytes the download fetched: `done` of the last `download`-phase progress line (a phase's
/// last snapshot is always delivered). A patch is a few dozen bytes; the file's frame is its size.
fn download_bytes(stdout: &[u8]) -> u64 {
    let head = "{\"schema\":1,\"type\":\"progress\",\"phase\":\"download\",\"done\":";
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|l| l.strip_prefix(head))
        .filter_map(|rest| rest.split(',').next()?.parse::<u64>().ok())
        .next_back()
        .expect("a download progress line")
}

/// The lines of an update from 1.0.0 to 1.1.0 once it is staged and applied: the new version
/// starts with the restart argument, sees the update, confirms.
fn applied_delta_lines() -> Vec<&'static str> {
    vec![
        "1.1.0 start",
        "1.1.0 arg after-update",
        "1.1.0 event updated 1.0.0",
        "1.1.0 event first_run",
        "1.1.0 confirmed",
    ]
}

/// Stages 1.1.0 with `download --json` from the installed 1.0.0 and returns what the runtime
/// printed. Rows assert on its progress lines (RUNTIME.md schema 1), not on log text.
fn download_delta_update(lab: &Lab) -> Vec<u8> {
    let run = lab.run_cmd(&installed_runtime_1_0_0(lab), &["download", "--json"], None);
    assert_eq!(run.code, 0, "download exited {}", run.code);
    let last = run.last_line();
    assert!(
        last.contains("\"version\":\"1.1.0\",\"staged\":true"),
        "download stages 1.1.0: {last}"
    );
    assert_eq!(
        lab.record().and_then(|r| r.staged),
        Some("1.1.0".to_owned()),
        "the record names the staged version"
    );
    // The staged tree matches the manifest: the changed file and the version marker.
    let staged = lab.root.join("versions/1.1.0");
    assert_eq!(
        std::fs::read(staged.join("share/delta.bin")).expect("the staged file"),
        delta_content(DELTA_BYTES, D2.delta_tweak),
        "the staged tree's share/delta.bin"
    );
    assert_eq!(
        std::fs::read(staged.join("share/version.txt")).expect("the staged version marker"),
        b"1.1.0\n"
    );
    run.stdout
}

/// Applies the staged 1.1.0 through `apply-and-restart` (waiting for a short-lived process of this
/// harness), lets the new version confirm, and checks the record and the trees. Returns the
/// outcome lines.
fn apply_delta_update(lab: &Lab) -> Vec<String> {
    let mut waited = Command::new("sleep")
        .arg("1")
        .spawn()
        .expect("start the process to wait for");
    let pid = waited.id().to_string();
    let run = lab.run_cmd(
        &installed_runtime_1_0_0(lab),
        &[
            "apply-and-restart",
            "--json",
            "--wait-pid",
            &pid,
            "--expect-version",
            "1.1.0",
            "--",
            "--after-update",
        ],
        None,
    );
    let _ = waited.wait();
    assert_eq!(run.code, 0, "apply-and-restart exited {}", run.code);
    let lines = lab.expect_lines(&applied_delta_lines());
    lab.wait_runtime_gone();
    assert_eq!(
        lab.record(),
        Some(record("1.1.0", Some("1.0.0"), &[], 0)),
        "the record after the confirmed update"
    );
    assert_eq!(lab.versions(), ["1.0.0", "1.1.0"]);
    assert_current_link(lab, "1.1.0");
    assert_eq!(
        std::fs::read(lab.root.join("versions/1.1.0/share/delta.bin")).expect("the new file"),
        delta_content(DELTA_BYTES, D2.delta_tweak),
        "the applied tree's share/delta.bin"
    );
    assert_log_is_schema_1(lab);
    lines
}

/// Row 10: 1.1.0 changes 16 bytes of one file; the packer writes a delta from 1.0.0 (the file is
/// there), `download` fetches that file as a patch, the update applies and confirms.
fn row_delta_update(lab: &mut Lab) -> Vec<String> {
    let mut lines = install_release(lab, &D1);
    lab.publish(&D2);
    assert_eq!(
        lab.delta_files("1.1.0"),
        [format!("{TARGET}.from-1.0.0.delta")],
        "the packer wrote the delta from 1.0.0"
    );
    let before = lab.requests().len();
    let stdout = download_delta_update(lab);
    let fetched = download_bytes(&stdout);
    assert!(
        fetched < DELTA_BYTES as u64 / 4,
        "the download fetched {fetched} bytes: the file's frame, not a patch"
    );
    let sources = file_sources(&stdout, "share/delta.bin");
    assert!(
        sources.iter().all(|s| s == "patch"),
        "share/delta.bin arrives as a patch: {sources:?}"
    );
    assert!(
        lab.requests()[before..]
            .iter()
            .any(|u| u.contains(".from-1.0.0.delta")),
        "the delta file was never requested"
    );
    if lab.is_folder_app() {
        // A folder app's other files did not change: none of them is fetched again (that none was
        // is also what the byte bound above says, for a folder of about 190 files and 80 MB).
        let mut seen = 0;
        for (path, source) in stage_files(&stdout) {
            if path != "share/delta.bin" && path != "share/version.txt" {
                assert_eq!(source, "unchanged", "{path} is not fetched again");
                seen += 1;
            }
        }
        eprintln!("e2e: row 10: {seen} stage lines of the app's own files, all unchanged");
    }
    lines.extend(apply_delta_update(lab));
    lines
}

/// Row 11: the installed copy of the base file differs by one byte, so no patch can apply to it:
/// the file arrives as its frame by `range`, the rest of the update is unchanged.
fn row_delta_base_changed(lab: &mut Lab) -> Vec<String> {
    let mut lines = install_release(lab, &D1);
    lab.publish(&D2);
    let base = lab.root.join("versions/1.0.0/share/delta.bin");
    let mut bytes = std::fs::read(&base).expect("the installed base file");
    bytes[100] ^= 1;
    let mut perm = std::fs::metadata(&base).expect("metadata").permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o644);
    std::fs::set_permissions(&base, perm).expect("make the base file writable");
    std::fs::write(&base, bytes).expect("change the installed base file");
    let stdout = download_delta_update(lab);
    let fetched = download_bytes(&stdout);
    assert!(
        fetched >= DELTA_BYTES as u64,
        "the download fetched {fetched} bytes: not the file's frame"
    );
    let sources = file_sources(&stdout, "share/delta.bin");
    assert!(
        sources.iter().all(|s| s == "range"),
        "share/delta.bin is fetched by range, never as a patch: {sources:?}"
    );
    lines.extend(apply_delta_update(lab));
    lines
}

/// Row 12: the signed manifest lists the delta but the server has no such file: the failed patch
/// is not retried, the file arrives as its frame by `range`, and the update completes.
fn row_delta_missing(lab: &mut Lab) -> Vec<String> {
    let mut lines = install_release(lab, &D1);
    lab.publish_with(&D2, true);
    assert!(
        lab.delta_files("1.1.0").is_empty(),
        "the delta file is gone from the release directory"
    );
    let stdout = download_delta_update(lab);
    let fetched = download_bytes(&stdout);
    assert!(
        fetched >= DELTA_BYTES as u64,
        "the download fetched {fetched} bytes: not the file's frame"
    );
    let sources = file_sources(&stdout, "share/delta.bin");
    assert!(
        sources.iter().all(|s| s == "range"),
        "share/delta.bin falls back to range: {sources:?}"
    );
    lines.extend(apply_delta_update(lab));
    lines
}

/// Whether the desktop-file validator is installed (the suite says so when it is not).
pub fn validator_note() -> &'static str {
    if have_desktop_file_validate() {
        "desktop-file-validate: present"
    } else {
        "desktop-file-validate: not installed (the entry's own bytes are still compared)"
    }
}
