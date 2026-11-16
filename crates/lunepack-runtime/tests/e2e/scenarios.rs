//! The scenario table of the end-to-end suite (M5-D13): one list of rows, each an action and the
//! state it must leave behind (the record, the trees, the `current` link, the desktop entry, the
//! command link and the outcome lines). The table is data, so the suite can run it again with
//! another app (the shell app of M5 step 14) and compare the outcome logs.
//!
//! Rows 1 to 7 share one lab on the loopback `http:` feed; row 8 runs rows 1 and 2 again on a
//! fresh lab over a `file:` feed. Every outcome line is `<tree version> <outcome>`, written by the
//! app under test, so the log holds versions and outcomes only.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use crate::lab::{
    App, Binaries, FeedKind, Lab, RUNTIME_FILE, RecordView, Release, desktop_file_validates,
    have_desktop_file_validate, kill9, runtime_apply_pids,
};

/// One row of the table.
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

/// Runs the whole table on a fresh lab per feed kind, stopping at the first failing row.
/// Returns the normalised outcome log, or the failure.
pub fn run_table(bins: &Binaries, app: &App) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    for (kind, rows) in [(FeedKind::Http, HTTP_ROWS), (FeedKind::File, FILE_ROWS)] {
        let mut lab = Lab::new(bins, app, kind);
        for row in rows {
            eprintln!("e2e: row {}: {}", row.id, row.name);
            let started = Instant::now();
            match catch_unwind(AssertUnwindSafe(|| (row.run)(&mut lab))) {
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
    }
    Ok(log)
}

fn record(current: &str, previous: Option<&str>, bad: &[&str], events: usize) -> RecordView {
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
fn assert_integration(lab: &Lab, entry: &str) {
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

fn assert_current_link(lab: &Lab, version: &str) {
    assert_eq!(
        lab.current_link().as_deref(),
        Some(format!("versions/{version}").as_str()),
        "R/current"
    );
}

/// Every line of the runtime log is a schema-1 object.
fn assert_log_is_schema_1(lab: &Lab) {
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
fn update_from_link(lab: &Lab) {
    let status = lab.run_app(&lab.bin_link(), &["--update"]);
    assert!(status.success(), "the --update run failed: {status}");
}

/// Runs the app through the command link with no arguments.
fn start_from_link(lab: &Lab) {
    let status = lab.run_app(&lab.bin_link(), &[]);
    assert!(status.success(), "the app failed: {status}");
}

fn row_install(lab: &mut Lab) -> Vec<String> {
    lab.publish(&V1);
    let boot = lab.bootstrap();
    let (code, stdout) = lab.run_runtime(&boot.join("bin").join(RUNTIME_FILE), "install");
    assert_eq!(code, 0, "install exited {code}: {stdout}");
    assert!(
        stdout.contains("\"outcome\":\"installed\""),
        "the install result line"
    );

    let mut want = record("1.0.0", None, &[], 2);
    want.staged = None;
    assert_eq!(lab.record(), Some(want), "the record after the install");
    assert_eq!(lab.versions(), ["1.0.0"]);
    assert_current_link(lab, "1.0.0");
    assert_integration(lab, &lab.entry_rel(&V1));
    if lab.feed_kind() == FeedKind::Http {
        assert!(
            !lab.requests().is_empty(),
            "the loopback server saw no request"
        );
    }

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
    let lines = lab.expect_lines(&[
        "1.0.0 start",
        "1.0.0 nothing-pending",
        "1.0.0 check 2.0.0",
        "1.0.0 staged 2.0.0",
        "1.0.0 apply-scheduled",
        "2.0.0 start",
        "2.0.0 arg after-update",
        "2.0.0 event updated 1.0.0",
        "2.0.0 event first_run",
        "2.0.0 confirmed",
    ]);
    lab.wait_runtime_gone();
    assert_eq!(
        lab.record(),
        Some(record("2.0.0", Some("1.0.0"), &[], 0)),
        "the record after the confirmed update"
    );
    // GC keeps the current and the previous version, and there is nothing older.
    assert_eq!(lab.versions(), ["1.0.0", "2.0.0"]);
    assert_current_link(lab, "2.0.0");
    assert_integration(lab, &lab.entry_rel(&V2));
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
    // Foreign files beside the install's own: another app's entry and command.
    let foreign_desktop = lab.data.join("applications/other.desktop");
    let foreign_bin = lab.home.join(".local/bin/other-tool");
    std::fs::write(
        &foreign_desktop,
        b"[Desktop Entry]\nType=Application\nName=Other\nExec=other\n",
    )
    .expect("plant a desktop entry");
    std::fs::write(&foreign_bin, b"#!/bin/sh\n").expect("plant a command");

    let runtime = lab.root.join("versions/4.0.0").join(RUNTIME_FILE);
    let (code, stdout) = lab.run_runtime(&runtime, "uninstall");
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

/// Whether the desktop-file validator is installed (the suite says so when it is not).
pub fn validator_note() -> &'static str {
    if have_desktop_file_validate() {
        "desktop-file-validate: present"
    } else {
        "desktop-file-validate: not installed (the entry's own bytes are still compared)"
    }
}
