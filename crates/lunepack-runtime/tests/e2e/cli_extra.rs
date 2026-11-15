//! The extra command-line tests of the end-to-end suite (M5 step 14), which run once after the
//! scenario tables:
//!
//! - `apply-and-restart` with nothing staged: exit 12 and a typed error object;
//! - a hard kill (SIGKILL) of the runtime during `download` and during staging: the next
//!   `download` resumes without fetching again what was completed, and is never `busy`;
//! - planted secrets (C4 Output): a distinctive health token, the install id, a feed URL with a
//!   unique host label and path component, and the temporary home's path are planted, every
//!   command is run in success and in each reachable error, with and without `--json`, and no
//!   planted string may show in stdout, stderr or the runtime's log, in its plain, JSON-escaped or
//!   hex form. An instrument check comes first.
//!
//! A failure names only the stream and the planted item that matched, never the value or the
//! stream's content (a lesson of 2026-10-31).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lunepack_testkit::TransportFault;

use crate::lab::{
    App, Binaries, Captured, FeedKind, Lab, LabOptions, RUNTIME_FILE, Release, WAIT, wait_for,
};

/// The size of the filler the killed downloads fetch: with `SlowChunks` they cannot end early.
const BLOB: usize = 3 << 20;

/// The versions the staging kill tries, in turn (see [`hard_kill`]).
const STAGING_VERSIONS: [&str; 5] = ["3.0.0", "4.0.0", "5.0.0", "6.0.0", "7.0.0"];

/// A test of this file: it panics when an expectation fails.
type Test = fn(&Binaries, &App);

const TESTS: &[(&str, Test)] = &[
    ("apply-and-restart with nothing staged", nothing_staged),
    ("hard kill during download and during staging", hard_kill),
    (
        "planted secrets: the instrument finds a planted string",
        instrument_check,
    ),
    ("planted secrets: json output", |b, a| {
        planted_secrets(b, a, true)
    }),
    ("planted secrets: text output", |b, a| {
        planted_secrets(b, a, false)
    }),
    ("planted secrets: an unreachable https feed", |b, a| {
        unreachable_feed(b, a)
    }),
];

/// Runs every test, stopping at the first failure.
pub fn run_all(bins: &Binaries, app: &App) -> Result<(), String> {
    for (name, test) in TESTS {
        eprintln!("e2e: extra: {name}");
        let started = Instant::now();
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| test(bins, app))) {
            let why = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_else(|| "a panic".to_owned());
            return Err(format!("extra test `{name}` failed: {why}"));
        }
        eprintln!("e2e: extra ok ({:.1}s)", started.elapsed().as_secs_f32());
    }
    Ok(())
}

// ---- helpers -------------------------------------------------------------------------------------

/// The runtime beside the entry of `release` in the tree at `tree`.
fn runtime_in(tree: &Path, lab: &Lab, release: &Release) -> PathBuf {
    let entry = lab.entry_rel(release);
    let dir = Path::new(&entry).parent().unwrap_or(Path::new(""));
    tree.join(dir).join(RUNTIME_FILE)
}

/// The runtime of an installed version.
fn installed_runtime(lab: &Lab, release: &Release) -> PathBuf {
    runtime_in(
        &lab.root.join("versions").join(release.version),
        lab,
        release,
    )
}

/// Installs the newest release the feed offers through the runtime's own install mode.
fn install_via_runtime(lab: &Lab, release: &Release) -> Captured {
    let boot = lab.bootstrap();
    lab.run_cmd(&runtime_in(&boot, lab, release), &["install"], None)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// A running runtime that is killed when the guard goes (also when a check panics).
struct Victim {
    child: Child,
}

impl Victim {
    fn start(lab: &Lab, runtime: &Path, args: &[&str]) -> Victim {
        let mut cmd = lab.command(runtime);
        cmd.args(args).stdout(Stdio::null()).stderr(Stdio::null());
        Victim {
            child: cmd.spawn().expect("start the runtime"),
        }
    }

    /// SIGKILL, then reap.
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Victim {
    fn drop(&mut self) {
        self.kill();
    }
}

/// The length of the longest `.part` file under `dir` (0 when there is none).
fn longest_part(dir: &Path) -> u64 {
    let mut longest = 0;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => longest = longest.max(longest_part(&path)),
            Ok(_) if path.extension().is_some_and(|e| e == "part") => {
                longest = longest.max(std::fs::metadata(&path).map_or(0, |m| m.len()));
            }
            _ => {}
        }
    }
    longest
}

// ---- apply-and-restart with nothing staged --------------------------------------------------------

fn nothing_staged(bins: &Binaries, app: &App) {
    let lab = Lab::new(bins, app, FeedKind::Http);
    let v1 = Release::plain("1.0.0");
    lab.publish(&v1);
    let installed = install_via_runtime(&lab, &v1);
    assert_eq!(installed.code, 0, "the install exited {}", installed.code);
    let runtime = installed_runtime(&lab, &v1);
    let me = std::process::id().to_string();

    let json = lab.run_cmd(
        &runtime,
        &["apply-and-restart", "--json", "--wait-pid", &me],
        None,
    );
    assert_eq!(json.code, 12, "the exit code with --json");
    assert_eq!(
        String::from_utf8_lossy(&json.stdout),
        "{\"schema\":1,\"type\":\"error\",\"command\":\"apply-and-restart\",\
         \"tree_version\":\"1.0.0\",\"kind\":\"nothing_staged\",\"exit_code\":12}\n",
        "the typed error object"
    );

    let text = lab.run_cmd(&runtime, &["apply-and-restart", "--wait-pid", &me], None);
    assert_eq!(text.code, 12, "the exit code without --json");
    assert!(text.stdout.is_empty(), "an error prints nothing on stdout");

    // Nothing was started and nothing changed.
    assert!(
        crate::lab::runtime_apply_pids().is_empty(),
        "an applier was started"
    );
    assert_eq!(lab.record().and_then(|r| r.staged), None);
}

// ---- a hard kill during download and during staging -----------------------------------------------

/// Whether a request is for a signed document rather than for pack or frame bytes.
fn is_document(url: &str) -> bool {
    url.split('?').next().unwrap_or_default().ends_with(".json")
}

fn hard_kill(bins: &Binaries, app: &App) {
    let lab = Lab::new(bins, app, FeedKind::Http);
    let v1 = Release::plain("1.0.0");
    lab.publish(&v1);
    let installed = install_via_runtime(&lab, &v1);
    assert_eq!(installed.code, 0, "the install exited {}", installed.code);
    let runtime = installed_runtime(&lab, &v1);

    // ---- killed while the download is under way ----
    let v2 = Release {
        blob_bytes: BLOB,
        ..Release::plain("2.0.0")
    };
    lab.publish(&v2);
    // From here every file arrives one byte per segment: the runtime cannot finish before it is
    // killed, and the cache holds a part.
    lab.origin().add_fault(TransportFault::SlowChunks);
    let mut victim = Victim::start(&lab, &runtime, &["download", "--json"]);
    let cache = lab.root.join("cache");
    wait_for("the download to leave a part", || {
        longest_part(&cache) >= 4096
    });

    // The instrument for "never busy": while the victim holds the lock, another run is refused.
    let refused = lab.run_cmd(&runtime, &["download", "--json"], None);
    assert_eq!(refused.code, 4, "a second download while one is running");
    assert!(
        refused.last_line().contains("\"kind\":\"busy\""),
        "the refusal is the busy error"
    );

    victim.kill();
    let part = longest_part(&cache);
    assert!(part >= 4096, "the part holds {part} bytes after the kill");
    let before = lab.origin().requests().len();
    lab.origin().set_faults(Vec::new());

    let again = lab.run_cmd(&runtime, &["download", "--json"], None);
    assert_ne!(again.code, 4, "the lock of a killed process stays held");
    assert_eq!(
        again.code, 0,
        "the download after the kill exited {}",
        again.code
    );
    let last = again.last_line();
    assert!(
        last.contains("\"version\":\"2.0.0\",\"staged\":true"),
        "the download after the kill staged 2.0.0"
    );
    let seen = lab.origin().requests();
    let data: Vec<_> = seen[before..]
        .iter()
        .filter(|r| !is_document(&r.url))
        .collect();
    assert!(!data.is_empty(), "the resumed download asked for no bytes");
    assert!(
        data.iter()
            .all(|r| r.range.is_some_and(|range| range.first > 0)),
        "a request after the kill did not resume from a byte past 0: {data:?}"
    );
    assert_eq!(longest_part(&cache), 0, "a part is left after the resume");
    assert_eq!(
        lab.record().and_then(|r| r.staged),
        Some("2.0.0".to_owned()),
        "the record after the resume"
    );

    // ---- killed while the staging is under way ----
    // Staging can still have ended before the kill lands (the record then holds the version),
    // which proves nothing: try the next version, up to `STAGING_VERSIONS.len()` times, until a
    // kill leaves the version unstaged.
    let mut interrupted = None;
    for version in STAGING_VERSIONS {
        let release = Release {
            blob_bytes: BLOB,
            small_files: 400,
            ..Release::plain(version)
        };
        lab.publish(&release);
        let mut victim = Victim::start(&lab, &runtime, &["download", "--json"]);
        // Staging builds the tree in `<version>.partial`: the kill follows its appearance.
        let partial = lab.root.join("versions").join(format!("{version}.partial"));
        let deadline = Instant::now() + WAIT;
        while std::fs::symlink_metadata(&partial).is_err() {
            assert!(Instant::now() < deadline, "staging never began");
            std::thread::sleep(Duration::from_micros(200));
        }
        victim.kill();
        let staged = lab.record().and_then(|r| r.staged);
        if staged.as_deref() != Some(version) {
            interrupted = Some(version);
            break;
        }
    }
    let version = interrupted.expect("staging was never interrupted before it ended");
    let before = lab.origin().requests().len();

    let again = lab.run_cmd(&runtime, &["download", "--json"], None);
    assert_ne!(again.code, 4, "the lock of a killed process stays held");
    assert_eq!(
        again.code, 0,
        "the download after the kill exited {}",
        again.code
    );
    assert!(
        again
            .last_line()
            .contains(&format!("\"version\":\"{version}\",\"staged\":true")),
        "the download after the kill staged {version}"
    );
    let seen = lab.origin().requests();
    let data: Vec<_> = seen[before..]
        .iter()
        .filter(|r| !is_document(&r.url))
        .collect();
    assert!(
        data.is_empty(),
        "bytes completed before the kill were fetched again: {data:?}"
    );
    assert_eq!(
        lab.record().and_then(|r| r.staged),
        Some(version.to_owned()),
        "the record after the second resume"
    );
}

// ---- planted secrets --------------------------------------------------------------------------------

/// The health token the harness puts into every command's environment: 32 bytes as hex.
const TOKEN: &str = "7f3a9c21b8e4d6055a1c93e7f20b48d6e1a7c5339bd0f8264a5e17c3d9b20f84";
/// A unique component of the temporary home's path.
const HOME_PART: &str = "plant-home-5e07a9";
/// A unique path component of the loopback feed.
const FEED_PART: &str = "plant-feed-2b86d4";
/// The unique host label and path component of the unreachable https feed.
const HOST_LABEL: &str = "plant-host-4c9e2b71";
const URL_PART: &str = "plant-path-83d1f6";

/// One planted string.
struct Needle {
    label: &'static str,
    value: String,
}

fn needle(label: &'static str, value: impl Into<String>) -> Needle {
    Needle {
        label,
        value: value.into(),
    }
}

fn json_escape(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The forms a planted string may take in an output: as is, JSON-escaped (with and without the
/// optional escape of `/`), and as hex digits of its bytes.
fn forms(value: &str) -> Vec<(&'static str, Vec<u8>)> {
    let json = json_escape(value);
    let hex: String = value.bytes().map(|b| format!("{b:02x}")).collect();
    vec![
        ("plain", value.as_bytes().to_vec()),
        ("json", json.clone().into_bytes()),
        ("json-slash", json.replace('/', "\\/").into_bytes()),
        ("hex", hex.into_bytes()),
    ]
}

/// The first stream that holds a planted string, named by stream, item and form only.
fn find_hit(streams: &[(&str, &[u8])], needles: &[Needle]) -> Option<String> {
    for (stream, bytes) in streams {
        for needle in needles {
            for (form, text) in forms(&needle.value) {
                if contains(bytes, &text) {
                    return Some(format!(
                        "the {stream} holds the planted {} ({form} form)",
                        needle.label
                    ));
                }
            }
        }
    }
    None
}

/// The instrument check: a planted string, in each form, in one known output of a real child
/// process, is found; clean output is not.
fn instrument_check(bins: &Binaries, app: &App) {
    let lab = Lab::new(bins, app, FeedKind::File);
    // Characters that make the forms differ.
    let probe = [needle("probe", "pl\"an\\t/x")];
    for (form, text) in forms(&probe[0].value) {
        let text = String::from_utf8(text).expect("ascii forms");
        let stdout = lab.run_cmd(
            Path::new("/bin/sh"),
            &["-c", "printf 'noise %s noise' \"$1\"", "sh", &text],
            None,
        );
        let hit = find_hit(&[("stdout", &stdout.stdout)], &probe);
        assert!(
            hit.as_deref()
                .is_some_and(|m| m.contains(&format!("({form} form)"))),
            "the {form} form planted in a stdout was not found"
        );
        let stderr = lab.run_cmd(
            Path::new("/bin/sh"),
            &["-c", "printf 'noise %s noise' \"$1\" >&2", "sh", &text],
            None,
        );
        assert!(
            find_hit(&[("stderr", &stderr.stderr)], &probe).is_some(),
            "the {form} form planted in a stderr was not found"
        );
        assert!(
            find_hit(&[("log", format!("a {text} b").as_bytes())], &probe).is_some(),
            "the {form} form planted in a log was not found"
        );
    }
    assert!(
        find_hit(&[("stdout", b"clean output, nothing planted")], &probe).is_none(),
        "clean output was reported"
    );
}

/// A lab, its runtime commands and the planted strings they are checked for.
struct Probe<'a> {
    lab: &'a Lab,
    needles: Vec<Needle>,
    /// Whether the app-facing commands get `--json`.
    json: bool,
}

impl Probe<'_> {
    fn check(&self, label: &str, got: &Captured) {
        let mut streams: Vec<(String, &[u8])> = vec![
            (format!("stdout of `{label}`"), &got.stdout),
            (format!("stderr of `{label}`"), &got.stderr),
        ];
        let logs = self.lab.runtime_logs();
        for (name, bytes) in &logs {
            streams.push((format!("{name} after `{label}`"), bytes));
        }
        let view: Vec<(&str, &[u8])> = streams.iter().map(|(n, b)| (n.as_str(), *b)).collect();
        if let Some(why) = find_hit(&view, &self.needles) {
            panic!("{why}");
        }
    }

    /// Runs `runtime <command> [--json] <options> [-- <tail>]` with the planted token in its
    /// environment and checks it prints no planted string. `label` names the run in a failure.
    fn command(
        &self,
        label: &str,
        runtime: &Path,
        command: &str,
        options: &[&str],
        tail: &[&str],
        want: i32,
    ) -> Captured {
        let mut args = vec![command];
        if self.json {
            args.push("--json");
        }
        args.extend_from_slice(options);
        if !tail.is_empty() {
            args.push("--");
            args.extend_from_slice(tail);
        }
        self.run(label, runtime, &args, want)
    }

    /// Runs `runtime <args>` as given.
    fn run(&self, label: &str, runtime: &Path, args: &[&str], want: i32) -> Captured {
        let got = self.lab.run_cmd(runtime, args, Some(TOKEN));
        assert_eq!(got.code, want, "`{label}` exited {}, not {want}", got.code);
        self.check(label, &got);
        got
    }
}

fn base_needles(lab: &Lab) -> Vec<Needle> {
    vec![
        needle("health token", TOKEN),
        needle("home path", lab.home.to_string_lossy()),
        needle("home path component", HOME_PART),
        needle("feed path component", FEED_PART),
        needle("feed host label", HOST_LABEL),
        needle("feed URL path component", URL_PART),
    ]
}

fn planted_options() -> LabOptions {
    LabOptions {
        tmp_prefix: concat!("plant-home-5e07a9", "-"),
        feed_component: Some(FEED_PART),
    }
}

/// Every command of the runtime in its success and in each error a harness can reach: from a
/// tree that is not installed, a tree with a broken update configuration, a malformed or unknown
/// command line (carrying planted strings), a staged update that is not there, a process that
/// is not there, an update that is not the one expected, and an update applied in the end.
fn planted_secrets(bins: &Binaries, app: &App, json: bool) {
    let lab = Lab::with_options(bins, app, FeedKind::Http, planted_options());
    let v1 = Release::plain("1.0.0");
    lab.publish(&v1);
    let boot = lab.bootstrap();
    let boot_runtime = runtime_in(&boot, &lab, &v1);

    let mut probe = Probe {
        lab: &lab,
        needles: base_needles(&lab),
        json,
    };
    let home = lab.home.to_string_lossy().into_owned();

    // A bootstrap tree is not an installed one.
    probe.command("not-installed check", &boot_runtime, "check", &[], &[], 3);
    probe.command(
        "not-installed download",
        &boot_runtime,
        "download",
        &[],
        &[],
        3,
    );

    // A tree whose update configuration is broken, with planted strings in the file.
    let broken = lab.work.join("broken");
    std::fs::create_dir_all(&broken).expect("create dir");
    copy_dir(&boot, &broken);
    std::fs::write(
        broken.join("lunepack-update.json"),
        format!(
            "{{\"feed\":\"https://{HOST_LABEL}.invalid/{URL_PART}/\",\"token\":\"{TOKEN}\",\"path\":\"{home}\"}}"
        ),
    )
    .expect("break the configuration");
    probe.command(
        "broken-config check",
        &runtime_in(&broken, &lab, &v1),
        "check",
        &[],
        &[],
        14,
    );

    // The install, then its record's install id is planted too.
    let installed = probe.run("install", &boot_runtime, &["install"], 0);
    assert!(installed.last_line().contains("\"outcome\":\"installed\""));
    let id = lab.install_id_hex().expect("the record's install id");
    probe.needles.push(needle("install id", id));
    probe.check("install (after the record exists)", &installed);

    let runtime = installed_runtime(&lab, &v1);
    probe.command("startup", &runtime, "startup", &[], &[TOKEN, &home], 0);
    probe.command("confirm", &runtime, "confirm", &[], &[], 0);
    probe.command("check (nothing new)", &runtime, "check", &[], &[], 0);

    // Command lines outside the grammar, with planted strings as the offending words.
    let bad_channel = format!("BAD/{TOKEN}/{home}");
    let bad_option = format!("--{HOST_LABEL}-{URL_PART}");
    probe.run(
        "usage: bad channel",
        &runtime,
        &["check", "--channel", &bad_channel],
        2,
    );
    probe.run("usage: bad option", &runtime, &["check", &bad_option], 2);
    probe.run("usage: stray word", &runtime, &["check", &home], 2);
    probe.run("usage: bad command", &runtime, &[&bad_option], 2);
    probe.run(
        "usage: bad version",
        &runtime,
        &["download", "--expect-version", &bad_channel],
        2,
    );
    probe.run(
        "usage: bad wait pid",
        &runtime,
        &["apply-and-restart", "--wait-pid", &home],
        2,
    );
    probe.run(
        "usage: json",
        &runtime,
        &["check", "--json", "--channel", &bad_channel],
        2,
    );
    probe.command(
        "schema mismatch",
        &runtime,
        "check",
        &["--expect-schema", "2"],
        &[],
        13,
    );

    // A wait target that is not there, then nothing staged.
    probe.command(
        "apply-and-restart: no such process",
        &runtime,
        "apply-and-restart",
        &["--wait-pid", "4294967295"],
        &[TOKEN],
        19,
    );
    let me = std::process::id().to_string();
    probe.command(
        "apply-and-restart: nothing staged",
        &runtime,
        "apply-and-restart",
        &["--wait-pid", &me],
        &[],
        12,
    );

    // An update, an unexpected version, the download, and the update applied.
    lab.publish(&Release::plain("2.0.0"));
    probe.command("check (an update)", &runtime, "check", &[], &[], 0);
    probe.command(
        "download: unexpected version",
        &runtime,
        "download",
        &["--expect-version", "9.9.9"],
        &[],
        15,
    );
    probe.command("download", &runtime, "download", &[], &[], 0);

    let mut waited = Command::new("sleep")
        .arg("1")
        .spawn()
        .expect("start the process to wait for");
    let target = waited.id().to_string();
    probe.command(
        "apply-and-restart",
        &runtime,
        "apply-and-restart",
        &["--wait-pid", &target, "--expect-version", "2.0.0"],
        &["--after-update"],
        0,
    );
    let _ = waited.wait();
    wait_for("the applier to finish", || {
        crate::lab::runtime_apply_pids().is_empty()
    });
    assert_eq!(
        lab.record().and_then(|r| r.current),
        Some("2.0.0".to_owned()),
        "the update was not applied"
    );
    // The applier's own log, after a whole update.
    assert!(
        !lab.runtime_logs().is_empty(),
        "the applier wrote no log to check"
    );
    probe.check(
        "the applier",
        &Captured {
            code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        },
    );

    let v2 = Release::plain("2.0.0");
    let uninstalled = probe.run(
        "uninstall",
        &installed_runtime(&lab, &v2),
        &["uninstall"],
        0,
    );
    assert!(
        uninstalled
            .last_line()
            .contains("\"outcome\":\"uninstalled\"")
    );
}

/// An installed tree whose own feed is an https URL that cannot be reached: every network
/// command fails in DNS or connect, the path on which a URL is most likely to leak.
fn unreachable_feed(bins: &Binaries, app: &App) {
    for json in [true, false] {
        let mut lab = Lab::with_options(bins, app, FeedKind::Http, planted_options());
        lab.set_release_feed(&format!("https://{HOST_LABEL}.invalid/{URL_PART}/"));
        let v1 = Release::plain("1.0.0");
        lab.publish(&v1);
        lab.install_in_place();
        let mut probe = Probe {
            lab: &lab,
            needles: base_needles(&lab),
            json,
        };
        if let Some(id) = lab.install_id_hex() {
            probe.needles.push(needle("install id", id));
        }
        let runtime = installed_runtime(&lab, &v1);
        probe.command("unreachable check", &runtime, "check", &[], &[], 8);
        probe.command("unreachable download", &runtime, "download", &[], &[], 8);
    }
}

/// Copies a directory tree: files with their mode, symlinks as symlinks.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create dir");
    for entry in std::fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        let (src, dst) = (entry.path(), to.join(entry.file_name()));
        let kind = entry.file_type().expect("file type");
        if kind.is_dir() {
            copy_dir(&src, &dst);
        } else if kind.is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(&src).expect("read link"), &dst)
                .expect("symlink");
        } else {
            std::fs::copy(&src, &dst).expect("copy file");
        }
    }
}
