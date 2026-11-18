//! The app-facing command line with the real binary (M5 steps 12 and 13, C4, M5-D11, M5-D12): the
//! grammar and its refusals, schema 1 objects against goldens, the exit codes, output hygiene, a
//! closed stdout, and the hand-off of `apply-and-restart` to the detached applier (its wait
//! target, and a shell capture that returns at once).
//!
//! Each case publishes releases into a `file:` feed under a temporary directory: documents signed
//! with Ed25519 keys generated at test time, every frame stored, the config of each tree written
//! by the core's writer. The installed tree's own runtime is run, with `HOME` set to an empty
//! temporary home. Linux only.

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lunepack::{InstallMeta, RelPath, Target, TrustedRoot, UpdateConfig, Version};
use lunepack_core::state::{InstallState, UserScope};
use lunepack_core::{
    AppId, Channel, CodecId, EncodedFrame, Encoder, Hasher as _, PayloadKind, ReleaseLayout,
    Signer, pack_file,
};
use lunepack_crypto::{Ed25519Signer, Ed25519Verifier, Sha256Hasher, generate_key_file};
use lunepack_fs::StdFs;
use lunepack_testkit::{ChainFixture, FakeCodec, SUITE_APP_ID, SUITE_CHANNEL};

const RUNTIME: &str = env!("CARGO_BIN_EXE_lunepack-runtime");
const BIN: &str = "lp-cli-test";
const DAY: u64 = 86_400;
const LIMIT: Duration = Duration::from_secs(120);
const USAGE_STDERR: &str = "lunepack-runtime: usage error\n";
/// The file (in the lab's home) where the launched app writes its arguments.
const APP_ARGS: &str = "app-args";
/// How long the launched app runs before it confirms.
const APP_SLEEP_SECS: u64 = 3;
/// The golden lines of `apply-and-restart`: its result, `nothing_staged`, `unexpected_version`.
const GOLDEN_SCHEDULED: usize = 38;
const GOLDEN_NOTHING_STAGED: usize = 39;
const GOLDEN_UNEXPECTED: usize = 40;

#[cfg(target_arch = "aarch64")]
const TARGET: Target = Target::LinuxAarch64;
#[cfg(not(target_arch = "aarch64"))]
const TARGET: Target = Target::LinuxX86_64;

const GOLDEN_OBJECTS: &str = include_str!("golden/objects.jsonl");

fn app_id() -> AppId {
    AppId::parse(SUITE_APP_ID).expect("app id")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

/// An encoder that implements nothing, so every frame is stored.
struct StoreOnly;

impl Encoder for StoreOnly {
    fn encode(&self, codec: CodecId, _: &[u8]) -> Result<EncodedFrame, lunepack_core::Error> {
        Err(lunepack_core::error::CodecError::Unsupported(codec).into())
    }

    fn encode_memory(&self, _: CodecId, input_len: u64) -> u64 {
        input_len
    }
}

fn write_file(path: &Path, bytes: &[u8], exec: bool) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
    std::fs::write(path, bytes).expect("write");
    let mode = if exec { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
}

/// The golden line `n` of the final objects (0-based).
fn golden(n: usize) -> &'static str {
    GOLDEN_OBJECTS.lines().nth(n).expect("golden line")
}

/// One case's world: a signed `file:` feed, a bootstrap tree, an empty home, an installed 1.0.0.
struct Lab {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    home: PathBuf,
    root: PathBuf,
    boot: PathBuf,
    signers: Vec<Ed25519Signer>,
    t: u64,
    publishes: u64,
}

impl Lab {
    /// Publishes 1.0.0 and installs it.
    fn installed() -> Lab {
        let tmp = tempfile::Builder::new()
            .prefix("cli-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .expect("tmp");
        let base = std::fs::canonicalize(tmp.path()).expect("canonical");
        let home = base.join("home");
        std::fs::create_dir_all(&home).expect("home");
        let keys = tempfile::tempdir().expect("keys");
        let signers = (0..2)
            .map(|i| {
                let key = generate_key_file(&keys.path().join(format!("k{i}"))).expect("key");
                Ed25519Signer::from_key_file(&key.path).expect("load key")
            })
            .collect();
        let mut lab = Lab {
            root: home.join(".local/share").join(SUITE_APP_ID),
            boot: base.join("boot"),
            _tmp: tmp,
            base,
            home,
            signers,
            t: now(),
            publishes: 0,
        };
        lab.publish(&["1.0.0"]);
        let run = lab.run(&lab.boot.join("bin/lunepack-runtime"), &["install"], &[]);
        assert_eq!(run.code, 0, "install: {run:?}");
        lab
    }

    fn release_dir(&self) -> PathBuf {
        self.base.join("release")
    }

    /// The installed runtime of `version`.
    fn runtime_of(&self, version: &str) -> PathBuf {
        self.root
            .join("versions")
            .join(version)
            .join("bin/lunepack-runtime")
    }

    /// Writes keys, a feed that lists exactly `versions` (ascending), their manifests and packs,
    /// and (once) the bootstrap tree of the first version.
    fn publish(&mut self, versions: &[&str]) {
        self.publishes += 1;
        let signers = &self.signers;
        let sign = |seed: u8, message: &[u8]| {
            let signer = &signers[usize::from(seed)];
            (
                signer.public_key(),
                signer.sign(message).expect("sign with a fresh key"),
            )
        };
        let mut small_order = [0u8; 32];
        small_order[0] = 1;
        let fx = ChainFixture {
            hasher: &Sha256Hasher,
            verifier: &Ed25519Verifier,
            sign: &sign,
            invalid_key: small_order,
        };
        let t = self.t;
        let root = TrustedRoot::from_parts(
            app_id(),
            1,
            1,
            &[fx.public_key(0)],
            &Sha256Hasher,
            &Ed25519Verifier,
        )
        .expect("root");
        let release = self.release_dir();
        let feed = format!("file://{}/", release.display());
        let target = TARGET.as_str();
        let mut releases = Vec::new();
        for (index, version) in versions.iter().enumerate() {
            let meta = InstallMeta {
                entry: RelPath::parse("bin/app").expect("entry"),
                name: "CLI test".to_owned(),
                comment: None,
                icon: None,
                categories: Vec::new(),
                bin: Some(BIN.to_owned()),
                terminal: false,
                publisher: None,
                file_types: Vec::new(),
                url_schemes: Vec::new(),
                autostart: false,
            };
            let config = UpdateConfig::new(
                &root,
                Version::parse(version).expect("version"),
                TARGET,
                &feed,
                Channel::parse(SUITE_CHANNEL).expect("channel"),
                60,
                meta,
            )
            .expect("config")
            .to_bytes()
            .expect("config bytes");
            let files: Vec<(&str, Vec<u8>, bool)> = vec![
                // Started by the applier, the app records its arguments, stays up a while (so an
                // applier that kept a caller's stdio would hold a capture open), then confirms its
                // health through its own runtime.
                (
                    "bin/app",
                    format!(
                        "#!/bin/sh\n# {version}\nprintf '%s\\n' \"$@\" > \"$HOME/{APP_ARGS}\"\nsleep {APP_SLEEP_SECS}\nexec \"${{0%/*}}/lunepack-runtime\" confirm\n"
                    )
                    .into_bytes(),
                    true,
                ),
                (
                    "bin/lunepack-runtime",
                    std::fs::read(RUNTIME).expect("runtime"),
                    true,
                ),
                ("share/readme.txt", b"read me\n".repeat(20), false),
                ("lunepack-update.json", config, false),
            ];
            let mut layout = ReleaseLayout::new(app_id(), version, TARGET).expect("layout");
            for (path, bytes, exec) in &files {
                let packed = pack_file(bytes, &StoreOnly, &FakeCodec::new(), &Sha256Hasher)
                    .expect("pack file");
                layout
                    .add_file(RelPath::parse(path).expect("path"), *exec, &packed)
                    .expect("add file");
                if self.publishes == 1 && index == 0 {
                    write_file(&self.boot.join(path), bytes, *exec);
                }
            }
            let (doc, pack) = layout
                .finish(t - 3600 + index as u64 * 60, &Sha256Hasher)
                .expect("finish");
            let manifest = fx.envelope(PayloadKind::Manifest, &doc.to_payload(), &[1]);
            releases.push(fx.release(version, &[(TARGET, &manifest)], None));
            for (name, bytes) in [
                (format!("{version}/{target}.manifest.json"), manifest),
                (format!("{version}/{target}.pack"), pack),
            ] {
                write_file(&release.join(name), &bytes, false);
            }
        }
        let mut ks = fx.keyset_document(1, 1, None, 1, &[1]);
        ks.keys = vec![fx.release_key(1, t - DAY, t + 1000 * DAY)];
        let ks_bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
        let mut feed_doc = fx.feed_document(self.publishes, Some(t + 30 * DAY), releases);
        feed_doc.issued = lunepack_core::U53::new(t - 3600).expect("u53");
        let feed_bytes = fx.envelope(PayloadKind::Feed, &feed_doc.to_payload(), &[1]);
        write_file(&release.join("keys.json"), &ks_bytes, false);
        write_file(
            &release.join(format!("feed-{SUITE_CHANNEL}.json")),
            &feed_bytes,
            false,
        );
    }

    /// A command for `program` under the lab's home, without any health token.
    fn command(&self, program: &Path) -> Command {
        let mut cmd = Command::new(program);
        cmd.env("HOME", &self.home)
            .env_remove("XDG_DATA_HOME")
            .env_remove("LUNEPACK_HEALTH_TOKEN")
            .current_dir(&self.base)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// Runs `program` with `args` (and `vars` on top) under the lab's home.
    fn run(&self, program: &Path, args: &[&str], vars: &[(&str, &str)]) -> Run {
        let mut cmd = self.command(program);
        cmd.args(args);
        for (k, v) in vars {
            cmd.env(k, v);
        }
        Run::of(finish(cmd.spawn().expect("spawn")))
    }

    /// An app-facing command of the installed 1.0.0.
    fn cmd(&self, args: &[&str]) -> Run {
        self.run(&self.runtime_of("1.0.0"), args, &[])
    }

    fn record(&self) -> Option<InstallState> {
        UserScope {
            dir: self.root.join("state"),
            app_id: app_id(),
        }
        .load(&StdFs::new(), &Sha256Hasher)
        .ok()
        .and_then(|l| l.record)
    }
}

/// A finished run.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl std::fmt::Debug for Run {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "exit {} stdout {:?} stderr {:?}",
            self.code, self.stdout, self.stderr
        )
    }
}

impl Run {
    fn of(out: Output) -> Run {
        Run {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8(out.stdout).expect("utf-8 stdout"),
            stderr: String::from_utf8(out.stderr).expect("utf-8 stderr"),
        }
    }

    /// The one stdout line.
    fn line(&self) -> &str {
        let lines: Vec<&str> = self.stdout.lines().collect();
        assert_eq!(lines.len(), 1, "one stdout line: {self:?}");
        lines[0]
    }

    /// The last stdout line, after any progress lines.
    fn last_line(&self) -> &str {
        self.stdout.lines().last().expect("a stdout line")
    }

    /// Nothing printed holds a path of the case, a URL or a secret.
    fn assert_clean(&self, lab: &Lab, secrets: &[&str]) {
        let base = lab.base.display().to_string();
        for text in [&self.stdout, &self.stderr] {
            assert!(!text.contains(&base), "a path was printed: {self:?}");
            assert!(!text.contains("file://"), "a URL was printed: {self:?}");
            assert!(!text.contains("http"), "a URL was printed: {self:?}");
            for secret in secrets {
                assert!(!text.contains(secret), "a secret was printed: {self:?}");
            }
        }
    }
}

fn finish(mut child: std::process::Child) -> Output {
    let start = Instant::now();
    while child.try_wait().expect("wait").is_none() {
        if start.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the runtime ran too long");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().expect("output")
}

/// Every path under `dir` (symlinks not followed), relative, sorted.
fn listing(dir: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("entry").path();
            out.push(
                path.strip_prefix(root)
                    .expect("inside")
                    .display()
                    .to_string(),
            );
            if std::fs::symlink_metadata(&path).expect("lstat").is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Runs the cargo-built runtime itself, from a place with no update config above it.
fn plain(args: &[&str]) -> Run {
    let mut cmd = Command::new(RUNTIME);
    cmd.args(args)
        .env_remove("LUNEPACK_HEALTH_TOKEN")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Run::of(finish(cmd.spawn().expect("spawn")))
}

fn token(seed: u8) -> String {
    raw_token(seed).iter().map(|b| format!("{b:02x}")).collect()
}

fn raw_token(seed: u8) -> [u8; 32] {
    let mut raw = [0u8; 32];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    raw
}

// ---- the grammar ----------------------------------------------------------------------------

/// Command lines that are not in the grammar. Run from a tree with no update config, where
/// discovery would say 14, they exit 2 first.
const BAD_LINES: &[&[&str]] = &[
    &[],
    &["frobnicate"],
    &["Check"],
    &["check", "extra"],
    &["check", "--unknown"],
    &["check", "--json", "--json"],
    &["check", "--channel"],
    &["check", "--channel", "a", "--channel", "b"],
    &["check", "--channel", "Not A Channel"],
    &["check", "--channel=stable"],
    &["check", "--expect-version", "1.0.0"],
    &["check", "--"],
    &["download", "--expect-version", "v1.0.0"],
    &["download", "--expect-version"],
    &[
        "download",
        "--expect-version",
        "1.0.0",
        "--expect-version",
        "1.0.0",
    ],
    &["startup", "--channel", "stable"],
    &["startup", "stray"],
    &["confirm", "--"],
    &["confirm", "--expect-schema"],
    &["confirm", "--expect-schema", "x"],
    &["confirm", "--expect-schema", "1", "--expect-schema", "1"],
    &["confirm", "--wait-pid", "42"],
    &["apply-and-restart", "--wait-pid"],
    &["apply-and-restart", "--wait-pid", "0"],
    &["apply-and-restart", "--wait-pid", "1"],
    &["apply-and-restart", "--wait-pid", "x"],
    &["apply-and-restart", "--wait-pid", "042"],
    &["apply-and-restart", "--wait-pid", "4294967296"],
    &["apply-and-restart", "--wait-pid", "42", "--wait-pid", "42"],
    &["apply-and-restart", "--expect-version", "v1.1.0"],
    &["apply-and-restart", "--channel", "stable"],
    &["apply-and-restart", "stray"],
];

/// A refusal is an object on stdout when `--json` stands before any `--`, else one fixed line on
/// stderr; never both, and it names nothing of the arguments.
fn assert_usage_refusal(run: &Run, args: &[&str]) {
    let json = args
        .iter()
        .take_while(|a| **a != "--")
        .any(|a| *a == "--json");
    if json {
        assert_eq!(run.stdout.trim_end(), golden(10), "{args:?}");
        assert_eq!(run.stderr, "", "{args:?}");
    } else {
        assert_eq!(run.stdout, "", "{args:?}");
        assert_eq!(run.stderr, USAGE_STDERR, "{args:?}");
    }
}

#[test]
fn a_command_line_outside_the_grammar_is_a_usage_error_before_anything_else() {
    // The control: a good line from the same place is found to have no update config (14).
    let control = plain(&["check"]);
    assert_eq!(control.code, 14, "control: {control:?}");

    for args in BAD_LINES {
        let run = plain(args);
        assert_eq!(run.code, 2, "{args:?}: {run:?}");
        assert_usage_refusal(&run, args);
        // With --json anywhere before `--`: an object on stdout, nothing on stderr.
        let mut json_args: Vec<&str> = args.to_vec();
        json_args.insert(1.min(json_args.len()), "--json");
        let run = plain(&json_args);
        assert_eq!(run.code, 2, "{json_args:?}: {run:?}");
        assert_eq!(run.stdout.trim_end(), golden(10), "{json_args:?}");
        assert_eq!(run.stderr, "", "{json_args:?}");
    }
}

#[test]
fn a_usage_error_changes_nothing_in_an_installed_tree() {
    let lab = Lab::installed();
    let before = listing(&lab.root);
    let record_before = lab.record();
    for args in BAD_LINES {
        let run = lab.cmd(args);
        assert_eq!(run.code, 2, "{args:?}: {run:?}");
        assert_usage_refusal(&run, args);
    }
    assert_eq!(listing(&lab.root), before);
    assert_eq!(lab.record(), record_before);
}

#[test]
fn an_argument_value_is_never_echoed() {
    let run = plain(&["check", "--secret-option-name", "secret-value-7"]);
    assert_eq!(run.code, 2);
    assert!(!run.stderr.contains("secret"), "{run:?}");
    let run = plain(&["check", "--json", "--channel", "SECRET-VALUE-7"]);
    assert_eq!(run.code, 2);
    assert!(
        !run.stdout.contains("SECRET") && !run.stderr.contains("SECRET"),
        "{run:?}"
    );
}

#[test]
fn a_different_schema_is_refused_before_any_action() {
    let lab = Lab::installed();
    let run = lab.cmd(&["check", "--json", "--expect-schema", "2"]);
    assert_eq!(run.code, 13, "{run:?}");
    assert_eq!(
        run.line(),
        "{\"schema\":1,\"type\":\"error\",\"command\":\"check\",\"tree_version\":null,\"kind\":\"schema_mismatch\",\"exit_code\":13}"
    );
    // Before discovery, too: a tree with no config says the same.
    assert_eq!(plain(&["check", "--expect-schema", "9"]).code, 13);
    // The schema it speaks is accepted.
    let run = lab.cmd(&["check", "--json", "--expect-schema", "1"]);
    assert_eq!(run.code, 0, "{run:?}");
}

// ---- check and download ----------------------------------------------------------------------

#[test]
fn check_reports_no_update_and_then_an_update() {
    let mut lab = Lab::installed();
    let run = lab.cmd(&["check", "--json"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.line(), golden(0));
    assert_eq!(run.stderr, "");
    run.assert_clean(&lab, &[]);

    lab.publish(&["1.0.0", "1.1.0"]);
    let run = lab.cmd(&["check", "--json"]);
    assert_eq!(run.code, 0, "{run:?}");
    let line = run.line();
    let head = "{\"schema\":1,\"type\":\"result\",\"command\":\"check\",\"tree_version\":\"1.0.0\",\"update\":{\"version\":\"1.1.0\",\"download_size_max\":";
    let tail = ",\"time_checked\":true}}";
    assert!(line.starts_with(head) && line.ends_with(tail), "{line}");
    let size = &line[head.len()..line.len() - tail.len()];
    assert!(
        size.bytes().all(|b| b.is_ascii_digit()) && size != "0",
        "{line}"
    );
    // The golden has the same shape (its own size is a fixed example).
    assert!(golden(1).starts_with(head) && golden(1).ends_with(tail));
    run.assert_clean(&lab, &[]);

    // The human form is one line, and nothing is staged by a check.
    let run = lab.cmd(&["check"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.stdout, "check: update 1.1.0 is available\n");
    assert_eq!(run.stderr, "");
    assert!(lab.record().expect("record").staged.is_none());
}

#[test]
fn download_stages_the_update_and_is_repeatable() {
    let mut lab = Lab::installed();
    lab.publish(&["1.0.0", "1.1.0"]);
    let run = lab.cmd(&["download", "--json"]);
    assert_eq!(run.code, 0, "{run:?}");
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert!(!lines.is_empty());
    for line in &lines[..lines.len() - 1] {
        assert!(
            line.starts_with("{\"schema\":1,\"type\":\"progress\",\"phase\":\""),
            "{line}"
        );
    }
    assert_eq!(run.last_line(), golden(3));
    assert_eq!(run.stderr, "");
    run.assert_clean(&lab, &[]);
    let record = lab.record().expect("record");
    assert_eq!(record.staged.expect("staged").version.to_string(), "1.1.0");
    assert!(
        lab.root
            .join("versions/1.1.0/lunepack-update.json")
            .is_file()
    );

    // A second run finds it staged and says so the same way.
    let run = lab.cmd(&["download", "--json"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.last_line(), golden(3));

    // The human form: one result line on stdout, progress (if any) on stderr.
    let run = lab.cmd(&["download"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.stdout, "download: staged 1.1.0\n");
}

#[test]
fn download_with_nothing_new_stages_nothing() {
    let lab = Lab::installed();
    let run = lab.cmd(&["download", "--json"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.line(), golden(4));
    assert!(lab.record().expect("record").staged.is_none());
}

#[test]
fn download_refuses_another_version_than_the_one_expected() {
    let mut lab = Lab::installed();
    lab.publish(&["1.0.0", "1.1.0"]);
    let run = lab.cmd(&["download", "--json", "--expect-version", "1.2.0"]);
    assert_eq!(run.code, 15, "{run:?}");
    assert_eq!(
        run.line(),
        "{\"schema\":1,\"type\":\"error\",\"command\":\"download\",\"tree_version\":\"1.0.0\",\"kind\":\"unexpected_version\",\"exit_code\":15}"
    );
    assert!(
        lab.record().expect("record").staged.is_none(),
        "nothing staged"
    );
    let run = lab.cmd(&["download", "--json", "--expect-version", "1.1.0"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.last_line(), golden(3));
}

#[test]
fn a_feed_that_cannot_be_read_is_a_closed_error_naming_nothing() {
    let lab = Lab::installed();
    std::fs::remove_dir_all(lab.release_dir()).expect("remove the feed");
    let run = lab.cmd(&["check", "--json"]);
    assert_ne!(run.code, 0, "{run:?}");
    assert!(run.line().contains("\"type\":\"error\""), "{run:?}");
    assert!(
        run.line().contains(&format!("\"exit_code\":{}", run.code)),
        "the code is in the object: {run:?}"
    );
    run.assert_clean(&lab, &[]);
}

// ---- startup and confirm ---------------------------------------------------------------------

#[test]
fn startup_delivers_the_install_events_once() {
    let lab = Lab::installed();
    let run = lab.cmd(&["startup", "--json"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(
        run.line(),
        "{\"schema\":1,\"type\":\"result\",\"command\":\"startup\",\"tree_version\":\"1.0.0\",\"events\":[{\"kind\":\"installed\",\"version\":\"1.0.0\"},{\"kind\":\"first_run\",\"version\":\"1.0.0\"}],\"action\":\"continue\",\"pending\":false}"
    );
    run.assert_clean(&lab, &[]);
    let run = lab.cmd(&["startup", "--json", "--", "--flag", "value"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.line(), golden(5));
    assert_eq!(
        lab.cmd(&["startup"]).stdout,
        "startup: continue, 0 event(s)\n"
    );
}

#[test]
fn confirm_with_nothing_pending_says_so() {
    let lab = Lab::installed();
    let run = lab.cmd(&["confirm", "--json"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.line(), golden(9));
    assert_eq!(lab.cmd(&["confirm"]).stdout, "confirm: nothing_pending\n");
}

#[test]
fn a_malformed_token_is_a_mismatch_and_is_never_printed() {
    let lab = Lab::installed();
    let secret = "ZZ-not-a-token-ZZ";
    let run = lab.run(
        &lab.runtime_of("1.0.0"),
        &["confirm", "--json"],
        &[("LUNEPACK_HEALTH_TOKEN", secret)],
    );
    assert_eq!(run.code, 16, "{run:?}");
    assert_eq!(
        run.line(),
        "{\"schema\":1,\"type\":\"error\",\"command\":\"confirm\",\"tree_version\":\"1.0.0\",\"kind\":\"token_mismatch\",\"exit_code\":16}"
    );
    run.assert_clean(&lab, &[secret]);
}

#[test]
fn confirm_with_the_right_token_confirms_and_with_another_changes_nothing() {
    let mut lab = Lab::installed();
    lab.publish(&["1.0.0", "1.1.0"]);
    assert_eq!(lab.cmd(&["download", "--json"]).code, 0);
    // What the applier would have committed: 1.1.0 current and pending, with its token's digest.
    let store = UserScope {
        dir: lab.root.join("state"),
        app_id: app_id(),
    };
    let fs = StdFs::new();
    let loaded = store.load(&fs, &Sha256Hasher).expect("load");
    let record = loaded.record.clone().expect("record");
    let v110 = Version::parse("1.1.0").expect("version");
    let digest = Sha256Hasher.sha256(&raw_token(7));
    let next = lunepack_core::apply(&record, &v110, digest).expect("apply");
    store
        .commit(&fs, &loaded, &next, &Sha256Hasher)
        .expect("commit");

    let right = token(7);
    let wrong = token(8);
    let runtime = lab.runtime_of("1.1.0");

    let run = lab.run(
        &runtime,
        &["confirm", "--json"],
        &[("LUNEPACK_HEALTH_TOKEN", &wrong)],
    );
    assert_eq!(run.code, 16, "{run:?}");
    run.assert_clean(&lab, &[&right, &wrong]);
    assert!(
        lab.record().expect("record").pending.is_some(),
        "nothing changed"
    );

    let run = lab.run(
        &runtime,
        &["confirm", "--json"],
        &[("LUNEPACK_HEALTH_TOKEN", &right)],
    );
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(
        run.line(),
        "{\"schema\":1,\"type\":\"result\",\"command\":\"confirm\",\"tree_version\":\"1.1.0\",\"outcome\":\"confirmed\"}"
    );
    run.assert_clean(&lab, &[&right, &wrong]);
    assert!(lab.record().expect("record").pending.is_none());

    let run = lab.run(
        &runtime,
        &["confirm", "--json"],
        &[("LUNEPACK_HEALTH_TOKEN", &right)],
    );
    assert_eq!(run.line(), golden(9).replace("1.0.0", "1.1.0"));
}

// ---- a tree that is not installed ------------------------------------------------------------

#[test]
fn a_tree_that_is_not_installed_has_nothing_to_check_or_download() {
    let lab = Lab::installed();
    let boot = lab.boot.join("bin/lunepack-runtime");
    for command in ["check", "download"] {
        let run = lab.run(&boot, &[command, "--json"], &[]);
        assert_eq!(run.code, 3, "{command}: {run:?}");
        assert_eq!(
            run.line(),
            format!(
                "{{\"schema\":1,\"type\":\"error\",\"command\":\"{command}\",\"tree_version\":\"1.0.0\",\"kind\":\"not_installed\",\"exit_code\":3}}"
            )
        );
    }
    let run = lab.run(&boot, &["startup", "--json"], &[]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.line(), golden(5));
    let run = lab.run(&boot, &["confirm", "--json"], &[]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.line(), golden(9));
}

// ---- a closed stdout --------------------------------------------------------------------------

#[test]
fn a_closed_stdout_cancels_and_the_next_run_goes_on() {
    let mut lab = Lab::installed();
    lab.publish(&["1.0.0", "1.1.0"]);
    // The reader goes away before the runtime writes its first line.
    let mut cmd = lab.command(Path::new("sh"));
    cmd.args(["-c", "sleep 1; exec \"$0\" \"$@\""])
        .arg(lab.runtime_of("1.0.0"))
        .args(["download", "--json"]);
    let mut child = cmd.spawn().expect("spawn");
    drop(child.stdout.take());
    let run = Run::of(finish(child));
    assert_eq!(run.code, 5, "{run:?}");
    assert_eq!(run.stdout, "");

    let run = lab.cmd(&["download", "--json"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.last_line(), golden(3));
    assert_eq!(
        lab.record()
            .expect("record")
            .staged
            .expect("staged")
            .version
            .to_string(),
        "1.1.0"
    );
}

// ---- apply-and-restart --------------------------------------------------------------------------

fn now_ms() -> u64 {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_millis();
    u64::try_from(ms).expect("ms")
}

impl Lab {
    /// 1.0.0 installed, 1.1.0 published, downloaded and staged.
    fn staged() -> Lab {
        let mut lab = Lab::installed();
        lab.publish(&["1.0.0", "1.1.0"]);
        let run = lab.cmd(&["download", "--json"]);
        assert_eq!(run.code, 0, "download: {run:?}");
        lab
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.root.join("logs/runtime.log")).unwrap_or_default()
    }

    /// Waits for the applier's final event in the log; returns the whole log.
    fn applier_end(&self) -> String {
        let start = Instant::now();
        loop {
            let log = self.log();
            let ended = log.lines().any(|l| {
                l.contains("\"command\":\"apply\"")
                    && (l.contains("\"type\":\"result\"") || l.contains("\"type\":\"error\""))
            });
            if ended {
                return log;
            }
            assert!(start.elapsed() < LIMIT, "the applier did not finish: {log}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The applier confirmed 1.1.0, which was started with `args`; nothing it logged holds a
    /// path of the case.
    fn assert_applied(&self, log: &str, args: &[&str]) {
        assert!(
            log.lines().any(|l| l.contains("\"command\":\"apply\"")
                && l.contains("\"outcome\":\"confirmed\"")
                && l.contains("\"version\":\"1.1.0\"")),
            "{log}"
        );
        assert!(!log.contains(&self.base.display().to_string()), "{log}");
        let record = self.record().expect("record");
        assert_eq!(
            record.current.expect("current").version.to_string(),
            "1.1.0"
        );
        assert!(record.pending.is_none());
        let mut want: String = args.iter().map(|a| format!("{a}\n")).collect();
        if args.is_empty() {
            want.push('\n');
        }
        let got = std::fs::read_to_string(self.home.join(APP_ARGS)).expect("app args");
        assert_eq!(got, want);
    }

    /// Nothing was started: after a while there is still no applier log, and 1.1.0 is still the
    /// staged version.
    fn assert_nothing_started(&self) {
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(self.log(), "", "an applier ran");
        let record = self.record().expect("record");
        assert_eq!(
            record.current.expect("current").version.to_string(),
            "1.0.0"
        );
        assert!(record.pending.is_none());
    }
}

/// The `time_ms` of the first log line of `phase`.
fn phase_time(log: &str, phase: &str) -> u64 {
    let needle = format!("\"phase\":\"{phase}\"");
    let line = log
        .lines()
        .find(|l| l.contains(&needle))
        .unwrap_or_else(|| panic!("no {phase} line: {log}"));
    let (_, rest) = line.split_once("\"time_ms\":").expect("time_ms");
    rest.trim_end_matches('}').parse().expect("time_ms")
}

/// The start time (`/proc/<pid>/stat` field 22) of a running process.
fn start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let (_, rest) = stat.rsplit_once(')').expect("comm");
    rest.split_whitespace()
        .nth(19)
        .expect("starttime")
        .parse()
        .expect("ticks")
}

/// The state letter (`/proc/<pid>/stat` field 3) of a process.
fn state_of(pid: u32) -> char {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let (_, rest) = stat.rsplit_once(')').expect("comm");
    rest.trim_start().chars().next().expect("state")
}

/// The error object of `apply-and-restart` for `kind` (the golden's line for `check`, renamed).
fn golden_error(kind: &str) -> String {
    GOLDEN_OBJECTS
        .lines()
        .find(|l| {
            l.contains("\"command\":\"check\"") && l.contains(&format!("\"kind\":\"{kind}\""))
        })
        .expect("golden error")
        .replace("\"command\":\"check\"", "\"command\":\"apply-and-restart\"")
}

#[test]
fn a_shell_capture_returns_at_once_while_the_applier_goes_on() {
    let lab = Lab::staged();
    // `x=$(cmd)`: the shell runs the command directly, so its parent is the shell.
    let mut cmd = lab.command(Path::new("sh"));
    cmd.args([
        "-c",
        r#"x=$("$0" apply-and-restart --json -- --restarted "two words"); printf '%s\n' "$x""#,
    ])
    .arg(lab.runtime_of("1.0.0"));
    let started = Instant::now();
    let run = Run::of(finish(cmd.spawn().expect("spawn")));
    let took = started.elapsed();
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.line(), golden(GOLDEN_SCHEDULED));
    assert_eq!(run.stderr, "");
    run.assert_clean(&lab, &[]);
    // The app the applier starts runs for APP_SLEEP_SECS: an applier holding the caller's stdio
    // would keep the capture (and this pipe) open that long.
    assert!(took < Duration::from_secs(2), "the capture took {took:?}");
    let log = lab.applier_end();
    lab.assert_applied(&log, &["--restarted", "two words"]);
}

#[test]
fn the_applier_waits_for_the_parent_recorded_at_start() {
    let lab = Lab::staged();
    let out = lab.base.join("out");
    // The shell is the runtime's parent; it outlives the runtime by two seconds.
    let mut cmd = lab.command(Path::new("sh"));
    cmd.args(["-c", r#""$0" apply-and-restart --json > "$1"; sleep 2"#])
        .arg(lab.runtime_of("1.0.0"))
        .arg(&out);
    let spawned = now_ms();
    let run = Run::of(finish(cmd.spawn().expect("spawn")));
    assert_eq!(run.code, 0, "{run:?}");
    let printed = std::fs::read_to_string(&out).expect("out");
    assert_eq!(printed.trim_end(), golden(GOLDEN_SCHEDULED));
    let log = lab.applier_end();
    let (wait, apply) = (phase_time(&log, "wait"), phase_time(&log, "apply"));
    assert!(wait <= apply, "{log}");
    assert!(
        apply >= spawned + 2000,
        "the applier went on before its parent exited: {log}"
    );
    lab.assert_applied(&log, &[]);
}

#[test]
fn a_shell_caller_passes_its_own_pid_and_is_waited_for() {
    let lab = Lab::staged();
    let out = lab.base.join("out");
    // `x=$(cmd; true)`: the runtime's parent is a subshell that exits at once; `--wait-pid $$`
    // names the shell itself, which lives two more seconds.
    let mut cmd = lab.command(Path::new("sh"));
    cmd.args([
        "-c",
        r#"x=$("$0" apply-and-restart --json --wait-pid $$; true); printf '%s\n' "$x" > "$1"; sleep 2"#,
    ])
    .arg(lab.runtime_of("1.0.0"))
    .arg(&out);
    let spawned = now_ms();
    let started = Instant::now();
    let child = cmd.spawn().expect("spawn");
    // The capture returns at once.
    loop {
        let printed = std::fs::read_to_string(&out).unwrap_or_default();
        if printed.ends_with('\n') {
            assert_eq!(printed.trim_end(), golden(GOLDEN_SCHEDULED));
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the capture did not return"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let run = Run::of(finish(child));
    assert_eq!(run.code, 0, "{run:?}");
    let log = lab.applier_end();
    assert!(
        phase_time(&log, "apply") >= spawned + 2000,
        "the applier went on when the subshell exited: {log}"
    );
    lab.assert_applied(&log, &[]);
}

#[test]
fn a_wait_pid_is_named_with_its_start_time_and_a_reused_pid_is_not_waited_for() {
    let lab = Lab::staged();
    let mut target = Command::new("sleep").arg("60").spawn().expect("sleep");
    let pid = target.id();
    let run = lab.cmd(&[
        "apply-and-restart",
        "--json",
        "--wait-pid",
        &pid.to_string(),
    ]);
    assert_eq!(run.code, 0, "{run:?}");
    assert_eq!(run.line(), golden(GOLDEN_SCHEDULED));
    // The applier waits for the live target (the start time it was handed is the target's).
    std::thread::sleep(Duration::from_millis(1500));
    let log = lab.log();
    assert!(log.contains("\"phase\":\"wait\""), "{log}");
    assert!(
        !log.contains("\"phase\":\"apply\""),
        "it did not wait: {log}"
    );
    let ended = now_ms();
    target.kill().expect("kill");
    target.wait().expect("reap");
    let log = lab.applier_end();
    assert!(phase_time(&log, "apply") >= ended, "{log}");
    lab.assert_applied(&log, &[]);

    // The pid now names another process (another start time): the hand-off's target counts as
    // exited, and the applier does not wait for the newcomer.
    let mut lab = lab;
    lab.publish(&["1.0.0", "1.1.0", "1.2.0"]);
    let run = lab.run(&lab.runtime_of("1.1.0"), &["download", "--json"], &[]);
    assert_eq!(run.code, 0, "{run:?}");
    let mut other = Command::new("sleep").arg("60").spawn().expect("sleep");
    let other_pid = other.id();
    let stale_start = start_ticks(other_pid) + 1;
    let started = Instant::now();
    let run = lab.run(
        &lab.runtime_of("1.1.0"),
        &[
            "apply",
            "--wait-pid",
            &other_pid.to_string(),
            "--wait-start",
            &stale_start.to_string(),
            "--version",
            "1.2.0",
        ],
        &[],
    );
    assert_eq!(run.code, 0, "{run:?}");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "it waited for the newcomer"
    );
    assert!(other.try_wait().expect("try_wait").is_none(), "still alive");
    let _ = other.kill();
    let _ = other.wait();
    let record = lab.record().expect("record");
    assert_eq!(
        record.current.expect("current").version.to_string(),
        "1.2.0"
    );
}

#[test]
fn a_wait_target_that_is_not_running_starts_nothing() {
    let lab = Lab::staged();
    // No such process (above any pid_max).
    let run = lab.cmd(&["apply-and-restart", "--json", "--wait-pid", "4294967295"]);
    assert_eq!(run.code, 19, "{run:?}");
    assert_eq!(run.line(), golden_error("process"));
    // A zombie: it has exited, so there is nothing to wait for.
    let mut zombie = Command::new("true").spawn().expect("true");
    let pid = zombie.id();
    let start = Instant::now();
    while state_of(pid) != 'Z' {
        assert!(start.elapsed() < LIMIT, "no zombie");
        std::thread::sleep(Duration::from_millis(10));
    }
    let run = lab.cmd(&[
        "apply-and-restart",
        "--json",
        "--wait-pid",
        &pid.to_string(),
    ]);
    zombie.wait().expect("reap");
    assert_eq!(run.code, 19, "{run:?}");
    assert_eq!(run.line(), golden_error("process"));
    run.assert_clean(&lab, &[]);
    lab.assert_nothing_started();
}

#[test]
fn apply_and_restart_with_nothing_staged_or_another_version_starts_nothing() {
    let lab = Lab::installed();
    let run = lab.cmd(&["apply-and-restart", "--json"]);
    assert_eq!(run.code, 12, "{run:?}");
    assert_eq!(run.line(), golden(GOLDEN_NOTHING_STAGED));
    let run = lab.cmd(&["apply-and-restart"]);
    assert_eq!(run.code, 12, "{run:?}");
    assert_eq!(run.stdout, "");
    assert_eq!(
        run.stderr,
        "apply-and-restart: error: nothing_staged (exit 12)\n"
    );
    assert_eq!(lab.log(), "");

    let lab = Lab::staged();
    let run = lab.cmd(&["apply-and-restart", "--json", "--expect-version", "1.2.0"]);
    assert_eq!(run.code, 15, "{run:?}");
    assert_eq!(run.line(), golden(GOLDEN_UNEXPECTED));
    run.assert_clean(&lab, &[]);
    lab.assert_nothing_started();
    assert_eq!(
        lab.record()
            .expect("record")
            .staged
            .expect("staged")
            .version
            .to_string(),
        "1.1.0"
    );
}
