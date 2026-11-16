//! The runtime's `install` and `uninstall` modes with the real binary (M5 step 9, M5-D8,
//! M5-D10).
//!
//! Each case publishes a release into a `file:` feed under a temporary directory: documents signed
//! with Ed25519 keys generated at test time (never written into the repo), the pack and the
//! manifest written by the core's real writer, every frame stored (the real decoder reads it). The
//! release tree holds the update config, a shell-script entry that notes when it runs, and the
//! built `lunepack-runtime` beside it. A bootstrap copy of the same tree sits outside the install,
//! and its runtime runs `install` with `HOME` set to an empty temporary home. Linux only.
//!
//! The cases run in parallel on purpose: `uninstall`'s in-use scan must not count another case's
//! process caught while it exits as using the tree (F9).

#![cfg(target_os = "linux")]

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lunepack::{InstallMeta, RelPath, Target, TrustedRoot, UpdateConfig, Version};
use lunepack_core::state::{InstallState, UserScope};
use lunepack_core::{
    AppId, Channel, CodecId, EncodedFrame, Encoder, PayloadKind, ReleaseLayout, Signer, U53,
    pack_file,
};
use lunepack_crypto::{Ed25519Signer, Ed25519Verifier, Sha256Hasher, generate_key_file};
use lunepack_fs::StdFs;
use lunepack_testkit::{ChainFixture, FakeCodec, SUITE_APP_ID, SUITE_CHANNEL};

const RUNTIME: &str = env!("CARGO_BIN_EXE_lunepack-runtime");
/// Where the entry script notes that it ran (it must never run in these cases).
const OUT_VAR: &str = "LUNEPACK_INSTALL_TEST_OUT";
const V100: &str = "1.0.0";
const BIN: &str = "lp-install-test";
const DAY: u64 = 86_400;
const RUN_LIMIT: Duration = Duration::from_secs(120);

#[cfg(target_arch = "aarch64")]
const TARGET: Target = Target::LinuxAarch64;
#[cfg(not(target_arch = "aarch64"))]
const TARGET: Target = Target::LinuxX86_64;

/// Exit codes of the runtime's table (`modes.rs`).
const EXIT_OK: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_NOT_INSTALLED: i32 = 3;
const EXIT_ALREADY_INSTALLED: i32 = 23;
const EXIT_INTEGRATION: i32 = 24;
const EXIT_IN_USE: i32 = 25;
const EXIT_INSTALL_MISMATCH: i32 = 26;

fn app_id() -> AppId {
    AppId::parse(SUITE_APP_ID).expect("app id")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs()
}

fn u53(v: u64) -> U53 {
    U53::new(v).expect("u53")
}

/// An encoder that implements nothing, so every frame is stored (fast, and the runtime's real
/// decoder reads stored frames).
struct StoreOnly;

impl Encoder for StoreOnly {
    fn encode(&self, codec: CodecId, _: &[u8]) -> Result<EncodedFrame, lunepack_core::Error> {
        Err(lunepack_core::error::CodecError::Unsupported(codec).into())
    }

    fn encode_memory(&self, _: CodecId, input_len: u64) -> u64 {
        input_len
    }
}

/// The files of a release tree: `(path, bytes, exec)`, the config excluded.
fn tree_files() -> Vec<(String, Vec<u8>, bool)> {
    let script = format!("#!/bin/sh\n: > \"${OUT_VAR}/app-ran\"\n");
    vec![
        ("bin/app".to_owned(), script.into_bytes(), true),
        (
            "bin/lunepack-runtime".to_owned(),
            std::fs::read(RUNTIME).expect("runtime"),
            true,
        ),
        (
            "share/readme.txt".to_owned(),
            b"read me\n".repeat(20),
            false,
        ),
    ]
}

fn write_file(path: &Path, bytes: &[u8], exec: bool) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
    std::fs::write(path, bytes).expect("write");
    let mode = if exec { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
}

/// One case's world: a release on a `file:` feed, a bootstrap tree, an empty home.
struct Lab {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    home: PathBuf,
    data: PathBuf,
    root: PathBuf,
    out: PathBuf,
    boot: PathBuf,
}

impl Lab {
    /// Publishes 1.0.0 and writes its bootstrap tree.
    fn new() -> Lab {
        let tmp = tempfile::Builder::new()
            .prefix("install-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .expect("tmp");
        let base = std::fs::canonicalize(tmp.path()).expect("canonical");
        let home = base.join("home");
        let out = base.join("out");
        for d in [&home, &out] {
            std::fs::create_dir_all(d).expect("dirs");
        }
        let data = home.join(".local/share");
        let root = data.join(SUITE_APP_ID);
        let lab = Lab {
            _tmp: tmp,
            boot: base.join("boot").join(V100),
            base,
            home,
            data,
            root,
            out,
        };
        lab.publish();
        lab
    }

    fn release_dir(&self) -> PathBuf {
        self.base.join("release")
    }

    /// Signs and writes keys, feed, manifest and pack for 1.0.0, and the bootstrap tree.
    fn publish(&self) {
        let keys = tempfile::tempdir().expect("keys");
        let signers: Vec<Ed25519Signer> = (0..2)
            .map(|i| {
                let key = generate_key_file(&keys.path().join(format!("k{i}"))).expect("key");
                Ed25519Signer::from_key_file(&key.path).expect("load key")
            })
            .collect();
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
        let t = now();
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
        let meta = InstallMeta {
            entry: RelPath::parse("bin/app").expect("entry"),
            name: "Install test".to_owned(),
            comment: None,
            icon: None,
            categories: Vec::new(),
            bin: Some(BIN.to_owned()),
            terminal: false,
            publisher: None,
        };
        let config = UpdateConfig::new(
            &root,
            Version::parse(V100).expect("version"),
            TARGET,
            &feed,
            Channel::parse(SUITE_CHANNEL).expect("channel"),
            60,
            meta,
        )
        .expect("config")
        .to_bytes()
        .expect("config bytes");

        let mut files = tree_files();
        files.push(("lunepack-update.json".to_owned(), config, false));
        let mut layout = ReleaseLayout::new(app_id(), V100, TARGET).expect("layout");
        for (path, bytes, exec) in &files {
            let packed =
                pack_file(bytes, &StoreOnly, &FakeCodec::new(), &Sha256Hasher).expect("pack file");
            layout
                .add_file(RelPath::parse(path).expect("path"), *exec, &packed)
                .expect("add file");
            write_file(&self.boot.join(path), bytes, *exec);
        }
        let (doc, pack) = layout.finish(t - 3600, &Sha256Hasher).expect("finish");
        let manifest = fx.envelope(PayloadKind::Manifest, &doc.to_payload(), &[1]);

        let mut ks = fx.keyset_document(1, 1, None, 1, &[1]);
        ks.keys = vec![fx.release_key(1, t - DAY, t + 1000 * DAY)];
        let ks_bytes = fx.envelope(PayloadKind::Keys, &ks.to_payload(), &[0]);
        let rel = fx.release(V100, &[(TARGET, &manifest)], None);
        let mut feed_doc = fx.feed_document(1, Some(t + 30 * DAY), vec![rel]);
        feed_doc.issued = u53(t - 3600);
        let feed_bytes = fx.envelope(PayloadKind::Feed, &feed_doc.to_payload(), &[1]);

        let target = TARGET.as_str();
        for (name, bytes) in [
            ("keys.json".to_owned(), ks_bytes),
            (format!("feed-{SUITE_CHANNEL}.json"), feed_bytes),
            (format!("{V100}/{target}.manifest.json"), manifest),
            (format!("{V100}/{target}.pack"), pack),
        ] {
            write_file(&release.join(name), &bytes, false);
        }
    }

    fn boot_runtime(&self) -> PathBuf {
        self.boot.join("bin/lunepack-runtime")
    }

    fn tree(&self) -> PathBuf {
        self.root.join("versions").join(V100)
    }

    fn installed_runtime(&self) -> PathBuf {
        self.tree().join("bin/lunepack-runtime")
    }

    fn desktop_entry(&self) -> PathBuf {
        self.data
            .join("applications")
            .join(format!("{SUITE_APP_ID}.desktop"))
    }

    fn bin_link(&self) -> PathBuf {
        self.home.join(".local/bin").join(BIN)
    }

    fn command(&self, runtime: &Path, mode: &str) -> Command {
        let mut cmd = Command::new(runtime);
        cmd.arg(mode)
            .env("HOME", &self.home)
            .env_remove("XDG_DATA_HOME")
            .env_remove("LUNEPACK_HEALTH_TOKEN")
            .env(OUT_VAR, &self.out)
            .current_dir(&self.base)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    fn run(&self, runtime: &Path, mode: &str) -> Run {
        let child = self.command(runtime, mode).spawn().expect("runtime");
        Run::of(finish(child))
    }

    fn install(&self) -> Run {
        self.run(&self.boot_runtime(), "install")
    }

    fn installed(&self) -> Run {
        let run = self.install();
        assert_eq!(run.code, EXIT_OK, "install: {run:?}");
        run
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

    fn app_ran(&self) -> bool {
        self.out.join("app-ran").exists()
    }
}

/// A finished runtime run.
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

    /// The one line on stdout.
    fn line(&self) -> &str {
        let lines: Vec<&str> = self.stdout.lines().collect();
        assert_eq!(lines.len(), 1, "one stdout line: {self:?}");
        lines[0]
    }

    /// Nothing printed names a path of the case.
    fn assert_no_path(&self, lab: &Lab) {
        let base = lab.base.display().to_string();
        assert!(
            !self.stdout.contains(&base) && !self.stderr.contains(&base),
            "a path was printed: {self:?}"
        );
    }
}

fn finish(mut child: Child) -> Output {
    let start = Instant::now();
    while child.try_wait().expect("wait").is_none() {
        if start.elapsed() > RUN_LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the runtime ran too long");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().expect("output")
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
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
            let meta = std::fs::symlink_metadata(&path).expect("lstat");
            if meta.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

// ---- install --------------------------------------------------------------------------------

#[test]
fn install_into_an_empty_home_installs_and_integrates_without_launching() {
    let lab = Lab::new();
    let run = lab.installed();
    assert_eq!(
        run.line(),
        format!(
            "{{\"schema\":1,\"type\":\"result\",\"command\":\"install\",\"tree_version\":\"{V100}\",\"outcome\":\"installed\",\"version\":\"{V100}\"}}"
        )
    );
    run.assert_no_path(&lab);

    let record = lab.record().expect("record");
    assert_eq!(record.current.expect("current").version.to_string(), V100);
    assert_eq!(
        std::fs::read_link(lab.root.join("current")).expect("current"),
        Path::new("versions/1.0.0")
    );
    for (path, bytes, _) in tree_files() {
        assert_eq!(std::fs::read(lab.tree().join(&path)).expect("file"), bytes);
    }
    let entry = std::fs::read_to_string(lab.desktop_entry()).expect("desktop entry");
    assert!(entry.contains(&format!("X-Lunepack-App-Id={SUITE_APP_ID}")));
    assert_eq!(
        std::fs::read_link(lab.bin_link()).expect("bin link"),
        lab.root.join("current/bin/app")
    );
    assert!(!lab.app_ran(), "install launched the app");

    // A second run from the bootstrap finds the install done and changes nothing.
    let before = lab.record();
    let again = lab.install();
    assert_eq!(again.code, EXIT_ALREADY_INSTALLED, "{again:?}");
    assert!(again.line().contains("\"kind\":\"already_installed\""));
    assert_eq!(lab.record(), before);
}

#[test]
fn install_from_the_installed_tree_is_refused() {
    let lab = Lab::new();
    lab.installed();
    let before = (lab.record(), listing(&lab.root));
    let run = lab.run(&lab.installed_runtime(), "install");
    assert_eq!(run.code, EXIT_ALREADY_INSTALLED, "{run:?}");
    assert_eq!((lab.record(), listing(&lab.root)), before);
}

#[test]
fn a_rerun_after_a_kill_mid_install_resumes() {
    let lab = Lab::new();
    let mut child = lab
        .command(&lab.boot_runtime(), "install")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("runtime");
    // The record is created before the check and the stage; kill as soon as it exists.
    let start = Instant::now();
    let mut killed_with_record = false;
    while start.elapsed() < RUN_LIMIT {
        if lab.record().is_some() {
            child.kill().expect("kill");
            killed_with_record = true;
            break;
        }
        if child.try_wait().expect("wait").is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let _ = child.wait();
    assert!(killed_with_record, "the run ended before it was killed");
    let cut = lab.record().expect("record");
    assert!(
        cut.current.is_none(),
        "the run finished before it was killed"
    );
    assert!(!exists(&lab.root.join("current")));

    let run = lab.install();
    assert_eq!(run.code, EXIT_OK, "rerun: {run:?}");
    let record = lab.record().expect("record");
    assert_eq!(record.install_id, cut.install_id, "the record was resumed");
    assert_eq!(record.current.expect("current").version.to_string(), V100);
    assert!(exists(&lab.bin_link()) && exists(&lab.desktop_entry()));
    assert!(!lab.app_ran());
}

#[test]
fn a_pre_existing_foreign_root_is_not_adopted() {
    let lab = Lab::new();
    // The app's own user data from before lunepack, at the XDG path lunepack derives for `R`.
    write_file(&lab.root.join("settings.ini"), b"theme=dark\n", false);
    write_file(&lab.root.join("state/notes.txt"), b"mine\n", false);
    let before = listing(&lab.root);
    let run = lab.install();
    assert_eq!(run.code, EXIT_INSTALL_MISMATCH, "{run:?}");
    assert!(run.line().contains("\"kind\":\"install_mismatch\""));
    run.assert_no_path(&lab);
    assert_eq!(listing(&lab.root), before, "R was written");
    assert!(!exists(&lab.desktop_entry()) && !exists(&lab.bin_link()));
}

#[test]
fn a_root_holding_only_a_cut_off_runs_lock_is_adopted() {
    let lab = Lab::new();
    write_file(&lab.root.join("state/lock"), b"", false);
    let run = lab.install();
    assert_eq!(run.code, EXIT_OK, "{run:?}");
    assert_eq!(
        lab.record()
            .expect("record")
            .current
            .expect("current")
            .version
            .to_string(),
        V100
    );
}

#[test]
fn a_conflicting_command_link_stops_install_with_nothing_written() {
    let lab = Lab::new();
    let foreign = lab.bin_link();
    write_file(&foreign, b"someone else's tool\n", true);
    let run = lab.install();
    assert_eq!(run.code, EXIT_INTEGRATION, "{run:?}");
    assert!(run.line().contains("\"kind\":\"integration\""));
    run.assert_no_path(&lab);
    assert!(!exists(&lab.root), "R was created");
    assert!(!exists(&lab.desktop_entry()), "a desktop entry was written");
    assert_eq!(
        std::fs::read(&foreign).expect("foreign"),
        b"someone else's tool\n"
    );
}

#[test]
fn install_and_uninstall_take_no_arguments() {
    let lab = Lab::new();
    for mode in ["install", "uninstall"] {
        let child = lab
            .command(&lab.boot_runtime(), mode)
            .arg(lab.base.join("elsewhere"))
            .spawn()
            .expect("runtime");
        let run = Run::of(finish(child));
        assert_eq!(run.code, EXIT_USAGE, "{mode}: {run:?}");
        assert_eq!(run.stdout, "");
        assert_eq!(run.stderr, "lunepack-runtime: usage error\n");
    }
    assert!(!exists(&lab.root));
}

// ---- uninstall ------------------------------------------------------------------------------

#[test]
fn uninstall_removes_what_it_wrote_and_keeps_a_foreign_desktop_file() {
    let lab = Lab::new();
    lab.installed();
    let applications = lab.data.join("applications");
    let foreign = applications.join("org.example.other.desktop");
    write_file(&foreign, b"[Desktop Entry]\nName=Other\n", false);

    let run = lab.run(&lab.installed_runtime(), "uninstall");
    assert_eq!(run.code, EXIT_OK, "{run:?}");
    assert_eq!(
        run.line(),
        format!(
            "{{\"schema\":1,\"type\":\"result\",\"command\":\"uninstall\",\"tree_version\":\"{V100}\",\"outcome\":\"uninstalled\",\"version\":null}}"
        )
    );
    run.assert_no_path(&lab);
    assert!(!exists(&lab.root), "R is gone");
    assert!(!exists(&lab.desktop_entry()));
    assert!(!exists(&lab.bin_link()));
    assert_eq!(listing(&applications), vec!["org.example.other.desktop"]);
    assert!(listing(&lab.home.join(".local/bin")).is_empty());
    assert!(!lab.app_ran());
}

#[test]
fn uninstall_keeps_a_foreign_file_at_its_entry_name_and_reports_it() {
    let lab = Lab::new();
    lab.installed();
    let foreign = b"[Desktop Entry]\nName=Not lunepack's\n";
    std::fs::remove_file(lab.desktop_entry()).expect("remove");
    write_file(&lab.desktop_entry(), foreign, false);

    let run = lab.run(&lab.installed_runtime(), "uninstall");
    assert_eq!(run.code, EXIT_OK, "{run:?}");
    assert!(
        run.line()
            .contains("\"outcome\":\"uninstalled_with_leftovers\""),
        "{run:?}"
    );
    assert!(run.stderr.contains("\"code\":\"integration_kept\""));
    assert!(!exists(&lab.root));
    assert!(!exists(&lab.bin_link()));
    assert_eq!(
        std::fs::read(lab.desktop_entry()).expect("kept"),
        foreign.to_vec()
    );
}

#[test]
fn uninstall_from_a_copy_of_the_tree_outside_r_is_refused() {
    let lab = Lab::new();
    lab.installed();
    let before = listing(&lab.root);
    // A bare copy of the tree: not installed.
    let bare = lab.base.join("copy").join(V100);
    std::fs::create_dir_all(lab.base.join("copy")).expect("dirs");
    // A copy of the whole install root elsewhere: installed, but not where this home derives.
    let other = lab.base.join("other-root");
    for (from, to) in [
        (lab.tree(), bare.clone()),
        (lab.root.clone(), other.clone()),
    ] {
        let status = Command::new("cp")
            .arg("-a")
            .arg(&from)
            .arg(&to)
            .status()
            .expect("cp");
        assert!(status.success());
    }
    let cases = [
        (bare.join("bin/lunepack-runtime"), EXIT_NOT_INSTALLED),
        (
            other
                .join("versions")
                .join(V100)
                .join("bin/lunepack-runtime"),
            EXIT_INSTALL_MISMATCH,
        ),
    ];
    for (runtime, code) in cases {
        let run = lab.run(&runtime, "uninstall");
        assert_eq!(run.code, code, "{run:?}");
        run.assert_no_path(&lab);
    }
    assert_eq!(listing(&lab.root), before, "R was changed");
    assert!(exists(&lab.desktop_entry()) && exists(&lab.bin_link()));
    assert!(exists(&bare.join("bin/app")));
    assert!(exists(&other.join("state")));
}

#[test]
fn uninstall_through_a_symlinked_root_is_refused_and_the_target_is_untouched() {
    let lab = Lab::new();
    lab.installed();
    // R moves elsewhere and a symlink takes its place.
    let target = lab.base.join("moved-root");
    std::fs::rename(&lab.root, &target).expect("move");
    symlink(&target, &lab.root).expect("symlink");
    let before = listing(&target);

    for runtime in [
        lab.installed_runtime(),
        target
            .join("versions")
            .join(V100)
            .join("bin/lunepack-runtime"),
    ] {
        let run = lab.run(&runtime, "uninstall");
        assert_eq!(run.code, EXIT_INSTALL_MISMATCH, "{run:?}");
    }
    assert_eq!(listing(&target), before, "the target was changed");
    assert!(
        std::fs::symlink_metadata(&lab.root)
            .expect("link")
            .file_type()
            .is_symlink()
    );
    assert!(exists(&lab.desktop_entry()) && exists(&lab.bin_link()));
}

#[test]
fn uninstall_while_a_process_runs_from_r_is_refused() {
    let lab = Lab::new();
    lab.installed();
    let sleeper = lab.tree().join("helper-sleep");
    let sleep = ["/bin/sleep", "/usr/bin/sleep"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .expect("sleep");
    std::fs::copy(sleep, &sleeper).expect("copy sleep");
    let mut helper = Command::new(&sleeper)
        .arg("60")
        .current_dir(&lab.base)
        .spawn()
        .expect("helper");
    let before = listing(&lab.root);

    let run = lab.run(&lab.installed_runtime(), "uninstall");
    let _ = helper.kill();
    let _ = helper.wait();
    assert_eq!(run.code, EXIT_IN_USE, "{run:?}");
    assert!(run.line().contains("\"kind\":\"in_use\""));
    assert_eq!(listing(&lab.root), before, "R was changed");
    assert!(exists(&lab.desktop_entry()) && exists(&lab.bin_link()));

    // With the helper gone the same uninstall succeeds.
    let run = lab.run(&lab.installed_runtime(), "uninstall");
    assert_eq!(run.code, EXIT_OK, "{run:?}");
    assert!(!exists(&lab.root));
}

#[test]
fn a_symlink_inside_a_tree_pointing_outside_r_is_removed_not_followed() {
    let lab = Lab::new();
    lab.installed();
    let outside = lab.base.join("outside");
    write_file(&outside.join("keep.txt"), b"keep me\n", false);
    symlink(outside.join("keep.txt"), lab.tree().join("file-link")).expect("file link");
    symlink(&outside, lab.tree().join("share/dir-link")).expect("dir link");

    let run = lab.run(&lab.installed_runtime(), "uninstall");
    assert_eq!(run.code, EXIT_OK, "{run:?}");
    assert!(!exists(&lab.root));
    assert_eq!(
        std::fs::read(outside.join("keep.txt")).expect("kept"),
        b"keep me\n"
    );
    assert_eq!(listing(&outside), vec!["keep.txt"]);
}

// ---- tombstones (F18) -------------------------------------------------------------------------

impl Lab {
    /// A tombstone of this app id beside `R`, as an uninstall names it.
    fn tombstone(&self, n: u8) -> PathBuf {
        self.data
            .join(lunepack_core::tombstone_name(&app_id(), &[n; 8]))
    }

    /// The entries of the data home that look like this app's tombstones (by prefix, so a near
    /// miss counts too).
    fn tombstones(&self) -> Vec<String> {
        let prefix = format!(".{SUITE_APP_ID}.removing-");
        let mut names: Vec<String> = std::fs::read_dir(&self.data)
            .map(|entries| {
                entries
                    .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                    .filter(|n| n.starts_with(&prefix))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// What an uninstall cut off inside its tombstone removal leaves: the integration removed,
    /// `R` renamed to a tombstone, and part of the tombstone removed (its `state` first; `versions`
    /// half gone, a link pointing outside still inside). Returns the tombstone.
    fn cut_off_uninstall(&self) -> PathBuf {
        std::fs::remove_file(self.desktop_entry()).expect("desktop entry");
        std::fs::remove_file(self.bin_link()).expect("bin link");
        let tomb = self.tombstone(7);
        std::fs::rename(&self.root, &tomb).expect("rename");
        std::fs::remove_dir_all(tomb.join("state")).expect("state");
        std::fs::remove_dir_all(tomb.join("versions").join(V100).join("share")).expect("share");
        symlink(self.base.join("outside"), tomb.join("versions/link-out")).expect("link");
        tomb
    }
}

fn write_outside(lab: &Lab) {
    write_file(&lab.base.join("outside/keep.txt"), b"keep me\n", false);
}

fn assert_outside_kept(lab: &Lab) {
    assert_eq!(
        std::fs::read(lab.base.join("outside/keep.txt")).expect("kept"),
        b"keep me\n"
    );
}

fn assert_installed(lab: &Lab) {
    let record = lab.record().expect("record");
    assert_eq!(record.current.expect("current").version.to_string(), V100);
    assert_eq!(
        std::fs::read_link(lab.root.join("current")).expect("current"),
        Path::new("versions/1.0.0")
    );
    assert!(exists(&lab.bin_link()) && exists(&lab.desktop_entry()));
}

#[test]
fn uninstall_goes_through_a_tombstone_and_leaves_none() {
    let lab = Lab::new();
    lab.installed();
    let run = lab.run(&lab.installed_runtime(), "uninstall");
    assert_eq!(run.code, EXIT_OK, "{run:?}");
    run.assert_no_path(&lab);
    assert!(!exists(&lab.root));
    assert_eq!(lab.tombstones(), Vec::<String>::new());
    // The data home holds nothing of the app.
    assert_eq!(listing(&lab.data), vec!["applications"]);
    // A reinstall works.
    lab.installed();
    assert_installed(&lab);
}

#[test]
fn an_uninstall_cut_off_inside_the_tombstone_removal_is_recovered_by_reinstall() {
    let lab = Lab::new();
    lab.installed();
    write_outside(&lab);
    let tomb = lab.cut_off_uninstall();
    assert!(!exists(&lab.root));

    let run = lab.install();
    assert_eq!(run.code, EXIT_OK, "reinstall: {run:?}");
    assert_installed(&lab);
    assert!(!exists(&tomb), "the tombstone stayed");
    assert_eq!(lab.tombstones(), Vec::<String>::new());
    assert_outside_kept(&lab);

    // And the reinstalled app uninstalls.
    let run = lab.run(&lab.installed_runtime(), "uninstall");
    assert_eq!(run.code, EXIT_OK, "{run:?}");
    assert!(!exists(&lab.root));
    assert_eq!(lab.tombstones(), Vec::<String>::new());
}

#[test]
fn a_leftover_tombstone_beside_an_empty_root_does_not_stop_install() {
    let lab = Lab::new();
    write_outside(&lab);
    std::fs::create_dir_all(&lab.root).expect("empty R");
    let tomb = lab.tombstone(9);
    write_file(&tomb.join("versions/1.0.0/bin/app"), b"old\n", true);
    symlink(lab.base.join("outside"), tomb.join("link-out")).expect("link");

    let run = lab.install();
    assert_eq!(run.code, EXIT_OK, "{run:?}");
    assert_installed(&lab);
    assert!(!exists(&tomb));
    assert_outside_kept(&lab);
}

#[test]
fn uninstall_removes_a_leftover_tombstone_and_nothing_else_beside_r() {
    let lab = Lab::new();
    lab.installed();
    write_outside(&lab);
    // A cut-off uninstall's tombstone of an earlier install of this app.
    let old = lab.tombstone(1);
    write_file(&old.join("versions/0.9.0/bin/app"), b"old\n", true);
    symlink(lab.base.join("outside"), old.join("link-out")).expect("link");
    // Not ours: another app's tombstone, a near miss, and a symlink at a tombstone name.
    let theirs = lab.data.join(lunepack_core::tombstone_name(
        &AppId::parse("org.other").expect("id"),
        &[1; 8],
    ));
    write_file(&theirs.join("x"), b"theirs\n", false);
    let near = lab.data.join(format!(".{SUITE_APP_ID}.removing-0101"));
    write_file(&near.join("x"), b"near\n", false);
    let link = lab.tombstone(2);
    symlink(lab.base.join("outside"), &link).expect("tombstone-named link");

    let run = lab.run(&lab.installed_runtime(), "uninstall");
    assert_eq!(run.code, EXIT_OK, "{run:?}");
    assert!(!exists(&lab.root) && !exists(&old));
    assert_eq!(
        std::fs::read(theirs.join("x")).expect("theirs"),
        b"theirs\n"
    );
    assert_eq!(std::fs::read(near.join("x")).expect("near"), b"near\n");
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("link")
            .file_type()
            .is_symlink()
    );
    assert_outside_kept(&lab);
    assert_eq!(listing(&lab.base.join("outside")), vec!["keep.txt"]);
}
