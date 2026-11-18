//! The Windows uninstall hand-off (M7-D5, M7 step 11) with the real binary: phase 1 copies the
//! runtime out of `R` and starts the copy; phase 2 runs only from such a copy and validates the
//! root it is given (M7-D16) before it removes anything; stale hand-off directories are cleared.
//!
//! Windows has no data-home redirect: each case builds an install by hand in the real per-user
//! program files folder (the tree as `R\app\1.0.0`, a first record by the core's writer), under a
//! unique test app id and display name, and removes what it created when it ends. The install has
//! no desktop integration applied, so its removal touches no registry or Start-menu entry of
//! anyone. Keys are generated at test time.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use lunepack::{InstallMeta, ProcessId, RelPath, Rng as _, Target, TrustedRoot, UpdateConfig};
use lunepack_core::state::{InstallState, UserScope};
use lunepack_core::{AppId, Channel, LayoutScheme, Signer, UserLayout, Version};
use lunepack_crypto::{Ed25519Signer, Ed25519Verifier, OsRng, Sha256Hasher, generate_key_file};
use lunepack_fs::StdFs;
use lunepack_testkit::{ChainFixture, SUITE_CHANNEL};

const RUNTIME: &str = env!("CARGO_BIN_EXE_lunepack-runtime");
const SCHEME: LayoutScheme = LayoutScheme::WINDOWS;
const MARKER: &str = "lunepack-marker.json";
const LIMIT: Duration = Duration::from_secs(60);
const EXIT_USAGE: i32 = 2;
const EXIT_INSTALL_MISMATCH: i32 = 26;

#[cfg(target_arch = "aarch64")]
const TARGET: Target = Target::WindowsAarch64;
#[cfg(not(target_arch = "aarch64"))]
const TARGET: Target = Target::WindowsX86_64;

fn hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    OsRng.fill(&mut b).expect("random");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn temp_home() -> PathBuf {
    std::fs::canonicalize(std::env::temp_dir()).expect("temp dir")
}

fn data_home() -> PathBuf {
    let dir = lunepack_os_windows::user_program_files().expect("program files");
    std::fs::create_dir_all(&dir).expect("program files");
    std::fs::canonicalize(&dir).expect("canonical")
}

/// This test process's identity.
fn me() -> ProcessId {
    lunepack_os_windows::WindowsProcess::new()
        .process_id(std::process::id())
        .expect("me")
        .expect("me")
}

/// An identity no process has: this process's pid with another start time (counts as ended).
fn gone() -> ProcessId {
    let me = me();
    ProcessId {
        pid: me.pid,
        start_ticks: me.start_ticks + 1,
    }
}

/// Removes `path` (a directory tree or a junction), retrying while an image in it still runs.
fn remove_retrying(path: &Path) {
    let start = Instant::now();
    while std::fs::symlink_metadata(path).is_ok() && start.elapsed() < Duration::from_secs(20) {
        let is_link = std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
        let done = if is_link {
            std::fs::remove_dir(path).is_ok()
        } else {
            std::fs::remove_dir_all(path).is_ok()
        };
        if done {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Waits until `path` is gone; false after `limit`.
fn gone_within(path: &Path, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if std::fs::symlink_metadata(path).is_err() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

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

/// One case's world: an app id and display name of its own, keys, an output directory, and the
/// paths it made (removed at the end).
struct Lab {
    _tmp: tempfile::TempDir,
    out: PathBuf,
    data_home: PathBuf,
    app_id: String,
    name: String,
    signer: Ed25519Signer,
    made: std::cell::RefCell<Vec<PathBuf>>,
}

impl Drop for Lab {
    fn drop(&mut self) {
        // Junctions first (never followed), then folders.
        let made = self.made.borrow().clone();
        for path in made.iter().rev() {
            remove_retrying(path);
        }
        // Hand-off directories of this case's app id.
        let mine = format!("{{\"app_id\":\"{}\",", self.app_id);
        if let Ok(entries) = std::fs::read_dir(temp_home()) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let ours = std::fs::read_to_string(e.path().join(MARKER))
                    .is_ok_and(|m| m.starts_with(&mine));
                if name.starts_with("lunepack-uninstall-") && ours {
                    remove_retrying(&e.path());
                }
            }
        }
    }
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::Builder::new()
            .prefix("uninstall-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .expect("tmp");
        let out = std::fs::canonicalize(tmp.path()).expect("canonical");
        let keys = tempfile::tempdir().expect("keys");
        let key = generate_key_file(&keys.path().join("k0")).expect("key");
        let tag = hex(4);
        Lab {
            _tmp: tmp,
            out,
            data_home: data_home(),
            app_id: format!("org.lunepack-test.u{tag}"),
            name: format!("LP Uninstall {tag}"),
            signer: Ed25519Signer::from_key_file(&key.path).expect("load key"),
            made: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn made(&self, path: &Path) {
        self.made.borrow_mut().push(path.to_path_buf());
    }

    fn app(&self, app_id: &str) -> AppId {
        AppId::parse(app_id).expect("app id")
    }

    /// An install of `app_id` at `root` (made here, removed at the end): the tree `R\app\1.0.0`
    /// with the runtime (and, with `ui`, a fake UI) in `bin`, its config, and a first record.
    fn install(&self, root: &Path, app_id: &str, ui: bool) {
        self.made(root);
        let layout = UserLayout::from_root(root.to_path_buf(), SCHEME);
        let version = Version::parse("1.0.0").expect("version");
        let tree = layout.version_dir(&version);
        let bin = tree.join("bin");
        std::fs::create_dir_all(&bin).expect("tree");
        std::fs::copy(RUNTIME, bin.join("lunepack-runtime.exe")).expect("runtime");
        std::fs::write(bin.join("app.exe"), b"app").expect("app");
        if ui {
            std::fs::copy(
                std::env::current_exe().expect("test exe"),
                bin.join("lunepack-ui.exe"),
            )
            .expect("ui");
        }
        let sign = |_: u8, message: &[u8]| {
            (
                self.signer.public_key(),
                self.signer.sign(message).expect("sign"),
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
        let root_doc = TrustedRoot::from_parts(
            self.app(app_id),
            1,
            1,
            &[fx.public_key(0)],
            &Sha256Hasher,
            &Ed25519Verifier,
        )
        .expect("root");
        let meta = InstallMeta {
            entry: RelPath::parse("bin/app.exe").expect("entry"),
            name: self.name.clone(),
            comment: None,
            icon: None,
            categories: Vec::new(),
            bin: None,
            terminal: false,
            publisher: None,
            file_types: Vec::new(),
            url_schemes: Vec::new(),
            autostart: false,
        };
        let config = UpdateConfig::new(
            &root_doc,
            version.clone(),
            TARGET,
            "https://updates.example.invalid/",
            Channel::parse(SUITE_CHANNEL).expect("channel"),
            60,
            meta,
        )
        .expect("config")
        .to_bytes()
        .expect("config bytes");
        std::fs::write(tree.join("lunepack-update.json"), config).expect("config");
        std::fs::create_dir_all(layout.state_dir()).expect("state");
        let fs = StdFs::new();
        let store = UserScope {
            dir: layout.state_dir(),
            app_id: self.app(app_id),
        };
        let loaded = store.load(&fs, &Sha256Hasher).expect("load");
        let first = InstallState::new(
            1,
            self.app(app_id),
            lunepack_core::Scope::User,
            [3; 16],
            TARGET,
        );
        let record =
            lunepack_core::install_first(&first, version, 10, [3; 16]).expect("first install");
        store
            .commit(&fs, &loaded, &record, &Sha256Hasher)
            .expect("commit");
    }

    /// `R`'s runtime of 1.0.0.
    fn runtime_in(&self, root: &Path) -> PathBuf {
        UserLayout::from_root(root.to_path_buf(), SCHEME)
            .version_dir(&Version::parse("1.0.0").expect("version"))
            .join("bin")
            .join("lunepack-runtime.exe")
    }

    /// A hand-off directory made by hand under the temp dir: `name` (default: a valid one), a
    /// marker naming `marker_app` and this test process (so no other run's cleanup takes it),
    /// and a copy of the runtime. Returns the copy.
    fn hand_off_copy(&self, name: Option<&str>, marker_app: Option<&str>) -> PathBuf {
        let name = name.map_or_else(|| format!("lunepack-uninstall-{}", hex(8)), str::to_owned);
        let dir = temp_home().join(name);
        std::fs::create_dir(&dir).expect("hand-off dir");
        self.made(&dir);
        if let Some(app) = marker_app {
            let me = me();
            std::fs::write(
                dir.join(MARKER),
                format!(
                    "{{\"app_id\":\"{app}\",\"pid\":{},\"start\":{}}}\n",
                    me.pid, me.start_ticks
                ),
            )
            .expect("marker");
        }
        let copy = dir.join("lunepack-runtime.exe");
        std::fs::copy(RUNTIME, &copy).expect("copy");
        copy
    }

    fn run(&self, program: &Path, args: &[&str]) -> Run {
        let child = Command::new(program)
            .args(args)
            .env_remove("LUNEPACK_HEALTH_TOKEN")
            .env_remove("LUNEPACK_NO_UI")
            .current_dir(&self.out)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        let start = Instant::now();
        let mut child = child;
        while child.try_wait().expect("wait").is_none() {
            if start.elapsed() > LIMIT {
                let _ = child.kill();
                panic!("the runtime ran too long");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = child.wait_with_output().expect("output");
        Run {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Phase 2 started from `copy` with `root`, a wait target that has ended, silent.
    fn phase_2(&self, copy: &Path, root: &Path) -> Run {
        let wait = gone();
        let root = root.to_str().expect("root text");
        self.run(
            copy,
            &[
                "uninstall",
                "--install-root",
                root,
                "--wait-pid",
                &wait.pid.to_string(),
                "--wait-start",
                &wait.start_ticks.to_string(),
                "--silent",
            ],
        )
    }

    /// The hand-off directories under the temp dir whose marker names `app_id`.
    fn hand_off_dirs(&self, app_id: &str) -> Vec<PathBuf> {
        let mine = format!("{{\"app_id\":\"{app_id}\",");
        std::fs::read_dir(temp_home())
            .expect("temp")
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("lunepack-uninstall-")
            })
            .filter(|e| {
                std::fs::read_to_string(e.path().join(MARKER)).is_ok_and(|m| m.starts_with(&mine))
            })
            .map(|e| e.path())
            .collect()
    }
}

/// Phase 1 from inside `R` hands off and exits 0 at once, printing nothing; the copy removes `R`.
/// `/S` is `--silent` (the setup tests assert that no UI starts, with their fake UI). The cleanup
/// of the same run removes a stale hand-off directory (owner gone) and keeps one whose owner
/// runs.
#[test]
fn phase_1_hands_off_and_the_copy_removes_the_install() {
    let lab = Lab::new();
    let root = lab.data_home.join(&lab.name);
    lab.install(&root, &lab.app_id, true);
    // Stale and live directories for the cleanup that phase 1 runs first.
    let stale = temp_home().join(format!("lunepack-uninstall-{}", hex(8)));
    std::fs::create_dir(&stale).expect("stale");
    lab.made(&stale);
    std::fs::write(
        stale.join(MARKER),
        "{\"app_id\":\"org.example.gone\",\"pid\":4294967291,\"start\":1}\n",
    )
    .expect("marker");
    let live_copy = lab.hand_off_copy(None, Some("org.example.live"));
    let live = live_copy.parent().expect("dir").to_path_buf();

    let run = lab.run(&lab.runtime_in(&root), &["uninstall", "/S"]);
    assert_eq!(run.code, 0, "{run:?}");
    assert!(run.stdout.is_empty(), "{run:?}");
    assert!(gone_within(&root, LIMIT), "the install root is still there");
    assert!(!stale.exists(), "a stale hand-off directory was kept");
    assert!(
        live.join(MARKER).exists(),
        "a live hand-off directory was removed"
    );
    // The copy: a fresh directory of the exact name, its marker naming the app, the runtime in
    // it (the UI's copy is removed by phase 2 at its end).
    let dirs = lab.hand_off_dirs(&lab.app_id);
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    assert!(dirs[0].join("lunepack-runtime.exe").is_file());
    // Nothing of the app is left in the data home (the tombstone went as well).
    let left: Vec<String> = std::fs::read_dir(&lab.data_home)
        .expect("data home")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(&lab.app_id) || n.contains(&lab.name))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

/// `--install-root` outside an uninstaller's own temp copy is a usage error before any action:
/// from the built runtime, from a directory of the wrong name, from one with no marker.
#[test]
fn the_hand_off_arguments_are_refused_anywhere_else() {
    let lab = Lab::new();
    let root = lab.data_home.join(&lab.name);
    lab.install(&root, &lab.app_id, false);
    let wrong_name = lab.hand_off_copy(
        Some(&format!("lunepack-uninstall-{}", hex(7))),
        Some(&lab.app_id),
    );
    let upper = lab.hand_off_copy(
        Some(&format!("lunepack-uninstall-{}", hex(8).to_uppercase())),
        Some(&lab.app_id),
    );
    let no_marker = lab.hand_off_copy(None, None);
    for program in [
        PathBuf::from(RUNTIME),
        lab.runtime_in(&root),
        wrong_name,
        upper,
        no_marker,
    ] {
        let run = lab.phase_2(&program, &root);
        assert_eq!(run.code, EXIT_USAGE, "{program:?}: {run:?}");
        assert_eq!(run.stderr.trim(), "lunepack-runtime: usage error");
        assert!(lab.runtime_in(&root).is_file(), "the install changed");
    }
}

/// Phase 2 refuses a root holding another app's record, a junction to a real install, and an
/// install one level too deep; each is left as it was.
#[test]
fn phase_2_refuses_roots_that_are_not_this_apps_install() {
    let lab = Lab::new();
    // Another app's install, with the marker naming this app.
    let other_id = format!("{}x", lab.app_id);
    let other = lab.data_home.join(format!("{} Other", lab.name));
    lab.install(&other, &other_id, false);
    // This app's install, reached through a junction in the data home.
    let real = lab.data_home.join(&lab.name);
    lab.install(&real, &lab.app_id, false);
    let junction = lab.data_home.join(format!("{} Link", lab.name));
    let made = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&real)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("mklink");
    assert!(made.success(), "mklink /J");
    lab.made(&junction);
    // This app's install under a folder inside the data home.
    let outer = lab.data_home.join(format!("{} Outer", lab.name));
    std::fs::create_dir(&outer).expect("outer");
    lab.made(&outer);
    let nested = outer.join(&lab.name);
    lab.install(&nested, &lab.app_id, false);

    for root in [&other, &junction, &nested] {
        let copy = lab.hand_off_copy(None, Some(&lab.app_id));
        let run = lab.phase_2(&copy, root);
        assert_eq!(run.code, EXIT_INSTALL_MISMATCH, "{root:?}: {run:?}");
        assert!(
            run.stdout.contains("\"kind\":\"install_mismatch\""),
            "{run:?}"
        );
    }
    for root in [&other, &real, &nested] {
        assert!(lab.runtime_in(root).is_file(), "{root:?} changed");
    }
    assert!(std::fs::symlink_metadata(&junction).is_ok_and(|m| m.file_type().is_symlink()));
}

/// Phase 2 removes an install whose folder the user renamed: `R`'s name is never checked.
#[test]
fn phase_2_removes_a_renamed_install() {
    let lab = Lab::new();
    let first = lab.data_home.join(&lab.name);
    lab.install(&first, &lab.app_id, false);
    let renamed = lab.data_home.join(format!("{} Renamed", lab.name));
    std::fs::rename(&first, &renamed).expect("rename");
    lab.made(&renamed);
    let copy = lab.hand_off_copy(None, Some(&lab.app_id));
    let run = lab.phase_2(&copy, &renamed);
    assert_eq!(run.code, 0, "{run:?}");
    assert!(
        run.stdout.contains("\"outcome\":\"uninstalled\""),
        "{run:?}"
    );
    assert!(!renamed.exists(), "the renamed install is still there");
    assert!(!first.exists());
}
