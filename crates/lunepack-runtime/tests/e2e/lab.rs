//! The lab of the end-to-end suite (M5-D13): one publisher, one feed, one temporary home and the
//! helpers that drive the real binaries (the `lunepack` command line, the static runtime, the
//! app under test) and read back what they left.
//!
//! Everything runs in a temporary directory with its own `HOME`; no child sees the real one. Keys
//! are generated at run time. Linux only.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lunepack::{
    AppId, CancelToken, Channel, DownloadOptions, InstallMeta, Installation, Platform, RelPath,
    Target, TrustedRoot, UpdateConfig, Version, blocking,
};
use lunepack_core::state::UserScope;
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};
use lunepack_fs::StdFs;
use lunepack_testkit::{FakeIntegration, FakeOrigin, LoopbackServer};

/// The app id of every release of the suite.
pub const APP_ID: &str = "org.lunepack.e2e";
/// The channel.
pub const CHANNEL: &str = "stable";
/// The name of the command link.
pub const BIN: &str = "lunepack-e2e";
/// The name of the display name in the desktop entry.
pub const APP_NAME: &str = "Lunepack E2E";
/// The environment variable that names the outcome file (the apps' own contract).
pub const OUT_VAR: &str = "LUNEPACK_E2E_OUT";
/// The environment variable that names the detail file.
pub const DETAIL_VAR: &str = "LUNEPACK_E2E_DETAIL";
/// The runtime's file name beside the entry.
pub const RUNTIME_FILE: &str = "lunepack-runtime";

/// How long a wait for something the runtime or an app does may take.
pub const WAIT: Duration = Duration::from_secs(90);
/// How long one pack, feed or install command may take.
const COMMAND_LIMIT: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_millis(50);

#[cfg(target_arch = "aarch64")]
pub const TARGET: &str = "linux-aarch64";
#[cfg(not(target_arch = "aarch64"))]
pub const TARGET: &str = "linux-x86_64";

#[cfg(target_arch = "aarch64")]
const TARGET_ID: Target = Target::LinuxAarch64;
#[cfg(not(target_arch = "aarch64"))]
const TARGET_ID: Target = Target::LinuxX86_64;

/// The binaries under test, from the environment.
#[derive(Clone)]
pub struct Binaries {
    /// The static runtime that `pack --runtime` places.
    pub runtime: PathBuf,
    /// The `lunepack` command line.
    pub cli: PathBuf,
    /// The stand-in UI that `pack --ui` places ([`Ui::Fake`]); it needs no display.
    pub fake_ui: PathBuf,
    /// The real `lunepack-ui` ([`Ui::Real`]).
    pub real_ui: PathBuf,
}

/// The UI a release carries beside its runtime (`pack --ui`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ui {
    /// None: the release has no UI, as every release of the M5 rows.
    None,
    /// The stand-in of `tests/e2e/fake-ui`.
    Fake,
    /// The real `lunepack-ui`.
    Real,
}

/// The app under test: its built file (or folder) and the file name its entry has in a tree.
#[derive(Clone)]
pub struct App {
    /// The built app: one file, or, for a folder app, the folder.
    pub binary: PathBuf,
    /// The entry's file name in a tree (`e2e_app`).
    pub name: String,
    /// A folder app (the .NET example, M13 step 7; the C example, M14 step 6): `binary` is a
    /// folder that holds the entry `name` and every file the app needs, all of them packed beside
    /// the entry. A single-file app is just the entry.
    pub folder: bool,
}

/// Where the feed is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FeedKind {
    /// `http://127.0.0.1:<port>/` over the testkit's loopback server (M5-D16).
    Http,
    /// `file:///<release dir>/`.
    File,
}

/// What one release of the suite holds.
#[derive(Clone, Debug)]
pub struct Release {
    pub version: &'static str,
    /// The directives of the `e2e-flags` marker file, one per line.
    pub flags: &'static [&'static str],
    /// The entry sits at the tree's root instead of under `bin/` (P3).
    pub moved_entry: bool,
    /// `[update] health_timeout_secs` of this release.
    pub health_timeout_secs: u64,
    /// Bytes of incompressible filler in `share/blob.bin` (0: no file), so a download takes time.
    pub blob_bytes: usize,
    /// Small filler files under `share/many/` (4 KiB each), so staging takes time.
    pub small_files: usize,
    /// The UI packed beside the runtime.
    pub ui: Ui,
    /// Bytes of `share/delta.bin` (0: no file): incompressible filler that is the same in every
    /// release but for 16 bytes in the middle, which `delta_tweak` sets (M12 step 7), so a patch
    /// from an earlier release is a few dozen bytes against a frame of the file's size.
    pub delta_bytes: usize,
    /// Which 16 bytes `delta.bin` has in the middle (0: the filler as it is).
    pub delta_tweak: u8,
}

impl Release {
    /// A plain release under `bin/`, with a 20 s health timeout.
    pub const fn plain(version: &'static str) -> Release {
        Release {
            version,
            flags: &[],
            moved_entry: false,
            health_timeout_secs: 20,
            blob_bytes: 0,
            small_files: 0,
            ui: Ui::None,
            delta_bytes: 0,
            delta_tweak: 0,
        }
    }
}

/// How a lab differs from the plain one: names the planted-secrets tests choose.
#[derive(Clone, Copy, Default)]
pub struct LabOptions {
    /// Prefix of the temporary directory's name, so the home's path holds a chosen component.
    pub tmp_prefix: &'static str,
    /// A path component the feed URL carries (`http://127.0.0.1:<port>/<component>/`).
    pub feed_component: Option<&'static str>,
}

/// What a command printed, byte for byte.
pub struct Captured {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Captured {
    /// The last non-empty stdout line.
    pub fn last_line(&self) -> String {
        String::from_utf8_lossy(&self.stdout)
            .lines()
            .rfind(|l| !l.is_empty())
            .unwrap_or_default()
            .to_owned()
    }
}

/// Deterministic incompressible bytes (a xorshift stream), `seed` telling releases apart.
fn filler(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The bytes of `share/delta.bin` of a release: the same filler for every release, with 16 bytes
/// in the middle XORed with `tweak`.
pub fn delta_content(len: usize, tweak: u8) -> Vec<u8> {
    let mut bytes = filler(len, 0xD17A);
    for byte in bytes.iter_mut().skip(len / 2).take(16) {
        *byte ^= tweak;
    }
    bytes
}

/// The record, as far as the scenarios look at it.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct RecordView {
    pub current: Option<String>,
    pub previous: Option<String>,
    pub pending: Option<(String, u64)>,
    pub staged: Option<String>,
    pub bad: Vec<String>,
    /// Lifecycle events not yet delivered.
    pub events: usize,
}

/// One scenario world.
pub struct Lab {
    _tmp: tempfile::TempDir,
    pub work: PathBuf,
    pub home: PathBuf,
    /// `<home>/.local/share`.
    pub data: PathBuf,
    /// The install root `R`.
    pub root: PathBuf,
    pub out: PathBuf,
    pub detail: PathBuf,
    pub release_dir: PathBuf,
    cfg_dir: PathBuf,
    bins: Binaries,
    app: App,
    feed: String,
    /// The path under which the release directory is served (empty, or `<component>/`).
    feed_prefix: String,
    /// The feed the packed configs name instead of `feed` (the seed install still uses `feed`).
    release_feed: Option<String>,
    /// `[update] publisher_check` of the published releases (M9-D2); `None` leaves it out.
    publisher_check: Option<&'static str>,
    kind: FeedKind,
    _server: Option<LoopbackServer>,
    origin: Option<FakeOrigin>,
    root_key: [u8; 32],
    /// The first release, whose config the writers share.
    first: Option<Release>,
    /// Variables the lab's commands get besides the fixed ones (the UI's, M6 step 11).
    extra_vars: Vec<(String, String)>,
}

fn hex_decode(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    assert_eq!(bytes.len(), 64, "a public key is 64 hex digits");
    let digit = |b: u8| match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => panic!("not lowercase hex"),
    };
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks(2).enumerate() {
        out[i] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    out
}

fn write_file(path: &Path, bytes: &[u8], exec: bool) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
    std::fs::write(path, bytes).expect("write file");
    let mode = if exec { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set mode");
}

/// Copies a directory tree: regular files with their mode, symlinks as symlinks.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create dir");
    for entry in std::fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("entry");
        let (src, dst) = (entry.path(), to.join(entry.file_name()));
        let kind = entry.file_type().expect("file type");
        if kind.is_dir() {
            copy_tree(&src, &dst);
        } else if kind.is_symlink() {
            symlink(std::fs::read_link(&src).expect("read link"), &dst).expect("symlink");
        } else {
            std::fs::copy(&src, &dst).expect("copy file");
        }
    }
}

/// Waits for `cond` to hold, up to [`WAIT`]; panics naming `what` when it does not.
pub fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(POLL);
    }
}

/// Runs `cmd` to completion within `limit` (killing it after), returning its output. A command
/// that spawns detached children must not have a piped output: those would keep the pipe open.
fn run_limited(mut cmd: Command, limit: Duration, what: &str) -> Output {
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|_| panic!("could not start {what}"));
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => return child.wait_with_output().expect("output"),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{what} ran past {limit:?}");
            }
            None => std::thread::sleep(POLL),
        }
    }
}

/// Pids of the runtime processes in `apply` mode, from `/proc` (a zombie has no command line).
pub fn runtime_apply_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return pids;
    };
    for entry in dir.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(raw) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let mut argv = raw.split(|b| *b == 0);
        let program = argv.next().unwrap_or_default();
        let name = Path::new(OsStr::from_bytes(program)).file_name();
        if name == Some(OsStr::new(RUNTIME_FILE)) && argv.next() == Some(b"apply".as_slice()) {
            pids.push(pid);
        }
    }
    pids
}

/// Kills a process with SIGKILL through the shell's builtin (no signal crate is a dependency).
pub fn kill9(pid: u32) {
    let status = Command::new("sh")
        .args(["-c", "kill -9 \"$1\"", "sh", &pid.to_string()])
        .status()
        .expect("sh");
    assert!(status.success(), "kill -9 {pid}");
}

impl Lab {
    /// A publisher with generated keys and a signed key set, a feed of the given kind, and an
    /// empty temporary home.
    pub fn new(bins: &Binaries, app: &App, kind: FeedKind) -> Lab {
        Lab::with_options(bins, app, kind, LabOptions::default())
    }

    /// As [`Lab::new`], with the names of `options`.
    pub fn with_options(bins: &Binaries, app: &App, kind: FeedKind, options: LabOptions) -> Lab {
        let tmp = tempfile::Builder::new()
            .prefix(&format!("lunepack-e2e-{}", options.tmp_prefix))
            .tempdir()
            .expect("temporary directory");
        let work = std::fs::canonicalize(tmp.path()).expect("canonical");
        let home = work.join("home");
        let data = home.join(".local/share");
        let release_dir = work.join("release");
        let cfg_dir = work.join("pub");
        for dir in [&home, &release_dir, &cfg_dir] {
            std::fs::create_dir_all(dir).expect("create dir");
        }
        let feed_prefix = options
            .feed_component
            .map(|c| format!("{c}/"))
            .unwrap_or_default();
        let (server, origin, feed) = match kind {
            FeedKind::Http => {
                let origin = FakeOrigin::new();
                let server = LoopbackServer::start(origin.clone()).expect("loopback server");
                let feed = format!("{}/{feed_prefix}", server.base_url());
                (Some(server), Some(origin), feed)
            }
            FeedKind::File => (None, None, format!("file://{}/", release_dir.display())),
        };
        let mut lab = Lab {
            root: data.join(APP_ID),
            out: work.join("outcome.txt"),
            detail: work.join("detail.txt"),
            _tmp: tmp,
            work,
            home,
            data,
            release_dir,
            cfg_dir,
            bins: bins.clone(),
            app: app.clone(),
            feed,
            feed_prefix,
            release_feed: None,
            publisher_check: None,
            kind,
            _server: server,
            origin,
            root_key: [0; 32],
            first: None,
            extra_vars: Vec::new(),
        };
        lab.setup_publisher();
        lab
    }

    pub fn feed_kind(&self) -> FeedKind {
        self.kind
    }

    /// Runs the `lunepack` command line in the publisher's directory; panics unless it succeeds.
    fn cli(&self, args: &[&OsStr]) -> String {
        let mut cmd = Command::new(&self.bins.cli);
        cmd.args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.work.join("cli-home"))
            .current_dir(&self.work)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = run_limited(cmd, COMMAND_LIMIT, "the lunepack command line");
        assert!(
            output.status.success(),
            "lunepack {:?} failed ({}): {}",
            args.first().map(|a| a.to_string_lossy().into_owned()),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn cli_str(&self, args: &[&str]) -> String {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        self.cli(&args)
    }

    fn setup_publisher(&mut self) {
        std::fs::create_dir_all(self.work.join("cli-home")).expect("cli home");
        let mut public = Vec::new();
        for name in ["root", "release"] {
            let key = self.cfg_dir.join(format!("{name}.key"));
            let out = self.cli(&[OsStr::new("keys"), OsStr::new("gen"), key.as_os_str()]);
            let hex = out
                .lines()
                .find_map(|l| l.strip_prefix("public: "))
                .expect("a public line")
                .trim()
                .to_owned();
            public.push(hex);
        }
        let cfg = self.cfg_dir.join("lunepack.toml");
        self.cli_str(&[
            "init",
            "--app-id",
            APP_ID,
            "--root-key",
            &public[0],
            "--config",
            &cfg.to_string_lossy(),
        ]);
        self.root_key = hex_decode(&public[0]);
        // `init` wrote the config and the publisher state file; the full config replaces the
        // first (the state file stays).
        let first = Release::plain("1.0.0");
        self.write_config(&cfg, &first, &public[0]);
        self.first = Some(first);
        let rd = self.release_dir.to_string_lossy().into_owned();
        self.cli_str(&[
            "keys",
            "set",
            "--release-dir",
            &rd,
            "--release-key",
            &public[1],
            "--sign",
            "root",
            "--config",
            &cfg.to_string_lossy(),
        ]);
        self.sync();
    }

    fn root_key_hex(&self) -> String {
        self.root_key.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn write_config(&self, path: &Path, release: &Release, root_hex: &str) {
        let entry = self.entry_rel(release);
        let text = format!(
            "app_id = \"{APP_ID}\"\n\
             \n\
             [root]\n\
             version = 1\n\
             threshold = 1\n\
             keys = [\"{root_hex}\"]\n\
             \n\
             [signers.root]\n\
             file = \"root.key\"\n\
             \n\
             [signers.release]\n\
             file = \"release.key\"\n\
             \n\
             [update]\n\
             feed = \"{feed}\"\n\
             channel = \"{CHANNEL}\"\n\
             health_timeout_secs = {timeout}\n\
             {publisher_check}\
             \n\
             [install]\n\
             entry = \"{entry}\"\n\
             name = \"{APP_NAME}\"\n\
             comment = \"The lunepack end-to-end app\"\n\
             categories = [\"Utility\"]\n\
             bin = \"{BIN}\"\n\
             terminal = false\n",
            feed = self.release_feed.as_deref().unwrap_or(&self.feed),
            timeout = release.health_timeout_secs,
            publisher_check = self
                .publisher_check
                .map(|p| format!("publisher_check = \"{p}\"\n"))
                .unwrap_or_default(),
        );
        std::fs::write(path, text).expect("write config");
    }

    /// The entry's path in a tree of `release`.
    pub fn entry_rel(&self, release: &Release) -> String {
        if release.moved_entry {
            self.app.name.clone()
        } else {
            format!("bin/{}", self.app.name)
        }
    }

    /// Packs `release` with the real command line, adds it to the feed and serves it.
    pub fn publish(&self, release: &Release) {
        self.publish_with(release, false);
    }

    /// As [`Lab::publish`]; with `drop_deltas` the release's `.delta` files are removed from the
    /// release directory after the manifest and the feed were written, so what the signed
    /// manifest lists is not served (the fallback of M12-D5).
    pub fn publish_with(&self, release: &Release, drop_deltas: bool) {
        let input = self.work.join(format!("in-{}", release.version));
        let entry = self.entry_rel(release);
        if self.app.folder {
            // Every file of the folder goes beside the entry, with the mode the publish gave it;
            // only the entry is made executable besides.
            let dir = Path::new(&entry).parent().unwrap_or(Path::new(""));
            copy_tree(&self.app.binary, &input.join(dir));
            let mut mode = std::fs::metadata(input.join(&entry))
                .expect("the folder app holds its entry")
                .permissions();
            mode.set_mode(0o755);
            std::fs::set_permissions(input.join(&entry), mode).expect("make the entry executable");
        } else {
            let bytes = std::fs::read(&self.app.binary).expect("read the app");
            write_file(&input.join(&entry), &bytes, true);
        }
        write_file(
            &input.join("share/version.txt"),
            format!("{}\n", release.version).as_bytes(),
            false,
        );
        if release.blob_bytes > 0 {
            let seed = release.version.bytes().map(u64::from).sum::<u64>();
            write_file(
                &input.join("share/blob.bin"),
                &filler(release.blob_bytes, seed),
                false,
            );
        }
        if release.delta_bytes > 0 {
            write_file(
                &input.join("share/delta.bin"),
                &delta_content(release.delta_bytes, release.delta_tweak),
                false,
            );
        }
        for n in 0..release.small_files {
            write_file(
                &input.join(format!("share/many/f{n:04}.bin")),
                &filler(4096, n as u64 + 1),
                false,
            );
        }
        if !release.flags.is_empty() {
            write_file(
                &input.join("e2e-flags"),
                format!("{}\n", release.flags.join("\n")).as_bytes(),
                false,
            );
        }
        let cfg = self
            .cfg_dir
            .join(format!("release-{}.toml", release.version));
        self.write_config(&cfg, release, &self.root_key_hex());
        let (input_s, rd, cfg_s, runtime) = (
            input.to_string_lossy().into_owned(),
            self.release_dir.to_string_lossy().into_owned(),
            cfg.to_string_lossy().into_owned(),
            self.bins.runtime.to_string_lossy().into_owned(),
        );
        let mut pack = vec![
            "pack",
            "--input",
            &input_s,
            "--version",
            release.version,
            "--target",
            TARGET,
            "--release-dir",
            &rd,
            "--sign",
            "release",
            "--runtime",
            &runtime,
            "--config",
            &cfg_s,
        ];
        let ui = match release.ui {
            Ui::None => None,
            Ui::Fake => Some(self.bins.fake_ui.to_string_lossy().into_owned()),
            Ui::Real => Some(self.bins.real_ui.to_string_lossy().into_owned()),
        };
        if let Some(ui) = &ui {
            pack.extend(["--ui", ui.as_str()]);
        }
        self.cli_str(&pack);
        let base = self
            .cfg_dir
            .join("lunepack.toml")
            .to_string_lossy()
            .into_owned();
        self.cli_str(&[
            "feed",
            "add",
            "--release-dir",
            &rd,
            "--channel",
            CHANNEL,
            "--version",
            release.version,
            "--sign",
            "release",
            "--config",
            &base,
        ]);
        if drop_deltas {
            for entry in std::fs::read_dir(self.release_dir.join(release.version))
                .expect("the release's directory")
            {
                let path = entry.expect("entry").path();
                if path.extension().is_some_and(|e| e == "delta") {
                    std::fs::remove_file(&path).expect("remove a delta file");
                }
            }
        }
        self.sync();
    }

    /// The delta files the release directory holds for `version`, by file name, sorted.
    pub fn delta_files(&self, version: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.release_dir.join(version))
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.ends_with(".delta"))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// Makes the loopback server serve what the release directory holds now (no-op for `file:`).
    fn sync(&self) {
        let Some(origin) = &self.origin else {
            return;
        };
        fn walk(origin: &FakeOrigin, prefix: &str, base: &Path, dir: &Path) {
            for entry in std::fs::read_dir(dir).expect("read dir") {
                let entry = entry.expect("entry");
                let path = entry.path();
                if entry.file_type().expect("file type").is_dir() {
                    walk(origin, prefix, base, &path);
                } else {
                    let rel = path.strip_prefix(base).expect("under base");
                    let url = rel.to_string_lossy().replace('\\', "/");
                    origin.put(
                        &format!("{prefix}{url}"),
                        std::fs::read(&path).expect("read file"),
                    );
                }
            }
        }
        walk(
            origin,
            &self.feed_prefix,
            &self.release_dir,
            &self.release_dir,
        );
    }

    /// The URL requests the loopback server has seen (empty for a `file:` feed).
    pub fn requests(&self) -> Vec<String> {
        self.origin
            .as_ref()
            .map(|o| o.requests().into_iter().map(|r| r.url).collect())
            .unwrap_or_default()
    }

    /// A bootstrap tree of the release the feed offers: the tree the real stage engine builds
    /// (never assembled here), copied out of a scratch install. The scratch install itself
    /// starts from a throwaway seed tree that carries only the update config (M5-D8).
    pub fn bootstrap(&self) -> PathBuf {
        let scratch = self.work.join("scratch");
        let tree = self.facade_install(&scratch.join("seed"), &scratch.join("data"));
        let boot = self.work.join("boot");
        copy_tree(&tree, &boot);
        boot
    }

    /// Installs the release the feed offers into this lab's own data home through the facade (a
    /// fake desktop integration, so no desktop entry or command link): an installed tree and its
    /// record without the runtime's install mode. Returns the installed version's tree.
    pub fn install_in_place(&self) -> PathBuf {
        self.facade_install(&self.work.join("seed"), &self.data)
    }

    /// The seed tree at `seed` (an update config for the feed, a stub entry), then the facade's
    /// install of the newest release into `data`. Returns the installed tree.
    fn facade_install(&self, seed: &Path, data: &Path) -> PathBuf {
        let root = TrustedRoot::from_parts(
            AppId::parse(APP_ID).expect("app id"),
            1,
            1,
            &[self.root_key],
            &Sha256Hasher,
            &Ed25519Verifier,
        )
        .expect("trusted root");
        let name = self.app.name.clone();
        let meta = InstallMeta {
            entry: RelPath::parse(&format!("bin/{name}")).expect("entry"),
            name: APP_NAME.to_owned(),
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
            &root,
            Version::parse("0.0.1").expect("version"),
            TARGET_ID,
            &self.feed,
            Channel::parse(CHANNEL).expect("channel"),
            60,
            meta,
        )
        .expect("seed config")
        .to_bytes()
        .expect("seed config bytes");
        write_file(&seed.join("lunepack-update.json"), &config, false);
        write_file(&seed.join("bin").join(&name), b"seed", true);

        let platform = Platform::native()
            .with_data_home(data.to_path_buf())
            .with_integration(Arc::new(FakeIntegration::new()))
            .with_health_token(None);
        let inst = Installation::from_exe_with(&seed.join("bin").join(&name), platform)
            .expect("seed installation");
        let updater = blocking::Updater::from(
            inst.updater_builder()
                .expect("updater builder")
                .build()
                .expect("updater"),
        );
        let installed = updater
            .install(DownloadOptions::default(), &CancelToken::new())
            .expect("the facade install");
        data.join(APP_ID)
            .join("versions")
            .join(installed.version().to_string())
    }

    /// The published releases name `feed` in their configs from now on, while the seed install
    /// keeps using the loopback feed (so a tree can be installed whose own feed is unreachable).
    pub fn set_release_feed(&mut self, feed: &str) {
        self.release_feed = Some(feed.to_owned());
    }

    /// The published releases carry `[update] publisher_check = "<policy>"` from now on.
    pub fn set_publisher_check(&mut self, policy: &'static str) {
        self.publisher_check = Some(policy);
    }

    /// The loopback origin (an `http:` lab).
    pub fn origin(&self) -> &FakeOrigin {
        self.origin.as_ref().expect("an http lab")
    }

    /// Whether the app under test is a folder of files, not one executable.
    pub fn is_folder_app(&self) -> bool {
        self.app.folder
    }

    /// The app's file name in a tree.
    pub fn app_name(&self) -> &str {
        &self.app.name
    }

    /// A command for `program` with the lab's environment: its own `HOME`, the two outcome files,
    /// no data home override and no health token.
    pub fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .env(OUT_VAR, &self.out)
            .env(DETAIL_VAR, &self.detail)
            .current_dir(&self.work)
            .stdin(Stdio::null());
        for (name, value) in &self.extra_vars {
            cmd.env(name, value);
        }
        cmd
    }

    /// Sets a variable of every command of the lab from now on (replacing an earlier value).
    pub fn set_var(&mut self, name: &str, value: &str) {
        self.unset_var(name);
        self.extra_vars.push((name.to_owned(), value.to_owned()));
    }

    /// Drops a variable set by [`Lab::set_var`].
    pub fn unset_var(&mut self, name: &str) {
        self.extra_vars.retain(|(n, _)| n != name);
    }

    /// Makes the stand-in UI behave as `mode` says (`proceed` or `die`, see `tests/e2e/fake-ui`)
    /// and note its life in the lab's own `ui-notes` directory. `display` sets `DISPLAY` to a
    /// name nothing serves (the stand-in never connects to it), so the runtime wants a UI; without
    /// it neither `DISPLAY` nor `WAYLAND_DISPLAY` is set.
    pub fn fake_ui_env(&mut self, mode: &str, display: bool) {
        let dir = self.work.join("ui-notes");
        std::fs::create_dir_all(&dir).expect("notes directory");
        // Each call starts a scenario: what an earlier one noted is not this one's.
        for name in ["ui-spawns", "ui-hello", "ui-prompts"] {
            let _ = std::fs::remove_file(dir.join(name));
        }
        self.set_var("LUNEPACK_E2E_UI_DIR", &dir.to_string_lossy());
        self.set_var("LUNEPACK_E2E_UI_MODE", mode);
        if display {
            self.set_var("DISPLAY", ":99");
        } else {
            self.unset_var("DISPLAY");
        }
    }

    /// What the stand-in UI noted under `name` since the last call or the last
    /// [`Lab::fake_ui_env`], one string per line (the file starts empty again).
    pub fn ui_notes(&self, name: &str) -> Vec<String> {
        let path = self.work.join("ui-notes").join(name);
        let lines = std::fs::read_to_string(&path)
            .map(|t| t.lines().map(str::to_owned).collect())
            .unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        lines
    }

    /// Builds the Linux setup file of the published `version` with `lunepack setup`, from the
    /// lab's release directory, and returns its path.
    pub fn build_setup(&self, version: &str) -> PathBuf {
        let out = self.work.join(format!("{APP_ID}-{version}-{TARGET}-setup"));
        let (rd, out_s) = (
            self.release_dir.to_string_lossy().into_owned(),
            out.to_string_lossy().into_owned(),
        );
        let cfg = self
            .cfg_dir
            .join("lunepack.toml")
            .to_string_lossy()
            .into_owned();
        self.cli_str(&[
            "setup",
            &rd,
            "--version",
            version,
            "--target",
            TARGET,
            "--out",
            &out_s,
            "--config",
            &cfg,
        ]);
        out
    }

    /// Runs a runtime mode (`install`, `uninstall`) and returns its exit code and stdout.
    pub fn run_runtime(&self, runtime: &Path, mode: &str) -> (i32, String) {
        let mut cmd = self.command(runtime);
        cmd.arg(mode).stdout(Stdio::piped()).stderr(Stdio::piped());
        let output = run_limited(cmd, COMMAND_LIMIT, "the runtime");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    }

    /// Runs `program` with `args` to completion (no more than [`COMMAND_LIMIT`]) and returns what
    /// it printed. `token` is put into `LUNEPACK_HEALTH_TOKEN` of its environment when given.
    pub fn run_cmd(&self, program: &Path, args: &[&str], token: Option<&str>) -> Captured {
        let mut cmd = self.command(program);
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(token) = token {
            cmd.env("LUNEPACK_HEALTH_TOKEN", token);
        }
        let output = run_limited(cmd, COMMAND_LIMIT, "a runtime command");
        Captured {
            code: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        }
    }

    /// Runs an app (a path, usually the command link) with `args` and returns its status. Its
    /// output goes nowhere: the outcome file is the app's channel, and a detached runtime that
    /// inherits a pipe would hold the harness's read open.
    pub fn run_app(&self, program: &Path, args: &[&str]) -> ExitStatus {
        let mut cmd = self.command(program);
        cmd.args(args).stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = cmd.spawn().expect("start the app");
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the app ran past {WAIT:?}");
            }
            std::thread::sleep(POLL);
        }
    }

    /// The command link `~/.local/bin/<bin>`.
    pub fn bin_link(&self) -> PathBuf {
        self.home.join(".local/bin").join(BIN)
    }

    /// The desktop entry.
    pub fn desktop_file(&self) -> PathBuf {
        self.data
            .join("applications")
            .join(format!("{APP_ID}.desktop"))
    }

    /// The outcome lines so far.
    pub fn lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.out)
            .map(|t| t.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    /// The detail lines so far.
    pub fn detail_lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.detail)
            .map(|t| t.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    /// Waits until the outcome file holds exactly `want`, in this order, and returns the lines
    /// (taking them: the file starts empty for the next step).
    pub fn expect_lines(&self, want: &[&str]) -> Vec<String> {
        self.expect(want, false)
    }

    /// As [`Lab::expect_lines`], in any order (two processes race to write): the returned lines
    /// are sorted, so a log compares the same in every run.
    pub fn expect_lines_unordered(&self, want: &[&str]) -> Vec<String> {
        self.expect(want, true)
    }

    fn expect(&self, want: &[&str], unordered: bool) -> Vec<String> {
        let norm = |mut v: Vec<String>| {
            if unordered {
                v.sort();
            }
            v
        };
        let want: Vec<String> = norm(want.iter().map(|s| (*s).to_owned()).collect());
        let deadline = Instant::now() + WAIT;
        loop {
            let got = norm(self.lines());
            if got == want {
                // A late extra line would be a failure; give the writers a moment to show it.
                std::thread::sleep(Duration::from_millis(200));
                let again = norm(self.lines());
                assert_eq!(again, want, "outcome lines changed after matching");
                std::fs::write(&self.out, b"").expect("truncate outcome file");
                return got;
            }
            assert!(
                Instant::now() < deadline,
                "outcome lines differ:\n  want {want:#?}\n  got  {got:#?}"
            );
            std::thread::sleep(POLL);
        }
    }

    /// Waits until no runtime is in `apply` mode.
    pub fn wait_runtime_gone(&self) {
        wait_for("the runtime to finish", || runtime_apply_pids().is_empty());
    }

    /// The install record, when there is one.
    pub fn record(&self) -> Option<RecordView> {
        let loaded = UserScope {
            dir: self.root.join("state"),
            app_id: AppId::parse(APP_ID).expect("app id"),
        }
        .load(&StdFs::new(), &Sha256Hasher)
        .ok()?;
        let r = loaded.record?;
        Some(RecordView {
            current: r.current.map(|c| c.version.to_string()),
            previous: r.previous.map(|p| p.version.to_string()),
            pending: r.pending.map(|p| (p.version.to_string(), p.attempts)),
            staged: r.staged.map(|s| s.version.to_string()),
            bad: r.bad.iter().map(ToString::to_string).collect(),
            events: r.lifecycle.map_or(0, |l| l.events.len()),
        })
    }

    /// The version directories under `R/versions`, sorted.
    pub fn versions(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.root.join("versions"))
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// The target of `R/current`, as written.
    pub fn current_link(&self) -> Option<String> {
        std::fs::read_link(self.root.join("current"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// The target of the command link, as written.
    pub fn bin_target(&self) -> Option<String> {
        std::fs::read_link(self.bin_link())
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// The bytes the desktop entry must have for an entry at `entry` (step 6's golden form).
    pub fn expected_desktop(&self, entry: &str) -> String {
        format!(
            "[Desktop Entry]\nType=Application\nVersion=1.5\nName={APP_NAME}\n\
             Comment=The lunepack end-to-end app\n\
             Exec=\"{root}/current/{entry}\"\nTerminal=false\nCategories=Utility;\n\
             X-Lunepack-App-Id={APP_ID}\n",
            root = self.root.display()
        )
    }

    /// The runtime log's lines (empty before the install has one).
    pub fn runtime_log(&self) -> String {
        std::fs::read_to_string(self.root.join("logs/runtime.log")).unwrap_or_default()
    }

    /// Every file of the runtime's log (`runtime.log`, `runtime.log.1`), by name and bytes.
    pub fn runtime_logs(&self) -> Vec<(String, Vec<u8>)> {
        let mut logs = Vec::new();
        for name in ["runtime.log", "runtime.log.1"] {
            if let Ok(bytes) = std::fs::read(self.root.join("logs").join(name)) {
                logs.push((name.to_owned(), bytes));
            }
        }
        logs
    }

    /// The install id of the record, as the record writes it (hex), when there is a record.
    pub fn install_id_hex(&self) -> Option<String> {
        let loaded = UserScope {
            dir: self.root.join("state"),
            app_id: AppId::parse(APP_ID).expect("app id"),
        }
        .load(&StdFs::new(), &Sha256Hasher)
        .ok()?;
        let record = loaded.record?;
        Some(
            record
                .install_id
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )
    }

    /// What a failure should show: the outcome and the log. Neither holds a secret (the token
    /// is only ever in an environment).
    pub fn diagnostics(&self) -> String {
        format!(
            "outcome file:\n{}\nruntime log:\n{}\nrecord: {:?}\nversions: {:?}\n",
            self.lines().join("\n"),
            self.runtime_log(),
            self.record(),
            self.versions()
        )
    }
}

/// Runs `desktop-file-validate` on `path` when it is installed; `true` when it is not or passes.
pub fn desktop_file_validates(path: &Path) -> bool {
    match Command::new("desktop-file-validate").arg(path).status() {
        Ok(status) => status.success(),
        Err(_) => true,
    }
}

/// Whether `desktop-file-validate` is installed.
pub fn have_desktop_file_validate() -> bool {
    Command::new("desktop-file-validate")
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}
