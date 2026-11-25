//! The macOS rows of the end-to-end suite (M8 step 10): the real `lunepack` command line packs and
//! signs bundle releases, a loopback server serves them, and the installed bundle updates itself
//! through the real runtime: installed from a `.dmg`, swapped, rolled back, adopted out of a
//! `.zip`, uninstalled. `scripts/e2e-macos.sh` builds the binaries, makes the one temporary root
//! (`LUNEPACK_E2E_ROOT`, canonical) and sets `HOME` inside it; every child here runs with an empty
//! environment plus its own `HOME` under that root, and the suite refuses to run when the root is
//! not what the script says it is.
//!
//! A row is a function over a [`World`]: a fresh publisher, feed and temporary home. A row that
//! needs a disk image attaches it under its own directory and detaches it in a drop guard.
//! LaunchServices is used only by row 3b and row 12: the bundles started through `open` are
//! unregistered with `lsregister -u` in a drop guard (the script's trap does it again).

use std::ffi::OsStr;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use lunepack::AppId;
use lunepack_core::state::UserScope;
use lunepack_crypto::Sha256Hasher;
use lunepack_fs::StdFs;
use lunepack_testkit::{FakeOrigin, LoopbackServer, TransportFault};

pub const APP_ID: &str = "org.lunepack.e2e";
const CHANNEL: &str = "stable";
const APP_NAME: &str = "Lunepack E2E";
/// The entry's file name in the bundle (`Contents/MacOS/<ENTRY>`).
const ENTRY: &str = "lunepack-e2e";
/// The .NET example's host in its bundle (the assembly name of `examples/dotnet`).
const DOTNET_ENTRY: &str = "Example";
const OUT_VAR: &str = "LUNEPACK_E2E_OUT";
const DETAIL_VAR: &str = "LUNEPACK_E2E_DETAIL";
const WAIT: Duration = Duration::from_secs(90);
const COMMAND_LIMIT: Duration = Duration::from_secs(300);
const POLL: Duration = Duration::from_millis(50);
/// The framework's top-level link in the bundle input, in the standard form.
const FRAMEWORK_LINK: &str = "Versions/Current/Foo";
const LSREGISTER: &str = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";

#[cfg(target_arch = "aarch64")]
const TARGET: &str = "macos-aarch64";
#[cfg(not(target_arch = "aarch64"))]
const TARGET: &str = "macos-x86_64";

/// The binaries under test.
#[derive(Clone)]
pub struct Bins {
    pub runtime: PathBuf,
    pub cli: PathBuf,
    pub app: PathBuf,
    pub shell_app: PathBuf,
    pub fake_ui: PathBuf,
    /// The .NET example as an app bundle (`scripts/build-example-dotnet.sh --macos-bundle`): the
    /// host alone in `Contents/MacOS`, the rest under `Contents/Resources/app` (M13 step 8). `None`
    /// when its row is skipped by name (`LUNEPACK_E2E_DOTNET=0`).
    pub dotnet_bundle: Option<PathBuf>,
}

/// Who signs a release through the packager's `[codesign.macos]` templates (M9-D2).
#[derive(Clone, Copy)]
pub enum Signer {
    /// `codesign --sign -`: no identity, no key; every Mac can do it.
    AdHoc,
    /// The throwaway identity named by `LUNEPACK_E2E_IDENTITY_A` in the keychain at
    /// `LUNEPACK_E2E_KEYCHAIN` (`--ci` only: `scripts/ci/macos-selfsigned.sh` makes them).
    IdentityA,
    /// The second throwaway identity (`LUNEPACK_E2E_IDENTITY_B`): another publisher.
    IdentityB,
}

impl Signer {
    /// The `[codesign.macos]` table. The `{env:}` values are names and paths, not secrets.
    fn toml(self) -> String {
        let who = match self {
            Signer::AdHoc => "\"-\"",
            Signer::IdentityA => "\"{env:LUNEPACK_E2E_IDENTITY_A}\"",
            Signer::IdentityB => "\"{env:LUNEPACK_E2E_IDENTITY_B}\"",
        };
        let keychain = match self {
            Signer::AdHoc => "",
            _ => ", \"--keychain\", \"{env:LUNEPACK_E2E_KEYCHAIN}\"",
        };
        format!(
            "\n[codesign.macos]\n\
             sign = [\"/usr/bin/codesign\", \"--force\", \"--sign\", {who}{keychain}, \"--timestamp=none\", \"{{path}}\"]\n\
             verify = [\"/usr/bin/codesign\", \"--verify\", \"--deep\", \"--strict\", \"{{path}}\"]\n"
        )
    }
}

/// What one release holds.
#[derive(Clone, Copy)]
pub struct Release {
    pub version: &'static str,
    /// The directives of the `e2e-flags` marker (one per line).
    pub flags: &'static [&'static str],
    pub health_timeout_secs: u64,
    /// Which app the bundle's entry is.
    pub shell: bool,
    /// `[install] autostart`: the install writes a LaunchAgent (M8-D12).
    pub autostart: bool,
    /// Bytes of `Contents/Resources/delta.bin` (0: no file): incompressible filler, the same in
    /// every release but for 16 bytes in the middle that `delta_tweak` sets (M12 step 7).
    pub delta_bytes: usize,
    /// Which 16 bytes `delta.bin` has in the middle (0: the filler as it is).
    pub delta_tweak: u8,
}

impl Release {
    pub const fn plain(version: &'static str) -> Release {
        Release {
            version,
            flags: &[],
            health_timeout_secs: 20,
            shell: false,
            autostart: false,
            delta_bytes: 0,
            delta_tweak: 0,
        }
    }
}

const V1: Release = Release::plain("1.0.0");
const V2: Release = Release::plain("1.1.0");
const V3_CRASH: Release = Release {
    version: "1.2.0",
    flags: &["crash-on-start"],
    health_timeout_secs: 20,
    shell: false,
    autostart: false,
    delta_bytes: 0,
    delta_tweak: 0,
};

/// The size of `Contents/Resources/delta.bin` of the delta rows' releases.
const DELTA_BYTES: usize = 256 << 10;
const D1: Release = Release {
    delta_bytes: DELTA_BYTES,
    ..V1
};
const D2: Release = Release {
    delta_bytes: DELTA_BYTES,
    delta_tweak: 0x5A,
    ..V2
};

pub type RowFn = fn(&Bins) -> Vec<String>;

/// One row: its id, name and body (a panic is its failure).
pub struct Row {
    pub id: &'static str,
    pub name: &'static str,
    pub run: RowFn,
    /// Only with `LUNEPACK_E2E_CI=1`.
    pub ci_only: bool,
}

pub const ROWS: &[Row] = &[
    Row {
        id: "1",
        name: "install 1.0.0 from the .dmg with --silent",
        run: row_install,
        ci_only: false,
    },
    Row {
        id: "2",
        name: "the installer app with the stand-in UI as its main executable; the UI dying changes nothing",
        run: row_installer_app,
        ci_only: false,
    },
    Row {
        id: "3",
        name: "update to 1.1.0 through the library and through the command line",
        run: row_update,
        ci_only: false,
    },
    Row {
        id: "3c",
        name: "update by delta: the changed file arrives as a patch",
        run: row_delta_update,
        ci_only: false,
    },
    Row {
        id: "3d",
        name: "delta fallback: the installed base file changed by one byte",
        run: row_delta_base_changed,
        ci_only: false,
    },
    Row {
        id: "3e",
        name: "delta fallback: the delta file is not served",
        run: row_delta_missing,
        ci_only: false,
    },
    Row {
        id: "4",
        name: "1.2.0 crashes on start: swap back, bad, collected",
        run: row_crash_rolls_back,
        ci_only: false,
    },
    Row {
        id: "5",
        name: "crash states on the real disk heal at the next start",
        run: row_crash_states,
        ci_only: false,
    },
    Row {
        id: "6",
        name: "install, update and rollback on an HFS+ volume (no RENAME_SWAP)",
        run: row_hfs_fallback,
        ci_only: false,
    },
    Row {
        id: "7",
        name: "location refusals: read_only, other_volume, not_writable",
        run: row_location,
        ci_only: false,
    },
    Row {
        id: "8",
        name: "the signed flow: assemble, ad-hoc sign, pack; codesign-clean after every change",
        run: row_signed,
        ci_only: false,
    },
    Row {
        id: "13",
        name: "the packager signs through [codesign.macos] (ad hoc): install, update, verify after the swap",
        run: row_codesign_templates,
        ci_only: false,
    },
    Row {
        id: "13b",
        name: "publisher continuity with an ad-hoc install under enforce: download proceeds, installed_unsigned",
        run: row_continuity_ad_hoc,
        ci_only: false,
    },
    Row {
        id: "14",
        name: "publisher continuity with throwaway identities: same certificate updates, another or an ad-hoc one is refused (exit 29)",
        run: row_continuity_identities,
        ci_only: true,
    },
    Row {
        id: "3b",
        name: "update through apply-and-restart --background; a crashing 1.2.0 rolls back at the deadline",
        run: row_background,
        ci_only: false,
    },
    Row {
        id: "9",
        name: "the shell-script app updates through the command line only",
        run: row_shell_app,
        ci_only: false,
    },
    Row {
        id: "15",
        name: "the .NET example bundle (ad hoc signed by the packager): install, delta update, crash and rollback, the fixed version, uninstall; codesign-clean throughout",
        run: row_dotnet,
        ci_only: false,
    },
    Row {
        id: "10",
        name: "uninstall, foreign items kept, a second cycle clean",
        run: row_uninstall,
        ci_only: false,
    },
    Row {
        id: "10b",
        name: "Trash and reinstall: floors kept; a copy beside a live install is not adopted",
        run: row_trash_and_reinstall,
        ci_only: false,
    },
    Row {
        id: "10c",
        name: "a Finder-style move inside the volume is followed",
        run: row_move,
        ci_only: false,
    },
    Row {
        id: "12",
        name: "the installed bundle launched through LaunchServices writes its marker",
        run: row_open,
        ci_only: true,
    },
    Row {
        id: "11",
        name: "the .zip: adopted by the check, updated, refused when altered, left alone elsewhere, uninstalled",
        run: row_zip,
        ci_only: false,
    },
];

fn write_file(path: &Path, bytes: &[u8], exec: bool) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
    std::fs::write(path, bytes).expect("write file");
    let mode = if exec { 0o755 } else { 0o644 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set mode");
}

/// Copies a directory tree: files with their mode, symlinks as symlinks.
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

/// The bytes of `Contents/Resources/delta.bin` of a release: a deterministic incompressible
/// stream (xorshift), the same for every release, with 16 bytes in the middle XORed with `tweak`.
fn delta_content(len: usize, tweak: u8) -> Vec<u8> {
    let mut x = 0xD17A_u64.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut bytes = Vec::with_capacity(len + 8);
    while bytes.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        bytes.extend_from_slice(&x.to_le_bytes());
    }
    bytes.truncate(len);
    for byte in bytes.iter_mut().skip(len / 2).take(16) {
        *byte ^= tweak;
    }
    bytes
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(POLL);
    }
}

/// Runs `cmd` to completion within `limit`, killing it after; a command that leaves detached
/// children must not have a piped output.
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

/// Pids of the runtime's `apply` processes started from under `under`, from `ps`.
fn apply_pids(under: &Path) -> Vec<u32> {
    let out = Command::new("/bin/ps")
        .args(["-axo", "pid=,args="])
        .output()
        .expect("ps");
    let prefix = under.to_string_lossy().into_owned();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, args) = line.split_once(' ')?;
            let args = args.trim_start();
            (args.starts_with(&prefix) && args.contains("/lunepack-runtime apply"))
                .then(|| pid.parse().ok())
                .flatten()
        })
        .collect()
}

/// A mounted disk image, detached when dropped.
pub struct Mounted {
    pub at: PathBuf,
}

impl Mounted {
    fn attach(image: &Path, at: &Path, extra: &[&str]) -> Mounted {
        std::fs::create_dir_all(at).expect("mount point");
        let mut cmd = Command::new("/usr/bin/hdiutil");
        cmd.args([
            "attach",
            "-nobrowse",
            "-noverify",
            "-noautoopen",
            "-mountpoint",
        ])
        .arg(at)
        .args(extra)
        .arg(image)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        let out = run_limited(cmd, Duration::from_secs(120), "hdiutil attach");
        assert!(
            out.status.success(),
            "hdiutil attach: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Mounted {
            at: at.to_path_buf(),
        }
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        let mut cmd = Command::new("/usr/bin/hdiutil");
        cmd.args(["detach", "-force"])
            .arg(&self.at)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _ = run_limited(cmd, Duration::from_secs(120), "hdiutil detach");
    }
}

/// A bundle started through LaunchServices, unregistered when dropped.
pub struct Registered(PathBuf);

impl Registered {
    pub fn new(app: &Path) -> Registered {
        Registered(app.to_path_buf())
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        if Path::new(LSREGISTER).exists() {
            let mut cmd = Command::new(LSREGISTER);
            cmd.arg("-u")
                .arg(&self.0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let _ = run_limited(cmd, Duration::from_secs(60), "lsregister -u");
        }
    }
}

/// The install record as the rows look at it.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct RecordView {
    pub current: Option<String>,
    pub previous: Option<String>,
    pub pending: Option<(String, u64)>,
    /// The staged version (`download` recorded it; the apply has not run).
    pub staged: Option<String>,
    pub bad: Vec<String>,
    pub events: usize,
}

/// One scenario world: a publisher, a feed and a temporary home, all under the suite's root.
pub struct World {
    /// An image mounted at `home` (row 6); declared first so it detaches before the directory goes.
    _home_mount: Option<Mounted>,
    _tmp: tempfile::TempDir,
    pub work: PathBuf,
    pub home: PathBuf,
    /// `<home>/Applications`.
    pub apps: PathBuf,
    /// The install root `R`.
    pub root: PathBuf,
    pub out: PathBuf,
    pub detail: PathBuf,
    release_dir: PathBuf,
    cfg_dir: PathBuf,
    bins: Bins,
    feed: String,
    _server: LoopbackServer,
    pub origin: FakeOrigin,
    root_key_hex: String,
    extra_vars: Vec<(String, String)>,
    /// Variables of the `lunepack` command line's environment (the signer templates' `{env:}`).
    cli_vars: Vec<(String, String)>,
    /// `HOME` as the children see it, when it differs from `home` (a symlink to it).
    home_env: Option<PathBuf>,
    /// The releases of this world are the .NET example's bundle, not the Rust or shell app's.
    dotnet: bool,
}

/// The suite's root, checked: absolute, canonical, and `HOME` of this process inside it.
fn suite_root() -> PathBuf {
    let root = PathBuf::from(
        std::env::var_os("LUNEPACK_E2E_ROOT").expect("LUNEPACK_E2E_ROOT is set by the script"),
    );
    let canonical = std::fs::canonicalize(&root).expect("the root exists");
    assert_eq!(canonical, root, "the suite's root is not canonical");
    let home = std::env::var_os("HOME").map(PathBuf::from).expect("HOME");
    assert!(
        home.starts_with(root.parent().expect("root parent")),
        "HOME is not under the suite's root: the script did not set it"
    );
    root
}

impl World {
    pub fn new(bins: &Bins) -> World {
        World::build(bins, false)
    }

    /// A world whose `HOME` is a fresh HFS+ volume (no `RENAME_SWAP`).
    pub fn on_hfs(bins: &Bins) -> World {
        World::build(bins, true)
    }

    fn build(bins: &Bins, hfs_home: bool) -> World {
        let tmp = tempfile::Builder::new()
            .prefix("row-")
            .tempdir_in(suite_root())
            .expect("row directory");
        let work = tmp.path().to_path_buf();
        let home = work.join("home");
        let release_dir = work.join("release");
        let cfg_dir = work.join("pub");
        let home_mount = hfs_home.then(|| {
            let image = hfs_image(&work.join("home.dmg"), "e2ehome");
            Mounted::attach(&image, &home, &[])
        });
        for dir in [
            &home,
            &release_dir,
            &cfg_dir,
            &home.join("Library/Application Support"),
        ] {
            std::fs::create_dir_all(dir).expect("create dir");
        }
        let origin = FakeOrigin::new();
        let server = LoopbackServer::start(origin.clone()).expect("loopback server");
        let feed = format!("{}/", server.base_url());
        let mut w = World {
            _home_mount: home_mount,
            root: home.join("Library/Application Support").join(APP_ID),
            apps: home.join("Applications"),
            out: work.join("outcome.txt"),
            detail: work.join("detail.txt"),
            _tmp: tmp,
            work,
            home,
            release_dir,
            cfg_dir,
            bins: bins.clone(),
            feed,
            _server: server,
            origin,
            root_key_hex: String::new(),
            extra_vars: Vec::new(),
            cli_vars: Vec::new(),
            home_env: None,
            dotnet: false,
        };
        w.setup_publisher();
        w
    }

    /// A world whose releases are the .NET example's bundle (M13 step 8).
    pub fn dotnet(bins: &Bins) -> World {
        let mut w = World::build(bins, false);
        w.dotnet = true;
        w
    }

    /// The file name of the entry in `Contents/MacOS`.
    fn entry_name(&self) -> &'static str {
        if self.dotnet { DOTNET_ENTRY } else { ENTRY }
    }

    /// The live bundle `B`.
    pub fn bundle(&self) -> PathBuf {
        self.apps.join(format!("{APP_NAME}.app"))
    }

    pub fn entry(&self) -> PathBuf {
        self.bundle().join("Contents/MacOS").join(self.entry_name())
    }

    pub fn runtime_in(&self, bundle: &Path) -> PathBuf {
        bundle.join("Contents/MacOS/lunepack-runtime")
    }

    fn cli(&self, args: &[&str]) -> String {
        let mut cmd = Command::new(&self.bins.cli);
        cmd.args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.work.join("cli-home"))
            .current_dir(&self.work)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in &self.cli_vars {
            cmd.env(name, value);
        }
        let output = run_limited(cmd, COMMAND_LIMIT, "the lunepack command line");
        assert!(
            output.status.success(),
            "lunepack {:?} failed ({}): {}",
            args.first(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn setup_publisher(&mut self) {
        std::fs::create_dir_all(self.work.join("cli-home")).expect("cli home");
        let mut public = Vec::new();
        for name in ["root", "release"] {
            let key = self.cfg_dir.join(format!("{name}.key"));
            let out = self.cli(&["keys", "gen", &key.to_string_lossy()]);
            let hex = out
                .lines()
                .find_map(|l| l.strip_prefix("public: "))
                .expect("a public line")
                .trim()
                .to_owned();
            public.push(hex);
        }
        let cfg = self.cfg_dir.join("lunepack.toml");
        self.cli(&[
            "init",
            "--app-id",
            APP_ID,
            "--root-key",
            &public[0],
            "--config",
            &cfg.to_string_lossy(),
        ]);
        self.root_key_hex = public[0].clone();
        self.write_config(&cfg, &V1);
        let rd = self.release_dir.to_string_lossy().into_owned();
        self.cli(&[
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

    fn write_config(&self, path: &Path, release: &Release) {
        self.write_config_with(path, release, "");
    }

    /// The config of `release` with `extra` (TOML tables, such as `[codesign.macos]`) appended.
    fn write_config_with(&self, path: &Path, release: &Release, extra: &str) {
        let text = format!(
            "app_id = \"{APP_ID}\"\n\
             \n\
             [root]\n\
             version = 1\n\
             threshold = 1\n\
             keys = [\"{root}\"]\n\
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
             \n\
             [install]\n\
             entry = \"Contents/MacOS/{entry}\"\n\
             name = \"{APP_NAME}\"\n\
             comment = \"The lunepack end-to-end app\"\n\
             autostart = {autostart}\n\
             {extra}",
            root = self.root_key_hex,
            feed = self.feed,
            timeout = release.health_timeout_secs,
            autostart = release.autostart,
            entry = self.entry_name(),
        );
        std::fs::write(path, text).expect("write config");
    }

    /// The bundle input of `release`: an `Info.plist`, the entry (the Rust or the shell app), a
    /// framework with the standard `Versions/` symlinks, an executable helper and a data file.
    pub fn bundle_input(&self, release: &Release) -> PathBuf {
        let input = self.work.join(format!("in-{}", release.version));
        if self.dotnet {
            return self.dotnet_input(release, input);
        }
        let app = if release.shell {
            &self.bins.shell_app
        } else {
            &self.bins.app
        };
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\
             <key>CFBundleExecutable</key><string>{ENTRY}</string>\
             <key>CFBundleIdentifier</key><string>org.lunepack.e2e.app</string>\
             <key>CFBundlePackageType</key><string>APPL</string>\
             <key>CFBundleName</key><string>{APP_NAME}</string>\
             <key>CFBundleShortVersionString</key><string>{}</string>\
             </dict></plist>\n",
            release.version
        );
        write_file(&input.join("Contents/Info.plist"), plist.as_bytes(), false);
        write_file(
            &input.join("Contents/MacOS").join(ENTRY),
            &std::fs::read(app).expect("read the app"),
            true,
        );
        write_file(
            &input.join("Contents/Resources/version.txt"),
            format!("{}\n", release.version).as_bytes(),
            false,
        );
        if release.delta_bytes > 0 {
            write_file(
                &input.join("Contents/Resources/delta.bin"),
                &delta_content(release.delta_bytes, release.delta_tweak),
                false,
            );
        }
        if !release.flags.is_empty() {
            write_file(
                &input.join("Contents/Resources/e2e-flags"),
                format!("{}\n", release.flags.join("\n")).as_bytes(),
                false,
            );
        }
        let fw = input.join("Contents/Frameworks/Foo.framework");
        write_file(&fw.join("Versions/A/Foo"), b"framework binary\n", true);
        symlink("A", fw.join("Versions/Current")).expect("symlink");
        // The standard form: through the link `Versions/Current` (FORMAT 10.2, M8-D20).
        symlink(FRAMEWORK_LINK, fw.join("Foo")).expect("symlink");
        write_file(
            &input.join("Contents/Helpers/tool"),
            b"#!/bin/sh\nexit 0\n",
            true,
        );
        input
    }

    /// The bundle input of `release` for the .NET example (M13 step 8): the bundle the build script
    /// made (the host alone in `Contents/MacOS`, every other file under `Contents/Resources/app`,
    /// an `Info.plist`), and the files the rows read in `Contents/Resources`.
    fn dotnet_input(&self, release: &Release, input: PathBuf) -> PathBuf {
        let bundle = self
            .bins
            .dotnet_bundle
            .as_ref()
            .expect("the .NET bundle is named by the environment");
        copy_tree(bundle, &input);
        write_file(
            &input.join("Contents/Resources/version.txt"),
            format!("{}\n", release.version).as_bytes(),
            false,
        );
        if release.delta_bytes > 0 {
            write_file(
                &input.join("Contents/Resources/delta.bin"),
                &delta_content(release.delta_bytes, release.delta_tweak),
                false,
            );
        }
        if !release.flags.is_empty() {
            write_file(
                &input.join("Contents/Resources/e2e-flags"),
                format!("{}\n", release.flags.join("\n")).as_bytes(),
                false,
            );
        }
        input
    }

    /// Packs `release` with the real command line (the stand-in UI as the helper), adds it to the
    /// feed and serves it.
    pub fn publish(&self, release: &Release) {
        self.publish_with(release, None);
    }

    /// Packs `release` as an unsigned bundle of real Mach-O code and lets the packager sign it
    /// through `signer`'s `[codesign.macos]` templates (M9): no `codesign` call of this harness.
    pub fn publish_codesigned(&self, release: &Release, signer: Signer) {
        self.publish_with(release, Some(signer));
    }

    fn publish_with(&self, release: &Release, signer: Option<Signer>) {
        self.publish_opts(release, signer, false);
    }

    /// Packs `release` (and lets nothing but the `.delta` files out when `drop_deltas`: they are
    /// removed from the release directory after the manifest and the feed were written, so the
    /// signed manifest lists what the server does not have, the fallback of M12-D5).
    fn publish_opts(&self, release: &Release, signer: Option<Signer>, drop_deltas: bool) {
        let input = self.bundle_input(release);
        if signer.is_some() && !self.dotnet {
            // Only code `codesign` can seal: no text framework, no script.
            std::fs::remove_dir_all(input.join("Contents/Frameworks")).expect("no framework");
            std::fs::remove_dir_all(input.join("Contents/Helpers")).expect("no helper tool");
        }
        let cfg = self
            .cfg_dir
            .join(format!("release-{}.toml", release.version));
        self.write_config_with(&cfg, release, &signer.map(Signer::toml).unwrap_or_default());
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let (input_s, rd, cfg_s) = (s(&input), s(&self.release_dir), s(&cfg));
        let (runtime, ui) = (s(&self.bins.runtime), s(&self.bins.fake_ui));
        self.cli(&[
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
            "--ui",
            &ui,
            "--config",
            &cfg_s,
        ]);
        let base = s(&self.cfg_dir.join("lunepack.toml"));
        self.cli(&[
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
    fn delta_files(&self, version: &str) -> Vec<String> {
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

    /// Packs `release` as a code-signed bundle (M8-D8): the plain bundle with real Mach-O files,
    /// `pack --assemble`, ad-hoc signatures from the inside out, then `pack` of the signed tree
    /// with the signed runtime and UI copies.
    pub fn publish_signed(&self, release: &Release) {
        let input = self.bundle_input(release);
        // A bundle that is signed holds only code `codesign` can seal: no text framework, no script.
        std::fs::remove_dir_all(input.join("Contents/Frameworks")).expect("no framework");
        std::fs::remove_dir_all(input.join("Contents/Helpers")).expect("no helper tool");
        let cfg = self
            .cfg_dir
            .join(format!("release-{}.toml", release.version));
        self.write_config(&cfg, release);
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let assembled = self.work.join(format!("assembled-{}", release.version));
        let (input_s, rd, cfg_s, asm) = (s(&input), s(&self.release_dir), s(&cfg), s(&assembled));
        let (runtime, ui) = (s(&self.bins.runtime), s(&self.bins.fake_ui));
        let common = |extra: &[&str]| -> Vec<String> {
            let mut v: Vec<String> = [
                "pack",
                "--input",
                &input_s,
                "--version",
                release.version,
                "--target",
                TARGET,
                "--runtime",
                &runtime,
                "--ui",
                &ui,
                "--config",
                &cfg_s,
            ]
            .iter()
            .map(|x| (*x).to_owned())
            .collect();
            v.extend(extra.iter().map(|x| (*x).to_owned()));
            v
        };
        let args = common(&["--assemble", &asm]);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.cli(&args);
        let helper = assembled.join("Contents/Helpers/lunepack-update.app");
        let signed_runtime = assembled.join("Contents/MacOS/lunepack-runtime");
        let signed_ui = helper.join("Contents/MacOS/lunepack-ui");
        for code in [&signed_runtime, &signed_ui, &helper, &assembled] {
            codesign_adhoc(code);
        }
        let (rt, ui2, asm_in) = (s(&signed_runtime), s(&signed_ui), s(&assembled));
        let mut v: Vec<String> = [
            "pack",
            "--input",
            &asm_in,
            "--version",
            release.version,
            "--target",
            TARGET,
            "--runtime",
            &rt,
            "--ui",
            &ui2,
            "--config",
            &cfg_s,
            "--release-dir",
            &rd,
            "--sign",
            "release",
        ]
        .iter()
        .map(|x| (*x).to_owned())
        .collect();
        v.shrink_to_fit();
        let args: Vec<&str> = v.iter().map(String::as_str).collect();
        self.cli(&args);
        let base = s(&self.cfg_dir.join("lunepack.toml"));
        self.cli(&[
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
        self.sync();
    }

    /// Serves what the release directory holds now.
    fn sync(&self) {
        fn walk(origin: &FakeOrigin, base: &Path, dir: &Path) {
            for entry in std::fs::read_dir(dir).expect("read dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    walk(origin, base, &path);
                } else {
                    let rel = path.strip_prefix(base).expect("under base");
                    origin.put(
                        &rel.to_string_lossy(),
                        std::fs::read(&path).expect("read file"),
                    );
                }
            }
        }
        walk(&self.origin, &self.release_dir, &self.release_dir);
    }

    pub fn requests(&self) -> Vec<String> {
        self.origin.requests().into_iter().map(|r| r.url).collect()
    }

    /// The `.dmg` of the published `version` (`lunepack setup`).
    pub fn build_dmg(&self, version: &str) -> PathBuf {
        self.build_dmg_from(version, &self.cfg_dir.join("lunepack.toml"))
    }

    /// The `.dmg` of `version` built with the release's own config (its `[codesign.macos]` signs
    /// the installer app and the image, M9 step 4).
    pub fn build_dmg_signed(&self, version: &str) -> PathBuf {
        self.build_dmg_from(
            version,
            &self.cfg_dir.join(format!("release-{version}.toml")),
        )
    }

    fn build_dmg_from(&self, version: &str, cfg: &Path) -> PathBuf {
        let out = self.work.join(format!("{APP_ID}-{version}.dmg"));
        let (rd, o) = (
            self.release_dir.to_string_lossy().into_owned(),
            out.to_string_lossy().into_owned(),
        );
        self.cli(&[
            "setup",
            &rd,
            "--version",
            version,
            "--target",
            TARGET,
            "--out",
            &o,
            "--config",
            &cfg.to_string_lossy(),
        ]);
        out
    }

    /// The `.zip` of the published `version`.
    pub fn build_zip(&self, version: &str) -> PathBuf {
        let out = self.work.join(format!("{APP_ID}-{version}.zip"));
        let (rd, o) = (
            self.release_dir.to_string_lossy().into_owned(),
            out.to_string_lossy().into_owned(),
        );
        let cfg = self.cfg_dir.join("lunepack.toml");
        self.cli(&[
            "setup",
            &rd,
            "--version",
            version,
            "--target",
            TARGET,
            "--zip",
            "--out",
            &o,
            "--config",
            &cfg.to_string_lossy(),
        ]);
        out
    }

    /// Extracts `zip` with `ditto -x -k` into `dir` (created).
    pub fn extract_zip(&self, zip: &Path, dir: &Path) {
        std::fs::create_dir_all(dir).expect("extract dir");
        let mut cmd = Command::new("/usr/bin/ditto");
        cmd.args(["-x", "-k"])
            .arg(zip)
            .arg(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let out = run_limited(cmd, Duration::from_secs(120), "ditto");
        assert!(out.status.success(), "ditto -x -k failed");
    }

    /// A command for `program` with the world's environment: an empty one plus its own `HOME`,
    /// the two outcome files and what [`World::set_var`] added.
    pub fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.home_env.as_ref().unwrap_or(&self.home))
            .env(OUT_VAR, &self.out)
            .env(DETAIL_VAR, &self.detail)
            .current_dir(&self.work)
            .stdin(Stdio::null());
        for (name, value) in &self.extra_vars {
            cmd.env(name, value);
        }
        cmd
    }

    /// Gives the children `HOME` through a symlink (the product must canonicalise by itself).
    pub fn home_through_symlink(&mut self) {
        let link = self.work.join("home-link");
        symlink(&self.home, &link).expect("home symlink");
        self.home_env = Some(link);
    }

    pub fn set_var(&mut self, name: &str, value: &str) {
        self.extra_vars.retain(|(n, _)| n != name);
        self.extra_vars.push((name.to_owned(), value.to_owned()));
    }

    /// Sets a variable of the `lunepack` command line's environment (a signer template's
    /// `{env:NAME}`); never a secret: names, paths and identities only.
    pub fn set_cli_var(&mut self, name: &str, value: &str) {
        self.cli_vars.retain(|(n, _)| n != name);
        self.cli_vars.push((name.to_owned(), value.to_owned()));
    }

    /// Runs the installer app's runtime of `dmg` with `--silent` from a read-only mount and
    /// returns its exit code.
    pub fn install_from_dmg(&self, dmg: &Path) -> i32 {
        let mount = Mounted::attach(dmg, &self.work.join("mnt-install"), &["-readonly"]);
        let installer = mount.at.join(format!("Install {APP_NAME}.app"));
        let mut cmd = self.command(self.runtime_in(&installer));
        cmd.arg("--silent")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run_limited(cmd, COMMAND_LIMIT, "the installer runtime");
        out.status.code().unwrap_or(-1)
    }

    /// Runs an app (or any program) with `args`, output to nowhere, and returns its status code.
    pub fn run_app(&self, program: &Path, args: &[&str]) -> i32 {
        let mut cmd = self.command(program);
        cmd.args(args).stdout(Stdio::null()).stderr(Stdio::null());
        let mut child = cmd.spawn().expect("start the app");
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                return status.code().unwrap_or(-1);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the app ran past {WAIT:?}");
            }
            std::thread::sleep(POLL);
        }
    }

    /// Runs the live bundle's runtime with `args`; returns the exit code and stdout.
    pub fn runtime(&self, args: &[&str]) -> (i32, String) {
        let mut cmd = self.command(self.runtime_in(&self.bundle()));
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        let out = run_limited(cmd, COMMAND_LIMIT, "the runtime");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    pub fn lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.out)
            .map(|t| t.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    /// Waits until the outcome file holds exactly `want` (any order when `unordered`), returns
    /// the lines and empties the file for the next step.
    pub fn expect_lines(&self, want: &[String], unordered: bool) -> Vec<String> {
        let norm = |mut v: Vec<String>| {
            if unordered {
                v.sort();
            }
            v
        };
        let want = norm(want.to_vec());
        let deadline = Instant::now() + WAIT;
        loop {
            let got = norm(self.lines());
            if got == want {
                std::thread::sleep(Duration::from_millis(300));
                assert_eq!(
                    norm(self.lines()),
                    want,
                    "outcome lines changed after matching"
                );
                std::fs::write(&self.out, b"").expect("truncate outcome file");
                return got;
            }
            assert!(
                Instant::now() < deadline,
                "outcome lines differ:\n  want {want:#?}\n  got  {got:#?}\n{}",
                self.diagnostics()
            );
            std::thread::sleep(POLL);
        }
    }

    pub fn wait_runtime_gone(&self) {
        let deadline = Instant::now() + WAIT;
        while !apply_pids(&self.work).is_empty() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for the runtime to finish: pids {:?}\n{}",
                apply_pids(&self.work),
                self.diagnostics()
            );
            std::thread::sleep(POLL);
        }
    }

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

    pub fn install_id(&self) -> Option<Vec<u8>> {
        let loaded = UserScope {
            dir: self.root.join("state"),
            app_id: AppId::parse(APP_ID).expect("app id"),
        }
        .load(&StdFs::new(), &Sha256Hasher)
        .ok()?;
        Some(loaded.record?.install_id.to_vec())
    }

    /// The names in `R/versions`, sorted (the slots included).
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

    /// The version the live bundle holds, from its `Contents/Resources/version.txt`.
    pub fn bundle_version(&self) -> Option<String> {
        std::fs::read_to_string(self.bundle().join("Contents/Resources/version.txt"))
            .ok()
            .map(|t| t.trim().to_owned())
    }

    pub fn runtime_log(&self) -> String {
        std::fs::read_to_string(self.root.join("logs/runtime.log")).unwrap_or_default()
    }

    pub fn diagnostics(&self) -> String {
        format!(
            "outcome file:\n{}\nruntime log:\n{}\nrecord: {:?}\nversions: {:?}\n",
            self.lines().join("\n"),
            self.runtime_log(),
            self.record(),
            self.versions()
        )
    }

    /// Checks the layout a first install leaves (row 1): `B`, `R`, the pointer and its identity,
    /// the record and no quarantine attribute anywhere in `B`.
    pub fn assert_installed(&self, version: &str) {
        let b = self.bundle();
        assert!(b.is_dir(), "B is missing");
        assert_eq!(
            std::fs::read_link(self.root.join("bundle")).expect("R/bundle"),
            b,
            "R/bundle points at B"
        );
        assert!(self.root.join("bundle.id").is_file(), "R/bundle.id");
        assert!(self.root.join("state").is_dir(), "R/state");
        assert_eq!(self.bundle_version().as_deref(), Some(version));
        assert_eq!(
            self.record().and_then(|r| r.current).as_deref(),
            Some(version)
        );
        assert_no_quarantine(&b);
    }
}

/// No `com.apple.quarantine` anywhere under `tree` (`xattr -lr`).
pub fn assert_no_quarantine(tree: &Path) {
    let mut cmd = Command::new("/usr/bin/xattr");
    cmd.arg("-lr")
        .arg(tree)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = run_limited(cmd, Duration::from_secs(60), "xattr");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("com.apple.quarantine"),
        "a quarantine attribute under the bundle"
    );
}

/// No extended attribute named like `prefix` anywhere under `tree` (`xattr -lr`).
fn assert_no_xattr_with(tree: &Path, prefix: &str) {
    let mut cmd = Command::new("/usr/bin/xattr");
    cmd.arg("-lr")
        .arg(tree)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = run_limited(cmd, Duration::from_secs(120), "xattr");
    let names: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.rsplit_once(": ").map(|(_, rest)| rest))
        .filter(|rest| rest.starts_with(prefix))
        .map(str::to_owned)
        .collect();
    assert!(
        names.is_empty(),
        "an extended attribute named {prefix}* under the bundle: {} of them",
        names.len()
    );
}

/// The outcome lines of an update from `from` to `to` that the new version confirms.
fn confirmed_update_lines(from: &str, to: &str) -> Vec<String> {
    [
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
    .to_vec()
}

fn first_install_lines() -> Vec<String> {
    [
        "1.0.0 start",
        "1.0.0 event installed",
        "1.0.0 event first_run",
        "1.0.0 nothing-pending",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

// ---- the rows -----------------------------------------------------------------------------------

/// Row 1: the `.dmg`, opened read-only, installs with `--silent`; the entry started directly runs.
fn row_install(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    w.publish(&V1);
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0, "the installer's exit code");
    w.assert_installed("1.0.0");
    // A second run of the installer finds the live install.
    assert_eq!(
        w.install_from_dmg(&dmg),
        23,
        "an installer rerun over a live install"
    );
    // The framework's top-level link passes through `Versions/Current` (M8-D20) and was placed as
    // packed: its text unchanged, and reading through it gives `Versions/A/Foo`'s bytes.
    let fw = w.bundle().join("Contents/Frameworks/Foo.framework");
    assert_eq!(
        std::fs::read_link(fw.join("Foo")).expect("read the framework link"),
        Path::new(FRAMEWORK_LINK),
        "the framework link's text"
    );
    assert_eq!(
        std::fs::read(fw.join("Foo")).expect("read through the framework link"),
        std::fs::read(fw.join("Versions/A/Foo")).expect("read the framework binary"),
        "reading through the framework link"
    );
    let status = w.run_app(&w.entry(), &[]);
    assert_eq!(status, 0, "the entry run directly");
    let lines = w.expect_lines(&first_install_lines(), false);

    // `HOME` given through a symlink: the product canonicalises it by itself (M8-D1), so `R` and
    // `B` are the same canonical paths.
    let mut w2 = World::new(bins);
    w2.publish(&V1);
    let dmg2 = w2.build_dmg("1.0.0");
    w2.home_through_symlink();
    assert_eq!(
        w2.install_from_dmg(&dmg2),
        0,
        "install with HOME through a symlink"
    );
    w2.assert_installed("1.0.0");
    lines
}

/// A started process that is killed and reaped when dropped, so a failed assertion leaves none.
struct Held(std::process::Child);

impl Drop for Held {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The file the executable of process `pid` runs from now, from `lsof` (the system's own path of
/// the running vnode, which follows a rename of a directory above it). Checked once against a
/// known answer by its caller: the path before the swap.
fn exe_path_of(pid: u32) -> PathBuf {
    let mut cmd = Command::new("/usr/sbin/lsof");
    cmd.args(["-p", &pid.to_string(), "-a", "-d", "txt", "-Fn"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let out = run_limited(cmd, Duration::from_secs(60), "lsof");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix('n').map(PathBuf::from))
        .unwrap_or_else(|| panic!("lsof named no executable of pid {pid}"))
}

/// Row 3: the update to 1.1.0 through the library (`--update`), then to 1.2.0 and 1.3.0 while an
/// instance of 1.0.0 keeps running: it runs from `versions/1.0.0` after the first swap, GC keeps
/// that tree while the instance runs, and removes it once the instance has exited (the command
/// line is driven by the shell app in row 9).
fn row_update(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    w.publish(&V1);
    w.publish(&V2);
    // Install the first release only: the feed lists both, so install 1.0.0 from its dmg.
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0);
    w.assert_installed("1.0.0");
    w.run_app(&w.entry(), &[]);
    w.expect_lines(&first_install_lines(), false);

    // An old instance: 1.0.0 started from `B`, kept running across the swaps.
    let mut cmd = w.command(w.entry());
    cmd.args(["--hold", "300"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let old = Held(cmd.spawn().expect("start the old instance"));
    wait_for("the old instance to hold", || {
        w.lines().iter().any(|l| l == "1.0.0 hold")
    });
    w.expect_lines(
        &[
            "1.0.0 start".to_owned(),
            "1.0.0 nothing-pending".to_owned(),
            "1.0.0 hold".to_owned(),
        ],
        false,
    );
    assert_eq!(
        exe_path_of(old.0.id()),
        w.entry(),
        "the instrument names the executable under B before any swap"
    );

    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    let lines = w.expect_lines(&confirmed_update_lines("1.0.0", "1.1.0"), false);
    w.wait_runtime_gone();
    assert_eq!(
        w.bundle_version().as_deref(),
        Some("1.1.0"),
        "B holds 1.1.0"
    );
    assert_eq!(
        w.versions(),
        ["1.0.0"],
        "the kept version only (B holds 1.1.0), no slot"
    );
    let r = w.record().expect("a record");
    assert_eq!(r.current.as_deref(), Some("1.1.0"));
    assert_eq!(r.previous.as_deref(), Some("1.0.0"));
    assert_no_quarantine(&w.bundle());
    assert_eq!(
        exe_path_of(old.0.id()),
        w.root.join("versions/1.0.0/Contents/MacOS").join(ENTRY),
        "the old instance runs from versions/1.0.0 after the swap"
    );

    // 1.2.0: 1.0.0 is now older than the previous version (1.1.0), so GC would remove it, but the
    // old instance still runs from it.
    w.publish(&Release::plain("1.2.0"));
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    w.expect_lines(&confirmed_update_lines("1.1.0", "1.2.0"), false);
    w.wait_runtime_gone();
    assert_eq!(w.bundle_version().as_deref(), Some("1.2.0"));
    assert_eq!(
        w.versions(),
        ["1.0.0", "1.1.0"],
        "GC kept the tree an old instance runs from"
    );
    assert!(
        w.root
            .join("versions/1.0.0/Contents/MacOS")
            .join(ENTRY)
            .is_file(),
        "the old instance's executable is still there"
    );
    assert_eq!(
        exe_path_of(old.0.id()),
        w.root.join("versions/1.0.0/Contents/MacOS").join(ENTRY),
        "the old instance still runs from versions/1.0.0"
    );

    // The old instance exits; the next update's GC removes its tree.
    drop(old);
    w.publish(&Release::plain("1.3.0"));
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    w.expect_lines(&confirmed_update_lines("1.2.0", "1.3.0"), false);
    w.wait_runtime_gone();
    assert_eq!(w.bundle_version().as_deref(), Some("1.3.0"));
    assert_eq!(
        w.versions(),
        ["1.2.0"],
        "GC removed versions/1.0.0 and versions/1.1.0 after the old instance exited"
    );
    lines
}

/// Installs the delta rows' 1.0.0 from its `.dmg`, runs it once and returns the world and the
/// first-install lines.
fn delta_install(bins: &Bins) -> (World, Vec<String>) {
    let w = World::new(bins);
    w.publish(&D1);
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0, "the installer's exit code");
    w.assert_installed("1.0.0");
    w.run_app(&w.entry(), &[]);
    let lines = w.expect_lines(&first_install_lines(), false);
    (w, lines)
}

/// The `source` of every `stage` progress line of the runtime's JSON Lines `stdout` that names
/// `path`. The runtime writes at most ten progress lines a second and a stage phase's last one, so
/// a small file's own line may not be among them: rows use this only as a consistency check
/// (every line that is there names the right source), never to demand a line.
fn file_sources(stdout: &str, path: &str) -> Vec<String> {
    let needle = format!("\"file\":{{\"path\":\"{path}\",");
    let mut sources = Vec::new();
    for line in stdout.lines() {
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

/// The bytes the download fetched: `done` of the last `download`-phase progress line (a phase's
/// last snapshot is always delivered). A patch is a few dozen bytes; the file's frame is its size.
fn download_bytes(stdout: &str) -> u64 {
    let head = "{\"schema\":1,\"type\":\"progress\",\"phase\":\"download\",\"done\":";
    stdout
        .lines()
        .filter_map(|l| l.strip_prefix(head))
        .filter_map(|rest| rest.split(',').next()?.parse::<u64>().ok())
        .next_back()
        .expect("a download progress line")
}

/// Stages 1.1.0 with `download --json` from the live bundle's runtime; returns its stdout (the
/// rows assert on the progress lines of RUNTIME.md schema 1, not on log text).
fn delta_download(w: &World) -> String {
    let (code, stdout) = w.runtime(&["download", "--json"]);
    assert_eq!(code, 0, "download exited {code}");
    assert!(
        last_line(&stdout).contains("\"version\":\"1.1.0\",\"staged\":true"),
        "download stages 1.1.0"
    );
    assert_eq!(
        w.record().and_then(|r| r.staged),
        Some("1.1.0".to_owned()),
        "the record names the staged version"
    );
    stdout
}

/// Applies the staged 1.1.0 through the app, which confirms it, and checks that the bundle now
/// holds the 1.1.0 bytes of `delta.bin`. Returns the outcome lines.
fn delta_apply(w: &World) -> Vec<String> {
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    let lines = w.expect_lines(&confirmed_update_lines("1.0.0", "1.1.0"), false);
    w.wait_runtime_gone();
    assert_eq!(
        w.bundle_version().as_deref(),
        Some("1.1.0"),
        "B holds 1.1.0"
    );
    assert_eq!(
        std::fs::read(w.bundle().join("Contents/Resources/delta.bin")).expect("the new file"),
        delta_content(DELTA_BYTES, D2.delta_tweak),
        "the updated bundle's delta.bin"
    );
    let r = w.record().expect("a record");
    assert_eq!(r.current.as_deref(), Some("1.1.0"));
    assert_eq!(r.previous.as_deref(), Some("1.0.0"));
    assert!(r.bad.is_empty(), "nothing is marked bad");
    assert_no_quarantine(&w.bundle());
    lines
}

const DELTA_PATH: &str = "Contents/Resources/delta.bin";

/// Row 3c: 1.1.0 changes 16 bytes of one file; the packer writes a delta from 1.0.0, `download`
/// fetches that file as a patch, the update applies and confirms.
fn row_delta_update(bins: &Bins) -> Vec<String> {
    let (w, mut lines) = delta_install(bins);
    w.publish(&D2);
    assert_eq!(
        w.delta_files("1.1.0"),
        [format!("{TARGET}.from-1.0.0.delta")],
        "the packer wrote the delta from 1.0.0"
    );
    let before = w.requests().len();
    let stdout = delta_download(&w);
    let fetched = download_bytes(&stdout);
    assert!(
        fetched < DELTA_BYTES as u64 / 4,
        "the download fetched {fetched} bytes: the file's frame, not a patch"
    );
    let sources = file_sources(&stdout, DELTA_PATH);
    assert!(
        sources.iter().all(|s| s == "patch"),
        "delta.bin arrives as a patch: {sources:?}"
    );
    assert!(
        w.requests()[before..]
            .iter()
            .any(|u| u.contains(".from-1.0.0.delta")),
        "the delta file was never requested"
    );
    lines.extend(delta_apply(&w));
    lines
}

/// Row 3d: the installed copy of the base file differs by one byte, so no patch can apply to it:
/// the file arrives as its frame by `range`, the rest of the update is unchanged.
fn row_delta_base_changed(bins: &Bins) -> Vec<String> {
    let (w, mut lines) = delta_install(bins);
    w.publish(&D2);
    let base = w.bundle().join(DELTA_PATH);
    let mut bytes = std::fs::read(&base).expect("the installed base file");
    bytes[100] ^= 1;
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o644))
        .expect("make the base file writable");
    std::fs::write(&base, bytes).expect("change the installed base file");
    let stdout = delta_download(&w);
    let fetched = download_bytes(&stdout);
    assert!(
        fetched >= DELTA_BYTES as u64,
        "the download fetched {fetched} bytes: not the file's frame"
    );
    let sources = file_sources(&stdout, DELTA_PATH);
    assert!(
        sources.iter().all(|s| s == "range"),
        "delta.bin is fetched by range, never as a patch: {sources:?}"
    );
    lines.extend(delta_apply(&w));
    lines
}

/// Row 3e: the signed manifest lists the delta but the server has no such file: the failed patch
/// is not retried, the file arrives as its frame by `range`, and the update completes.
fn row_delta_missing(bins: &Bins) -> Vec<String> {
    let (w, mut lines) = delta_install(bins);
    w.publish_opts(&D2, None, true);
    assert!(
        w.delta_files("1.1.0").is_empty(),
        "the delta file is gone from the release directory"
    );
    let stdout = delta_download(&w);
    let fetched = download_bytes(&stdout);
    assert!(
        fetched >= DELTA_BYTES as u64,
        "the download fetched {fetched} bytes: not the file's frame"
    );
    let sources = file_sources(&stdout, DELTA_PATH);
    assert!(
        sources.iter().all(|s| s == "range"),
        "delta.bin falls back to range: {sources:?}"
    );
    lines.extend(delta_apply(&w));
    lines
}

/// Row 4: 1.2.0 crashes on start; the applier swaps 1.1.0 back and marks 1.2.0 bad.
fn row_crash_rolls_back(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    w.publish(&V1);
    w.publish(&V3_CRASH);
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0);
    w.run_app(&w.entry(), &[]);
    w.expect_lines(&first_install_lines(), false);
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    let want: Vec<String> = [
        "1.0.0 start",
        "1.0.0 nothing-pending",
        "1.0.0 check 1.2.0",
        "1.0.0 staged 1.2.0",
        "1.0.0 apply-scheduled",
        "1.2.0 start",
        "1.2.0 arg after-update",
        "1.2.0 event updated 1.0.0",
        "1.2.0 event first_run",
        "1.2.0 crash",
        "1.0.0 start",
        "1.0.0 arg after-update",
        "1.0.0 nothing-pending",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    let lines = w.expect_lines(&want, false);
    w.wait_runtime_gone();
    assert_eq!(
        w.bundle_version().as_deref(),
        Some("1.0.0"),
        "B holds 1.0.0 again"
    );
    let r = w.record().expect("a record");
    assert_eq!(r.current.as_deref(), Some("1.0.0"));
    assert_eq!(r.bad, ["1.2.0"]);
    // The applier collects after it relaunched the previous version: the bad tree is gone by
    // the time it has ended (the crashed 1.2.0, caught ending, does not hold it: M8-D19 (b)).
    assert!(
        w.versions().is_empty(),
        "the bad tree is collected by the rollback: {:?}",
        w.versions()
    );
    lines
}

/// Row 10: uninstall removes `B` and `R`; a foreign file in the apps folder and a foreign
/// LaunchAgent plist stay; a second install and uninstall cycle is as clean.
fn row_uninstall(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    w.publish(&V1);
    let dmg = w.build_dmg("1.0.0");
    let foreign_dir = w.home.join("Library/LaunchAgents");
    std::fs::create_dir_all(&foreign_dir).expect("LaunchAgents");
    let foreign_plist = foreign_dir.join("org.example.other.plist");
    std::fs::write(&foreign_plist, b"<plist><dict/></plist>\n").expect("foreign plist");
    std::fs::create_dir_all(&w.apps).expect("apps");
    let foreign_file = w.apps.join("notes.txt");
    std::fs::write(&foreign_file, b"mine\n").expect("foreign file");

    for cycle in 1..=2 {
        assert_eq!(w.install_from_dmg(&dmg), 0, "install, cycle {cycle}");
        w.assert_installed("1.0.0");
        let (code, _) = w.runtime(&["uninstall", "--silent"]);
        assert_eq!(code, 0, "uninstall, cycle {cycle}");
        assert!(!w.bundle().exists(), "B is gone");
        assert!(!w.root.exists(), "R is gone");
        assert_eq!(
            std::fs::read(&foreign_plist).unwrap(),
            b"<plist><dict/></plist>\n"
        );
        assert_eq!(std::fs::read(&foreign_file).unwrap(), b"mine\n");
        let left: Vec<String> = std::fs::read_dir(&w.apps)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            left,
            ["notes.txt"],
            "nothing else is left in the apps folder"
        );
    }
    Vec::new()
}

/// A release identical to `base` but with other flags and health timeout.
const fn with(base: Release, flags: &'static [&'static str], health: u64) -> Release {
    Release {
        version: base.version,
        flags,
        health_timeout_secs: health,
        shell: base.shell,
        autostart: base.autostart,
        delta_bytes: base.delta_bytes,
        delta_tweak: base.delta_tweak,
    }
}

/// The last non-empty stdout line.
fn last_line(text: &str) -> String {
    text.lines()
        .rfind(|l| !l.is_empty())
        .unwrap_or_default()
        .to_owned()
}

/// Row 3b: `apply-and-restart --background` (M8-D13): the relaunched app confirms with the token it
/// got through its environment, `ps` never shows the token, and a 1.2.0 that exits non-zero
/// before confirming is rolled back at the health deadline.
fn row_background(bins: &Bins) -> Vec<String> {
    let mut w = World::new(bins);
    w.set_var("LUNEPACK_E2E_NOTE_TOKEN", "1");
    w.publish(&V1);
    w.publish(&with(V2, &["hold 6"], 20));
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0);
    let _registered = Registered::new(&w.bundle());
    w.run_app(&w.entry(), &[]);
    w.expect_lines(&first_install_lines(), false);

    w.run_app(&w.entry(), &["--update", "--no-ui", "--background"]);
    // While 1.1.0 holds, the token is in no argv of any process.
    wait_for("1.1.0 to hold", || {
        w.lines().iter().any(|l| l == "1.1.0 hold")
    });
    let token = std::fs::read_to_string(&w.detail)
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("1.1.0 token ").map(str::to_owned))
        .expect("the relaunched app noted its token");
    assert!(token.len() >= 16, "a token of some length");
    let ps = Command::new("/bin/ps")
        .args(["-axo", "args="])
        .output()
        .expect("ps");
    assert!(
        !String::from_utf8_lossy(&ps.stdout).contains(&token),
        "the token is in an argv"
    );
    let mut want = confirmed_update_lines("1.0.0", "1.1.0");
    want.push("1.1.0 hold".to_owned());
    let mut lines = w.expect_lines(&want, false);
    w.wait_runtime_gone();
    assert_eq!(w.bundle_version().as_deref(), Some("1.1.0"));

    // 1.2.0 exits non-zero before confirming: nobody confirms, so the deadline decides.
    w.publish(&with(V3_CRASH, &["crash-on-start"], 5));
    w.run_app(&w.entry(), &["--update", "--no-ui", "--background"]);
    wait_for("the rollback to 1.1.0", || {
        w.lines()
            .iter()
            .filter(|l| l.starts_with("1.1.0 start"))
            .count()
            >= 2
            && w.record().is_some_and(|r| r.bad == ["1.2.0"])
    });
    w.wait_runtime_gone();
    assert_eq!(w.bundle_version().as_deref(), Some("1.1.0"), "rolled back");
    let log = w.runtime_log();
    // The background launch cannot see the app's exit status (`ExitKind::Unknown`), so the
    // deadline decides: the rollback's reason is `timeout`, not `crashed`.
    assert!(
        log.contains("\"reason\":\"timeout\"") && !log.contains("\"reason\":\"crashed\""),
        "the rollback was decided by the deadline:\n{log}"
    );
    lines.extend(w.lines());
    std::fs::write(&w.out, b"").expect("truncate");
    lines
}

/// Row 9: the shell-script app, the same update over the command line only.
fn row_shell_app(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    let (v1, v2) = (Release { shell: true, ..V1 }, Release { shell: true, ..V2 });
    w.publish(&v1);
    w.publish(&v2);
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0);
    w.assert_installed("1.0.0");
    w.run_app(&w.entry(), &[]);
    w.expect_lines(&first_install_lines(), false);
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    let lines = w.expect_lines(&confirmed_update_lines("1.0.0", "1.1.0"), false);
    w.wait_runtime_gone();
    assert_eq!(w.bundle_version().as_deref(), Some("1.1.0"));
    lines
}

/// Moves the live bundle `from` to `to` with `mv` (a rename on one volume, as Finder does).
fn mv(from: &Path, to: &Path) {
    std::fs::create_dir_all(to.parent().expect("parent")).expect("parent dir");
    std::fs::rename(from, to).expect("rename the bundle");
}

/// Row 10b: the user trashes `B`.
fn row_trash_and_reinstall(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    w.publish(&V1);
    w.publish(&V2);
    let zip = w.build_zip("1.0.0");
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0);
    w.assert_installed("1.0.0");
    let key_before = w.record();
    let id_before = w.install_id();

    // 1. B goes to the Trash; 2. started from there it is not installed.
    let trash = w.home.join(".Trash/Lunepack E2E.app");
    mv(&w.bundle(), &trash);
    let (code, _) = {
        let mut cmd = w.command(w.runtime_in(&trash));
        cmd.args(["check", "--json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run_limited(cmd, COMMAND_LIMIT, "the runtime");
        (out.status.code().unwrap_or(-1), ())
    };
    assert_eq!(code, 3, "a bundle in the Trash is not installed");

    // 3. The installer rerun installs anew into a fresh B, keeping the floors.
    assert_eq!(
        w.install_from_dmg(&dmg),
        0,
        "the installer over an orphaned install"
    );
    w.assert_installed("1.0.0");
    assert_ne!(w.install_id(), id_before, "a new install id");
    assert_eq!(
        w.record().map(|r| r.current),
        key_before.map(|r| r.current),
        "the same version is current again"
    );

    // 4. A .zip extracted to Other.app while the reinstalled app is live: not adopted, no request.
    let requests = w.requests().len();
    let other = w.apps.join("Other.app");
    let tmp = w.work.join("zip-x");
    w.extract_zip(&zip, &tmp);
    mv(&tmp.join("Lunepack E2E.app"), &other);
    let (code, _) = {
        let mut cmd = w.command(w.runtime_in(&other));
        cmd.args(["check", "--json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = run_limited(cmd, COMMAND_LIMIT, "the runtime");
        (out.status.code().unwrap_or(-1), ())
    };
    assert_eq!(code, 3, "a copy beside a live install is not installed");
    assert_eq!(w.requests().len(), requests, "no request was made");

    // 5. B goes to the Trash again: the same copy is now adopted, the floors kept.
    mv(&w.bundle(), &w.home.join(".Trash/Lunepack E2E 2.app"));
    let mut cmd = w.command(w.runtime_in(&other));
    cmd.args(["check", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = run_limited(cmd, COMMAND_LIMIT, "the runtime");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(out.status.code(), Some(0), "the adopting check: {stdout}");
    assert!(
        last_line(&stdout).contains("\"adopted\":true"),
        "adopted: {stdout}"
    );
    assert_eq!(
        std::fs::read_link(w.root.join("bundle")).expect("pointer"),
        other,
        "R/bundle points at the adopted copy"
    );
    Vec::new()
}

/// Row 10c: a move on one volume is followed by the next start, and an update swaps at the new
/// place.
fn row_move(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    w.publish(&V1);
    w.publish(&V2);
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0);
    let moved = w.apps.join("Sub/Lunepack E2E.app");
    mv(&w.bundle(), &moved);
    let entry = moved.join("Contents/MacOS").join(ENTRY);
    // The move is adopted at the next start (the install follows it).
    w.run_app(&entry, &[]);
    w.expect_lines(&first_install_lines(), false);
    assert_eq!(
        std::fs::read_link(w.root.join("bundle")).expect("pointer"),
        moved,
        "R/bundle was re-pointed"
    );
    w.run_app(&entry, &["--update", "--no-ui"]);
    let lines = w.expect_lines(&confirmed_update_lines("1.0.0", "1.1.0"), false);
    w.wait_runtime_gone();
    let version = std::fs::read_to_string(moved.join("Contents/Resources/version.txt"))
        .expect("version at the new place");
    assert_eq!(
        version.trim(),
        "1.1.0",
        "the swap happened at the new place"
    );
    lines
}

/// Row 11: M8-D9 (b): a bundle dragged out of the `.zip` is adopted by the check.
fn row_zip(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    w.publish(&V1);
    w.publish(&V2);
    let zip = w.build_zip("1.0.0");
    // 1. ditto into ~/Applications; the check adopts it and reports the newer release.
    std::fs::create_dir_all(&w.apps).expect("apps");
    w.extract_zip(&zip, &w.apps);
    let (code, stdout) = w.runtime(&["check", "--json"]);
    assert_eq!(code, 0, "the adopting check: {stdout}");
    assert!(
        last_line(&stdout).contains("\"adopted\":true"),
        "adopted: {stdout}"
    );
    assert!(
        last_line(&stdout).contains("\"update\":{\"version\":\"1.1.0\""),
        "the same check reports 1.1.0: {stdout}"
    );
    w.assert_installed("1.0.0");
    // 2. The first start delivers the queued events, then an update swaps it.
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    let mut want = vec![
        "1.0.0 start".to_owned(),
        "1.0.0 event installed".to_owned(),
        "1.0.0 event first_run".to_owned(),
        "1.0.0 nothing-pending".to_owned(),
    ];
    want.extend(confirmed_update_lines("1.0.0", "1.1.0").into_iter().skip(2));
    let lines = w.expect_lines(&want, false);
    w.wait_runtime_gone();
    assert_eq!(w.bundle_version().as_deref(), Some("1.1.0"));

    // 3. A fresh root: a copy with one byte changed in its entry is refused (7), B unchanged.
    let w3 = World::new(bins);
    w3.publish(&V1);
    w3.publish(&V2);
    let zip3 = w3.build_zip("1.0.0");
    std::fs::create_dir_all(&w3.apps).expect("apps");
    w3.extract_zip(&zip3, &w3.apps);
    let entry = w3.entry();
    let mut bytes = std::fs::read(&entry).expect("read the entry");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    std::fs::write(&entry, &bytes).expect("alter the entry");
    let (code, _) = w3.runtime(&["check", "--json"]);
    assert_eq!(code, 7, "one byte changed: verify");
    assert_eq!(
        std::fs::read(&entry).expect("read"),
        bytes,
        "B is unchanged"
    );
    assert_eq!(
        w3.record().and_then(|r| r.current),
        None,
        "no current version"
    );

    // 4. A copy in ~/Desktop is not installed, and no request is made.
    let w4 = World::new(bins);
    w4.publish(&V1);
    let zip4 = w4.build_zip("1.0.0");
    let desktop = w4.home.join("Desktop");
    w4.extract_zip(&zip4, &desktop);
    let before = w4.requests().len();
    let mut cmd = w4.command(w4.runtime_in(&desktop.join("Lunepack E2E.app")));
    cmd.args(["check", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = run_limited(cmd, COMMAND_LIMIT, "the runtime");
    assert_eq!(out.status.code(), Some(3), "a copy on the Desktop");
    assert_eq!(w4.requests().len(), before, "no request was made");

    // 5. The feed unreachable: transport (8) and no current version; reachable: adopted, with
    //    the LaunchAgent of its `autostart` (M8-D12).
    let w5 = World::new(bins);
    w5.publish(&Release {
        autostart: true,
        ..V1
    });
    let zip5 = w5.build_zip("1.0.0");
    std::fs::create_dir_all(&w5.apps).expect("apps");
    w5.extract_zip(&zip5, &w5.apps);
    w5.origin.set_faults(vec![TransportFault::ErrorAfter(0)]);
    let (code, _) = w5.runtime(&["check", "--json"]);
    assert_eq!(code, 8, "the feed is down");
    assert_eq!(
        w5.record().and_then(|r| r.current),
        None,
        "no current version"
    );
    w5.origin.set_faults(Vec::new());
    let (code, stdout) = w5.runtime(&["check", "--json"]);
    assert_eq!(code, 0, "{stdout}");
    assert!(last_line(&stdout).contains("\"adopted\":true"), "{stdout}");
    let agent = w5
        .home
        .join("Library/LaunchAgents")
        .join(format!("{APP_ID}.lunepack.plist"));
    assert!(agent.is_file(), "the adoption wrote the LaunchAgent");
    assert!(
        w5.root.join("versions").is_dir(),
        "R/versions exists, as after any install"
    );

    // 6. Uninstalled right after the adoption, before any update: B, R and the LaunchAgent go.
    let (code, _) = w5.runtime(&["uninstall", "--silent"]);
    assert_eq!(code, 0, "uninstall of a freshly adopted bundle");
    assert!(!w5.bundle().exists(), "B is gone");
    assert!(!w5.root.exists(), "R is gone");
    assert!(!agent.exists(), "the LaunchAgent is gone");
    lines
}

/// A new HFS+ disk image of 40 MB at `path` (`hdiutil create`, argv, bounded).
fn hfs_image(path: &Path, volname: &str) -> PathBuf {
    let mut cmd = Command::new("/usr/bin/hdiutil");
    cmd.args(["create", "-size", "40m", "-fs", "HFS+", "-volname", volname])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let out = run_limited(cmd, Duration::from_secs(120), "hdiutil create");
    assert!(
        out.status.success(),
        "hdiutil create: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    path.to_path_buf()
}

/// Whether `dir` is on a volume that refuses `renamex_np(RENAME_SWAP)`: probed with the system's
/// python3 (ctypes), because the harness has no `unsafe`. `None` when python3 cannot say.
fn volume_refuses_swap(dir: &Path) -> Option<bool> {
    let script = "import ctypes,os,sys\n\
        d=sys.argv[1];a=os.path.join(d,'sa');b=os.path.join(d,'sb');os.mkdir(a);os.mkdir(b)\n\
        libc=ctypes.CDLL(None,use_errno=True)\n\
        r=libc.renamex_np(a.encode(),b.encode(),2)\n\
        e=ctypes.get_errno()\n\
        os.rmdir(a);os.rmdir(b)\n\
        print('swap-ok' if r==0 else 'errno-%d'%e)\n";
    let out = Command::new("/usr/bin/python3")
        .args(["-I", "-c", script])
        .arg(dir)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    match text.trim() {
        "swap-ok" => Some(false),
        // ENOTSUP is 45 on macOS.
        "errno-45" => Some(true),
        _ => None,
    }
}

/// `codesign --verify --deep --strict` of `path`.
fn codesign_verify(path: &Path) -> Result<(), String> {
    let mut cmd = Command::new("/usr/bin/codesign");
    cmd.args(["--verify", "--deep", "--strict"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let out = run_limited(cmd, Duration::from_secs(120), "codesign --verify");
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// Signs `path` ad hoc, in place (no identity, no key).
fn codesign_adhoc(path: &Path) {
    let mut cmd = Command::new("/usr/bin/codesign");
    cmd.args(["--force", "--sign", "-", "--timestamp=none"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let out = run_limited(cmd, Duration::from_secs(120), "codesign");
    assert!(
        out.status.success(),
        "codesign {}: {}",
        path.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Runs the runtime of `bundle` with `args`; the exit code and the last stdout line.
fn runtime_of(w: &World, bundle: &Path, args: &[&str]) -> (i32, String) {
    let mut cmd = w.command(w.runtime_in(bundle));
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    let out = run_limited(cmd, COMMAND_LIMIT, "the runtime");
    (
        out.status.code().unwrap_or(-1),
        last_line(&String::from_utf8_lossy(&out.stdout)),
    )
}

/// Row 2: the installer app's own main executable (the stand-in UI) starts the runtime and drives
/// it; a UI that dies mid-install changes nothing (C10): the runtime finishes the install.
fn row_installer_app(bins: &Bins) -> Vec<String> {
    let mut w = World::new(bins);
    w.publish(&V1);
    let dmg = w.build_dmg("1.0.0");
    let notes = w.work.join("ui-notes");
    std::fs::create_dir_all(&notes).expect("notes");
    w.set_var("LUNEPACK_E2E_UI_DIR", &notes.to_string_lossy());

    let mount = Mounted::attach(&dmg, &w.work.join("mnt"), &["-readonly"]);
    let ui = mount
        .at
        .join(format!("Install {APP_NAME}.app/Contents/MacOS/lunepack-ui"));
    // The UI proceeds at every prompt: a window-driven install.
    w.set_var("LUNEPACK_E2E_UI_MODE", "proceed");
    assert_eq!(w.run_app(&ui, &[]), 0, "the installer app with its UI");
    w.assert_installed("1.0.0");
    let hello = std::fs::read_to_string(notes.join("ui-hello")).unwrap_or_default();
    assert!(hello.contains(APP_NAME), "the UI was told the app's name");
    let prompts = std::fs::read_to_string(notes.join("ui-prompts")).unwrap_or_default();
    assert!(
        prompts.contains("Welcome"),
        "the welcome prompt was shown: {prompts}"
    );
    drop(mount);

    // A second world: the UI aborts at the first progress report; the install still completes.
    let mut w2 = World::new(bins);
    w2.publish(&V1);
    let dmg2 = w2.build_dmg("1.0.0");
    let notes2 = w2.work.join("ui-notes");
    std::fs::create_dir_all(&notes2).expect("notes");
    w2.set_var("LUNEPACK_E2E_UI_DIR", &notes2.to_string_lossy());
    w2.set_var("LUNEPACK_E2E_UI_MODE", "die");
    // A runtime that loses its UI shows one native alert after the outcome (M8-D11, up to 120 s on
    // the screen). This row is about the install, not the alert, so the alert is turned off (the
    // user check of step 12 looks at the alert itself).
    w2.set_var("LUNEPACK_NO_UI", "1");
    let mount2 = Mounted::attach(&dmg2, &w2.work.join("mnt"), &["-readonly"]);
    let ui2 = mount2
        .at
        .join(format!("Install {APP_NAME}.app/Contents/MacOS/lunepack-ui"));
    let _ = w2.run_app(&ui2, &[]);
    wait_for("the headless install to finish", || {
        w2.record().and_then(|r| r.current).is_some() && !installer_runtime_running(&w2.work)
    });
    w2.assert_installed("1.0.0");
    Vec::new()
}

/// Whether a runtime of an installer app under `under` still runs.
fn installer_runtime_running(under: &Path) -> bool {
    let out = Command::new("/bin/ps")
        .args(["-axo", "args="])
        .output()
        .expect("ps");
    let prefix = under.to_string_lossy().into_owned();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.starts_with(&prefix) && l.contains("/lunepack-runtime"))
}

/// Row 5: states a crash can leave, built with plain renames from an updated install, healed by
/// the next start (the live bundle's runtime), or by the installer rerun when `B` is missing; once
/// on the plain tree, once on the code-signed one, which must still verify afterwards.
fn row_crash_states(bins: &Bins) -> Vec<String> {
    let mut report = crash_states(bins, false);
    report.extend(crash_states(bins, true));
    report
}

fn crash_states(bins: &Bins, signed: bool) -> Vec<String> {
    let mut report = Vec::new();
    let variant = if signed { "signed" } else { "plain" };
    for state in [
        "record-ahead",
        "swap-holds-new",
        "swap-holds-old",
        "out-present",
    ] {
        let w = World::new(bins);
        for release in [&V1, &V2] {
            if signed {
                w.publish_signed(release);
            } else {
                w.publish(release);
            }
        }
        let dmg = w.build_dmg("1.0.0");
        assert_eq!(w.install_from_dmg(&dmg), 0);
        w.run_app(&w.entry(), &["--update", "--no-ui"]);
        w.wait_runtime_gone();
        wait_for("the update to confirm", || {
            w.record()
                .is_some_and(|r| r.current.as_deref() == Some("1.1.0") && r.pending.is_none())
        });
        assert_eq!(w.bundle_version().as_deref(), Some("1.1.0"));
        let before = w.record();
        let (b, versions) = (w.bundle(), w.root.join("versions"));
        let (old, swap, out) = (
            versions.join("1.0.0"),
            versions.join(".swap"),
            versions.join(".out"),
        );
        match state {
            // The record names 1.1.0, B still holds 1.0.0, versions/1.1.0 holds 1.1.0.
            "record-ahead" => {
                std::fs::rename(&b, versions.join("1.1.0")).expect("rename");
                std::fs::rename(&old, &b).expect("rename");
            }
            // B holds 1.0.0, the swap slot holds 1.1.0.
            "swap-holds-new" => {
                std::fs::rename(&b, &swap).expect("rename");
                std::fs::rename(&old, &b).expect("rename");
            }
            // B holds 1.1.0, the swap slot holds 1.0.0.
            "swap-holds-old" => {
                std::fs::rename(&old, &swap).expect("rename");
            }
            // The two-rename fallback cut after its first step: B missing, .out holds 1.0.0,
            // .swap holds 1.1.0.
            _ => {
                std::fs::rename(&b, &swap).expect("rename");
                std::fs::rename(&old, &out).expect("rename");
            }
        }
        if state == "out-present" {
            // No bundle to start: the installer rerun finds the install and heals it.
            let code = w.install_from_dmg(&dmg);
            assert!(
                code == 0 || code == 23,
                "{state}: the installer rerun answered {code}"
            );
        } else {
            let (code, line) = w.runtime(&["startup", "--json"]);
            assert_eq!(code, 0, "{state}: startup: {line}");
        }
        assert_eq!(
            w.bundle_version().as_deref(),
            Some("1.1.0"),
            "{state}: B holds the recorded version\n{}",
            w.diagnostics()
        );
        assert_eq!(
            w.record().and_then(|r| r.current),
            before.and_then(|r| r.current),
            "{state}: the record is unchanged"
        );
        assert!(
            !w.root.join("versions/.out").exists(),
            "{state}: no .out is left"
        );
        if signed {
            codesign_verify(&w.bundle())
                .unwrap_or_else(|e| panic!("{state}: codesign --verify --deep --strict B: {e}"));
        }
        report.push(format!(
            "{variant} {state}: healed{}",
            if signed { ", codesign-clean" } else { "" }
        ));
    }
    report
}

/// Row 6: the whole install, update and rollback on an HFS+ volume, which has no `RENAME_SWAP`.
fn row_hfs_fallback(bins: &Bins) -> Vec<String> {
    let w = World::on_hfs(bins);
    let refuses = volume_refuses_swap(&w.home);
    let mut report = Vec::new();
    match refuses {
        Some(true) => {
            report.push("hfs: the volume refuses RENAME_SWAP (ENOTSUP), as expected".to_owned())
        }
        Some(false) => report.push(
            "hfs: NOTE the volume supports RENAME_SWAP: the fallback is not exercised".to_owned(),
        ),
        None => report.push(
            "hfs: NOTE python3 cannot probe RENAME_SWAP: the fallback is not proven".to_owned(),
        ),
    }
    w.publish(&V1);
    w.publish(&V2);
    w.publish(&V3_CRASH);
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0);
    w.assert_installed("1.0.0");
    w.run_app(&w.entry(), &[]);
    w.expect_lines(&first_install_lines(), false);
    // The feed lists 1.2.0 too, which is the newest: it crashes and rolls back, 1.1.0 is skipped.
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    wait_for("the rollback to finish", || {
        w.record().is_some_and(|r| r.bad == ["1.2.0"])
    });
    w.wait_runtime_gone();
    assert_eq!(w.bundle_version().as_deref(), Some("1.0.0"), "rolled back");
    assert_eq!(w.record().and_then(|r| r.current).as_deref(), Some("1.0.0"));
    assert!(!w.root.join("versions/.out").exists());
    report.push("hfs: install, update to a crashing 1.2.0 and rollback end as on APFS".to_owned());
    report
}

/// Row 7: nothing changes when the location is refused.
fn row_location(bins: &Bins) -> Vec<String> {
    let mut report = Vec::new();
    // read_only: a copy of the installed B on a read-only image.
    let w = World::new(bins);
    w.publish(&V1);
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0);
    let record = w.record();
    let src = w.work.join("ro-src");
    std::fs::create_dir_all(&src).expect("src");
    let mut cmd = Command::new("/usr/bin/ditto");
    cmd.arg(w.bundle())
        .arg(src.join(format!("{APP_NAME}.app")))
        .stdin(Stdio::null());
    assert!(
        run_limited(cmd, Duration::from_secs(120), "ditto")
            .status
            .success()
    );
    let image = w.work.join("ro.dmg");
    let mut cmd = Command::new("/usr/bin/hdiutil");
    cmd.args([
        "create",
        "-format",
        "UDRO",
        "-fs",
        "HFS+",
        "-volname",
        "e2ero",
        "-srcfolder",
    ])
    .arg(&src)
    .arg(&image)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    assert!(
        run_limited(cmd, Duration::from_secs(120), "hdiutil create")
            .status
            .success()
    );
    let ro = Mounted::attach(&image, &w.work.join("mnt-ro"), &["-readonly"]);
    let copy = ro.at.join(format!("{APP_NAME}.app"));
    for args in [
        &["check", "--json"][..],
        &["apply-and-restart", "--json"][..],
    ] {
        let (code, line) = runtime_of(&w, &copy, args);
        assert_eq!(code, 28, "{args:?} from a read-only mount: {line}");
        assert!(line.contains("\"reason\":\"read_only\""), "{line}");
    }
    assert_eq!(w.record(), record, "the real install is unchanged");
    report.push("read_only: 28 from the read-only mount".to_owned());
    drop(ro);

    // not_writable: the apps folder loses its write bit.
    // An update is staged first (staging is under R, which stays writable).
    w.publish(&V2);
    let (code, line) = w.runtime(&["download", "--json"]);
    assert_eq!(code, 0, "staging 1.1.0: {line}");
    let record = w.record();
    let apps = w.apps.clone();
    let restore = RestoreMode(
        apps.clone(),
        std::fs::metadata(&apps).expect("meta").permissions().mode(),
    );
    std::fs::set_permissions(&apps, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    // The app stages the update and hands it over (`--no-ui`: a refused location otherwise shows
    // the native "move it" alert on the screen); the applier meets the refusal and ends with the
    // typed failure in its log, changing nothing.
    let _ = w.run_app(&w.entry(), &["--update", "--no-ui"]);
    w.wait_runtime_gone();
    let log = w.runtime_log();
    assert!(
        log.contains("not_writable") && log.contains("\"exit_code\":28"),
        "the applier's refusal is in its log:\n{log}"
    );
    assert_eq!(
        w.bundle_version().as_deref(),
        Some("1.0.0"),
        "B is unchanged"
    );
    assert_eq!(
        w.record().and_then(|r| r.current).as_deref(),
        Some("1.0.0"),
        "the record still names 1.0.0"
    );
    let _ = &record;
    drop(restore);
    report.push("not_writable: 28 with nothing changed".to_owned());

    // other_volume: an HFS+ image mounted at the apps folder before a fresh install.
    let w2 = World::new(bins);
    w2.publish(&V1);
    let dmg2 = w2.build_dmg("1.0.0");
    std::fs::create_dir_all(&w2.apps).expect("apps");
    let image = hfs_image(&w2.work.join("apps.dmg"), "e2eapps");
    let _vol = Mounted::attach(&image, &w2.apps, &[]);
    assert_eq!(
        w2.install_from_dmg(&dmg2),
        28,
        "the apps folder is another volume"
    );
    let left: Vec<String> = std::fs::read_dir(&w2.apps)
        .expect("read apps")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    assert!(
        left.is_empty(),
        "nothing written under the apps folder: {left:?}"
    );
    assert!(
        !w2.root.join("versions").exists(),
        "nothing written under R/versions"
    );
    report.push("other_volume: 28 with nothing written".to_owned());
    report.push(
        "translocated, not_owned: not exercised here (needs a notarized app, and root)".to_owned(),
    );
    report
}

/// Puts a directory's mode back when dropped.
struct RestoreMode(PathBuf, u32);

impl Drop for RestoreMode {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(self.1));
    }
}

/// Row 8: the signed flow of CLI.md and M8-D8, with real Mach-O files.
fn row_signed(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    let mut report = Vec::new();
    let v1 = Release::plain("1.0.0");
    let v2 = Release::plain("1.1.0");
    let v3 = with(V3_CRASH, &["crash-on-start"], 20);
    for r in [&v1, &v2, &v3] {
        w.publish_signed(r);
    }
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0);
    codesign_verify(&w.bundle()).expect("codesign after the install");
    report.push("signed: verify passes after the install".to_owned());
    w.run_app(&w.entry(), &[]);
    w.expect_lines(&first_install_lines(), false);

    // The newest release is the crashing 1.2.0: update, rollback, and 1.0.0 is still signed.
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    wait_for("the rollback", || {
        w.record().is_some_and(|r| r.bad == ["1.2.0"])
    });
    w.wait_runtime_gone();
    assert_eq!(w.bundle_version().as_deref(), Some("1.0.0"));
    codesign_verify(&w.bundle()).expect("codesign after the rollback");
    report.push("signed: verify passes after the rollback".to_owned());
    let _ = std::fs::write(&w.out, b"");

    // A good 1.3.0 is the newest now: update to it and verify.
    w.publish_signed(&Release::plain("1.3.0"));
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    wait_for("the update to 1.3.0", || {
        w.record()
            .is_some_and(|r| r.current.as_deref() == Some("1.3.0") && r.pending.is_none())
    });
    w.wait_runtime_gone();
    assert_eq!(w.bundle_version().as_deref(), Some("1.3.0"));
    codesign_verify(&w.bundle()).expect("codesign after the update");
    report.push("signed: verify passes after the update".to_owned());

    // The instruments of P-M1: recorded, never asserted. Names and verdicts only.
    for (name, program, args) in [
        (
            "spctl",
            "/usr/sbin/spctl",
            vec!["--assess", "--type", "execute"],
        ),
        (
            "syspolicy_check",
            "/usr/bin/syspolicy_check",
            vec!["distribution"],
        ),
    ] {
        if !Path::new(program).exists() {
            report.push(format!("instrument {name}: absent"));
            continue;
        }
        let mut cmd = Command::new(program);
        cmd.args(&args)
            .arg(w.bundle())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status = run_limited(cmd, Duration::from_secs(60), name).status;
        report.push(format!(
            "instrument {name}: exit {}",
            status.code().unwrap_or(-1)
        ));
    }
    assert_no_quarantine(&w.bundle());
    report.push("instrument xattr: no com.apple.quarantine under B".to_owned());
    report
}

/// `codesign --verify --deep --strict` of a plain file (a disk image) or a bundle.
fn assert_verifies(what: &str, path: &Path) {
    if let Err(why) = codesign_verify(path) {
        panic!("{what} does not verify: {why}");
    }
}

/// The instrument check of a verify: a copy of `bundle` whose runtime lost its signature does not
/// verify, so a pass means something.
fn assert_verify_can_fail(w: &World, bundle: &Path) {
    let copy = w
        .work
        .join("verify-control")
        .join(format!("{APP_NAME}.app"));
    std::fs::create_dir_all(copy.parent().expect("parent")).expect("control dir");
    let mut cmd = Command::new("/usr/bin/ditto");
    cmd.arg(bundle)
        .arg(&copy)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let out = run_limited(cmd, Duration::from_secs(120), "ditto");
    assert!(out.status.success(), "ditto of the control copy failed");
    let mut cmd = Command::new("/usr/bin/codesign");
    cmd.args(["--remove-signature"])
        .arg(copy.join("Contents/MacOS/lunepack-runtime"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let out = run_limited(cmd, Duration::from_secs(60), "codesign --remove-signature");
    assert!(out.status.success(), "could not unsign the control copy");
    assert!(
        codesign_verify(&copy).is_err(),
        "the verify passes a bundle whose runtime is unsigned: it cannot tell"
    );
    std::fs::remove_dir_all(w.work.join("verify-control")).expect("remove the control copy");
}

/// Row 13 (M9 step 9): no `codesign` call of the harness: the packager signs 1.0.0 and 1.1.0
/// through ad-hoc `[codesign.macos]` templates (and the installer app and the `.dmg` through the
/// same section), the runtime installs and updates, and the live bundle passes `codesign --verify
/// --deep --strict` after the install and after the swap. The update runs under the default
/// policy `enforce` (the section is there, M9-D6) on an ad-hoc install: no baseline, so it goes
/// through (M9-D9).
fn row_codesign_templates(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    let mut report = Vec::new();
    for release in [&V1, &V2] {
        w.publish_codesigned(release, Signer::AdHoc);
    }
    let dmg = w.build_dmg_signed("1.0.0");
    assert_verifies("the signed .dmg", &dmg);
    report.push("codesign: the .dmg verifies".to_owned());
    {
        let mount = Mounted::attach(&dmg, &w.work.join("mnt-verify"), &["-readonly"]);
        let installer = mount.at.join(format!("Install {APP_NAME}.app"));
        assert_verifies("the installer app in the .dmg", &installer);
        report.push("codesign: the installer app in the .dmg verifies".to_owned());
    }
    assert_eq!(w.install_from_dmg(&dmg), 0, "the installer's exit code");
    w.assert_installed("1.0.0");
    assert_verifies("the installed bundle", &w.bundle());
    assert_verify_can_fail(&w, &w.bundle());
    report.push("codesign: B verifies after the install (the verify can fail)".to_owned());
    assert_eq!(w.run_app(&w.entry(), &[]), 0, "the entry run directly");
    w.expect_lines(&first_install_lines(), false);

    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    w.expect_lines(&confirmed_update_lines("1.0.0", "1.1.0"), false);
    w.wait_runtime_gone();
    assert_eq!(w.bundle_version().as_deref(), Some("1.1.0"));
    assert_verifies("the bundle after the swap", &w.bundle());
    let r = w.record().expect("a record");
    assert_eq!(r.current.as_deref(), Some("1.1.0"));
    assert!(r.bad.is_empty(), "nothing is marked bad");
    report.push("codesign: B verifies after the swap to 1.1.0".to_owned());
    assert_no_quarantine(&w.bundle());
    report
}

/// What the .NET row asks of the live bundle after every install, update and rollback: it passes
/// `codesign --verify --deep --strict`, and no file of it carries a `com.apple.cs.*` attribute
/// (a signature kept in an extended attribute is what a pack cannot carry, M13-D12).
fn assert_sealed(w: &World, what: &str) {
    assert_verifies(&format!("the live bundle {what}"), &w.bundle());
    assert_no_xattr_with(&w.bundle(), "com.apple.cs");
}

/// Row 15 (M13 step 8): the .NET example as an app bundle (the host alone in `Contents/MacOS`,
/// the managed files under `Contents/Resources/app`), signed ad hoc by the packager's own
/// `[codesign.macos]` templates, driving only the runtime's command line. Installed from the
/// `.dmg`; updated by delta (the changed file arrives as a patch, none of the app's own files is
/// fetched again); a version that crashes on start is rolled back and marked bad; the fixed version
/// is taken; the app is uninstalled. The bundle verifies strictly after every step and carries no
/// signature in an extended attribute. The outcome lines are the shell app's for the same steps
/// (`run_all` compares the update to 1.1.0 with row 9's).
fn row_dotnet(bins: &Bins) -> Vec<String> {
    if bins.dotnet_bundle.is_none() {
        // Skipped by name (`LUNEPACK_E2E_DOTNET=0`): the suite said SKIPPED once.
        return Vec::new();
    }
    const CRASH: Release = Release {
        version: "1.2.0",
        flags: &["crash-on-start"],
        ..D2
    };
    const FIXED: Release = Release {
        version: "1.3.0",
        ..D2
    };
    let w = World::dotnet(bins);
    w.publish_codesigned(&D1, Signer::AdHoc);
    let dmg = w.build_dmg_signed("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0, "the installer's exit code");
    w.assert_installed("1.0.0");
    assert_sealed(&w, "after the install");
    assert_eq!(w.run_app(&w.entry(), &[]), 0, "the entry run directly");
    let mut lines = w.expect_lines(&first_install_lines(), false);

    // The delta update: 16 bytes of one file changed.
    w.publish_codesigned(&D2, Signer::AdHoc);
    assert_eq!(
        w.delta_files("1.1.0"),
        [format!("{TARGET}.from-1.0.0.delta")],
        "the packer wrote the delta from 1.0.0"
    );
    let before = w.requests().len();
    let stdout = delta_download(&w);
    // The changed file, the re-signed host and the bundle's seal are fetched; the 189 files of the
    // app are not (they are about 80 MB, 35 MB packed).
    let fetched = download_bytes(&stdout);
    assert!(
        fetched < 4 << 20,
        "the download fetched {fetched} bytes: the app's own files were fetched again"
    );
    let sources = file_sources(&stdout, DELTA_PATH);
    assert!(
        sources.iter().all(|s| s == "patch"),
        "delta.bin arrives as a patch: {sources:?}"
    );
    let mut app_files = 0;
    for line in stdout.lines() {
        if line.starts_with("{\"schema\":1,\"type\":\"progress\",\"phase\":\"stage\"")
            && let Some(rest) = line.split("\"file\":{\"path\":\"").nth(1)
            && let Some((path, rest)) = rest.split_once('"')
            && path.starts_with("Contents/Resources/app/")
            && let Some(source) = rest
                .split("\"source\":\"")
                .nth(1)
                .and_then(|r| r.split('"').next())
        {
            assert_eq!(source, "unchanged", "{path} is not fetched again");
            app_files += 1;
        }
    }
    eprintln!("e2e: row 15: {app_files} stage lines of the app's own files, all unchanged");
    assert!(
        w.requests()[before..]
            .iter()
            .any(|u| u.contains(".from-1.0.0.delta")),
        "the delta file was never requested"
    );
    lines.extend(delta_apply(&w));
    assert_sealed(&w, "after the delta update");

    // 1.2.0 crashes on start: the applier swaps 1.1.0 back and marks 1.2.0 bad.
    w.publish_codesigned(&CRASH, Signer::AdHoc);
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    let want: Vec<String> = [
        "1.1.0 start",
        "1.1.0 nothing-pending",
        "1.1.0 check 1.2.0",
        "1.1.0 staged 1.2.0",
        "1.1.0 apply-scheduled",
        "1.2.0 start",
        "1.2.0 arg after-update",
        "1.2.0 event updated 1.1.0",
        "1.2.0 event first_run",
        "1.2.0 crash",
        "1.1.0 start",
        "1.1.0 arg after-update",
        "1.1.0 nothing-pending",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    lines.extend(w.expect_lines(&want, false));
    w.wait_runtime_gone();
    assert_eq!(
        w.bundle_version().as_deref(),
        Some("1.1.0"),
        "B holds 1.1.0 again"
    );
    let r = w.record().expect("a record");
    assert_eq!(r.current.as_deref(), Some("1.1.0"));
    assert_eq!(r.bad, ["1.2.0"]);
    assert_sealed(&w, "after the rollback");

    // The fixed version.
    w.publish_codesigned(&FIXED, Signer::AdHoc);
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    lines.extend(w.expect_lines(&confirmed_update_lines("1.1.0", "1.3.0"), false));
    w.wait_runtime_gone();
    assert_eq!(
        w.bundle_version().as_deref(),
        Some("1.3.0"),
        "B holds 1.3.0"
    );
    let r = w.record().expect("a record");
    assert_eq!(r.current.as_deref(), Some("1.3.0"));
    assert_eq!(r.bad, ["1.2.0"], "the bad version stays marked");
    assert_sealed(&w, "after the fixed version");
    assert_no_quarantine(&w.bundle());

    // The uninstall.
    let (code, _) = w.runtime(&["uninstall", "--silent"]);
    assert_eq!(code, 0, "uninstall");
    assert!(!w.bundle().exists(), "B is gone");
    assert!(!w.root.exists(), "R is gone");
    lines
}

/// Row 13b: the same ad-hoc install, asked through the runtime's command line: `download` runs the
/// installed tree's policy (`enforce`, the default of a signed pack), the baseline is unsigned, so
/// the update is staged and the result says `publisher: installed_unsigned` (M9-D9); the update
/// goes on to apply.
fn row_continuity_ad_hoc(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    for release in [&V1, &V2] {
        w.publish_codesigned(release, Signer::AdHoc);
    }
    let dmg = w.build_dmg_signed("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0, "the installer's exit code");
    w.assert_installed("1.0.0");
    let config =
        std::fs::read_to_string(w.bundle().join("Contents/Resources/lunepack-update.json"))
            .expect("the installed bundle's update configuration");
    let parsed = lunepack_core::UpdateConfig::parse(config.as_bytes())
        .expect("the installed update configuration parses");
    assert_eq!(
        parsed.publisher_check,
        lunepack_core::PublisherPolicy::Enforce,
        "the signed pack wrote the default policy `enforce`"
    );
    let (code, out) = w.runtime(&["download", "--json"]);
    assert_eq!(code, 0, "download under enforce, installed ad hoc: {out}");
    let line = last_line(&out);
    assert!(
        line.contains("\"version\":\"1.1.0\",\"staged\":true")
            && line.contains("\"publisher\":\"installed_unsigned\""),
        "the result names the finding: {line}"
    );
    let r = w.record().expect("a record");
    assert_eq!(r.staged.as_deref(), Some("1.1.0"), "1.1.0 is staged");
    assert!(r.bad.is_empty(), "nothing is marked bad");
    // The staged update applies (the app finds it staged).
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    wait_for("the update to 1.1.0", || {
        w.record()
            .is_some_and(|r| r.current.as_deref() == Some("1.1.0") && r.pending.is_none())
    });
    w.wait_runtime_gone();
    assert_verifies("the bundle after the swap", &w.bundle());
    vec![
        "continuity: download under enforce on an ad-hoc install reports installed_unsigned"
            .to_owned(),
    ]
}

/// The throwaway identities `scripts/ci/macos-selfsigned.sh` made: the keychain and two names.
/// A missing variable fails the row as INVALID, never as a pass.
fn identity_vars() -> [(&'static str, String); 3] {
    [
        "LUNEPACK_E2E_KEYCHAIN",
        "LUNEPACK_E2E_IDENTITY_A",
        "LUNEPACK_E2E_IDENTITY_B",
    ]
    .map(|name| {
        let value = std::env::var(name)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                panic!(
                    "INVALID: {name} is not set (scripts/e2e-macos.sh --ci makes the identities)"
                )
            });
        (name, value)
    })
}

/// Row 14 (`--ci`): two throwaway self-signed identities in a temporary keychain. Every negative
/// has its positive control in the run: an update signed by the installed certificate must be
/// staged and applied first, else the row is INVALID (the runner refused the identity, or the
/// check cannot tell publishers apart) and fails the job. Then a release signed by the other
/// certificate is refused with exit 29 `different` and marked bad, and an ad-hoc one with
/// `candidate_unsigned`; `check` never offers either again.
fn row_continuity_identities(bins: &Bins) -> Vec<String> {
    let mut w = World::new(bins);
    for (name, value) in identity_vars() {
        w.set_cli_var(name, &value);
    }
    let mut report = Vec::new();
    for release in [&V1, &V2] {
        w.publish_codesigned(release, Signer::IdentityA);
    }
    let dmg = w.build_dmg_signed("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0, "the installer's exit code");
    w.assert_installed("1.0.0");
    assert_verifies("B signed by the throwaway identity", &w.bundle());

    // The control: the same certificate updates.
    let (code, out) = w.runtime(&["download", "--json"]);
    let line = last_line(&out);
    assert!(
        code == 0 && line.contains("\"version\":\"1.1.0\",\"staged\":true"),
        "INVALID: the control failed (same certificate, exit {code}): {line}"
    );
    assert!(
        !line.contains("publisher"),
        "INVALID: the control reports a finding where the certificates are the same: {line}"
    );
    w.run_app(&w.entry(), &["--update", "--no-ui"]);
    wait_for("the control update to 1.1.0", || {
        w.record()
            .is_some_and(|r| r.current.as_deref() == Some("1.1.0") && r.pending.is_none())
    });
    w.wait_runtime_gone();
    assert_verifies("B after the control update", &w.bundle());
    report.push("continuity: same certificate: download and apply proceed".to_owned());

    // Another certificate.
    w.publish_codesigned(&Release::plain("1.2.0"), Signer::IdentityB);
    let (code, out) = w.runtime(&["download", "--json"]);
    let line = last_line(&out);
    assert_eq!(code, 29, "another certificate: {line}");
    assert!(
        line.contains("\"kind\":\"publisher_mismatch\"")
            && line.contains("\"reason\":\"different\""),
        "another certificate: {line}"
    );
    let r = w.record().expect("a record");
    assert_eq!(r.bad, ["1.2.0"], "the refused version is marked bad");
    assert_eq!(r.staged, None, "nothing is staged");
    assert_eq!(w.bundle_version().as_deref(), Some("1.1.0"));
    let (code, out) = w.runtime(&["download", "--json"]);
    assert_eq!(code, 0, "a bad version is not offered again: {out}");
    assert!(
        last_line(&out).contains("\"version\":null,\"staged\":false"),
        "nothing new: {out}"
    );
    report.push(
        "continuity: another certificate: exit 29 different, marked bad, not offered again"
            .to_owned(),
    );

    // An ad-hoc candidate.
    w.publish_codesigned(&Release::plain("1.3.0"), Signer::AdHoc);
    let (code, out) = w.runtime(&["download", "--json"]);
    let line = last_line(&out);
    assert_eq!(code, 29, "an ad-hoc candidate: {line}");
    assert!(
        line.contains("\"reason\":\"candidate_unsigned\""),
        "an ad-hoc candidate: {line}"
    );
    let r = w.record().expect("a record");
    assert_eq!(r.bad, ["1.2.0", "1.3.0"], "both refusals are marked bad");
    assert_eq!(r.staged, None, "nothing is staged");
    assert_eq!(w.bundle_version().as_deref(), Some("1.1.0"));
    assert_verifies("B after the refusals", &w.bundle());
    report.push("continuity: ad-hoc candidate: exit 29 candidate_unsigned, marked bad".to_owned());
    report
}

/// Row 12 (`--ci`): the installed bundle started through LaunchServices as a user would.
fn row_open(bins: &Bins) -> Vec<String> {
    let w = World::new(bins);
    w.publish(&V1);
    let dmg = w.build_dmg("1.0.0");
    assert_eq!(w.install_from_dmg(&dmg), 0);
    let _registered = Registered::new(&w.bundle());
    let mut cmd = w.command("/usr/bin/open");
    cmd.args(["-n", "-g", "-W"])
        .arg(w.bundle())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let out = run_limited(cmd, Duration::from_secs(120), "open");
    assert!(out.status.success(), "open exited {:?}", out.status.code());
    w.expect_lines(&first_install_lines(), false)
}

/// Runs the rows, printing one line each; returns the failures' names.
pub fn run_all(bins: &Bins, ci: bool) -> Result<Vec<String>, String> {
    let _ = suite_root();
    let mut log = Vec::new();
    let mut by_row: Vec<(&str, Vec<String>)> = Vec::new();
    for row in ROWS {
        if row.ci_only && !ci {
            eprintln!("e2e: row {} skipped (needs --ci): {}", row.id, row.name);
            continue;
        }
        eprintln!("e2e: row {}: {}", row.id, row.name);
        let run = row.run;
        let b = bins.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || run(&b)));
        match result {
            Ok(lines) => {
                log.push(format!("row {} ok", row.id));
                log.extend(lines.iter().map(|l| format!("  {l}")));
                by_row.push((row.id, lines));
            }
            Err(panic) => {
                let why = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                    .unwrap_or_else(|| "a panic".to_owned());
                return Err(format!("row {} ({}): {why}", row.id, row.name));
            }
        }
    }
    // The .NET app's outcome lines for the steps the shell app (row 9) also ran, the update from
    // 1.0.0 to 1.1.0 after the first install's lines, must be the same.
    let lines_of = |id: &str| by_row.iter().find(|(i, _)| *i == id).map(|(_, l)| l);
    if let (Some(shell), Some(dotnet)) = (lines_of("9"), lines_of("15"))
        && !dotnet.is_empty()
    {
        let from = first_install_lines().len();
        let got = dotnet.get(from..from + shell.len()).unwrap_or_default();
        if got != shell.as_slice() {
            let at = shell
                .iter()
                .zip(got)
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| shell.len().min(got.len()));
            return Err(format!(
                "the .NET app's outcome lines differ from the shell app's at line {at}: {:?} against {:?}",
                got.get(at),
                shell.get(at)
            ));
        }
    }
    Ok(log)
}
