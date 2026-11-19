//! What the runtime's integration tests (`apply`, `cli`) share: the layout scheme of the OS the
//! test runs on, a temporary home, where a tree keeps its entry, its runtime and its config, how a
//! live version is projected, where a version's tree is after a swap, and the process facts that
//! differ per OS. One arm per scheme (Linux `XDG`, Windows `WINDOWS`, macOS `MACOS`), chosen by
//! `cfg`; the test files hold no scheme `cfg` of their own except for a mechanism one OS lacks.
//!
//! Fixture state comes from the core's own writers (M8-D18): the bundle pointer and its identity
//! through `set_bundle_pointer` and `write_bundle_identity`, records through the state store. No
//! test writes `R/bundle`, `R/bundle.id`, `R/current` or a record by hand.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use lunepack::{Target, UpdateConfig};
use lunepack_core::{
    LayoutScheme, Projection, UserLayout, set_bundle_pointer, write_bundle_identity,
};
use lunepack_fs::StdFs;

/// The layout scheme of this OS (what the runtime's platform picks).
#[cfg(windows)]
pub const SCHEME: LayoutScheme = LayoutScheme::WINDOWS;
#[cfg(target_os = "macos")]
pub const SCHEME: LayoutScheme = LayoutScheme::MACOS;
#[cfg(not(any(windows, target_os = "macos")))]
pub const SCHEME: LayoutScheme = LayoutScheme::XDG;

/// The OS's name as the skip lines print it.
#[cfg(windows)]
pub const OS_NAME: &str = "Windows";
#[cfg(target_os = "macos")]
pub const OS_NAME: &str = "macOS";
#[cfg(not(any(windows, target_os = "macos")))]
pub const OS_NAME: &str = "Linux";

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub const TARGET: Target = Target::LinuxAarch64;
#[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
pub const TARGET: Target = Target::LinuxX86_64;
#[cfg(all(windows, target_arch = "aarch64"))]
pub const TARGET: Target = Target::WindowsAarch64;
#[cfg(all(windows, not(target_arch = "aarch64")))]
pub const TARGET: Target = Target::WindowsX86_64;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const TARGET: Target = Target::MacosAarch64;
#[cfg(all(target_os = "macos", not(target_arch = "aarch64")))]
pub const TARGET: Target = Target::MacosX86_64;

/// The built runtime.
pub const RUNTIME: &str = env!("CARGO_BIN_EXE_lunepack-runtime");

// ---- where a tree keeps its files -------------------------------------------------------------

/// The runtime's file name.
#[cfg(windows)]
pub const RUNTIME_FILE: &str = "lunepack-runtime.exe";
#[cfg(not(windows))]
pub const RUNTIME_FILE: &str = "lunepack-runtime";

/// The directory of the entry, relative to a tree; the runtime stands beside the entry.
#[cfg(target_os = "macos")]
pub const ENTRY_DIR: &str = "Contents/MacOS";
#[cfg(not(target_os = "macos"))]
pub const ENTRY_DIR: &str = "bin";

/// The entry as the update config names it (no `.exe`: [`exe`] adds that).
#[cfg(target_os = "macos")]
pub const ENTRY: &str = "Contents/MacOS/app";
#[cfg(not(target_os = "macos"))]
pub const ENTRY: &str = "bin/app";

/// An entry in another directory than [`ENTRY`]'s (the entry directory may change between
/// versions).
#[cfg(target_os = "macos")]
pub const OTHER_ENTRY: &str = "Contents/MacOS/other/app";
#[cfg(not(target_os = "macos"))]
pub const OTHER_ENTRY: &str = "app";

/// The entry's path in a release (`.exe` on Windows).
#[cfg(windows)]
pub const APP_PATH: &str = "bin/app.exe";
#[cfg(target_os = "macos")]
pub const APP_PATH: &str = "Contents/MacOS/app";
#[cfg(not(any(windows, target_os = "macos")))]
pub const APP_PATH: &str = "bin/app";

/// The runtime's path in a release.
#[cfg(windows)]
pub const RUNTIME_PATH: &str = "bin/lunepack-runtime.exe";
#[cfg(target_os = "macos")]
pub const RUNTIME_PATH: &str = "Contents/MacOS/lunepack-runtime";
#[cfg(not(any(windows, target_os = "macos")))]
pub const RUNTIME_PATH: &str = "bin/lunepack-runtime";

/// A plain data file's path in a release.
#[cfg(target_os = "macos")]
pub const README_PATH: &str = "Contents/Resources/readme.txt";
#[cfg(not(target_os = "macos"))]
pub const README_PATH: &str = "share/readme.txt";

/// The update config's path in a tree (`Contents/Resources/lunepack-update.json` on macOS).
pub const CONFIG_PATH: &str = SCHEME.config;

/// An entry path as this OS names an executable (`bin/app` is `bin/app.exe` on Windows).
pub fn exe(entry: &str) -> String {
    if cfg!(windows) {
        format!("{entry}.exe")
    } else {
        entry.to_owned()
    }
}

/// `base` joined with each `/`-separated name of `rel` (a path built to be compared with one an app
/// reports for itself: on Windows a `/` inside a joined name would stay a `/`).
pub fn join_rel(base: &Path, rel: &str) -> PathBuf {
    rel.split('/')
        .fold(base.to_path_buf(), |path, name| path.join(name))
}

/// The config file of the tree at `tree`.
pub fn config_in(tree: &Path) -> PathBuf {
    join_rel(tree, CONFIG_PATH)
}

/// Writes the update config `bytes` into the tree at `tree`.
pub fn write_config(tree: &Path, bytes: &[u8]) {
    let path = config_in(tree);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("config dir");
    std::fs::write(path, bytes).expect("config");
}

/// The version the tree at `tree` names in its config; `None` when there is no readable config.
pub fn version_in(tree: &Path) -> Option<String> {
    let bytes = std::fs::read(config_in(tree)).ok()?;
    Some(UpdateConfig::parse(&bytes).ok()?.version.to_string())
}

/// Places `from` at `to`: a hard link when possible, else a copy. On macOS always a copy: the
/// kernel names a hard-linked executable by whichever of its paths it looked up last, so a
/// process running from one tree can be reported under another and the in-use scan that GC runs
/// answers for the wrong tree (the same executable did that: `proc_pidpath` of `b/app` returned
/// `c/app` after `a/app`, `b/app`, `c/app` were each run in turn).
pub fn place(from: &Path, to: &Path) {
    std::fs::create_dir_all(to.parent().expect("parent")).expect("dirs");
    // Never copy over an existing link: that would write into the linked binary.
    assert!(std::fs::symlink_metadata(to).is_err(), "already placed");
    if cfg!(target_os = "macos") || std::fs::hard_link(from, to).is_err() {
        std::fs::copy(from, to).expect("copy");
    }
}

/// This test binary as the entry `entry` of the tree at `dir` (the entry as the config names
/// it, `.exe` included on Windows), and the built runtime beside it.
pub fn place_app(dir: &Path, entry: &str) {
    let entry_path = dir.join(entry);
    place(&std::env::current_exe().expect("exe"), &entry_path);
    place(
        Path::new(RUNTIME),
        &entry_path.parent().expect("dir").join(RUNTIME_FILE),
    );
}

// ---- the temporary home -----------------------------------------------------------------------

/// A case's temporary home, canonical (macOS: `/var` is `/private/var`; Windows: no `\\?\`).
pub struct Home {
    /// Removes the directory when dropped.
    pub tmp: tempfile::TempDir,
    pub base: PathBuf,
    pub home: PathBuf,
    /// The data home: `home/.local/share` (Linux, and Windows for `apply`),
    /// `home/Library/Application Support` (macOS).
    pub data: PathBuf,
    /// `R`: the data home / the app id, as `HOME`-relative data homes make it; on Windows
    /// `windows_root` names it under `home/Programs` when given.
    pub root: PathBuf,
}

/// `path` without Windows' `\\?\` prefix (a canonical path there), so it equals the path an app
/// reports for itself.
pub fn plain(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy().into_owned();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path,
    }
}

/// A new temporary directory named `prefix…` and its canonical path (macOS: `/var` is
/// `/private/var`; Windows: no `\\?\`).
///
/// It is under the target directory (the binaries can be hard-linked from there), except on
/// macOS: a Docker Desktop bind mount of the working tree makes its VM process, which runs as the
/// user, hold a descriptor on every file the container has looked at under the tree, and the
/// in-use scan (GC, uninstall) rightly counts that process as using a tree of ours. The system's
/// temporary directory is not shared.
pub fn scratch(prefix: &str) -> (tempfile::TempDir, PathBuf) {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);
    #[cfg(target_os = "macos")]
    let tmp = builder.tempdir().expect("tmp");
    #[cfg(not(target_os = "macos"))]
    let tmp = builder
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("tmp");
    let base = plain(std::fs::canonicalize(tmp.path()).expect("canonical"));
    (tmp, base)
}

impl Home {
    /// A new home under a temporary directory named `prefix…`. `app_id` names `R` in the data
    /// home; `windows_root` (when given) names it `home/Programs/<name>` on Windows instead.
    /// `create_root` makes `R` itself (Linux and Windows `apply` start from an existing one; the
    /// runtime's `install` makes its own). On macOS `home/Applications` exists, as a user's does.
    /// The directory is [`scratch`]'s.
    pub fn new(prefix: &str, app_id: &str, windows_root: Option<&str>, create_root: bool) -> Home {
        let (tmp, base) = scratch(prefix);
        let home = base.join("home");
        let data = join_rel(
            &home,
            if cfg!(target_os = "macos") {
                "Library/Application Support"
            } else {
                ".local/share"
            },
        );
        let root = match windows_root {
            Some(name) if cfg!(windows) => home.join("Programs").join(name),
            _ => data.join(app_id),
        };
        std::fs::create_dir_all(&home).expect("home");
        if cfg!(target_os = "macos") {
            for dir in [home.join("Applications"), data.clone()] {
                std::fs::create_dir_all(dir).expect("dirs");
            }
        } else if create_root {
            std::fs::create_dir_all(&data).expect("data");
        }
        if create_root {
            std::fs::create_dir_all(&root).expect("root");
        }
        Home {
            tmp,
            base,
            home,
            data,
            root,
        }
    }

    /// The layout of `R` under this OS's scheme.
    pub fn layout(&self) -> UserLayout {
        UserLayout::from_root(self.root.clone(), SCHEME)
    }

    /// Where the bundle `name` goes when no pointer names one yet (macOS).
    pub fn bundle_default(&self, name: &str) -> PathBuf {
        self.home.join("Applications").join(format!("{name}.app"))
    }
}

/// Keeps a spawned runtime or app from putting up a window or a notice on a developer's screen
/// (macOS; the other OSes show none without a display or a UI beside the runtime).
pub fn quiet_ui(cmd: &mut std::process::Command) {
    if cfg!(target_os = "macos") {
        cmd.env("LUNEPACK_NO_UI", "1");
    }
}

// ---- projecting and finding the live version --------------------------------------------------

/// Makes `current` the live version the way the installed layout shows it, for a fixture whose
/// version trees all stand in `versions/<v>` (as the other OSes keep them):
///
/// - `CurrentLink`: nothing; `R/current` is the runtime's to make at its first reconcile;
/// - `None`: nothing; the record alone names the live version;
/// - `Bundle`: the tree of `current` is moved to the live bundle `B` (`R/bundle`'s target when a
///   pointer exists, else `default_bundle`), the version `B` held until now is parked in
///   `versions/<its version>`, then the pointer and the identity are written by the core's
///   writers.
pub fn project(layout: &UserLayout, default_bundle: &Path, current: &str) {
    if layout.scheme().projection != Projection::Bundle {
        return;
    }
    let fs = StdFs::new();
    let bundle = layout
        .bundle_path(&fs)
        .expect("pointer")
        .unwrap_or_else(|| default_bundle.to_path_buf());
    let dir = layout.versions_dir().join(current);
    if version_in(&bundle).as_deref() != Some(current) {
        if let Some(held) = version_in(&bundle) {
            std::fs::rename(&bundle, layout.versions_dir().join(held)).expect("park");
        }
        std::fs::rename(&dir, &bundle).expect("place the bundle");
    }
    set_bundle_pointer(&fs, layout, &bundle).expect("pointer");
    write_bundle_identity(&fs, layout, &bundle).expect("identity");
}

/// The live bundle `B`, from `R/bundle`.
pub fn bundle_of(layout: &UserLayout) -> PathBuf {
    layout
        .bundle_path(&StdFs::new())
        .expect("pointer")
        .expect("R/bundle exists")
}

/// The live tree: `R/current` (Linux), `versions/<current>` (Windows) or `B` (macOS).
pub fn live_tree(layout: &UserLayout, current: &str) -> PathBuf {
    match layout.scheme().projection {
        Projection::CurrentLink => layout.current_link().expect("current link"),
        Projection::None => layout.versions_dir().join(current),
        Projection::Bundle => bundle_of(layout),
    }
}

/// Where the tree holding `v` is now: `B` when it holds `v` (macOS), else `versions/<v>`.
pub fn tree_of(layout: &UserLayout, v: &str) -> PathBuf {
    if layout.scheme().projection == Projection::Bundle
        && let Ok(Some(bundle)) = layout.bundle_path(&StdFs::new())
        && version_in(&bundle).as_deref() == Some(v)
    {
        return bundle;
    }
    layout.versions_dir().join(v)
}

/// The tree an app of version `v` is started from: `B` on macOS (the new version runs in the
/// bundle), `versions/<v>` elsewhere.
pub fn run_tree(layout: &UserLayout, v: &str) -> PathBuf {
    match layout.scheme().projection {
        Projection::Bundle => bundle_of(layout),
        Projection::CurrentLink | Projection::None => layout.versions_dir().join(v),
    }
}

/// The live version is `v`: `R/current` names `versions/<v>` (Linux), `R/current` does not exist
/// and no swap slot is left (macOS), and the live tree's own config names `v`.
pub fn assert_live(layout: &UserLayout, v: &str) {
    let tree = live_tree(layout, v);
    match layout.scheme().projection {
        Projection::CurrentLink => {
            let link = std::fs::read_link(layout.root().join("current")).expect("current");
            assert_eq!(link, Path::new("versions").join(v));
        }
        Projection::None => {}
        Projection::Bundle => {
            assert!(
                std::fs::symlink_metadata(layout.root().join("current")).is_err(),
                "R/current exists in a bundle layout"
            );
            let pointer = std::fs::read_link(layout.bundle_link().expect("pointer path"))
                .expect("R/bundle is a link");
            assert_eq!(pointer, tree, "the pointer names another bundle");
            for slot in [layout.swap_slot(), layout.out_slot()] {
                assert!(std::fs::symlink_metadata(slot).is_err(), "a slot is left");
            }
        }
    }
    assert_eq!(
        version_in(&tree).as_deref(),
        Some(v),
        "the live tree does not hold {v}"
    );
}

/// `versions/<v>` holds the tree of `v`.
pub fn assert_parked(layout: &UserLayout, v: &str) {
    assert_eq!(
        version_in(&layout.versions_dir().join(v)).as_deref(),
        Some(v),
        "versions/{v} does not hold {v}"
    );
}

// ---- process facts ----------------------------------------------------------------------------

/// The start time of the running process `pid`, in the unit `--wait-start` takes on this OS:
/// `/proc/<pid>/stat` field 22 on Linux, the kernel's start time in microseconds on macOS.
#[cfg(target_os = "linux")]
pub fn start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let (_, rest) = stat.rsplit_once(')').expect("comm");
    rest.split_whitespace()
        .nth(19)
        .expect("starttime")
        .parse()
        .expect("ticks")
}

#[cfg(target_os = "macos")]
pub fn start_ticks(pid: u32) -> u64 {
    lunepack_os_macos::MacProcess::new()
        .process_id(pid)
        .expect("probe")
        .expect("running")
        .start_ticks
}

/// Whether `pid` is a zombie: its state letter is `Z` (`/proc/<pid>/stat` field 3 on Linux,
/// `ps -o stat=` on macOS).
#[cfg(target_os = "linux")]
pub fn is_zombie(pid: u32) -> bool {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let (_, rest) = stat.rsplit_once(')').expect("comm");
    rest.trim_start().starts_with('Z')
}

#[cfg(target_os = "macos")]
pub fn is_zombie(pid: u32) -> bool {
    let out = std::process::Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout).trim().starts_with('Z')
}

/// Windows has no zombie state (a process that ended is gone), so no case asks; the one that does
/// is skipped there.
#[cfg(windows)]
pub fn is_zombie(_pid: u32) -> bool {
    unreachable!("a zombie is a Unix process state")
}
