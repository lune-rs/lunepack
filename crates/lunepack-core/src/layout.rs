//! The per-user install layout and the discovery rules (M5-D2, M5-D17, C4 Locating), plus the
//! reconcile of the derived `current` link.
//!
//! Under the install root `R`: `versions/<version>/` (one tree per version, M4-D18), `state/`
//! (records and the lock), `cache/`, `logs/` and `current`, a relative symlink to
//! `versions/<current>` that is derived from the install record and never read as truth.
//!
//! Those are the names of [`LayoutScheme::XDG`] (Linux). [`LayoutScheme::WINDOWS`] (M7-D2 (b))
//! names `R` after the app's display name at first install, keeps the trees in `app/<version>/`
//! and the state, cache and logs under `.lunepack/`, and projects no `current` link; such an `R`
//! is found by its install record ([`resolve_root`], M7-D16).
//!
//! [`LayoutScheme::MACOS`] (M8-D1) has the directories of XDG and projects the record as a bundle:
//! the live app bundle `B` (outside `R`, named by `R/bundle`) holds the current version, and
//! [`UserLayout::reconcile`] moves trees between `B`, the slots `versions/.swap` and
//! `versions/.out` and `versions/<version>` by renames only (M8-D3, M8-D5); see
//! [`reconcile_bundle`].
//!
//! Every rule here works on path components, never on path strings, so the same code serves
//! Windows paths (`C:\…`, `\\?\C:\…`). The filesystem is touched only through [`Fs`].
//!
//! Uninstall removes `R` by renaming it to a tombstone beside it,
//! `.<app id>.removing-<16 lowercase hex>`, and then removing the tombstone (review finding F18):
//! from install's point of view `R` is whole or gone, never half removed. The name is derived from
//! the app id alone, never from state; an app id begins with `[a-z0-9]`, so a tombstone is never
//! an install root (an app id under XDG; a display name under Windows, which never starts with
//! `.`, M7-D15).

use std::ffi::OsStr;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use crate::error::LayoutError;
use crate::fs::{FileKind, Fs, FsError, FsErrorKind, PlaceFacts};
use crate::ident::AppId;
use crate::state::{InstallState, Scope, is_record_name, load_any};
use crate::traits::Hasher;
use crate::update_config::{
    MAX_UPDATE_CONFIG_BYTES, UPDATE_CONFIG_FILE, UPDATE_CONFIG_PATH_MACOS, UpdateConfig,
};
use crate::version::Version;

/// Most directories above the executable's own that [`tree_candidates`] offers (k = 1 ..= 31).
pub const MAX_TREE_DEPTH: usize = 31;
/// The directory of version trees under the install root.
pub const VERSIONS_DIR: &str = "versions";
/// The install-state directory under the install root.
pub const STATE_DIR: &str = "state";
/// The download cache under the install root.
pub const CACHE_DIR: &str = "cache";
/// The log directory under the install root.
pub const LOGS_DIR: &str = "logs";
/// The derived link to the current tree under the install root.
pub const CURRENT_LINK: &str = "current";
/// The pointer to the live bundle under a bundle layout's root (M8-D1): an absolute symlink.
pub const BUNDLE_LINK: &str = "bundle";
/// The live bundle's identity under a bundle layout's root (M8-D17): `<device> <inode>`.
pub const BUNDLE_ID_FILE: &str = "bundle.id";
/// The temporary file [`BUNDLE_ID_FILE`] is written through.
const BUNDLE_ID_TEMP: &str = "bundle.id.tmp";
/// Most bytes of [`BUNDLE_ID_FILE`] read (two 20-digit numbers and a space).
const MAX_BUNDLE_ID_BYTES: u64 = 64;
/// The slot a tree passes through on its way into or out of the bundle, in the versions
/// directory (M8-D3). Never a version's text, which starts with a digit.
pub const SWAP_SLOT: &str = ".swap";
/// The slot holding the old bundle while the bundle's name is empty, on the two-rename path only
/// (M8-D3).
pub const OUT_SLOT: &str = ".out";
/// The suffix of an app bundle's directory name.
pub const BUNDLE_SUFFIX: &str = ".app";
/// The path component under which macOS runs a translocated app (M8-D4).
pub const TRANSLOCATION_COMPONENT: &str = "AppTranslocation";
/// The file system type of a translocation mount (M8-D4).
pub const TRANSLOCATION_FS_TYPE: &str = "nullfs";
/// The Trash under the home directory; a bundle in it is never adopted (M8-D16, M8-D17).
pub const TRASH_DIR: &str = ".Trash";
/// The user's apps folder under the home directory (M8-D2); a bundle directly in it may be
/// adopted (M8-D9).
pub const USER_APPS_DIR: &str = "Applications";
/// The system's apps folder; a bundle directly in it may be adopted too (M8-D9).
pub const SYSTEM_APPS_DIR: &str = "/Applications";
/// Most UTF-8 bytes of an app's display name used as a bundle name (M8-D1, step 1).
pub const MAX_MACOS_NAME_BYTES: usize = 200;
/// Most bytes of a file name on the volumes macOS installs to (`NAME_MAX`).
const MAX_FILE_NAME_BYTES: usize = 255;
/// Most moves one reconcile makes; more means the disk changed under it.
const MAX_RECONCILE_STEPS: usize = 16;

/// What follows `.<app id>` in a tombstone's name, before its random part.
pub const TOMBSTONE_TAG: &str = ".removing-";
/// The random bytes in a tombstone's name, written as lowercase hex.
pub const TOMBSTONE_RANDOM_BYTES: usize = 8;

/// The name uninstall renames `R` to, in `R`'s parent: `.<app id>.removing-<random as 16
/// lowercase hex>`.
pub fn tombstone_name(app_id: &AppId, random: &[u8; TOMBSTONE_RANDOM_BYTES]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut name = format!(".{}{TOMBSTONE_TAG}", app_id.as_str());
    for b in random {
        name.push(char::from(DIGITS[usize::from(b >> 4)]));
        name.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    name
}

/// Whether `name` is exactly a [`tombstone_name`] of `app_id`: `.<app id>.removing-` followed by
/// 16 lowercase hex digits and nothing else.
pub fn is_tombstone_of(app_id: &AppId, name: &OsStr) -> bool {
    name.to_str()
        .and_then(|n| n.strip_prefix('.'))
        .and_then(|n| n.strip_prefix(app_id.as_str()))
        .and_then(|n| n.strip_prefix(TOMBSTONE_TAG))
        .is_some_and(|hex| {
            hex.len() == 2 * TOMBSTONE_RANDOM_BYTES
                && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// Removes what uninstalls of `app_id` cut off before the end left in `dir` (`R`'s parent, the
/// data home): every entry whose name [`is_tombstone_of`] `app_id` and that is a real directory
/// (checked with `symlink_metadata` right before its removal), with
/// [`Fs::remove_dir_all_nofollow`], so a symlink inside one is removed itself and never followed.
/// Anything else at such a name (a file, a symlink) is left alone. An entry that vanishes on the
/// way (another run removing it) is not an error; a missing `dir` has nothing to remove. Every
/// tombstone is tried; the first error is returned.
pub fn remove_tombstones(fs: &dyn Fs, dir: &Path, app_id: &AppId) -> Result<(), FsError> {
    let entries = match fs.list_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind == FsErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut first = None;
    for entry in entries {
        if entry.kind != FileKind::Dir || !is_tombstone_of(app_id, &entry.name) {
            continue;
        }
        let path = dir.join(&entry.name);
        let removed = match fs.symlink_metadata(&path) {
            Ok(Some(meta)) if meta.kind == FileKind::Dir => fs.remove_dir_all_nofollow(&path),
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        };
        match removed {
            Ok(()) => {}
            Err(e) if e.kind == FsErrorKind::NotFound => {}
            Err(e) => {
                first.get_or_insert(e);
            }
        }
    }
    match first {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// How an install root is named in its data home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootNaming {
    /// `R = <data home>/<app id>`: derived, never searched for (M5-D2, Linux).
    AppId,
    /// `R = <data home>/<display name at first install>`, found by its install record afterwards
    /// (M7-D2, M7-D16, Windows).
    DisplayName,
}

/// What the install projects from its record onto the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Projection {
    /// `R/current`, a relative symlink to the current version's tree (M5-D2).
    CurrentLink,
    /// Nothing: the record alone names the current version (Windows, M7-D2; the stub reads it).
    None,
    /// The live bundle `B` named by `R/bundle` holds the current version's tree (macOS, M8-D1).
    Bundle,
}

/// The names of a per-user layout: how `R` is named, where its directories are (each relative to
/// `R`, `/`-separated, plain names only) and what is projected. The composition root picks one
/// (the facade's platform, the runtime, the stub); the core holds no platform switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutScheme {
    /// How `R` is named.
    pub root: RootNaming,
    /// The version trees' directory.
    pub versions: &'static str,
    /// The install-state directory (records and the lock).
    pub state: &'static str,
    /// The download cache.
    pub cache: &'static str,
    /// The log directory.
    pub logs: &'static str,
    /// What is projected from the record.
    pub projection: Projection,
    /// The update config's path inside a version tree (`/`-separated, plain names only).
    pub config: &'static str,
}

impl LayoutScheme {
    /// Linux (XDG, M5-D2, M7-D18 (a)): `<data home>/<app id>` with `versions/`, `state/`,
    /// `cache/`, `logs/` and `current`.
    pub const XDG: LayoutScheme = LayoutScheme {
        root: RootNaming::AppId,
        versions: VERSIONS_DIR,
        state: STATE_DIR,
        cache: CACHE_DIR,
        logs: LOGS_DIR,
        projection: Projection::CurrentLink,
        config: UPDATE_CONFIG_FILE,
    };

    /// Windows per user (M7-D2 (b)): `<data home>\<display name>` with `app\<ver>\`,
    /// `.lunepack\state\`, `.lunepack\cache\`, `.lunepack\logs\` and no `current` link.
    pub const WINDOWS: LayoutScheme = LayoutScheme {
        root: RootNaming::DisplayName,
        versions: "app",
        state: ".lunepack/state",
        cache: ".lunepack/cache",
        logs: ".lunepack/logs",
        projection: Projection::None,
        config: UPDATE_CONFIG_FILE,
    };

    /// macOS per user (M8-D1): `<data home>/<app id>` (`~/Library/Application Support/<app id>`)
    /// with `versions/`, `state/`, `cache/`, `logs/`, the bundle pointer `bundle` and its identity
    /// `bundle.id`; the trees are bundles with the config at
    /// `Contents/Resources/lunepack-update.json`.
    pub const MACOS: LayoutScheme = LayoutScheme {
        root: RootNaming::AppId,
        versions: VERSIONS_DIR,
        state: STATE_DIR,
        cache: CACHE_DIR,
        logs: LOGS_DIR,
        projection: Projection::Bundle,
        config: UPDATE_CONFIG_PATH_MACOS,
    };

    /// Every scheme this build knows, for recognising a layout from its directories. XDG and MACOS
    /// name the same directories, so [`UserLayout::from_dirs`] finds XDG for both; a caller that
    /// knows its scheme uses [`UserLayout::from_dirs_as`].
    const ALL: [LayoutScheme; 3] = [
        LayoutScheme::XDG,
        LayoutScheme::WINDOWS,
        LayoutScheme::MACOS,
    ];
}

/// `base` joined with each `/`-separated name of `rel`.
fn join_names(base: &Path, rel: &str) -> PathBuf {
    let mut out = base.to_path_buf();
    for name in rel.split('/') {
        out.push(name);
    }
    out
}

/// The directories of a per-user install rooted at `R`, under a [`LayoutScheme`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLayout {
    root: PathBuf,
    scheme: LayoutScheme,
}

impl UserLayout {
    /// The layout under the install root `root` (already canonical; nothing is checked here) with
    /// `scheme`'s names.
    pub fn from_root(root: PathBuf, scheme: LayoutScheme) -> UserLayout {
        UserLayout { root, scheme }
    }

    /// The layout whose state and versions directories are exactly `state_dir` and
    /// `versions_dir` under one root, for the first scheme this build knows that names both (XDG
    /// before MACOS, which names the same directories); `None` when no scheme names both.
    pub fn from_dirs(state_dir: &Path, versions_dir: &Path) -> Option<UserLayout> {
        LayoutScheme::ALL
            .into_iter()
            .find_map(|scheme| UserLayout::from_dirs_as(state_dir, versions_dir, scheme))
    }

    /// The layout under `scheme` whose state and versions directories are exactly `state_dir` and
    /// `versions_dir` under one root; `None` when `scheme` does not name both.
    pub fn from_dirs_as(
        state_dir: &Path,
        versions_dir: &Path,
        scheme: LayoutScheme,
    ) -> Option<UserLayout> {
        let up = scheme.versions.split('/').count();
        let mut root = versions_dir;
        for _ in 0..up {
            root = root.parent()?;
        }
        let layout = UserLayout::from_root(root.to_path_buf(), scheme);
        (layout.versions_dir() == versions_dir && layout.state_dir() == state_dir).then_some(layout)
    }

    /// `R`.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The scheme the layout names its directories with.
    pub fn scheme(&self) -> LayoutScheme {
        self.scheme
    }

    /// The version trees' directory (`R/versions`, Windows `R\app`).
    pub fn versions_dir(&self) -> PathBuf {
        join_names(&self.root, self.scheme.versions)
    }

    /// The install-state directory (`R/state`, Windows `R\.lunepack\state`).
    pub fn state_dir(&self) -> PathBuf {
        join_names(&self.root, self.scheme.state)
    }

    /// The download cache (`R/cache`, Windows `R\.lunepack\cache`).
    pub fn cache_dir(&self) -> PathBuf {
        join_names(&self.root, self.scheme.cache)
    }

    /// The log directory (`R/logs`, Windows `R\.lunepack\logs`).
    pub fn logs_dir(&self) -> PathBuf {
        join_names(&self.root, self.scheme.logs)
    }

    /// `R/current`, only under [`Projection::CurrentLink`].
    pub fn current_link(&self) -> Option<PathBuf> {
        match self.scheme.projection {
            Projection::CurrentLink => Some(self.root.join(CURRENT_LINK)),
            Projection::None | Projection::Bundle => None,
        }
    }

    /// `R/bundle`, the pointer to the live bundle, only under [`Projection::Bundle`].
    pub fn bundle_link(&self) -> Option<PathBuf> {
        (self.scheme.projection == Projection::Bundle).then(|| self.root.join(BUNDLE_LINK))
    }

    /// `R/bundle.id`, the live bundle's identity, only under [`Projection::Bundle`].
    pub fn bundle_id_path(&self) -> Option<PathBuf> {
        (self.scheme.projection == Projection::Bundle).then(|| self.root.join(BUNDLE_ID_FILE))
    }

    /// The swap slot, `<versions>/.swap`.
    pub fn swap_slot(&self) -> PathBuf {
        self.versions_dir().join(SWAP_SLOT)
    }

    /// The out slot of the two-rename path, `<versions>/.out`.
    pub fn out_slot(&self) -> PathBuf {
        self.versions_dir().join(OUT_SLOT)
    }

    /// The live bundle `B` that `R/bundle` names (M8-D1): `None` when the layout projects no
    /// bundle or `R/bundle` does not exist. The pointer is read, never followed; anything at
    /// `R/bundle` that is not a symlink, and a target that is not UTF-8, absolute, plain and
    /// canonical (no symlink on its way, checked through `fs`) with a last name ending in
    /// `.app`, is [`LayoutError::BundlePointer`] and is not repaired. `B` itself may be missing.
    pub fn bundle_path(&self, fs: &dyn Fs) -> Result<Option<PathBuf>, LayoutError> {
        let Some(link) = self.bundle_link() else {
            return Ok(None);
        };
        match lstat(fs, &link)? {
            None => return Ok(None),
            Some(meta) if meta.kind == FileKind::Symlink => {}
            Some(_) => return Err(LayoutError::BundlePointer),
        }
        let target = PathBuf::from(fs.read_link(&link)?);
        match check_bundle_target(fs, &target) {
            Ok(()) => Ok(Some(target)),
            Err(LayoutError::NotCanonical) => Err(LayoutError::BundlePointer),
            Err(e) => Err(e),
        }
    }

    /// The live tree the facade's `Layout::User` names, read through `fs`: under
    /// [`Projection::Bundle`] the bundle `R/bundle` names ([`UserLayout::bundle_path`]), under
    /// the other projections `None` (the current tree is `<versions>/<current>`, M4-D4).
    pub fn current_tree_with(&self, fs: &dyn Fs) -> Result<Option<PathBuf>, LayoutError> {
        match self.scheme.projection {
            Projection::Bundle => self.bundle_path(fs),
            Projection::CurrentLink | Projection::None => Ok(None),
        }
    }

    /// The tree of `version` (`R/versions/<version>`, Windows `R\app\<version>`).
    pub fn version_dir(&self, version: &Version) -> PathBuf {
        self.versions_dir().join(version.to_string())
    }

    /// The update config of `version`'s tree (the scheme's config path inside it), where the
    /// applier reads another version's config with no walk (M5-D17).
    pub fn version_config_path(&self, version: &Version) -> PathBuf {
        join_names(&self.version_dir(version), self.scheme.config)
    }

    /// The live tree the facade's `Layout::User` names without reading the disk: `None`, because
    /// the current tree is `<versions>/<current>` (M4-D4); a bundle layout's is read with
    /// [`UserLayout::current_tree_with`].
    pub fn current_tree(&self) -> Option<PathBuf> {
        None
    }

    /// Projects `state` onto the filesystem as the scheme says: under
    /// [`Projection::CurrentLink`] as [`reconcile_current`] (with the scheme's versions
    /// directory), under [`Projection::None`] nothing, under [`Projection::Bundle`] as
    /// [`reconcile_bundle`].
    pub fn reconcile(&self, fs: &dyn Fs, state: &InstallState) -> Result<(), LayoutError> {
        match self.scheme.projection {
            Projection::CurrentLink => reconcile_link(fs, &self.root, self.scheme.versions, state),
            Projection::None => Ok(()),
            Projection::Bundle => reconcile_bundle(fs, self, state),
        }
    }
}

/// What [`discover`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discovery {
    /// The tree is `root/versions/<version>`, the version being the config's.
    Installed {
        /// The install root `R`.
        root: PathBuf,
        /// The tree's version.
        version: Version,
    },
    /// The tree is not under a versions directory of an install (a bootstrap tree, for one); the
    /// caller checks the record.
    NotInstalled,
}

/// Whether `path` is absolute and made only of a prefix, the root and plain names (no `.` or
/// `..`, which the lexical ancestor walk below would misread).
fn is_plain_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|c| {
            matches!(
                c,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

/// The directories an executable at `exe` looks in for its tree's [`UPDATE_CONFIG_FILE`], in
/// order: its own directory as `k = 0`, then each ancestor as `k = 1, 2, …`, up to
/// `k = `[`MAX_TREE_DEPTH`] or the filesystem root (included). The facade tests each for the
/// config and stops at the first it finds (P4).
///
/// `exe` must be absolute with no `.` or `..` component (a resolved executable path); any other
/// path has no candidate.
pub fn tree_candidates(exe: &Path) -> Vec<(PathBuf, usize)> {
    if !is_plain_absolute(exe) {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut at = exe.parent();
    while let Some(dir) = at {
        if out.len() > MAX_TREE_DEPTH {
            break;
        }
        out.push((dir.to_path_buf(), out.len()));
        at = dir.parent();
    }
    out
}

/// `path`'s components in order.
fn names(path: &Path) -> Vec<Component<'_>> {
    path.components().collect()
}

/// Where the executable `exe` stands, given that `tree` (the `k`-th entry of
/// [`tree_candidates`]`(exe)`) holds the update config `config` (P4, M5-D17).
///
/// The executable must lie in the entry's directory `D` (`config.install.entry` without its
/// file name): `k` equals the number of components of `D`, the `k` components of the exe's
/// directory below `tree` equal `D`'s byte for byte, and `tree` is that directory's `k`-th
/// ancestor. Otherwise [`LayoutError::NotThisTree`]: the caller stops, and never walks past a
/// config it found. The exe's file name is not checked, so the entry, the runtime and any other
/// binary beside the entry find the same tree.
///
/// The tree is installed when its name is the config's version text (byte-equal) and its parent
/// is `scheme`'s versions directory (its names, byte-equal, from the end): the install root is the
/// ancestor above them (`R/versions/<v>` under [`LayoutScheme::XDG`], `R\app\<v>` under
/// [`LayoutScheme::WINDOWS`]); anything else is [`Discovery::NotInstalled`].
pub fn discover(
    exe: &Path,
    tree: &Path,
    k: usize,
    config: &UpdateConfig,
    scheme: LayoutScheme,
) -> Result<Discovery, LayoutError> {
    check_entry_dir(exe, tree, k, config)?;
    let version_text = config.version.to_string();
    if tree.file_name() != Some(OsStr::new(&version_text)) {
        return Ok(Discovery::NotInstalled);
    }
    // The tree's parent must end in the scheme's versions directory, name by name; the root is
    // the ancestor above those names.
    let mut at = tree.parent();
    for want in scheme.versions.rsplit('/') {
        match at {
            Some(dir) if dir.file_name() == Some(OsStr::new(want)) => at = dir.parent(),
            _ => return Ok(Discovery::NotInstalled),
        }
    }
    match at {
        Some(root) => Ok(Discovery::Installed {
            root: root.to_path_buf(),
            version: config.version.clone(),
        }),
        None => Ok(Discovery::NotInstalled),
    }
}

/// [`discover`]'s first rule: the executable `exe` lies in the entry's directory of `tree`, the
/// `k`-th candidate; otherwise [`LayoutError::NotThisTree`].
fn check_entry_dir(
    exe: &Path,
    tree: &Path,
    k: usize,
    config: &UpdateConfig,
) -> Result<(), LayoutError> {
    if !is_plain_absolute(exe) || !is_plain_absolute(tree) {
        return Err(LayoutError::NotThisTree);
    }
    let entry: Vec<&str> = config.install.entry.components().collect();
    let entry_dir = &entry[..entry.len().saturating_sub(1)];
    if k != entry_dir.len() {
        return Err(LayoutError::NotThisTree);
    }
    let exe_dir = exe.parent().ok_or(LayoutError::NotThisTree)?;
    let dir = names(exe_dir);
    let top = names(tree);
    if dir.len() != top.len() + k || dir[..top.len()] != top[..] {
        return Err(LayoutError::NotThisTree);
    }
    let below = &dir[top.len()..];
    let matches = below.iter().zip(entry_dir).all(|(c, want)| match c {
        Component::Normal(name) => *name == OsStr::new(want),
        _ => false,
    });
    if !matches {
        return Err(LayoutError::NotThisTree);
    }
    Ok(())
}

/// `R/versions/<version>/lunepack-update.json` under [`LayoutScheme::XDG`]; other schemes use
/// [`UserLayout::version_config_path`].
pub fn version_config_path(root: &Path, version: &Version) -> PathBuf {
    root.join(VERSIONS_DIR)
        .join(version.to_string())
        .join(UPDATE_CONFIG_FILE)
}

/// The text `R/current` holds for `version` under [`LayoutScheme::XDG`]: `versions/<version>`.
pub fn current_target(version: &Version) -> String {
    format!("{VERSIONS_DIR}/{version}")
}

/// [`LayoutScheme::XDG`]'s projection: makes `root/current` a symlink to `versions/<current>` of
/// `state` (M5-D2), with
/// [`Fs::replace_symlink`] when it is missing or points elsewhere, then syncs `root` so the link
/// is durable. No current version: nothing is done. A file or directory at `root/current` is
/// [`LayoutError::CurrentNotALink`] and nothing is changed or deleted.
///
/// The caller holds the install's lock, so the record it passes is the one committed.
pub fn reconcile_current(
    fs: &dyn Fs,
    root: &Path,
    state: &InstallState,
) -> Result<(), LayoutError> {
    reconcile_link(fs, root, VERSIONS_DIR, state)
}

/// [`reconcile_current`] with `versions` as the link's directory part.
fn reconcile_link(
    fs: &dyn Fs,
    root: &Path,
    versions: &str,
    state: &InstallState,
) -> Result<(), LayoutError> {
    let Some(current) = &state.current else {
        return Ok(());
    };
    let want = format!("{versions}/{}", current.version);
    let link = root.join(CURRENT_LINK);
    let up_to_date = match fs.symlink_metadata(&link)? {
        None => false,
        Some(meta) if meta.kind == FileKind::Symlink => fs.read_link(&link)? == want,
        Some(_) => return Err(LayoutError::CurrentNotALink),
    };
    if !up_to_date {
        fs.replace_symlink(&want, &link)?;
    }
    // Also when nothing changed: an earlier run may have crashed before its sync.
    fs.sync_dir(root)?;
    Ok(())
}

// ---- Windows names and root resolution (M7-D15, M7-D16, M7-D17) ---------------------------------

/// Most UTF-16 code units a display name may have to be a folder and shortcut name (M7-D15 (1)).
pub const MAX_WINDOWS_NAME_UNITS: usize = 64;
/// Most entries of the data home [`resolve_root`] reads; more is a refusal (M7-D16, fail closed).
pub const MAX_DATA_HOME_ENTRIES: usize = 4096;

/// The rule of M7-D15 ([`windows_name_ok`]) or M8-D1 ([`macos_name_ok`]) a display name breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameRule {
    /// The name is empty.
    #[error("empty")]
    Empty,
    /// More than [`MAX_WINDOWS_NAME_UNITS`] UTF-16 code units (Windows) or
    /// [`MAX_MACOS_NAME_BYTES`] UTF-8 bytes (macOS).
    #[error("too long")]
    TooLong,
    /// Windows: one of `< > : " / \ | ? *` or a character below U+0020. macOS: `/`, `:` or a
    /// control character.
    #[error("a character Windows does not allow in a file name")]
    ForbiddenChar,
    /// Windows: a leading `.` or space, or a trailing `.` or space. macOS: a leading `.`.
    #[error("starts with a dot or space, or ends with a dot or space")]
    Edge,
    /// The stem is a Windows device name.
    #[error("a Windows device name")]
    DeviceName,
}

/// Windows device names (M7-D15 (4)), compared ASCII case-insensitively with a name's stem.
const DEVICE_NAMES: [&str; 32] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
];

/// Whether `name` (an app's display name) is a valid Windows folder and shortcut name (M7-D15):
/// non-empty; at most [`MAX_WINDOWS_NAME_UNITS`] UTF-16 code units; none of `< > : " / \ | ? *`
/// and no character below U+0020; no leading `.` or space and no trailing `.` or space; and its
/// stem (before the first `.`, trailing spaces removed) is no device name. It validates and never
/// rewrites.
pub fn windows_name_ok(name: &str) -> Result<(), NameRule> {
    if name.is_empty() {
        return Err(NameRule::Empty);
    }
    if name.encode_utf16().count() > MAX_WINDOWS_NAME_UNITS {
        return Err(NameRule::TooLong);
    }
    if name
        .chars()
        .any(|c| c < ' ' || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'))
    {
        return Err(NameRule::ForbiddenChar);
    }
    if name.starts_with(['.', ' ']) || name.ends_with(['.', ' ']) {
        return Err(NameRule::Edge);
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    if DEVICE_NAMES.iter().any(|d| stem.eq_ignore_ascii_case(d)) {
        return Err(NameRule::DeviceName);
    }
    Ok(())
}

/// Where a first install or setup puts `R` ([`resolve_root`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootChoice {
    /// An install of this app id is already there.
    Existing(PathBuf),
    /// No install of this app id was found; this path is absent or an empty real directory.
    New(PathBuf),
}

impl RootChoice {
    /// The chosen root.
    pub fn path(&self) -> &Path {
        match self {
            RootChoice::Existing(p) | RootChoice::New(p) => p,
        }
    }

    /// The chosen root, owned.
    pub fn into_path(self) -> PathBuf {
        match self {
            RootChoice::Existing(p) | RootChoice::New(p) => p,
        }
    }
}

/// What a data-home entry holds, as discovery reads it.
enum Holds {
    /// A whole install record of this app id.
    Ours,
    /// A record that cannot be read (torn records only are not this: they read as no record).
    Unreadable,
    /// Anything else: no state directory, no whole record, another app's record.
    Other,
}

/// What `dir` holds: a real directory with a real `<state>` directory (each component checked with
/// `symlink_metadata`, so no link or reparse point is followed) whose newest whole record is read
/// with [`crate::state::load_any`], read only.
fn holds(
    fs: &dyn Fs,
    hasher: &dyn Hasher,
    dir: &Path,
    app_id: &AppId,
    scheme: LayoutScheme,
) -> Holds {
    let mut at = dir.to_path_buf();
    if !is_real_dir(fs, &at) {
        return Holds::Other;
    }
    for name in scheme.state.split('/') {
        at.push(name);
        if !is_real_dir(fs, &at) {
            return Holds::Other;
        }
    }
    match load_any::<InstallState>(fs, &at, hasher) {
        Ok(Some(record)) if record.app_id == *app_id && record.scope == Scope::User => Holds::Ours,
        Ok(Some(record)) if record.app_id == *app_id => Holds::Unreadable,
        Ok(_) => Holds::Other,
        Err(_) => Holds::Unreadable,
    }
}

/// The updater lock's file name, in the state directory.
pub const LOCK_FILE: &str = "lock";

/// Whether `dir` is what a first install cut off after taking the lock but before its first record
/// leaves: a real directory holding nothing but the state directory (each level of
/// `scheme.state` a real directory holding only the next), and that holding no whole record and
/// only the lock and record-named files. Read only; a read failure is "no".
fn is_unfinished_install(
    fs: &dyn Fs,
    hasher: &dyn Hasher,
    dir: &Path,
    scheme: LayoutScheme,
) -> bool {
    let mut at = dir.to_path_buf();
    for name in scheme.state.split('/') {
        let Ok(listing) = fs.list_dir(&at) else {
            return false;
        };
        let [only] = listing.as_slice() else {
            return false;
        };
        if only.name.as_os_str() != OsStr::new(name) || only.kind != FileKind::Dir {
            return false;
        }
        at.push(name);
    }
    let Ok(listing) = fs.list_dir(&at) else {
        return false;
    };
    let only_ours = listing.iter().all(|e| {
        e.kind == FileKind::File
            && e.name
                .to_str()
                .is_some_and(|n| n == LOCK_FILE || is_record_name(n))
    });
    // A whole record (of any app) or a read that fails is an install, not a leftover.
    only_ours && matches!(load_any::<InstallState>(fs, &at, hasher), Ok(None))
}

/// Whether `path` is a real directory (not a symlink or reparse point). A read failure is "no".
fn is_real_dir(fs: &dyn Fs, path: &Path) -> bool {
    matches!(fs.symlink_metadata(path), Ok(Some(meta)) if meta.kind == FileKind::Dir)
}

/// Whether two folder names are the same on a case-insensitive filesystem (Unicode lowercase on
/// both sides; stricter than exact equality, which is what a refusal rule wants).
fn same_folder_name(a: &OsStr, b: &str) -> bool {
    a.to_str()
        .is_some_and(|a| a == b || a.to_lowercase() == b.to_lowercase())
}

/// Where the install of `app_id` with display name `name` lives, or goes, under `data_home`
/// (M7-D16, M7-D17 (a)). Reads only, through `fs` and the store reader; nothing is created.
///
/// [`RootNaming::AppId`]: `<data home>/<app id>`, with no listing of the data home: `Existing` when
/// it is a real directory, else `New` (the path is the same either way, as before M7).
///
/// [`RootNaming::DisplayName`]:
/// 1. `name` must pass [`windows_name_ok`] ([`LayoutError::NameNotAllowed`]).
/// 2. The data home's entries are listed (a missing data home has none; more than
///    [`MAX_DATA_HOME_ENTRIES`] is [`LayoutError::TooManyEntries`]). Every entry whose name does
///    not start with `.` (tombstones) and that is a real directory holding a real state directory
///    has its newest record read: one of this app id (scope user) is a match. An unreadable record
///    is skipped, except in the folder named `name` or `<name> (<app id>)` (compared ignoring
///    case), where it is [`LayoutError::InstallUnreadable`]. Two matches or more are
///    [`LayoutError::InstallAmbiguous`]; one is `Existing`.
/// 3. No match: `<data home>/<name>`, then `<data home>/<name> (<app id>)` (which must pass
///    [`windows_name_ok`] as well), is `New` when it does not exist, is an empty real directory
///    (adopted) or holds only what a first install cut off before its first record leaves (the
///    state directory with only the lock and record-named files, no whole record: resumed);
///    anything else there (a file, a link or reparse point, a non-empty directory,
///    another app's install) is taken and never touched. Both taken: [`LayoutError::FolderTaken`].
///
/// Errors carry no path or name.
pub fn resolve_root(
    fs: &dyn Fs,
    hasher: &dyn Hasher,
    data_home: &Path,
    app_id: &AppId,
    name: &str,
    scheme: LayoutScheme,
) -> Result<RootChoice, LayoutError> {
    if scheme.root == RootNaming::AppId {
        let root = data_home.join(app_id.as_str());
        return Ok(if is_real_dir(fs, &root) {
            RootChoice::Existing(root)
        } else {
            RootChoice::New(root)
        });
    }
    windows_name_ok(name).map_err(LayoutError::NameNotAllowed)?;
    let fallback = format!("{name} ({})", app_id.as_str());
    let entries = match fs.list_dir(data_home) {
        Ok(entries) => entries,
        Err(e) if e.kind == FsErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    if entries.len() > MAX_DATA_HOME_ENTRIES {
        return Err(LayoutError::TooManyEntries);
    }
    let mut found: Option<PathBuf> = None;
    for entry in &entries {
        if entry.kind != FileKind::Dir || entry.name.as_encoded_bytes().first() == Some(&b'.') {
            continue;
        }
        let dir = data_home.join(&entry.name);
        match holds(fs, hasher, &dir, app_id, scheme) {
            Holds::Ours if found.is_some() => return Err(LayoutError::InstallAmbiguous),
            Holds::Ours => found = Some(dir),
            Holds::Unreadable
                if same_folder_name(&entry.name, name)
                    || same_folder_name(&entry.name, &fallback) =>
            {
                return Err(LayoutError::InstallUnreadable);
            }
            Holds::Unreadable | Holds::Other => {}
        }
    }
    if let Some(root) = found {
        return Ok(RootChoice::Existing(root));
    }
    for candidate in [name, fallback.as_str()] {
        if windows_name_ok(candidate).is_err() {
            continue;
        }
        let path = data_home.join(candidate);
        let meta = match fs.symlink_metadata(&path) {
            Ok(meta) => meta,
            // A missing data home (an adapter may report its absence either way).
            Err(e) if e.kind == FsErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        match meta {
            None => return Ok(RootChoice::New(path)),
            Some(meta) if meta.kind == FileKind::Dir && fs.list_dir(&path)?.is_empty() => {
                return Ok(RootChoice::New(path));
            }
            // This app's own first install, cut off before its first record: resumed here, not
            // left behind beside a second copy (the writer's under-lock checks still guard it).
            Some(meta)
                if meta.kind == FileKind::Dir
                    && is_unfinished_install(fs, hasher, &path, scheme) =>
            {
                return Ok(RootChoice::New(path));
            }
            Some(_) => {}
        }
    }
    Err(LayoutError::FolderTaken)
}

/// Whether uninstall may remove `root`, the root its own path names (M5-D10, M7-D16). `data_home`
/// is canonical; the caller also checks that `root` is canonical and, under the lock, that its
/// record carries `app_id`.
///
/// [`RootNaming::AppId`]: `root` is exactly `<data home>/<app id>` and a real directory (M5-D10).
/// [`RootNaming::DisplayName`]: `root`'s parent is exactly the data home, its name does not start
/// with `.`, and it is a real directory (no link or reparse point). It need not be the only folder
/// holding this app's record, so a user's copy never blocks uninstall.
pub fn root_valid_for_uninstall(
    fs: &dyn Fs,
    data_home: &Path,
    root: &Path,
    app_id: &AppId,
    scheme: LayoutScheme,
) -> bool {
    let placed = match scheme.root {
        RootNaming::AppId => root == data_home.join(app_id.as_str()),
        RootNaming::DisplayName => {
            root.parent() == Some(data_home)
                && root
                    .file_name()
                    .is_some_and(|n| n.as_encoded_bytes().first() != Some(&b'.'))
        }
    };
    placed && is_real_dir(fs, root)
}

/// M7-D16 rule 3, run by every first-install writer under `R`'s lock before its first write:
/// `state_dir` holds no whole record of another app id ([`LayoutError::ForeignRecord`]). A record
/// that cannot be read is left to the writer's own load, which refuses it.
pub fn ensure_no_foreign_record(
    fs: &dyn Fs,
    hasher: &dyn Hasher,
    state_dir: &Path,
    app_id: &AppId,
) -> Result<(), LayoutError> {
    match load_any::<InstallState>(fs, state_dir, hasher) {
        Ok(Some(record)) if record.app_id != *app_id => Err(LayoutError::ForeignRecord),
        _ => Ok(()),
    }
}

// ---- macOS bundles (M8-D1, M8-D3, M8-D4, M8-D16, M8-D17) ----------------------------------------

/// Why a place is not one lunepack updates (M8-D4). The [`LocationReason::as_str`] names are the
/// closed set the runtime reports as `reason` (schema 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LocationReason {
    /// Translocated by Gatekeeper: on a `nullfs` mount or under an `AppTranslocation` component.
    #[error("translocated")]
    Translocated,
    /// On a read-only volume (a mounted disk image).
    #[error("read_only")]
    ReadOnly,
    /// The bundle's folder and the install root's versions directory are on different volumes.
    #[error("other_volume")]
    OtherVolume,
    /// The bundle is not owned by the caller.
    #[error("not_owned")]
    NotOwned,
    /// The caller may not create entries in the bundle's folder.
    #[error("not_writable")]
    NotWritable,
}

impl LocationReason {
    /// The reason's name: `translocated`, `read_only`, `other_volume`, `not_owned` or
    /// `not_writable`.
    pub const fn as_str(self) -> &'static str {
        match self {
            LocationReason::Translocated => "translocated",
            LocationReason::ReadOnly => "read_only",
            LocationReason::OtherVolume => "other_volume",
            LocationReason::NotOwned => "not_owned",
            LocationReason::NotWritable => "not_writable",
        }
    }
}

/// `symlink_metadata` with a missing parent read as a missing entry (an adapter may report it
/// either way).
fn lstat(fs: &dyn Fs, path: &Path) -> Result<Option<crate::fs::Meta>, FsError> {
    match fs.symlink_metadata(path) {
        Err(e) if e.kind == FsErrorKind::NotFound => Ok(None),
        other => other,
    }
}

/// Whether `path` has a component named [`TRANSLOCATION_COMPONENT`].
fn has_translocation_component(path: &Path) -> bool {
    path.components()
        .any(|c| c == Component::Normal(OsStr::new(TRANSLOCATION_COMPONENT)))
}

/// The translocation and read-only rules of M8-D4 for an entry at `path` with `facts`.
fn location_of(path: &Path, facts: &PlaceFacts) -> Result<(), LayoutError> {
    if facts.fs_type == TRANSLOCATION_FS_TYPE || has_translocation_component(path) {
        return Err(LayoutError::Location(LocationReason::Translocated));
    }
    if facts.read_only {
        return Err(LayoutError::Location(LocationReason::ReadOnly));
    }
    Ok(())
}

/// Text equality of versions: equal precedence with different build metadata are different trees.
fn same_version(a: &Version, b: &Version) -> bool {
    a == b && a.to_string() == b.to_string()
}

/// Whether `name` (an app's display name, `install.name`) may be a bundle's name (M8-D1): 1 to
/// [`MAX_MACOS_NAME_BYTES`] UTF-8 bytes, no `/`, `:`, NUL or other control character, and no
/// leading `.`. It validates and never rewrites. The packager and setup call it too.
pub fn macos_name_ok(name: &str) -> Result<(), NameRule> {
    if name.is_empty() {
        return Err(NameRule::Empty);
    }
    if name.len() > MAX_MACOS_NAME_BYTES {
        return Err(NameRule::TooLong);
    }
    if name
        .chars()
        .any(|c| c.is_control() || matches!(c, '/' | ':'))
    {
        return Err(NameRule::ForbiddenChar);
    }
    if name.starts_with('.') {
        return Err(NameRule::Edge);
    }
    Ok(())
}

/// Whether `path` is canonical as far as it exists: absolute, made of plain names, written in its
/// normal form (no doubled or trailing separator) and with no symlink at any existing prefix
/// (checked through `fs`, so nothing is followed). Otherwise [`LayoutError::NotCanonical`].
fn ensure_canonical(fs: &dyn Fs, path: &Path) -> Result<(), LayoutError> {
    if !is_plain_absolute(path) {
        return Err(LayoutError::NotCanonical);
    }
    let normal: PathBuf = path.components().collect();
    if normal.as_os_str() != path.as_os_str() {
        return Err(LayoutError::NotCanonical);
    }
    let mut at = PathBuf::new();
    for c in path.components() {
        at.push(c);
        if !matches!(c, Component::Normal(_)) {
            continue;
        }
        match lstat(fs, &at)? {
            // Nothing below a missing entry exists.
            None => break,
            Some(meta) if meta.kind == FileKind::Symlink => return Err(LayoutError::NotCanonical),
            Some(_) => {}
        }
    }
    Ok(())
}

/// The rules for a bundle path `B` (M8-D1): absolute, plain, in normal form and UTF-8, its folder
/// canonical ([`ensure_canonical`]), and a last name that ends in `.app` with something before it.
fn check_bundle_target(fs: &dyn Fs, bundle: &Path) -> Result<(), LayoutError> {
    let name_ok = bundle
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|n| n.len() > BUNDLE_SUFFIX.len() && n.ends_with(BUNDLE_SUFFIX));
    let Some(parent) = bundle.parent() else {
        return Err(LayoutError::NotCanonical);
    };
    if !name_ok || bundle.to_str().is_none() || !is_plain_absolute(bundle) {
        return Err(LayoutError::NotCanonical);
    }
    let normal: PathBuf = bundle.components().collect();
    if normal.as_os_str() != bundle.as_os_str() {
        return Err(LayoutError::NotCanonical);
    }
    // `B` itself is judged where it is used: a symlink there is never followed ([`tree_of`]).
    ensure_canonical(fs, parent)
}

/// Makes `R/bundle` point at `bundle` (M8-D1): at a first install, before its record is
/// committed, and when a moved install is followed ([`BundleDiscovery::MovedFrom`], under the
/// lock). `bundle` must be canonical, UTF-8 and end in `.app` ([`LayoutError::NotCanonical`]);
/// `R` must exist. A pointer that already holds `bundle` is left as it is. Then `R` is synced.
pub fn set_bundle_pointer(
    fs: &dyn Fs,
    layout: &UserLayout,
    bundle: &Path,
) -> Result<(), LayoutError> {
    let link = layout.bundle_link().ok_or(LayoutError::BundlePointer)?;
    check_bundle_target(fs, bundle)?;
    let text = bundle.to_str().ok_or(LayoutError::NotCanonical)?;
    let up_to_date = match lstat(fs, &link)? {
        Some(meta) if meta.kind == FileKind::Symlink => fs.read_link(&link)? == text,
        Some(_) => return Err(LayoutError::BundlePointer),
        None => false,
    };
    if !up_to_date {
        fs.replace_symlink(text, &link)?;
    }
    fs.sync_dir(layout.root())?;
    Ok(())
}

/// The identity `R/bundle.id` records (M8-D17): `(device, inode)` of the live bundle; `None` when
/// the file is missing, is not a regular file or does not hold exactly two decimal numbers
/// separated by one space (such a file identifies nothing).
pub fn read_bundle_identity(
    fs: &dyn Fs,
    layout: &UserLayout,
) -> Result<Option<(u64, u64)>, LayoutError> {
    let Some(path) = layout.bundle_id_path() else {
        return Ok(None);
    };
    match lstat(fs, &path)? {
        Some(meta) if meta.kind == FileKind::File => {}
        _ => return Ok(None),
    }
    let bytes = match fs.read_capped(&path, MAX_BUNDLE_ID_BYTES) {
        Ok(bytes) => bytes,
        Err(e) if e.kind == FsErrorKind::TooLarge => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let number = |s: &str| {
        (!s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0')))
        .then(|| s.parse::<u64>().ok())
        .flatten()
    };
    let parsed = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| text.split_once(' '))
        .and_then(|(d, i)| Some((number(d)?, number(i)?)));
    Ok(parsed)
}

/// Writes `R/bundle.id` for `bundle` as it is now (M8-D17), unless it already holds that
/// identity: the text goes to a temporary file in `R`, which is synced and renamed over the old
/// identity (removed first: [`Fs::rename`] never replaces), then `R` is synced. A crash on the way
/// leaves the old identity, none, or the new one; the next reconcile writes it again.
pub fn write_bundle_identity(
    fs: &dyn Fs,
    layout: &UserLayout,
    bundle: &Path,
) -> Result<(), LayoutError> {
    let path = layout.bundle_id_path().ok_or(LayoutError::BundlePointer)?;
    let facts = fs.place(bundle)?;
    if read_bundle_identity(fs, layout)? == Some((facts.device, facts.inode)) {
        return Ok(());
    }
    let temp = layout.root().join(BUNDLE_ID_TEMP);
    // Only files of ours are removed: a directory at either name is refused.
    for p in [&temp, &path] {
        if lstat(fs, p)?.is_some_and(|meta| meta.kind == FileKind::Dir) {
            return Err(LayoutError::BundlePointer);
        }
    }
    if lstat(fs, &temp)?.is_some() {
        fs.remove_file(&temp)?;
    }
    let text = format!("{} {}", facts.device, facts.inode);
    let mut file = fs.create_new(&temp)?;
    file.write_all(text.as_bytes())
        .map_err(|e| FsError::from_io(&temp, e))?;
    file.sync()?;
    drop(file);
    if lstat(fs, &path)?.is_some() {
        fs.remove_file(&path)?;
    }
    fs.rename(&temp, &path)?;
    fs.sync_dir(layout.root())?;
    Ok(())
}

/// The location rules of M8-D4 for the live bundle `bundle` of `layout`, read through
/// [`Fs::place`] and checked in this order: translocated and read-only (`B`'s folder, then `B`
/// when it exists), [`LocationReason::OtherVolume`] (`B`'s folder and `R/versions` on different
/// devices), [`LocationReason::NotOwned`] (`B` exists and is not the caller's) and
/// [`LocationReason::NotWritable`] (the caller may not create entries in `B`'s folder). `B`'s folder
/// need not be the caller's (M8-D4 (a)). A failure is [`LayoutError::Location`].
pub fn check_place(fs: &dyn Fs, layout: &UserLayout, bundle: &Path) -> Result<(), LayoutError> {
    let parent = bundle.parent().ok_or(LayoutError::BundlePointer)?;
    let folder = fs.place(parent)?;
    location_of(parent, &folder)?;
    let own = match lstat(fs, bundle)? {
        None => None,
        Some(meta) if meta.kind == FileKind::Dir => {
            let facts = fs.place(bundle)?;
            location_of(bundle, &facts)?;
            Some(facts)
        }
        Some(_) => return Err(LayoutError::NotATree),
    };
    let versions = fs.place(&layout.versions_dir())?;
    if versions.device != folder.device {
        return Err(LayoutError::Location(LocationReason::OtherVolume));
    }
    if own.is_some_and(|facts| !facts.owned_by_caller) {
        return Err(LayoutError::Location(LocationReason::NotOwned));
    }
    if !folder.writable {
        return Err(LayoutError::Location(LocationReason::NotWritable));
    }
    Ok(())
}

/// Where a first install puts the bundle `B` (M8-D1, M7-D17's rule): in `apps_dir` (canonical;
/// created with owner-only permissions when it is missing, never changed when it exists), named
/// after `name` when [`macos_name_ok`] accepts it and after the app id otherwise:
/// `<apps>/<name>.app`, else `<apps>/<name> (<app id>).app`. Any existing entry at a name is
/// taken and never touched (a fresh install has no bundle of its own yet: the caller runs this
/// only when the record has no current version or is orphaned); both taken is
/// [`LayoutError::BundleNameTaken`].
pub fn resolve_bundle_target(
    fs: &dyn Fs,
    apps_dir: &Path,
    name: &str,
    app_id: &AppId,
) -> Result<PathBuf, LayoutError> {
    ensure_canonical(fs, apps_dir)?;
    let parent = apps_dir.parent().ok_or(LayoutError::NotCanonical)?;
    match lstat(fs, apps_dir)? {
        None => {
            fs.create_dir_private(apps_dir)?;
            fs.sync_dir(parent)?;
        }
        Some(meta) if meta.kind == FileKind::Dir => {}
        Some(_) => return Err(LayoutError::NotCanonical),
    }
    let stem = if macos_name_ok(name).is_ok() {
        name
    } else {
        app_id.as_str()
    };
    for candidate in [
        format!("{stem}{BUNDLE_SUFFIX}"),
        format!("{stem} ({}){BUNDLE_SUFFIX}", app_id.as_str()),
    ] {
        if candidate.len() > MAX_FILE_NAME_BYTES {
            continue;
        }
        let path = apps_dir.join(&candidate);
        if lstat(fs, &path)?.is_none() {
            return Ok(path);
        }
    }
    Err(LayoutError::BundleNameTaken)
}

/// What [`discover_bundle`] is given about a running executable.
#[derive(Debug, Clone, Copy)]
pub struct BundleProbe<'a> {
    /// The running executable, canonical.
    pub exe: &'a Path,
    /// The `k`-th entry of [`tree_candidates`]`(exe)`, the first holding a config: the bundle.
    pub tree: &'a Path,
    /// `tree`'s walk depth.
    pub k: usize,
    /// `tree`'s update config.
    pub config: &'a UpdateConfig,
    /// [`Fs::place`] of `tree`.
    pub facts: &'a PlaceFacts,
    /// The canonical data home (`$HOME/Library/Application Support`).
    pub data_home: &'a Path,
    /// The canonical home directory (for its Trash).
    pub home: &'a Path,
}

/// What [`discover_bundle`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleDiscovery {
    /// The tree is the live bundle `R/bundle` names, or an old instance's tree in `R/versions`.
    Installed {
        /// The install root `R`.
        root: PathBuf,
        /// The tree's version.
        version: Version,
    },
    /// `R/bundle`'s target is gone and the tree is the recorded bundle, moved (M8-D17): the
    /// caller re-points `R/bundle` at the tree under the install's lock
    /// ([`set_bundle_pointer`]) after checking the record again.
    MovedFrom {
        /// The install root `R`.
        root: PathBuf,
        /// The tree's version (the record's current version).
        version: Version,
    },
    /// A bundle the user placed directly in an apps folder while this app has no live install
    /// for the user (M8-D9): no record, a record with no current version, or an orphaned one
    /// ([`bundle_orphaned`]). The update check may adopt it after proving it equal to its signed
    /// release; until then it is a development run.
    Adoptable {
        /// The install root `R`.
        root: PathBuf,
    },
    /// Any other copy: a development run.
    NotInstalled,
}

/// Where a running bundle stands under [`LayoutScheme::MACOS`] (M8-D1, M8-D4 amended, M8-D17),
/// checked in this order:
///
/// 1. The location of the running tree, before anything is read: on a `nullfs` volume or under an
///    `AppTranslocation` component is [`LocationReason::Translocated`], on a read-only volume
///    [`LocationReason::ReadOnly`] ([`LayoutError::Location`]).
/// 2. The executable lies in the entry's directory of the tree ([`LayoutError::NotThisTree`]).
/// 3. With `R = <data home>/<config's app id>`: a tree that is a real directory directly in
///    `R/versions` named by its config's version text is an old instance,
///    [`BundleDiscovery::Installed`].
/// 4. `R/bundle` is read ([`UserLayout::bundle_path`], refused when not canonical). Equal to the
///    tree byte for byte: [`BundleDiscovery::Installed`]. Its target exists: another copy of a
///    live install, [`BundleDiscovery::NotInstalled`] (one install per app id per user).
/// 5. The pointer is missing or its target is gone, and the tree is not under `<home>/.Trash`
///    ([`BundleDiscovery::NotInstalled`] otherwise). [`BundleDiscovery::MovedFrom`] when the
///    tree's device and inode are those `R/bundle.id` records and the install record (read only)
///    is this app's, per user, with the tree's version current. (A missing pointer is followed
///    too: an adoption cut off after its commit and before its pointer leaves exactly that.)
/// 6. [`BundleDiscovery::Adoptable`] when the tree's parent is, byte for byte, `<home>/`
///    [`USER_APPS_DIR`] or [`SYSTEM_APPS_DIR`], and `R` holds no record, a record of this app per
///    user with no current version, or an orphaned one ([`bundle_orphaned`]). A record that does
///    not load, or is another app's or scope's, is never adopted over.
/// 7. Otherwise [`BundleDiscovery::NotInstalled`].
///
/// Nothing here writes, follows a link in the tree or touches the network.
pub fn discover_bundle(
    fs: &dyn Fs,
    hasher: &dyn Hasher,
    probe: &BundleProbe<'_>,
) -> Result<BundleDiscovery, LayoutError> {
    location_of(probe.tree, probe.facts)?;
    check_entry_dir(probe.exe, probe.tree, probe.k, probe.config)?;
    let config = probe.config;
    let root = probe.data_home.join(config.app_id.as_str());
    let layout = UserLayout::from_root(root.clone(), LayoutScheme::MACOS);
    let installed = || BundleDiscovery::Installed {
        root: root.clone(),
        version: config.version.clone(),
    };

    let version_text = config.version.to_string();
    if probe.tree.parent() == Some(layout.versions_dir().as_path())
        && probe.tree.file_name() == Some(OsStr::new(&version_text))
        && is_real_dir(fs, probe.tree)
    {
        return Ok(installed());
    }

    let pointer = layout.bundle_path(fs)?;
    if let Some(bundle) = &pointer {
        if bundle.as_os_str() == probe.tree.as_os_str() {
            return Ok(installed());
        }
        if lstat(fs, bundle)?.is_some() {
            return Ok(BundleDiscovery::NotInstalled);
        }
    }
    if probe.tree.starts_with(probe.home.join(TRASH_DIR)) {
        return Ok(BundleDiscovery::NotInstalled);
    }
    let record = match load_any::<InstallState>(fs, &layout.state_dir(), hasher) {
        Ok(Some(record)) if record.app_id == config.app_id && record.scope == Scope::User => {
            Some(record)
        }
        Ok(None) => None,
        // Unreadable, another app's or another scope's: never followed, never adopted over.
        _ => return Ok(BundleDiscovery::NotInstalled),
    };
    let current = record.as_ref().and_then(|r| r.current.as_ref());
    if read_bundle_identity(fs, &layout)? == Some((probe.facts.device, probe.facts.inode))
        && current.is_some_and(|c| same_version(&c.version, &config.version))
    {
        return Ok(BundleDiscovery::MovedFrom {
            root,
            version: config.version.clone(),
        });
    }
    if !in_apps_folder(probe.tree, probe.home) {
        return Ok(BundleDiscovery::NotInstalled);
    }
    let free = match &record {
        None => true,
        Some(record) if record.current.is_none() => true,
        Some(record) => pointer.is_some() && bundle_orphaned(fs, &layout, record),
    };
    if free {
        return Ok(BundleDiscovery::Adoptable { root });
    }
    Ok(BundleDiscovery::NotInstalled)
}

/// Whether `tree`'s parent is, byte for byte, `<home>/Applications` or `/Applications` (M8-D9's
/// place rule; both sides are canonical, so a link or another spelling is never a match).
fn in_apps_folder(tree: &Path, home: &Path) -> bool {
    let Some(parent) = tree.parent() else {
        return false;
    };
    let user = home.join(USER_APPS_DIR);
    parent.as_os_str() == user.as_os_str()
        || parent.as_os_str() == Path::new(SYSTEM_APPS_DIR).as_os_str()
}

/// Whether `record` is orphaned under `layout` (M8-D16), read only: it names a current version,
/// `R/bundle` names a bundle that is gone, and none of `<versions>/<current>`, the swap slot and
/// the out slot holds that version of this app (by its own config, nothing followed). A missing
/// pointer, a pointer that is not canonical, a bundle that exists, or a tree that cannot be read
/// is not orphaned: only the state reconcile would answer [`LayoutError::Orphaned`] for is.
pub fn bundle_orphaned(fs: &dyn Fs, layout: &UserLayout, record: &InstallState) -> bool {
    let Some(current) = &record.current else {
        return false;
    };
    let bundle = match layout.bundle_path(fs) {
        Ok(Some(bundle)) => bundle,
        _ => return false,
    };
    if !matches!(lstat(fs, &bundle), Ok(None)) {
        return false;
    }
    let scheme = layout.scheme();
    for path in [
        layout.out_slot(),
        layout.swap_slot(),
        layout.version_dir(&current.version),
    ] {
        match tree_of(fs, scheme, &path) {
            Ok(None) => {}
            Ok(Some(tree))
                if tree.app_id == record.app_id
                    && !same_version(&tree.version, &current.version) => {}
            // It holds the current version, is another app's, or cannot be judged.
            _ => return false,
        }
    }
    true
}

/// What a bundle tree's own config says it is.
#[derive(Debug)]
struct TreeId {
    version: Version,
    app_id: AppId,
}

/// The tree at `path` as its own config identifies it (never by its name): `None` when nothing is
/// there; [`LayoutError::NotATree`] when anything but a real directory is; and
/// [`LayoutError::TreeUnreadable`] when a directory on the way to the config, or the config
/// itself, is missing, not real (a symlink is never followed) or does not parse. Read through the
/// capped reader.
fn tree_of(fs: &dyn Fs, scheme: LayoutScheme, path: &Path) -> Result<Option<TreeId>, LayoutError> {
    match lstat(fs, path)? {
        None => return Ok(None),
        Some(meta) if meta.kind == FileKind::Dir => {}
        Some(_) => return Err(LayoutError::NotATree),
    }
    let names: Vec<&str> = scheme.config.split('/').collect();
    let mut at = path.to_path_buf();
    for (i, name) in names.iter().enumerate() {
        at.push(name);
        let want = if i + 1 == names.len() {
            FileKind::File
        } else {
            FileKind::Dir
        };
        match lstat(fs, &at)? {
            Some(meta) if meta.kind == want => {}
            _ => return Err(LayoutError::TreeUnreadable),
        }
    }
    let bytes = match fs.read_capped(&at, MAX_UPDATE_CONFIG_BYTES) {
        Ok(bytes) => bytes,
        Err(e) if e.kind == FsErrorKind::TooLarge => return Err(LayoutError::TreeUnreadable),
        Err(e) => return Err(e.into()),
    };
    let config = UpdateConfig::parse(&bytes).map_err(|_| LayoutError::TreeUnreadable)?;
    Ok(Some(TreeId {
        version: config.version,
        app_id: config.app_id,
    }))
}

/// One move of [`reconcile_bundle`].
enum Move {
    /// Rename the first path to the second (which is free).
    Rename(PathBuf, PathBuf),
    /// Exchange the swap slot with the bundle.
    Swap,
    /// Rename the tree at the path to `<versions>/<version>`.
    Park(PathBuf, Version),
}

/// Renames `from` to `to`, then syncs `to`'s folder and, when it differs, `from`'s.
fn rename_synced(fs: &dyn Fs, from: &Path, to: &Path) -> Result<(), LayoutError> {
    fs.rename(from, to)?;
    let (to_dir, from_dir) = (to.parent(), from.parent());
    if let Some(dir) = to_dir {
        fs.sync_dir(dir)?;
    }
    if let Some(dir) = from_dir
        && from_dir != to_dir
    {
        fs.sync_dir(dir)?;
    }
    Ok(())
}

/// [`Projection::Bundle`]'s reconcile (M8-D3, M8-D5): makes the live bundle `B` (`R/bundle`'s
/// target) hold `state`'s current version, moving trees by renames only. Nothing is removed,
/// copied or written but `R/bundle.id` (M8-D17), which is written last whenever it does not
/// match `B`. No current version: nothing is done.
///
/// Every tree is identified by the version and app id of its own config, never by its name, and
/// nothing at `B`, the slots or a version tree is followed. Each move is chosen from a fresh look
/// at `B`, `S = <versions>/.swap`, `X = <versions>/.out` and `T = <versions>/<current>`, in this
/// order:
///
/// 1. `B` missing: `X`, then `S`, then `T`, whichever holds the current version, is renamed to `B`
///    (a two-rename cut short, or the first placement); none does: [`LayoutError::Orphaned`]
///    (M8-D16), nothing moved.
/// 2. `X` holds a tree: it is parked (renamed to `<versions>/<its version>`).
/// 3. `S` holds a tree: parked when `B` already holds the current version or `S` holds a third
///    version; swapped with `B` when `S` holds the current version.
/// 4. `B` holds another version: `T` must hold the current version
///    ([`LayoutError::BundleMissing`] otherwise) and is renamed to `S`.
///
/// A swap is [`Fs::exchange`]; when the volume answers [`FsErrorKind::Unsupported`] it is the
/// journaled two-rename `B -> X`, `S -> B`, `X -> S`. Every rename and exchange is followed by a
/// sync of the folders it changed, so any crash leaves a state the next reconcile finishes from.
/// Before the first move the place is checked ([`check_place`]). A tree of another app at `B` or
/// in a slot is [`LayoutError::ForeignTree`]; parking onto an existing name is
/// [`LayoutError::Duplicate`]. All paths are computed before the first move: the running
/// executable's own path moves with its tree.
///
/// The caller holds the install's lock, so the record it passes is the one committed.
pub fn reconcile_bundle(
    fs: &dyn Fs,
    layout: &UserLayout,
    state: &InstallState,
) -> Result<(), LayoutError> {
    let Some(current) = &state.current else {
        return Ok(());
    };
    let want = &current.version;
    let bundle = layout.bundle_path(fs)?.ok_or(LayoutError::BundlePointer)?;
    let folder = bundle
        .parent()
        .ok_or(LayoutError::BundlePointer)?
        .to_path_buf();
    let versions = layout.versions_dir();
    let swap = layout.swap_slot();
    let out = layout.out_slot();
    let target = layout.version_dir(want);
    let scheme = layout.scheme();
    let mut checked = false;

    for _ in 0..MAX_RECONCILE_STEPS {
        let b = tree_of(fs, scheme, &bundle)?;
        let s = tree_of(fs, scheme, &swap)?;
        let x = tree_of(fs, scheme, &out)?;
        let t = tree_of(fs, scheme, &target).or_else(|e| match e {
            // A version tree that cannot be read only matters when it is needed.
            LayoutError::TreeUnreadable | LayoutError::NotATree => Ok(None),
            e => Err(e),
        })?;
        if [&b, &s, &x]
            .into_iter()
            .flatten()
            .any(|tree| tree.app_id != state.app_id)
        {
            return Err(LayoutError::ForeignTree);
        }
        let is_want = |tree: &Option<TreeId>| {
            tree.as_ref().is_some_and(|tree| {
                tree.app_id == state.app_id && same_version(&tree.version, want)
            })
        };
        let next = if b.is_none() {
            if is_want(&x) {
                Move::Rename(out.clone(), bundle.clone())
            } else if is_want(&s) {
                Move::Rename(swap.clone(), bundle.clone())
            } else if is_want(&t) {
                Move::Rename(target.clone(), bundle.clone())
            } else {
                return Err(LayoutError::Orphaned);
            }
        } else if let Some(tree) = x {
            Move::Park(out.clone(), tree.version)
        } else if let Some(tree) = s {
            if is_want(&b) || !same_version(&tree.version, want) {
                Move::Park(swap.clone(), tree.version)
            } else {
                Move::Swap
            }
        } else if !is_want(&b) {
            if !is_want(&t) {
                return Err(LayoutError::BundleMissing);
            }
            Move::Rename(target.clone(), swap.clone())
        } else {
            write_bundle_identity(fs, layout, &bundle)?;
            return Ok(());
        };

        if !checked {
            check_place(fs, layout, &bundle)?;
            checked = true;
        }
        match next {
            Move::Rename(from, to) => rename_synced(fs, &from, &to)?,
            Move::Park(from, version) => {
                let to = versions.join(version.to_string());
                if lstat(fs, &to)?.is_some() {
                    return Err(LayoutError::Duplicate);
                }
                rename_synced(fs, &from, &to)?;
            }
            Move::Swap => match fs.exchange(&swap, &bundle) {
                Ok(()) => {
                    fs.sync_dir(&folder)?;
                    fs.sync_dir(&versions)?;
                }
                Err(e) if e.kind == FsErrorKind::Unsupported => {
                    rename_synced(fs, &bundle, &out)?;
                    rename_synced(fs, &swap, &bundle)?;
                    rename_synced(fs, &out, &swap)?;
                }
                Err(e) => return Err(e.into()),
            },
        }
    }
    // Every move takes the disk closer to the end state; this many means it changed under us.
    Err(LayoutError::BundleMissing)
}
