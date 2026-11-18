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
//! Every rule here works on path components, never on path strings, so the same code serves
//! Windows paths (`C:\…`, `\\?\C:\…`). Only [`reconcile_current`] and [`remove_tombstones`] touch
//! the filesystem, and only through [`Fs`].
//!
//! Uninstall removes `R` by renaming it to a tombstone beside it,
//! `.<app id>.removing-<16 lowercase hex>`, and then removing the tombstone (review finding F18):
//! from install's point of view `R` is whole or gone, never half removed. The name is derived from
//! the app id alone, never from state; an app id begins with `[a-z0-9]`, so a tombstone is never
//! an install root (an app id under XDG; a display name under Windows, which never starts with
//! `.`, M7-D15).

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use crate::error::LayoutError;
use crate::fs::{FileKind, Fs, FsError, FsErrorKind};
use crate::ident::AppId;
use crate::state::{InstallState, Scope, load_any};
use crate::traits::Hasher;
use crate::update_config::{UPDATE_CONFIG_FILE, UpdateConfig};
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
    };

    /// Every scheme this build knows, for recognising a layout from its directories.
    const ALL: [LayoutScheme; 2] = [LayoutScheme::XDG, LayoutScheme::WINDOWS];
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
    /// `versions_dir` under one root, for any scheme this build knows; `None` when no scheme
    /// names both.
    pub fn from_dirs(state_dir: &Path, versions_dir: &Path) -> Option<UserLayout> {
        LayoutScheme::ALL.into_iter().find_map(|scheme| {
            let up = scheme.versions.split('/').count();
            let mut root = versions_dir;
            for _ in 0..up {
                root = root.parent()?;
            }
            let layout = UserLayout::from_root(root.to_path_buf(), scheme);
            (layout.versions_dir() == versions_dir && layout.state_dir() == state_dir)
                .then_some(layout)
        })
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
            Projection::None => None,
        }
    }

    /// The tree of `version` (`R/versions/<version>`, Windows `R\app\<version>`).
    pub fn version_dir(&self, version: &Version) -> PathBuf {
        self.versions_dir().join(version.to_string())
    }

    /// The update config of `version`'s tree, where the applier reads another version's config
    /// with no walk (M5-D17).
    pub fn version_config_path(&self, version: &Version) -> PathBuf {
        self.version_dir(version).join(UPDATE_CONFIG_FILE)
    }

    /// The live tree the facade's `Layout::User` names: `None`, because the current tree is
    /// `<versions>/<current>` (M4-D4).
    pub fn current_tree(&self) -> Option<PathBuf> {
        None
    }

    /// Projects `state` onto the filesystem as the scheme says: under
    /// [`Projection::CurrentLink`] as [`reconcile_current`] (with the scheme's versions
    /// directory), under [`Projection::None`] nothing.
    pub fn reconcile(&self, fs: &dyn Fs, state: &InstallState) -> Result<(), LayoutError> {
        match self.scheme.projection {
            Projection::CurrentLink => reconcile_link(fs, &self.root, self.scheme.versions, state),
            Projection::None => Ok(()),
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

/// The rule of M7-D15 a display name breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameRule {
    /// The name is empty.
    #[error("empty")]
    Empty,
    /// More than [`MAX_WINDOWS_NAME_UNITS`] UTF-16 code units.
    #[error("too long")]
    TooLong,
    /// One of `< > : " / \ | ? *` or a character below U+0020.
    #[error("a character Windows does not allow in a file name")]
    ForbiddenChar,
    /// A leading `.` or space, or a trailing `.` or space.
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
///    [`windows_name_ok`] as well), is `New` when it does not exist or is an empty real directory
///    (adopted); anything else there (a file, a link or reparse point, a non-empty directory,
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
