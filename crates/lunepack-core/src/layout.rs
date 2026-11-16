//! The per-user install layout and the discovery rules (M5-D2, M5-D17, C4 Locating), plus the
//! reconcile of the derived `current` link.
//!
//! Under the install root `R`: `versions/<version>/` (one tree per version, M4-D18), `state/`
//! (records and the lock), `cache/`, `logs/` and `current`, a relative symlink to
//! `versions/<current>` that is derived from the install record and never read as truth.
//!
//! Every rule here works on path components, never on path strings, so the same code serves
//! Windows paths (`C:\…`, `\\?\C:\…`). Only [`reconcile_current`] and [`remove_tombstones`] touch
//! the filesystem, and only through [`Fs`].
//!
//! Uninstall removes `R` = `<data home>/<app id>` by renaming it to a tombstone beside it,
//! `.<app id>.removing-<16 lowercase hex>`, and then removing the tombstone (review finding F18):
//! from install's point of view `R` is whole or gone, never half removed. The name is derived from
//! the app id alone, never from state; an app id begins with `[a-z0-9]`, so a tombstone is never
//! an install root.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use crate::error::LayoutError;
use crate::fs::{FileKind, Fs, FsError, FsErrorKind};
use crate::ident::AppId;
use crate::state::InstallState;
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

/// The directories of a per-user install rooted at `R` (M5-D2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLayout {
    root: PathBuf,
}

impl UserLayout {
    /// The layout under the install root `root` (already canonical; nothing is checked here).
    pub fn from_root(root: PathBuf) -> UserLayout {
        UserLayout { root }
    }

    /// `R`.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `R/versions`.
    pub fn versions_dir(&self) -> PathBuf {
        self.root.join(VERSIONS_DIR)
    }

    /// `R/state`.
    pub fn state_dir(&self) -> PathBuf {
        self.root.join(STATE_DIR)
    }

    /// `R/cache`.
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join(CACHE_DIR)
    }

    /// `R/logs`.
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join(LOGS_DIR)
    }

    /// `R/current`.
    pub fn current_link(&self) -> PathBuf {
        self.root.join(CURRENT_LINK)
    }

    /// `R/versions/<version>`.
    pub fn version_dir(&self, version: &Version) -> PathBuf {
        self.versions_dir().join(version.to_string())
    }

    /// The live tree the facade's `Layout::User` names: `None`, because the current tree is
    /// `versions/<current>` (M4-D4).
    pub fn current_tree(&self) -> Option<PathBuf> {
        None
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
/// The tree is installed when its name is the config's version text (byte-equal), its parent is
/// named `versions`, and the install root is the grandparent; anything else is
/// [`Discovery::NotInstalled`].
pub fn discover(
    exe: &Path,
    tree: &Path,
    k: usize,
    config: &UpdateConfig,
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
    let installed = tree.file_name() == Some(OsStr::new(&version_text))
        && tree
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n == OsStr::new(VERSIONS_DIR));
    match tree.parent().and_then(Path::parent) {
        Some(root) if installed => Ok(Discovery::Installed {
            root: root.to_path_buf(),
            version: config.version.clone(),
        }),
        _ => Ok(Discovery::NotInstalled),
    }
}

/// `R/versions/<version>/lunepack-update.json`: where the applier reads another version's
/// config, with no walk (M5-D17).
pub fn version_config_path(root: &Path, version: &Version) -> PathBuf {
    root.join(VERSIONS_DIR)
        .join(version.to_string())
        .join(UPDATE_CONFIG_FILE)
}

/// The text `R/current` holds for `version`: `versions/<version>`.
pub fn current_target(version: &Version) -> String {
    format!("{VERSIONS_DIR}/{version}")
}

/// Makes `root/current` a symlink to `versions/<current>` of `state` (M5-D2), with
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
    let Some(current) = &state.current else {
        return Ok(());
    };
    let want = current_target(&current.version);
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
