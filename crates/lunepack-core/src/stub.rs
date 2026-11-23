//! The Windows stub launch contract, version 2 (M7-D7, M10-D6): what the stub launcher at
//! `R\<entry file name>` starts, read from the install it stands in.
//!
//! [`launch_target`] is the whole read path as a pure function over [`Fs`]: `R` is given (the
//! stub takes it from its own resolved path and from nothing else), the newest whole install
//! record under `R\.lunepack\state` names the current version (read only, no lock), and that
//! version's `R\app\<current>\lunepack-update.json` names the entry. The record may be a
//! per-user or a per-machine install's (version 2; version 1 refused a machine record). Every directory on the way
//! below `R` and the entry itself are checked with `symlink_metadata`, so no symlink or reparse
//! point is followed. `R`'s own name is never read: a renamed folder still launches.
//!
//! This is a cross-version contract (C5): once an app ships, every later stub must read an
//! install laid out this way. The exit codes are part of it.

use std::path::{Path, PathBuf};

use crate::fs::{FileKind, Fs};
use crate::layout::{LayoutScheme, UserLayout};
use crate::state::{InstallState, load_any};
use crate::traits::Hasher;
use crate::update_config::{
    MAX_UPDATE_CONFIG_BYTES, UPDATE_CONFIG_FILE, UpdateConfig, runtime_file,
};
use crate::version::Version;

/// The stub's file name in a version tree: beside the entry, `<entry dir>\lunepack-stub.exe`
/// (M7-D8). The packager reserves it.
pub const STUB_FILE: &str = "lunepack-stub.exe";

/// The version of the launch contract this build implements.
pub const STUB_CONTRACT_VERSION: u32 = 2;

/// Why the stub cannot start the app. Each has a fixed exit code (90–95) and a fixed message;
/// none carries a path or a value read from the install.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StubError {
    /// No install record, or one with no current version (exit 90).
    #[error("the app is not installed")]
    NotInstalled,
    /// The install record cannot be read (including a scope this build does not know) or is from
    /// a newer format (exit 91).
    #[error("the app's install state cannot be read")]
    State,
    /// The current version's update config is missing, unreadable or invalid, or does not name
    /// that version and the record's app (exit 92).
    #[error("the app's configuration cannot be read")]
    Config,
    /// The entry is missing or is not a regular file (exit 93).
    #[error("the app's executable is missing")]
    Entry,
    /// A symlink or reparse point on the path below the install folder (exit 94).
    #[error("the app's folder contains a link where a file or folder belongs")]
    Link,
    /// The entry could not be started (exit 95; the stub's own launch step, not
    /// [`launch_target`]).
    #[error("the app could not be started")]
    Launch,
}

impl StubError {
    /// The stub's exit code.
    pub const fn code(self) -> u8 {
        match self {
            StubError::NotInstalled => 90,
            StubError::State => 91,
            StubError::Config => 92,
            StubError::Entry => 93,
            StubError::Link => 94,
            StubError::Launch => 95,
        }
    }

    /// The fixed message the stub shows (a message box or one stderr line).
    pub fn message(self) -> &'static str {
        match self {
            StubError::NotInstalled => "The app is not installed. Run its setup again.",
            StubError::State => "The app's install state cannot be read. Run its setup again.",
            StubError::Config => "The app's configuration cannot be read. Run its setup again.",
            StubError::Entry => "The app's executable is missing. Run its setup again.",
            StubError::Link => {
                "The app's folder contains a link where a file or folder belongs. Run its setup again."
            }
            StubError::Launch => "The app could not be started.",
        }
    }
}

/// What the stub starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchTarget {
    /// The current version (the record's and its config's).
    pub version: Version,
    /// The entry executable, `R\app\<version>\<install.entry>`.
    pub entry_path: PathBuf,
    /// The version's runtime beside the entry (for the reserved `--lunepack-uninstall`); not
    /// checked here, the caller checks it before it starts it.
    pub runtime_path: PathBuf,
}

/// What `path` is, for a step that must be a real directory: missing → `missing`, a link →
/// [`StubError::Link`], anything else that is not a directory → `missing` as well.
fn real_dir(fs: &dyn Fs, path: &Path, missing: StubError) -> Result<(), StubError> {
    match fs.symlink_metadata(path) {
        Ok(Some(meta)) if meta.kind == FileKind::Dir => Ok(()),
        Ok(Some(meta)) if meta.kind == FileKind::Symlink => Err(StubError::Link),
        // Absent, another kind, or unreadable: the step's own failure.
        Ok(_) | Err(_) => Err(missing),
    }
}

/// `base` joined with each of `names`, every step a real directory (`missing` when absent).
fn walk_dirs<'a>(
    fs: &dyn Fs,
    base: &Path,
    names: impl IntoIterator<Item = &'a str>,
    missing: StubError,
) -> Result<PathBuf, StubError> {
    let mut at = base.to_path_buf();
    for name in names {
        at.push(name);
        real_dir(fs, &at, missing)?;
    }
    Ok(at)
}

/// The launch contract v2's read path (M7-D7, M10-D6) for the install rooted at `install_root` (the
/// directory of the stub's own resolved path), under [`LayoutScheme::WINDOWS`]:
///
/// 1. `R\.lunepack\state` (each step a real directory; absent → [`StubError::NotInstalled`]) and
///    its newest whole record, whatever app id it carries, read only with no lock
///    ([`load_any`]): none → `NotInstalled`; unreadable or newer format → [`StubError::State`];
///    no current version → `NotInstalled`. A record of scope `user` or `machine` is accepted. `record.current` is the version
///    to start, never `pending` or `previous`.
/// 2. `R\app\<current>\lunepack-update.json`: a regular file of at most 64 KiB that the config
///    reader accepts, for the record's app id and exactly the current version (text-equal);
///    anything else → [`StubError::Config`].
/// 3. The entry, `install.entry` joined name by name: every directory a real directory and the
///    file a regular file; absent or of another kind → [`StubError::Entry`].
///
/// A symlink or reparse point at any step below `R` is [`StubError::Link`].
pub fn launch_target(
    fs: &dyn Fs,
    hasher: &dyn Hasher,
    install_root: &Path,
) -> Result<LaunchTarget, StubError> {
    let scheme = LayoutScheme::WINDOWS;
    let layout = UserLayout::from_root(install_root.to_path_buf(), scheme);

    let state_dir = walk_dirs(
        fs,
        install_root,
        scheme.state.split('/'),
        StubError::NotInstalled,
    )?;
    let record = match load_any::<InstallState>(fs, &state_dir, hasher) {
        Ok(Some(record)) => record,
        Ok(None) => return Err(StubError::NotInstalled),
        Err(_) => return Err(StubError::State),
    };
    let current = record
        .current
        .as_ref()
        .map(|c| c.version.clone())
        .ok_or(StubError::NotInstalled)?;

    let version_text = current.to_string();
    let tree = walk_dirs(
        fs,
        install_root,
        scheme
            .versions
            .split('/')
            .chain(std::iter::once(version_text.as_str())),
        StubError::Config,
    )?;
    debug_assert_eq!(tree, layout.version_dir(&current));
    let config_path = tree.join(UPDATE_CONFIG_FILE);
    match fs.symlink_metadata(&config_path) {
        Ok(Some(meta)) if meta.kind == FileKind::File => {}
        Ok(Some(meta)) if meta.kind == FileKind::Symlink => return Err(StubError::Link),
        _ => return Err(StubError::Config),
    }
    let bytes = fs
        .read_capped(&config_path, MAX_UPDATE_CONFIG_BYTES)
        .map_err(|_| StubError::Config)?;
    let config = UpdateConfig::parse(&bytes).map_err(|_| StubError::Config)?;
    if config.app_id != record.app_id
        || config.version != current
        || config.version.to_string() != version_text
    {
        return Err(StubError::Config);
    }

    let names: Vec<&str> = config.install.entry.components().collect();
    let (file, dirs) = names.split_last().ok_or(StubError::Entry)?;
    let entry_dir = walk_dirs(fs, &tree, dirs.iter().copied(), StubError::Entry)?;
    let entry_path = entry_dir.join(file);
    match fs.symlink_metadata(&entry_path) {
        Ok(Some(meta)) if meta.kind == FileKind::File => {}
        Ok(Some(meta)) if meta.kind == FileKind::Symlink => return Err(StubError::Link),
        _ => return Err(StubError::Entry),
    }
    Ok(LaunchTarget {
        version: current,
        runtime_path: entry_dir.join(runtime_file(config.target)),
        entry_path,
    })
}
