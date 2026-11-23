//! An administrator's policy for one app on macOS (M11-D11): the JSON file
//! `/Library/Application Support/lunepack/.policy/<app id>.json`, one object with the optional booleans
//! `disable_self_update` and `no_update_ui`.
//!
//! No file: both off. A file that is there but not trustworthy or not valid fails toward no update
//! (M10-D12): both on. Trustworthy means a regular file (not a link, not a FIFO or device) owned
//! by root that neither its group nor others may write, at most [`MAX_POLICY_BYTES`], in a real
//! directory owned by root that neither its group nor others may write. Valid means
//! [`MachinePolicy::from_json`]. The file is opened without following a link and judged by the
//! descriptor it opened, so it cannot be swapped between the check and the read.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use lunepack_core::{AppId, MachinePolicy, PolicySource};

/// The policy directory.
pub const POLICY_DIR: &str = "/Library/Application Support/lunepack/.policy";
/// Most bytes a policy file may have.
pub const MAX_POLICY_BYTES: u64 = 4096;

/// [`PolicySource`] over the policy files.
#[derive(Debug, Clone)]
pub struct FilePolicy {
    dir: PathBuf,
    /// The uid the file and its directory must belong to (0).
    owner: u32,
}

impl Default for FilePolicy {
    fn default() -> Self {
        FilePolicy::new()
    }
}

impl FilePolicy {
    /// The files in [`POLICY_DIR`], owned by root.
    pub fn new() -> FilePolicy {
        FilePolicy {
            dir: PathBuf::from(POLICY_DIR),
            owner: 0,
        }
    }

    /// For tests that cannot run as root: the files in `dir`, owned by `owner`. Never used by a
    /// composition root.
    #[doc(hidden)]
    pub fn for_tests(dir: PathBuf, owner: u32) -> FilePolicy {
        FilePolicy { dir, owner }
    }

    /// Whether `meta` belongs to the owner and neither its group nor others may write it.
    fn trusted(&self, meta: &fs::Metadata) -> bool {
        meta.uid() == self.owner && meta.mode() & 0o022 == 0
    }

    /// The policy, or `None` for one that must fail closed.
    fn read_checked(&self, app_id: &AppId) -> Option<MachinePolicy> {
        match fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.is_dir() && self.trusted(&meta) => {}
            Ok(_) => return None,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Some(MachinePolicy::default());
            }
            Err(_) => return None,
        }
        let path = self.dir.join(format!("{}.json", app_id.as_str()));
        let file = match open_nofollow(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Some(MachinePolicy::default());
            }
            Err(_) => return None,
        };
        let meta = file.metadata().ok()?;
        if !meta.is_file() || !self.trusted(&meta) || meta.len() > MAX_POLICY_BYTES {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(MAX_POLICY_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > MAX_POLICY_BYTES {
            return None;
        }
        MachinePolicy::from_json(&bytes)
    }
}

/// Opens `path` for reading without following a final link and without blocking on a FIFO.
fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

impl PolicySource for FilePolicy {
    fn read(&self, app_id: &AppId) -> MachinePolicy {
        self.read_checked(app_id)
            .unwrap_or(MachinePolicy::FAIL_CLOSED)
    }
}
