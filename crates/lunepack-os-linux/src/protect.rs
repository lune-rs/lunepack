//! Protected directories of a per-machine install (M11-D7): [`LinuxProtect`] implements the core's
//! [`Protect`] with the unix rule of [`lunepack_core::unix_protect`] over what `lstat` and the
//! `system.posix_acl_access` attribute say.
//!
//! `check` applies the class's rule to the directory and the machine-tree rule to every ancestor
//! up to `/` (a group- or world-writable directory on the way would let someone swap the tree).
//! `create_dir` makes the directory owner-only, gives it to `0:0`, sets the class's exact mode
//! (never trusting the umask or an inherited default), makes it durable and then checks it.

use std::ffi::CString;
use std::fs::{self, DirBuilder, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, lchown};
use std::path::{Path, PathBuf};

use lunepack_core::layout::UnixOs;
use lunepack_core::unix_protect::{self, DirFacts};
use lunepack_core::{DirClass, Protect, ProtectError};

/// The mode a created directory of `class` gets.
pub const fn class_mode(class: DirClass) -> u32 {
    match class {
        DirClass::MachineTree => 0o755,
        DirClass::AdminOnly => 0o700,
    }
}

/// [`Protect`] for the root engine on Linux.
#[derive(Debug, Clone)]
pub struct LinuxProtect {
    /// The administrators' uid and gid (0 and 0).
    owner: (u32, u32),
    /// The highest directory checked as an ancestor; `None` is `/`.
    top: Option<PathBuf>,
}

impl Default for LinuxProtect {
    fn default() -> Self {
        LinuxProtect::new()
    }
}

impl LinuxProtect {
    /// Directories owned by `0:0`, every ancestor up to `/` checked.
    pub fn new() -> LinuxProtect {
        LinuxProtect {
            owner: (0, 0),
            top: None,
        }
    }

    /// For tests that cannot run as root: `uid:gid` stands for `0:0` and the ancestors are checked
    /// only up to `top` (a scratch directory). Never used by a composition root.
    #[doc(hidden)]
    pub fn for_tests(uid: u32, gid: u32, top: PathBuf) -> LinuxProtect {
        LinuxProtect {
            owner: (uid, gid),
            top: Some(top),
        }
    }

    /// What `lstat` and the ACL attribute say about `path`, with this adapter's owner read as
    /// uid and gid 0 (another uid or gid 0 is read as a non-zero id). `None` when nothing is there.
    fn facts(&self, path: &Path) -> io::Result<Option<DirFacts>> {
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let is_link = meta.file_type().is_symlink();
        let map = |id: u32, ours: u32| {
            if id == ours {
                0
            } else if id == 0 {
                u32::MAX
            } else {
                id
            }
        };
        Ok(Some(DirFacts {
            uid: map(meta.uid(), self.owner.0),
            gid: map(meta.gid(), self.owner.1),
            mode: meta.mode(),
            is_dir: meta.is_dir(),
            is_link,
            has_acl: !is_link && has_access_acl(path)?,
            os: UnixOs::Linux,
        }))
    }

    /// The class's rule on `path` itself.
    fn check_one(&self, path: &Path, class: DirClass) -> Result<(), ProtectError> {
        match self.facts(path) {
            Ok(None) => Err(ProtectError::NotFound),
            Ok(Some(facts)) => {
                unix_protect::check(&facts, class).map_err(|_| ProtectError::NotProtected)
            }
            Err(_) => Err(ProtectError::Os("the directory could not be read")),
        }
    }

    /// The machine-tree rule on every ancestor of `path`, up to `/` (or the test top).
    fn check_ancestors(&self, path: &Path) -> Result<(), ProtectError> {
        let mut at = path.parent();
        while let Some(dir) = at {
            if dir.as_os_str().is_empty() {
                break;
            }
            match self.facts(dir) {
                Ok(Some(facts)) => unix_protect::check(&facts, DirClass::MachineTree)
                    .map_err(|_| ProtectError::NotProtected)?,
                Ok(None) => return Err(ProtectError::NotFound),
                Err(_) => return Err(ProtectError::Os("an ancestor could not be read")),
            }
            if self.top.as_deref() == Some(dir) {
                break;
            }
            at = dir.parent();
        }
        Ok(())
    }
}

/// Whether `path` (not a link) carries a POSIX access ACL. A file system without ACLs, or a file
/// without one, answers no; any other failure is an error (the caller fails closed).
#[allow(unsafe_code)]
fn has_access_acl(path: &Path) -> io::Result<bool> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let name = c"system.posix_acl_access";
    // SAFETY: both pointers are valid NUL-terminated strings that outlive the call; a null value
    // pointer with size 0 asks only for the attribute's size, so nothing is written.
    let size = unsafe { libc::lgetxattr(c_path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size >= 0 {
        return Ok(size > 0);
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENODATA | libc::EOPNOTSUPP) => Ok(false),
        _ => Err(err),
    }
}

/// Makes `dir`'s entries durable.
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

impl Protect for LinuxProtect {
    fn create_dir(&self, path: &Path, class: DirClass) -> Result<(), ProtectError> {
        let parent = path.parent().ok_or(ProtectError::NotFound)?;
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(ProtectError::Exists),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(ProtectError::Os("the directory could not be read")),
        }
        match DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(ProtectError::Exists),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ProtectError::NotFound),
            Err(_) => return Err(ProtectError::Os("the directory could not be created")),
        }
        let made = (|| {
            lchown(path, Some(self.owner.0), Some(self.owner.1))?;
            // After the owner: a change of owner may clear mode bits.
            fs::set_permissions(path, fs::Permissions::from_mode(class_mode(class)))?;
            sync_dir(path)?;
            sync_dir(parent)
        })();
        let checked = match made {
            Ok(()) => self.check(path, class),
            Err(_) => Err(ProtectError::Os("the directory could not be protected")),
        };
        if checked.is_err() {
            // Only the empty directory this call made.
            let _ = fs::remove_dir(path);
        }
        checked
    }

    fn check(&self, path: &Path, class: DirClass) -> Result<(), ProtectError> {
        self.check_one(path, class)?;
        self.check_ancestors(path)
    }
}
