//! Protected directories of a per-machine install (M11-D7): [`MacProtect`] implements the core's
//! [`Protect`] with the unix rule of [`lunepack_core::unix_protect`] over what `lstat` and the
//! extended ACL (`acl_get_link_np(ACL_TYPE_EXTENDED)`, any entry fails) say.
//!
//! `check` applies the class's rule to the directory and the machine-tree rule to every ancestor
//! up to `/` (group `admin`, gid 80, may write a machine-tree directory on macOS). `create_dir`
//! makes the directory owner-only, gives it to `0:0`, sets the class's exact mode (never trusting
//! the umask or an inheritable ACL), makes it durable and then checks it.

#![allow(unsafe_code)]

use std::ffi::{CString, c_char, c_int, c_void};
use std::fs::{self, DirBuilder, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, lchown};
use std::path::{Path, PathBuf};

use lunepack_core::layout::UnixOs;
use lunepack_core::unix_protect::{self, DirFacts};
use lunepack_core::{DirClass, Protect, ProtectError};

/// `ACL_TYPE_EXTENDED` of `<sys/acl.h>`.
const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
/// `ACL_FIRST_ENTRY` of `<sys/acl.h>`.
const ACL_FIRST_ENTRY: c_int = 0;

unsafe extern "C" {
    fn acl_get_link_np(path: *const c_char, kind: c_int) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_free(obj: *mut c_void) -> c_int;
}

/// The mode a created directory of `class` gets.
pub const fn class_mode(class: DirClass) -> u32 {
    match class {
        DirClass::MachineTree => 0o755,
        DirClass::AdminOnly => 0o700,
    }
}

/// [`Protect`] for the root engine on macOS.
#[derive(Debug, Clone)]
pub struct MacProtect {
    /// The administrators' uid and gid (0 and 0).
    owner: (u32, u32),
    /// The highest directory checked as an ancestor; `None` is `/`.
    top: Option<PathBuf>,
}

impl Default for MacProtect {
    fn default() -> Self {
        MacProtect::new()
    }
}

impl MacProtect {
    /// Directories owned by `0:0`, every ancestor up to `/` checked.
    pub fn new() -> MacProtect {
        MacProtect {
            owner: (0, 0),
            top: None,
        }
    }

    /// For tests that cannot run as root: `uid:gid` stands for `0:0` and the ancestors are checked
    /// only up to `top` (a scratch directory). Never used by a composition root.
    #[doc(hidden)]
    pub fn for_tests(uid: u32, gid: u32, top: PathBuf) -> MacProtect {
        MacProtect {
            owner: (uid, gid),
            top: Some(top),
        }
    }

    /// What `lstat` and the ACL say about `path`, with this adapter's owner read as uid and gid 0
    /// (a real 0 is then read as another id). `None` when nothing is there.
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
            has_acl: has_extended_acl(path)?,
            os: UnixOs::Macos,
        }))
    }

    fn check_one(&self, path: &Path, class: DirClass) -> Result<(), ProtectError> {
        match self.facts(path) {
            Ok(None) => Err(ProtectError::NotFound),
            Ok(Some(facts)) => {
                unix_protect::check(&facts, class).map_err(|_| ProtectError::NotProtected)
            }
            Err(_) => Err(ProtectError::Os("the directory could not be read")),
        }
    }

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

/// Whether `path` (a link itself, not followed) carries an extended ACL with at least one entry.
/// No ACL answers no; any other failure is an error (the caller fails closed).
fn has_extended_acl(path: &Path) -> io::Result<bool> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call; the call only
    // reads it and returns an ACL this function owns (or null).
    let acl = unsafe { acl_get_link_np(c_path.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            // No ACL on the entry, or none supported by the volume.
            Some(libc::ENOENT | libc::EOPNOTSUPP) => Ok(false),
            _ => Err(err),
        };
    }
    let mut entry: *mut c_void = std::ptr::null_mut();
    // SAFETY: `acl` is the non-null ACL returned above, still owned here; `entry` is valid for one
    // pointer write. The entry points into `acl` and is not used after `acl_free`.
    let rc = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &raw mut entry) };
    // SAFETY: `acl` came from `acl_get_link_np` and is freed exactly once.
    unsafe {
        acl_free(acl);
    }
    Ok(rc == 0)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

impl Protect for MacProtect {
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
            fs::set_permissions(path, fs::Permissions::from_mode(class_mode(class)))?;
            sync_dir(path)?;
            sync_dir(parent)
        })();
        let checked = match made {
            // An inherited ACL makes the check fail: the directory is removed below.
            Ok(()) => self.check(path, class),
            Err(_) => Err(ProtectError::Os("the directory could not be protected")),
        };
        if checked.is_err() {
            let _ = fs::remove_dir(path);
        }
        checked
    }

    fn check(&self, path: &Path, class: DirClass) -> Result<(), ProtectError> {
        self.check_one(path, class)?;
        self.check_ancestors(path)
    }
}
