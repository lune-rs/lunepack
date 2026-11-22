//! The unix tree protection rule (M11-D7) as a pure function over the facts an adapter reads with
//! `lstat` and an ACL query. `lunepack-os-linux` and `lunepack-os-macos` implement
//! [`Protect`](crate::traits::Protect) with it: `check` of `R` applies [`DirClass::MachineTree`]
//! to every ancestor of `R` up to `/` as well, and `create_dir` checks what it made.
//!
//! - [`DirClass::MachineTree`]: a real directory (not a link) owned by uid 0, with no write bit
//!   for other, a group write bit only when the group is gid 0 (or gid 80, `admin`, on macOS),
//!   and no ACL. The sticky bit is no substitute for a missing write bit.
//! - [`DirClass::AdminOnly`]: a real directory owned by uid 0 with no bit at all for group or
//!   other, and no ACL.

use crate::layout::UnixOs;
use crate::traits::DirClass;

/// The group id of `root` (Linux) and `wheel` (macOS).
pub const ROOT_GID: u32 = 0;
/// The group id of `admin` on macOS, whose members are the Mac's administrators.
pub const MACOS_ADMIN_GID: u32 = 80;

/// What an adapter read about one directory entry, without following a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirFacts {
    /// The owner's user id.
    pub uid: u32,
    /// The owning group's id.
    pub gid: u32,
    /// The mode (`st_mode`; only the permission bits are read).
    pub mode: u32,
    /// The entry is a directory.
    pub is_dir: bool,
    /// The entry is a symbolic link.
    pub is_link: bool,
    /// The entry carries an access control list beyond its mode: an extended ACL on macOS, a
    /// `system.posix_acl_access` attribute on Linux.
    pub has_acl: bool,
    /// The OS the facts come from.
    pub os: UnixOs,
}

/// Why a directory is not protected as its class says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Reason {
    /// The entry is a symbolic link.
    #[error("a symbolic link")]
    Link,
    /// The entry is not a directory.
    #[error("not a directory")]
    NotADirectory,
    /// The owner is not uid 0.
    #[error("not owned by root")]
    Owner,
    /// Others may write.
    #[error("writable by others")]
    OtherWritable,
    /// A group other than the administrators' may write.
    #[error("writable by a group other than root")]
    GroupWritable,
    /// An admin-only directory grants something to its group or to others.
    #[error("open to group or others")]
    NotAdminOnly,
    /// The directory carries an access control list.
    #[error("carries an access control list")]
    Acl,
}

/// Whether `gid` may hold a group write bit on a machine tree directory on `os`.
fn admin_group(gid: u32, os: UnixOs) -> bool {
    gid == ROOT_GID || (os == UnixOs::Macos && gid == MACOS_ADMIN_GID)
}

/// `Ok(())` when `facts` describe a directory protected as `class` says (M11-D7); otherwise the
/// first rule it breaks, checked in the order link, directory, owner, ACL, mode.
pub fn check(facts: &DirFacts, class: DirClass) -> Result<(), Reason> {
    if facts.is_link {
        return Err(Reason::Link);
    }
    if !facts.is_dir {
        return Err(Reason::NotADirectory);
    }
    if facts.uid != 0 {
        return Err(Reason::Owner);
    }
    if facts.has_acl {
        return Err(Reason::Acl);
    }
    let mode = facts.mode & 0o777;
    match class {
        DirClass::MachineTree => {
            if mode & 0o002 != 0 {
                return Err(Reason::OtherWritable);
            }
            if mode & 0o020 != 0 && !admin_group(facts.gid, facts.os) {
                return Err(Reason::GroupWritable);
            }
        }
        DirClass::AdminOnly => {
            if mode & 0o077 != 0 {
                return Err(Reason::NotAdminOnly);
            }
        }
    }
    Ok(())
}
