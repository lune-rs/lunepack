//! Unix system calls behind [`lunepack_core::Fs::place`]: volume flags and the access check.
//! Every `unsafe` block is one libc call on a `CString` this module owns.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use lunepack_core::{FsError, FsErrorKind};

/// The path as a C string. A NUL byte is an error (kind `Other`), never a truncated path.
pub(crate) fn cstring(path: &Path) -> Result<CString, FsError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        FsError::new(
            FsErrorKind::Other,
            path,
            Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains a NUL byte",
            )),
        )
    })
}

/// The effective user id of this process.
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail and touches no memory.
    unsafe { libc::geteuid() }
}

/// Whether the effective user may write `path` (`faccessat(.., W_OK, AT_EACCESS)`): false on a
/// read-only volume and on any error.
pub(crate) fn writable(path: &Path) -> Result<bool, FsError> {
    let c = cstring(path)?;
    // SAFETY: `c` is a valid NUL-terminated string that outlives the call; `AT_FDCWD` makes the
    // path resolve as for `access`.
    let rc = unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::W_OK, libc::AT_EACCESS) };
    Ok(rc == 0)
}

/// The volume's file system type name and read-only flag.
#[cfg(target_os = "macos")]
pub(crate) fn volume(path: &Path) -> Result<(String, bool), FsError> {
    let c = cstring(path)?;
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `c` is a valid NUL-terminated string and `buf` is writable memory of the size of
    // `struct statfs`, which the call fills in whole when it returns 0.
    let rc = unsafe { libc::statfs(c.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(FsError::from_io(path, io::Error::last_os_error()).during("statfs"));
    }
    // SAFETY: `statfs` returned 0, so it initialised the whole struct.
    let st = unsafe { buf.assume_init() };
    let name: Vec<u8> = st
        .f_fstypename
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    let read_only = st.f_flags & (libc::MNT_RDONLY as u32) != 0;
    Ok((String::from_utf8_lossy(&name).into_owned(), read_only))
}

/// The volume's file system type name (none here) and read-only flag (`statvfs`).
#[cfg(not(target_os = "macos"))]
pub(crate) fn volume(path: &Path) -> Result<(String, bool), FsError> {
    let c = cstring(path)?;
    let mut buf = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c` is a valid NUL-terminated string and `buf` is writable memory of the size of
    // `struct statvfs`, which the call fills in whole when it returns 0.
    let rc = unsafe { libc::statvfs(c.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(FsError::from_io(path, io::Error::last_os_error()).during("statvfs"));
    }
    // SAFETY: `statvfs` returned 0, so it initialised the whole struct.
    let st = unsafe { buf.assume_init() };
    // The flag types differ by target (`c_ulong` on 64-bit Linux, narrower elsewhere): widen both,
    // which is a no-op where they are already `u64`.
    #[allow(clippy::unnecessary_cast)]
    let read_only = (st.f_flag as u64) & (libc::ST_RDONLY as u64) != 0;
    Ok((String::new(), read_only))
}
