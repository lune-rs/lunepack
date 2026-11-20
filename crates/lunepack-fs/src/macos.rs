//! macOS-only parts of [`crate::StdFs`]: the atomic swap of two entries (`renamex_np` with
//! `RENAME_SWAP`, M8-D3) and a file copy that carries no extended attributes (M8-D10).

#![allow(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use lunepack_core::{FsError, FsErrorKind};

use crate::unix_sys::cstring;

/// Swaps the entries at `a` and `b` atomically. `ENOTSUP` (a volume with no swap, such as HFS+)
/// is [`FsErrorKind::Unsupported`], a missing side `NotFound`; anything else keeps the OS error
/// as the cause. Never falls back to another way: the core decides what to do.
pub(crate) fn exchange(a: &Path, b: &Path) -> Result<(), FsError> {
    let ca = cstring(a)?;
    let cb = cstring(b)?;
    // SAFETY: both pointers are valid NUL-terminated strings owned by this frame for the whole
    // call; `RENAME_SWAP` is a documented flag of `renamex_np`, which neither follows a final
    // symlink nor keeps the pointers.
    let rc = unsafe { libc::renamex_np(ca.as_ptr(), cb.as_ptr(), libc::RENAME_SWAP) };
    if rc == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    Err(match e.raw_os_error() {
        Some(libc::ENOTSUP) => FsError::new(FsErrorKind::Unsupported, a, Some(e)),
        _ => FsError::from_io(a, e),
    }
    .during("exchange"))
}

/// Copies `from` to the new file `to_new` by plain reads and writes plus the permission bits, so
/// no extended attribute (`com.apple.quarantine`, `com.apple.provenance`, ...) reaches the copy
/// (std's `copy` uses `fcopyfile` and carries them; M8-D10). The destination is created with
/// `create_new`; a failed copy removes what it made.
pub(crate) fn copy_file(from: &Path, to_new: &Path) -> Result<(), FsError> {
    let mut src = File::open(from).map_err(|e| FsError::from_io(from, e).during("copy"))?;
    let mode = src
        .metadata()
        .map_err(|e| FsError::from_io(from, e).during("copy"))?
        .permissions()
        .mode();
    let mut dst = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(mode & 0o777)
        .open(to_new)
        .map_err(|e| FsError::from_io(to_new, e).during("copy"))?;
    let result = copy_bytes(&mut src, &mut dst).and_then(|()| {
        // The creation mode went through the umask; the copy keeps the source's bits exactly.
        dst.set_permissions(fs::Permissions::from_mode(mode & 0o7777))
    });
    if let Err(e) = result {
        drop(dst);
        let _ = fs::remove_file(to_new);
        return Err(FsError::from_io(from, e).during("copy"));
    }
    Ok(())
}

fn copy_bytes(src: &mut File, dst: &mut File) -> io::Result<()> {
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => dst.write_all(&buf[..n])?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}
