//! The libproc calls behind [`crate::MacProcess`]: process ids, identity, and the three places a
//! process can hold a directory tree: its executable path, its working directory and its open
//! vnode files (M5-D9's in-use scan, M8 step 3). Every `unsafe` block is one libproc call (or one
//! `fcntl` or `getattrlist` naming a path) on a buffer this module owns and sizes, with the
//! returned length checked, or the one view of a kernel path buffer's `c_char`s as bytes
//! (`vip_bytes`); nothing here allocates from a count the kernel reports without a cap.
//!
//! Hidden from the documentation: the crate's own tests read each source on its own (the premise
//! that a tree moved by a swap is reported under its new path is measured with these calls, not
//! with a command line tool).

#![allow(unsafe_code)]

use std::ffi::{CStr, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// `SZOMB` of `<sys/proc.h>`: the process has exited and is not yet reaped.
const SZOMB: u32 = 5;
/// `PROC_PIDFDVNODEPATHINFO` of `<sys/proc_info.h>` (a `proc_pidfdinfo` flavor): libc has no
/// constant for it.
const PROC_PIDFDVNODEPATHINFO: libc::c_int = 2;
/// The most pids one scan reads (the system's limit is far lower); a longer list is an error.
const MAX_PIDS: usize = 1 << 20;
/// The most open files of one process one scan reads; more is an error (fail closed).
const MAX_FDS: usize = 1 << 20;

/// `struct proc_fileinfo` of `<sys/proc_info.h>`.
#[repr(C)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

/// `struct vnode_fdinfowithpath` of `<sys/proc_info.h>`: libc has the pieces, not the whole.
#[repr(C)]
struct VnodeFdInfoWithPath {
    pfi: ProcFileInfo,
    pvip: libc::vnode_info_path,
}

/// What `PROC_PIDTBSDINFO` says about a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BsdInfo {
    /// The parent's pid.
    pub ppid: u32,
    /// The effective user id of the process.
    pub uid: u32,
    /// The start time in microseconds since the epoch: `pbi_start_tvsec * 1_000_000 +
    /// pbi_start_tvusec`, the second half of a `ProcessId`.
    pub start_micros: u64,
    /// The process has exited and is not yet reaped.
    pub zombie: bool,
}

fn gone(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ESRCH)
}

/// The path in a fixed NUL-terminated buffer (up to the first NUL, or the whole buffer when it has
/// none), `None` when empty.
fn path_of(bytes: &[u8]) -> Option<PathBuf> {
    let path = CStr::from_bytes_until_nul(bytes).map_or(bytes, CStr::to_bytes);
    (!path.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(path)))
}

/// The bytes of a `vip_path` (a `[[c_char; 32]; 32]` standing for `[c_char; MAXPATHLEN]`), all
/// 1024 of them, borrowed in place: the in-use scan reads one per open file of every process, so a
/// copy per byte made each scan slow (M13).
fn vip_bytes(info: &libc::vnode_info_path) -> &[u8] {
    let chars: &[libc::c_char] = info.vip_path.as_flattened();
    // SAFETY: `c_char` is `i8` or `u8`: one byte, alignment 1, every bit pattern valid as `u8`. So
    // `chars.len()` bytes from its start are initialised memory of the same allocation, borrowed
    // from `info` for the returned slice's lifetime and not written through.
    unsafe { std::slice::from_raw_parts(chars.as_ptr().cast::<u8>(), chars.len()) }
}

/// Every pid on the system, at the moment of the call.
pub fn list_pids() -> io::Result<Vec<u32>> {
    // SAFETY: a null buffer of size 0 asks only for the number of pids; nothing is written.
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    // Room for processes that start between the two calls; doubled while the list fills the buffer.
    let mut capacity = (n as usize).saturating_add(64);
    loop {
        if capacity > MAX_PIDS {
            return Err(io::Error::other("too many processes"));
        }
        let mut pids = vec![0 as libc::c_int; capacity];
        let bytes = i32::try_from(capacity * size_of::<libc::c_int>())
            .map_err(|_| io::Error::other("pid buffer too large"))?;
        // SAFETY: `pids` is writable memory of exactly `bytes` bytes, which is the size passed;
        // the call writes at most that many and returns the number of pids it wrote.
        let got = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        let got = got as usize;
        if got < capacity {
            pids.truncate(got);
            return Ok(pids
                .into_iter()
                .filter(|p| *p > 0)
                .map(|p| p as u32)
                .collect());
        }
        capacity = capacity.saturating_mul(2);
    }
}

/// `pid` as the C type, or `None` when it is out of range: no such process can exist.
fn pid_arg(pid: u32) -> Option<libc::c_int> {
    libc::c_int::try_from(pid).ok()
}

/// The identity facts of process `pid`; `None` when no such process exists.
pub fn bsd_info(pid: u32) -> io::Result<Option<BsdInfo>> {
    let Some(pid) = pid_arg(pid) else {
        return Ok(None);
    };
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` is writable memory of exactly `size` bytes, the size passed. The struct is
    // plain integers and byte arrays, so every bit pattern is valid, and it is only read after the
    // call returned exactly `size` bytes.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if got <= 0 {
        let err = io::Error::last_os_error();
        return if gone(&err) { Ok(None) } else { Err(err) };
    }
    if got != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short proc_bsdinfo",
        ));
    }
    // SAFETY: the call wrote the whole struct (`got == size`).
    let info = unsafe { info.assume_init() };
    Ok(Some(BsdInfo {
        ppid: info.pbi_ppid,
        uid: info.pbi_uid,
        start_micros: info
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec),
        zombie: info.pbi_status == SZOMB,
    }))
}

/// Source one: the path of the process's executable (`proc_pidpath`), as the kernel's name cache
/// has it now. `None` when the process is gone.
pub fn exe_path(pid: u32) -> io::Result<Option<PathBuf>> {
    let Some(pid) = pid_arg(pid) else {
        return Ok(None);
    };
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is writable memory of exactly the size passed; the call writes at most that
    // many bytes and returns how many.
    let got = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if got <= 0 {
        let err = io::Error::last_os_error();
        return if gone(&err) { Ok(None) } else { Err(err) };
    }
    Ok(path_of(&buf[..(got as usize).min(buf.len())]))
}

/// Source two: the process's working directory (`PROC_PIDVNODEPATHINFO`). `None` when the process
/// is gone or has none.
pub fn cwd_path(pid: u32) -> io::Result<Option<PathBuf>> {
    let Some(pid) = pid_arg(pid) else {
        return Ok(None);
    };
    let mut info = std::mem::MaybeUninit::<libc::proc_vnodepathinfo>::uninit();
    let size = size_of::<libc::proc_vnodepathinfo>() as libc::c_int;
    // SAFETY: `info` is writable memory of exactly `size` bytes, the size passed; the struct is
    // plain integers and byte arrays, read only after the call returned exactly `size` bytes.
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if got <= 0 {
        let err = io::Error::last_os_error();
        return if gone(&err) { Ok(None) } else { Err(err) };
    }
    if got != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short proc_vnodepathinfo",
        ));
    }
    // SAFETY: the call wrote the whole struct (`got == size`).
    let info = unsafe { info.assume_init() };
    Ok(path_of(vip_bytes(&info.pvi_cdir)))
}

/// The open file descriptors of `pid` with their types; `None` when the process is gone.
fn list_fds(pid: libc::c_int) -> io::Result<Option<Vec<libc::proc_fdinfo>>> {
    let entry = size_of::<libc::proc_fdinfo>();
    // SAFETY: a null buffer of size 0 asks only for the size needed; nothing is written.
    let need =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 {
        let err = io::Error::last_os_error();
        return if gone(&err) { Ok(None) } else { Err(err) };
    }
    // Room for descriptors opened between the two calls; doubled while the list fills the buffer.
    let mut capacity = (need as usize / entry).saturating_add(32);
    loop {
        if capacity > MAX_FDS {
            return Err(io::Error::other("too many open files"));
        }
        let mut fds: Vec<libc::proc_fdinfo> = Vec::with_capacity(capacity);
        let bytes = i32::try_from(capacity * entry)
            .map_err(|_| io::Error::other("descriptor buffer too large"))?;
        // SAFETY: `fds` has room for `capacity` entries, `bytes` bytes, the size passed; the call
        // writes at most that many bytes and returns how many it wrote.
        let got = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr().cast(),
                bytes,
            )
        };
        if got < 0 || (got == 0 && need > 0) {
            let err = io::Error::last_os_error();
            return if gone(&err) { Ok(None) } else { Err(err) };
        }
        let count = got as usize / entry;
        if count < capacity {
            // SAFETY: the call initialised `count` entries (plain integers) of the allocation,
            // and `count <= capacity`.
            unsafe { fds.set_len(count) };
            return Ok(Some(fds));
        }
        capacity = capacity.saturating_mul(2);
    }
}

/// Source three: the paths of the process's open vnode files (`PROC_PIDLISTFDS`, then
/// `PROC_PIDFDVNODEPATHINFO` for each vnode descriptor). A descriptor closed between the two calls
/// is skipped; a process that is gone gives an empty list.
pub fn fd_paths(pid: u32) -> io::Result<Vec<PathBuf>> {
    let Some(pid) = pid_arg(pid) else {
        return Ok(Vec::new());
    };
    let Some(fds) = list_fds(pid)? else {
        return Ok(Vec::new());
    };
    let mut paths = Vec::new();
    for fd in fds {
        if fd.proc_fdtype != libc::PROX_FDTYPE_VNODE as u32 {
            continue;
        }
        let mut info = std::mem::MaybeUninit::<VnodeFdInfoWithPath>::uninit();
        let size = size_of::<VnodeFdInfoWithPath>() as libc::c_int;
        // SAFETY: `info` is writable memory of exactly `size` bytes, the size passed; the struct is
        // plain integers and byte arrays, read only after the call returned exactly `size` bytes.
        let got = unsafe {
            libc::proc_pidfdinfo(
                pid,
                fd.proc_fd,
                PROC_PIDFDVNODEPATHINFO,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if got <= 0 {
            let err = io::Error::last_os_error();
            // The process ended or this descriptor was closed since the list was read.
            if gone(&err) || err.raw_os_error() == Some(libc::EBADF) {
                continue;
            }
            return Err(err);
        }
        if got != size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short vnode_fdinfowithpath",
            ));
        }
        // SAFETY: the call wrote the whole struct (`got == size`).
        let info = unsafe { info.assume_init() };
        if let Some(path) = path_of(vip_bytes(&info.pvip)) {
            paths.push(path);
        }
    }
    Ok(paths)
}

/// The path of the existing directory or file `path` as the kernel names it, like [`kernel_path`],
/// but without opening it: `getattrlist` with `ATTR_CMN_FULLPATH`, which reports from the same
/// source (`vn_getpath`). The in-use scan names its tree this way. A descriptor it opened on the
/// tree, even for an instant and close-on-exec, is copied into any child another thread of the
/// caller forks meanwhile, and that child holds it until its exec: a scan that reaches the child
/// first sees an open file in the tree, a tree in use that nobody uses (M13 step 5).
pub fn kernel_path_unopened(path: &std::path::Path) -> io::Result<PathBuf> {
    /// The reply: its length, the reference to the path, then the path (at most `PATH_MAX`
    /// bytes, NUL included).
    const REPLY: usize = 4 + 8 + libc::PATH_MAX as usize;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut request = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_FULLPATH,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut buf = vec![0u8; REPLY];
    // SAFETY: `c_path` is a NUL-terminated string and `request` a valid `attrlist`, both alive for
    // the call; `buf` is writable memory of exactly `buf.len()` bytes, the size passed, and the
    // call writes at most that many.
    let rc = unsafe {
        libc::getattrlist(
            c_path.as_ptr(),
            (&raw mut request).cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "bad ATTR_CMN_FULLPATH reply");
    let word = |at: usize| -> io::Result<[u8; 4]> {
        buf.get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(invalid)
    };
    let total = u32::from_ne_bytes(word(0)?) as usize;
    // The reference's offset counts from the reference itself (at byte 4).
    let offset = i32::from_ne_bytes(word(4)?);
    let length = u32::from_ne_bytes(word(8)?) as usize;
    let start = usize::try_from(offset)
        .ok()
        .and_then(|o| o.checked_add(4))
        .ok_or_else(invalid)?;
    let end = start.checked_add(length).ok_or_else(invalid)?;
    if total > buf.len() || end > total {
        return Err(invalid());
    }
    path_of(&buf[start..end]).ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}

/// The path of the existing directory or file `path` as the kernel names it (`F_GETPATH`): the
/// same source (`vn_getpath`) that `proc_pidpath` and the vnode path calls report from, so a
/// comparison with them is exact, on a case-insensitive volume and for a name the file system
/// stores in another Unicode normalization.
pub fn kernel_path(path: &std::path::Path) -> io::Result<PathBuf> {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: `F_GETPATH` writes a NUL-terminated path of at most PATH_MAX bytes into the buffer
    // its third argument points to; `buf` is writable memory of exactly PATH_MAX bytes, and the
    // descriptor is open for the whole call.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    path_of(&buf).ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}
