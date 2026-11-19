//! Filesystem adapter implementing the core filesystem trait ([`lunepack_core::Fs`]) over `std`,
//! plus the OS advisory lock through `fs4` (M4-D15). Almost every call is a safe std or `fs4` API.
//! The only `unsafe` code is in `unix_sys.rs` (`faccessat`, `geteuid`, `statfs` / `statvfs` for
//! [`Fs::place`]) and `macos.rs` (`renamex_np` for [`Fs::exchange`]); each block is one libc call
//! on a `CString` with a `// SAFETY:` comment.
//!
//! Care taken beyond plain `std`:
//!
//! - `create_new` never follows a symlink at the final component (`O_CREAT | O_EXCL | O_NOFOLLOW`
//!   on Unix), so a planted dangling link is `AlreadyExists`, not a write through it;
//! - `create_dir_all` refuses a path whose existing component is a symlink or a non-directory, so a
//!   link planted below a trusted directory cannot redirect later writes. Callers pass canonical
//!   base directories (a layout under a symlinked ancestor such as macOS `/var` must be
//!   canonicalised first);
//! - `remove_dir_all_nofollow` removes a symlink itself and never reaches through one;
//! - `copy_file` never overwrites;
//! - `replace_symlink` makes a temporary link in the link's own directory and renames it over the
//!   old one, so a reader sees the old target or the new one; it refuses a file or directory at
//!   the link;
//! - on macOS `copy_file` copies the data and the permission bits with plain reads and writes, so
//!   no extended attribute (`com.apple.quarantine`) reaches the copy (M8-D10; std's copy carries
//!   them);
//! - errors name only the file name of the path (`lunepack_core::FsError`).
//!
//! Transient locks (M7-D12): on Windows a rename or a removal can fail because another process (a
//! virus scanner, the search indexer, a backup) holds a handle for a moment. `rename`,
//! `remove_file`, `remove_dir_all_nofollow` and `replace_symlink`'s rename retry
//! `ERROR_ACCESS_DENIED` (5), `ERROR_SHARING_VIOLATION` (32) and `ERROR_LOCK_VIOLATION` (33) with a
//! backoff from 10 ms to 500 ms, within one deadline of about 2 s per call that every inner
//! removal shares. Nothing else is retried, and the error after the deadline is the last OS error
//! unchanged. On other systems the retry is the identity: the operation runs once.
//!
//! Durability: [`Fs::sync_dir`] is `fsync` on the directory on Unix. On Windows it calls
//! `FlushFileBuffers` on a directory handle (opened with `FILE_FLAG_BACKUP_SEMANTICS` and write
//! access); if the OS or the file system refuses that (`ERROR_ACCESS_DENIED` or
//! `ERROR_INVALID_FUNCTION`) the call returns `Ok`. That a Windows directory flush makes a new
//! entry durable is an assumption this crate has not verified: if it is wrong, a commit may be lost
//! on power loss, never corrupted (the install-state store only ever adds whole files).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use lunepack_core::{
    DirEntryInfo, FileKind, FileWrite, Fs, FsError, FsErrorKind, LockGuard, Meta, PlaceFacts,
    ReadAt,
};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(unix)]
mod unix_sys;

/// `FILE_FLAG_BACKUP_SEMANTICS`: needed to open a directory handle on Windows.
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `ERROR_ACCESS_DENIED` and `ERROR_INVALID_FUNCTION`.
#[cfg(windows)]
const WINDOWS_DIR_FLUSH_REFUSED: [i32; 2] = [5, 1];

/// How long one top-level call keeps retrying a transient lock (M7-D12).
const TRANSIENT_BUDGET: Duration = Duration::from_secs(2);
/// The first pause between two tries of a transient lock; it doubles up to [`TRANSIENT_PAUSE_MAX`].
const TRANSIENT_PAUSE_MIN: Duration = Duration::from_millis(10);
const TRANSIENT_PAUSE_MAX: Duration = Duration::from_millis(500);

/// Makes temporary link names unique within one process.
static TEMP_LINK_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The filesystem of the host, through `std`.
#[derive(Debug, Clone, Copy, Default)]
pub struct StdFs;

impl StdFs {
    /// A new handle (it holds no state).
    pub fn new() -> StdFs {
        StdFs
    }
}

/// Maps an `io::Error` of operation `op` on `path` to an [`FsError`] that names both.
/// How often `read_link` looks again after an EINVAL that a concurrent replace caused.
const READ_LINK_RETRIES: u32 = 16;

/// Whether `e` is a lock another process may release in a moment: on Windows `ERROR_ACCESS_DENIED`
/// (5), `ERROR_SHARING_VIOLATION` (32) and `ERROR_LOCK_VIOLATION` (33); never on other systems.
fn is_transient(e: &io::Error) -> bool {
    cfg!(windows) && matches!(e.raw_os_error(), Some(5 | 32 | 33))
}

/// The deadline of one top-level call, shared by every operation inside it.
fn transient_deadline() -> Instant {
    Instant::now() + TRANSIENT_BUDGET
}

/// Runs `op` (which must be safe to repeat after it failed) until it succeeds, fails with an error
/// `transient` does not name, or `deadline` has passed; the last error is returned unchanged.
fn retry_until<T>(
    deadline: Instant,
    transient: impl Fn(&io::Error) -> bool,
    mut op: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let mut pause = TRANSIENT_PAUSE_MIN;
    loop {
        match op() {
            Err(e) if transient(&e) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(e);
                }
                std::thread::sleep(pause.min(deadline - now));
                pause = (pause * 2).min(TRANSIENT_PAUSE_MAX);
            }
            other => return other,
        }
    }
}

/// [`retry_until`] with [`is_transient`]: the identity off Windows.
fn retry_transient<T>(deadline: Instant, op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    retry_until(deadline, is_transient, op)
}

fn err<'a>(op: &'static str, path: &'a Path) -> impl Fn(io::Error) -> FsError + 'a {
    move |e| FsError::from_io(path, e).during(op)
}

fn kind_of(ft: fs::FileType) -> FileKind {
    if ft.is_symlink() {
        FileKind::Symlink
    } else if ft.is_dir() {
        FileKind::Dir
    } else if ft.is_file() {
        FileKind::File
    } else {
        FileKind::Other
    }
}

fn lstat(path: &Path) -> Result<Option<fs::Metadata>, FsError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(FsError::from_io(path, e).during("lstat")),
    }
}

fn other(path: &Path, what: &'static str) -> FsError {
    FsError::new(FsErrorKind::Other, path, Some(io::Error::other(what)))
}

struct StdReader {
    file: File,
    path: PathBuf,
}

impl ReadAt for StdReader {
    fn size(&self) -> Result<u64, FsError> {
        self.file
            .metadata()
            .map(|m| m.len())
            .map_err(err("metadata", &self.path))
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
        read_exact_at(&self.file, offset, buf).map_err(err("read", &self.path))
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

struct StdWriter {
    file: File,
    path: PathBuf,
}

impl Write for StdWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl FileWrite for StdWriter {
    fn sync(&mut self) -> Result<(), FsError> {
        self.file.sync_all().map_err(err("sync", &self.path))
    }
}

/// An exclusive lock on a file; held while the file is open, so dropping the guard (or the
/// process dying) releases it.
struct StdLock {
    _file: File,
}

impl LockGuard for StdLock {}

impl Fs for StdFs {
    fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
        let file = File::open(path).map_err(err("open", path))?;
        let mut bytes = Vec::new();
        file.take(max.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(err("read", path))?;
        if bytes.len() as u64 > max {
            return Err(FsError::new(FsErrorKind::TooLarge, path, None));
        }
        Ok(bytes)
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
        let file = File::open(path).map_err(err("open", path))?;
        Ok(Box::new(StdReader {
            file,
            path: path.to_owned(),
        }))
    }

    fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path).map_err(err("create", path))?;
        Ok(Box::new(StdWriter {
            file,
            path: path.to_owned(),
        }))
    }

    fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        let file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(err("open", path))?;
        Ok(Box::new(StdWriter {
            file,
            path: path.to_owned(),
        }))
    }

    fn truncate(&self, path: &Path, len: u64) -> Result<(), FsError> {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(err("open", path))?;
        file.set_len(len).map_err(err("truncate", path))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        if lstat(to)?.is_some() {
            return Err(FsError::new(FsErrorKind::AlreadyExists, to, None));
        }
        retry_transient(transient_deadline(), || fs::rename(from, to)).map_err(err("rename", from))
    }

    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        let Some(meta) = lstat(path)? else {
            return Err(FsError::new(FsErrorKind::NotFound, path, None));
        };
        if meta.is_dir() {
            return Err(other(path, "is a directory"));
        }
        remove_link_or_file(path, &meta, transient_deadline())
    }

    fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), FsError> {
        let Some(meta) = lstat(path)? else {
            return Err(FsError::new(FsErrorKind::NotFound, path, None));
        };
        let deadline = transient_deadline();
        if meta.file_type().is_symlink() {
            return remove_link_or_file(path, &meta, deadline);
        }
        if !meta.is_dir() {
            return Err(FsError::new(FsErrorKind::NotADirectory, path, None));
        }
        // std's `remove_dir_all` does not follow symlinks inside the tree: it unlinks them. A lock
        // that fails it is retried as a whole: each try removes what it can and stops at the
        // first entry that is still held, so the tries share the one deadline of this call.
        retry_transient(deadline, || fs::remove_dir_all(path)).map_err(err("remove_dir_all", path))
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component);
            // A bare Windows prefix (`C:`, `\\?\C:`) is not a directory entry to inspect: `C:` means
            // the drive's current directory and `\\?\C:` names the volume device. The root component
            // after it (`\\?\C:\`) is checked as usual.
            if matches!(component, Component::Prefix(_)) {
                continue;
            }
            match lstat(&current)? {
                Some(meta) if meta.file_type().is_symlink() => {
                    return Err(FsError::new(FsErrorKind::IsSymlink, path, None));
                }
                Some(meta) if meta.is_dir() => {}
                Some(_) => return Err(FsError::new(FsErrorKind::NotADirectory, path, None)),
                None => match fs::create_dir(&current) {
                    Ok(()) => {}
                    // Lost a race with another creator: it must be a real directory now.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => match lstat(&current)? {
                        Some(m) if m.is_dir() && !m.file_type().is_symlink() => {}
                        _ => return Err(FsError::new(FsErrorKind::NotADirectory, path, None)),
                    },
                    Err(e) => return Err(FsError::from_io(path, e).during("create_dir")),
                },
            }
        }
        Ok(())
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(path).map_err(err("read_dir", path))? {
            let entry = entry.map_err(err("read_dir", path))?;
            let kind = entry.file_type().map_err(err("read_dir", path))?;
            out.push(DirEntryInfo {
                name: entry.file_name(),
                kind: kind_of(kind),
            });
        }
        Ok(out)
    }

    fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError> {
        Ok(lstat(path)?.map(|m| Meta {
            kind: kind_of(m.file_type()),
            len: m.len(),
        }))
    }

    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        sync_dir(path)
    }

    fn copy_file(&self, from: &Path, to_new: &Path) -> Result<(), FsError> {
        // The destination is a fresh path in a tree this operation owns (under the OS lock), so the
        // gap between this check and the copy is not a race anyone else can win.
        if lstat(to_new)?.is_some() {
            return Err(FsError::new(FsErrorKind::AlreadyExists, to_new, None));
        }
        #[cfg(target_os = "macos")]
        {
            macos::copy_file(from, to_new)
        }
        #[cfg(not(target_os = "macos"))]
        {
            fs::copy(from, to_new).map(drop).map_err(err("copy", from))
        }
    }

    fn set_exec(&self, path: &Path, exec: bool) -> Result<(), FsError> {
        let meta = fs::metadata(path).map_err(err("metadata", path))?;
        set_exec(path, &meta, exec)
    }

    fn symlink(&self, target: &str, link_path: &Path) -> Result<(), FsError> {
        symlink(target, link_path).map_err(err("symlink", link_path))
    }

    fn read_link(&self, path: &Path) -> Result<String, FsError> {
        // `lstat` then `readlink` is two lookups. When `replace_symlink` renames a new link over
        // the one `readlink` found, macOS can answer EINVAL ("not a symlink") for the old,
        // just-unlinked link (seen on the macOS CI runners). EINVAL after an `lstat` that saw a
        // symlink means the entry changed under us: look again, a bounded number of times.
        let mut attempts = 0;
        loop {
            match lstat(path)? {
                None => {
                    return Err(FsError::new(FsErrorKind::NotFound, path, None).during("read_link"));
                }
                Some(meta) if !meta.file_type().is_symlink() => {
                    return Err(
                        FsError::new(FsErrorKind::NotASymlink, path, None).during("read_link")
                    );
                }
                Some(_) => {}
            }
            match fs::read_link(path) {
                Ok(target) => {
                    return target
                        .into_os_string()
                        .into_string()
                        .map_err(|_| other(path, "link target is not UTF-8").during("read_link"));
                }
                Err(e)
                    if e.kind() == io::ErrorKind::InvalidInput && attempts < READ_LINK_RETRIES =>
                {
                    attempts += 1;
                }
                Err(e) => return Err(FsError::from_io(path, e).during("read_link")),
            }
        }
    }

    fn replace_symlink(&self, target: &str, link: &Path) -> Result<(), FsError> {
        // Refuse a file or directory before anything is created. A symlink (dangling or not) or
        // nothing at all is fine. The gap before the rename is not a race this crate can close:
        // the install root is the user's own directory under the state lock.
        if let Some(meta) = lstat(link)?
            && !meta.file_type().is_symlink()
        {
            return Err(
                FsError::new(FsErrorKind::NotASymlink, link, None).during("replace_symlink")
            );
        }
        let parent = link.parent().ok_or_else(|| {
            FsError::new(FsErrorKind::NotFound, link, None).during("replace_symlink")
        })?;
        // A fresh temporary name in the same directory, so the rename is atomic and never crosses
        // a file system. Names do not depend on the link's own name (which may be long).
        let mut temp = None;
        for _ in 0..16 {
            let n = TEMP_LINK_COUNTER.fetch_add(1, Ordering::Relaxed);
            let candidate = parent.join(format!(".lunepack-link-{}-{n}", std::process::id()));
            match symlink(target, &candidate) {
                Ok(()) => {
                    temp = Some(candidate);
                    break;
                }
                // A leftover of an earlier crash with a recycled pid: try the next name.
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(FsError::from_io(link, e).during("symlink")),
            }
        }
        let temp = temp.ok_or_else(|| {
            FsError::new(FsErrorKind::AlreadyExists, link, None).during("replace_symlink")
        })?;
        retry_transient(transient_deadline(), || fs::rename(&temp, link)).map_err(|e| {
            let _ = fs::remove_file(&temp);
            FsError::from_io(link, e).during("rename")
        })
    }

    fn exchange(&self, a: &Path, b: &Path) -> Result<(), FsError> {
        #[cfg(target_os = "macos")]
        {
            macos::exchange(a, b)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = b;
            Err(FsError::new(FsErrorKind::Unsupported, a, None).during("exchange"))
        }
    }

    fn place(&self, path: &Path) -> Result<PlaceFacts, FsError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let Some(meta) = lstat(path)? else {
                return Err(FsError::new(FsErrorKind::NotFound, path, None).during("place"));
            };
            if meta.file_type().is_symlink() {
                return Err(FsError::new(FsErrorKind::IsSymlink, path, None).during("place"));
            }
            let (fs_type, read_only) = unix_sys::volume(path)?;
            Ok(PlaceFacts {
                device: meta.dev(),
                inode: meta.ino(),
                read_only,
                fs_type,
                owned_by_caller: meta.uid() == unix_sys::effective_uid(),
                writable: unix_sys::writable(path)?,
            })
        }
        #[cfg(not(unix))]
        {
            Err(FsError::new(FsErrorKind::Unsupported, path, None).during("place"))
        }
    }

    fn create_dir_private(&self, path: &Path) -> Result<(), FsError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            // One level only (`recursive` is off); the mode only ever loses bits to the umask.
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(err("mkdir", path))
        }
        #[cfg(not(unix))]
        {
            Err(FsError::new(FsErrorKind::Unsupported, path, None).during("mkdir"))
        }
    }

    fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(err("open_lock", path))?;
        // By trait path: `std::fs::File` has inherent `try_lock` and `unlock` since Rust 1.89, which
        // would shadow the trait methods. Only `try_lock` is used; the lock ends with the file.
        match fs4::FileExt::try_lock(&file) {
            Ok(()) => Ok(Some(Box::new(StdLock { _file: file }))),
            Err(fs4::TryLockError::WouldBlock) => Ok(None),
            Err(fs4::TryLockError::Error(e)) => Err(FsError::from_io(path, e).during("lock")),
        }
    }
}

fn remove_link_or_file(path: &Path, meta: &fs::Metadata, deadline: Instant) -> Result<(), FsError> {
    #[cfg(windows)]
    {
        // A symlink to a directory is removed with `remove_dir` on Windows.
        use std::os::windows::fs::FileTypeExt;
        if meta.file_type().is_symlink_dir() {
            return retry_transient(deadline, || fs::remove_dir(path))
                .map_err(err("remove_dir", path));
        }
    }
    let _ = meta;
    retry_transient(deadline, || fs::remove_file(path)).map_err(err("remove_file", path))
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<(), FsError> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(err("sync_dir", path))
}

#[cfg(windows)]
fn sync_dir(path: &Path) -> Result<(), FsError> {
    use std::os::windows::fs::OpenOptionsExt;
    let result = OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .and_then(|dir| dir.sync_all());
    match result {
        Ok(()) => Ok(()),
        // Unverified assumption (module docs): where the OS refuses a directory flush, the commit
        // is not known to be durable, but it is never corrupted.
        Err(e)
            if e.raw_os_error()
                .is_some_and(|c| WINDOWS_DIR_FLUSH_REFUSED.contains(&c)) =>
        {
            Ok(())
        }
        Err(e) => Err(FsError::from_io(path, e).during("sync_dir")),
    }
}

#[cfg(unix)]
fn set_exec(path: &Path, meta: &fs::Metadata, exec: bool) -> Result<(), FsError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode();
    let new = if exec {
        // x wherever r is set.
        mode | ((mode & 0o444) >> 2)
    } else {
        mode & !0o111
    };
    if new == mode {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(new)).map_err(err("set_permissions", path))
}

#[cfg(windows)]
fn set_exec(_path: &Path, _meta: &fs::Metadata, _exec: bool) -> Result<(), FsError> {
    Ok(())
}

#[cfg(unix)]
fn symlink(target: &str, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn symlink(target: &str, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn transient_code(e: &io::Error) -> bool {
        e.raw_os_error() == Some(7777)
    }

    #[test]
    fn a_transient_error_is_retried_until_it_clears() {
        let tries = Cell::new(0);
        let started = Instant::now();
        let out = retry_until(
            Instant::now() + Duration::from_secs(5),
            transient_code,
            || {
                tries.set(tries.get() + 1);
                if tries.get() < 4 {
                    Err(io::Error::from_raw_os_error(7777))
                } else {
                    Ok(tries.get())
                }
            },
        );
        assert_eq!(out.unwrap(), 4);
        // 10 + 20 + 40 ms of backoff, well under a second.
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn the_last_error_is_returned_unchanged_at_the_deadline() {
        let started = Instant::now();
        let out: io::Result<()> = retry_until(
            Instant::now() + Duration::from_millis(150),
            transient_code,
            || Err(io::Error::from_raw_os_error(7777)),
        );
        let e = out.unwrap_err();
        assert_eq!(e.raw_os_error(), Some(7777));
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn another_error_fails_at_once_with_one_try() {
        let tries = Cell::new(0);
        let started = Instant::now();
        let out: io::Result<()> = retry_until(
            Instant::now() + Duration::from_secs(5),
            transient_code,
            || {
                tries.set(tries.get() + 1);
                Err(io::Error::from(io::ErrorKind::NotFound))
            },
        );
        assert_eq!(out.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(tries.get(), 1);
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn the_codes_are_exactly_5_32_and_33_and_only_on_windows() {
        for code in [2, 3, 4, 6, 31, 34, 145, 267] {
            assert!(!is_transient(&io::Error::from_raw_os_error(code)), "{code}");
        }
        for code in [5, 32, 33] {
            assert_eq!(
                is_transient(&io::Error::from_raw_os_error(code)),
                cfg!(windows),
                "{code}"
            );
        }
    }
}
