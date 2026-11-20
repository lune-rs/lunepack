//! Placing a finished document (M3-D9): written to a temporary file in the destination directory,
//! flushed, then moved into place, so a reader sees the old file or the whole new one and never a
//! partial one. Temporary names start with [`TMP_PREFIX`] and are removed on every error path.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// Prefix of every temporary file this module creates.
pub const TMP_PREFIX: &str = ".lunepack-tmp-";

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// How long a rename keeps retrying a transient lock on Windows (M7-D12): a virus scanner or the
/// search indexer holding the temporary file for a moment fails a rename with a sharing violation or
/// "access denied" (os error 5). The same bound and backoff as `lunepack-fs`.
const TRANSIENT_BUDGET: Duration = Duration::from_secs(2);
const TRANSIENT_PAUSE_MIN: Duration = Duration::from_millis(10);
const TRANSIENT_PAUSE_MAX: Duration = Duration::from_millis(500);

/// Whether `e` is a lock another process may release in a moment: on Windows `ERROR_ACCESS_DENIED`
/// (5), `ERROR_SHARING_VIOLATION` (32) and `ERROR_LOCK_VIOLATION` (33); never on other systems.
fn is_transient(e: &io::Error) -> bool {
    cfg!(windows) && matches!(e.raw_os_error(), Some(5 | 32 | 33))
}

/// Runs `op` until it succeeds, fails with an error `transient` does not name, or `deadline` has
/// passed; the last error is returned unchanged.
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

/// `fs::rename` that survives a transient lock on Windows; one plain call elsewhere.
fn rename(from: &Path, to: &Path) -> io::Result<()> {
    retry_until(Instant::now() + TRANSIENT_BUDGET, is_transient, || {
        fs::rename(from, to)
    })
}

/// A temporary file that is removed unless it was moved into place.
struct Temp {
    path: PathBuf,
    keep: bool,
}

impl Drop for Temp {
    fn drop(&mut self) {
        if !self.keep {
            // Best effort: this process created the file, nothing else is removed.
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn write_temp(dest: &Path, bytes: &[u8]) -> Result<Temp> {
    let dir = match dest.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .context("the destination has no usable file name")?;
    // create_new on a unique name: never opens a file this call did not create.
    for _ in 0..16 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("{TMP_PREFIX}{}-{n}-{name}", std::process::id()));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("cannot create a file in {}", dir.display()));
            }
        };
        let temp = Temp { path, keep: false };
        let written = file
            .write_all(bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all());
        drop::<File>(file);
        written.with_context(|| format!("cannot write {}", dest.display()))?;
        return Ok(temp);
    }
    bail!(
        "cannot find a free temporary name next to {}",
        dest.display()
    );
}

/// Writes `bytes` to `path`, which must not exist (create_new semantics). The file appears whole
/// or not at all: the bytes go to a temporary file first, and a hard link (which fails if `path`
/// exists) puts them in place; where the file system has no hard links the fallback checks that
/// `path` is free and renames, which leaves a window in which a racing writer is overwritten.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = write_temp(path, bytes)?;
    match fs::hard_link(&temp.path, path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            bail!("{} already exists", path.display())
        }
        Err(_) => {
            if fs::symlink_metadata(path).is_ok() {
                bail!("{} already exists", path.display());
            }
            let mut temp = temp;
            rename(&temp.path, path).with_context(|| format!("cannot place {}", path.display()))?;
            temp.keep = true;
            Ok(())
        }
    }
}

/// Moves the file `from` to `to`, which must not exist: a hard link (which fails if `to` exists)
/// puts it in place and `from` is then removed; where the file system has no hard links the
/// fallback checks that `to` is free and renames (a racing writer is overwritten in that window,
/// as in [`write_new`]). `from` and `to` must be on one file system.
pub fn move_new(from: &Path, to: &Path) -> Result<()> {
    match fs::hard_link(from, to) {
        Ok(()) => {
            // Best effort: the copy at `to` is complete, and the caller removes its scratch dir.
            let _ = fs::remove_file(from);
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            bail!("{} already exists", to.display())
        }
        Err(_) => {
            if fs::symlink_metadata(to).is_ok() {
                bail!("{} already exists", to.display());
            }
            rename(from, to).with_context(|| format!("cannot place {}", to.display()))
        }
    }
}

/// Writes `bytes` to `path`, replacing it if it exists: temporary file in the same directory, then
/// rename.
pub fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut temp = write_temp(path, bytes)?;
    rename(&temp.path, path).with_context(|| format!("cannot place {}", path.display()))?;
    temp.keep = true;
    Ok(())
}

#[cfg(test)]
mod transient_tests {
    use super::*;
    use std::cell::Cell;

    fn code_7777(e: &io::Error) -> bool {
        e.raw_os_error() == Some(7777)
    }

    #[test]
    fn a_transient_error_is_retried_and_then_succeeds() {
        let tries = Cell::new(0);
        let out = retry_until(Instant::now() + Duration::from_secs(5), code_7777, || {
            tries.set(tries.get() + 1);
            if tries.get() < 3 {
                Err(io::Error::from_raw_os_error(7777))
            } else {
                Ok(())
            }
        });
        assert!(out.is_ok());
        assert_eq!(tries.get(), 3);
    }

    #[test]
    fn the_deadline_returns_the_last_error_and_other_errors_are_not_retried() {
        let out: io::Result<()> = retry_until(
            Instant::now() + Duration::from_millis(100),
            code_7777,
            || Err(io::Error::from_raw_os_error(7777)),
        );
        assert_eq!(out.unwrap_err().raw_os_error(), Some(7777));
        let tries = Cell::new(0);
        let out: io::Result<()> =
            retry_until(Instant::now() + Duration::from_secs(5), code_7777, || {
                tries.set(tries.get() + 1);
                Err(io::Error::from(io::ErrorKind::NotFound))
            });
        assert_eq!(out.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(tries.get(), 1);
    }

    #[test]
    fn replace_and_write_new_keep_their_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.json");
        write_new(&path, b"one").unwrap();
        assert!(write_new(&path, b"two").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"one");
        replace(&path, b"three").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"three");
    }
}
