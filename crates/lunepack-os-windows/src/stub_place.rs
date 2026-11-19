//! The launcher stub at the install root (M7-D8): `R\<entry file name>` is made byte-equal to the
//! current version's `R\app\<version>\<entry dir>\lunepack-stub.exe`.
//!
//! A running image cannot be replaced or deleted on Windows, but it can be renamed (P-W1, step
//! 0). So the new bytes go to `R\.<name>.new-<16 hex>` first; one replacing rename moves them in
//! when nothing runs the old copy; else the old copy is renamed aside to `R\.<name>.old-<16 hex>`
//! and the new one moved in, and the old copy is removed when it can be (else
//! [`remove_stub_leftovers`] does it later). Every error path this code controls leaves the
//! destination as it was (restored from the aside name when needed); the one uncovered window is
//! a crash between the two renames, which the next apply repairs (the destination is then absent
//! and is simply placed).
//!
//! Nothing here follows a reparse point: the destination and the source are inspected with
//! `symlink_metadata`, and a directory or reparse point at the destination is a conflict.

use std::collections::hash_map::RandomState;
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher as _, Hasher as _};
use std::io::{self, Read as _, Write as _};
use std::os::windows::fs::MetadataExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use lunepack_core::{IntegrationError, IntegrationItem};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

/// The most bytes a stub may have (a launcher is far smaller; the cap bounds the reads).
pub(crate) const MAX_STUB_BYTES: u64 = 64 * 1024 * 1024;

/// How long a rename keeps retrying a transient lock (an anti-virus scan, the indexer), M7-D12.
const RETRY_BUDGET: Duration = Duration::from_secs(2);

/// What is at a path, without following a reparse point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    /// Nothing.
    Absent,
    /// A regular file that is no reparse point.
    File,
    /// A directory, a reparse point (symlink, junction, ...) or anything else.
    Other,
}

/// What is at `path`.
pub(crate) fn probe(path: &Path) -> Result<Slot, IntegrationError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => Ok(Slot::Other),
        Ok(m) if m.is_file() => Ok(Slot::File),
        Ok(_) => Ok(Slot::Other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Slot::Absent),
        Err(_) => Err(IntegrationError::Failed(
            "the launcher stub's place is not readable",
        )),
    }
}

/// Whether `path` is a real directory (no reparse point).
pub(crate) fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|m| m.is_dir() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0)
}

/// Reads at most [`MAX_STUB_BYTES`] of `path`; more is an error.
pub(crate) fn read_capped(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_STUB_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STUB_BYTES {
        return Err(io::Error::other("file too large"));
    }
    Ok(bytes)
}

/// 16 lowercase hex digits, unique enough for a temporary name (each use is `create_new` or
/// checked).
fn random_hex() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = RandomState::new().build_hasher();
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.write_u32(std::process::id());
    if let Ok(t) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        h.write_u128(t.as_nanos());
    }
    format!("{:016x}", h.finish())
}

/// Whether `name` is exactly `.<stub>.old-<16 lowercase hex>` or `.<stub>.new-<16 hex>` for a
/// non-empty `<stub>`.
pub(crate) fn is_leftover_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    if rest.len() < 21 || !rest.is_char_boundary(rest.len() - 21) {
        return false;
    }
    let (stub, tail) = rest.split_at(rest.len() - 21);
    let Some(hex) = tail
        .strip_prefix(".old-")
        .or_else(|| tail.strip_prefix(".new-"))
    else {
        return false;
    };
    !stub.is_empty()
        && hex.len() == 16
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The rename the placement does, replaceable so tests can fail any one of them.
pub(crate) trait Renamer {
    /// Renames `from` to `to`, replacing a file at `to`.
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()>;
}

/// The real rename (`MoveFileExW` with replace, through std).
pub(crate) struct StdRenamer;

impl Renamer for StdRenamer {
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }
}

fn transient(e: &io::Error) -> bool {
    e.raw_os_error().is_some_and(|c| {
        [
            ERROR_ACCESS_DENIED,
            ERROR_SHARING_VIOLATION,
            ERROR_LOCK_VIOLATION,
        ]
        .iter()
        .any(|&t| t as i32 == c)
    })
}

/// `op` retried on a transient lock until [`RETRY_BUDGET`] is spent.
fn retry_transient(mut op: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    let deadline = Instant::now() + RETRY_BUDGET;
    let mut pause = Duration::from_millis(10);
    loop {
        match op() {
            Ok(()) => return Ok(()),
            Err(e) if transient(&e) && Instant::now() + pause < deadline => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(250));
            }
            Err(e) => return Err(e),
        }
    }
}

/// `r.rename` retried on a transient lock until [`RETRY_BUDGET`] is spent.
fn rename_retry(r: &mut dyn Renamer, from: &Path, to: &Path) -> io::Result<()> {
    retry_transient(|| r.rename(from, to))
}

/// Renames `from` over `to` (replacing a file there), retrying a transient lock (a scan, the
/// indexer): for the Start-menu shortcut's write-then-rename.
pub(crate) fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    rename_retry(&mut StdRenamer, from, to)
}

/// Removes the file `path` (an absent file is fine), retrying a transient lock.
pub(crate) fn remove_file_retrying(path: &Path) -> io::Result<()> {
    retry_transient(|| match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    })
}

/// 16 lowercase hex digits for a temporary name (see [`random_hex`]).
pub(crate) fn temp_hex() -> String {
    random_hex()
}

/// Whether the placement changed the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placed {
    /// It already held the new bytes.
    Unchanged,
    /// It was created or replaced.
    Replaced,
}

/// Makes `root\name` hold exactly `bytes` (the source stub's, already read).
pub(crate) fn place_stub(
    root: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<Placed, IntegrationError> {
    place_with(&mut StdRenamer, root, name, bytes)
}

pub(crate) fn place_with(
    r: &mut dyn Renamer,
    root: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<Placed, IntegrationError> {
    const NOT_PLACED: IntegrationError =
        IntegrationError::Failed("the launcher stub was not placed");
    let dst = root.join(name);
    let present = match probe(&dst)? {
        Slot::Absent => false,
        Slot::File => {
            if read_capped(&dst).is_ok_and(|have| have == bytes) {
                return Ok(Placed::Unchanged);
            }
            true
        }
        Slot::Other => return Err(IntegrationError::Conflict(IntegrationItem::Stub)),
    };

    let tmp = write_new(root, name, bytes).map_err(|_| NOT_PLACED)?;
    let discard = |tmp: &Path| {
        let _ = fs::remove_file(tmp);
    };
    if !present {
        return match rename_retry(r, &tmp, &dst) {
            Ok(()) => Ok(Placed::Replaced),
            Err(_) => {
                discard(&tmp);
                Err(NOT_PLACED)
            }
        };
    }
    // One replacing rename, no retry: a running image refuses it every time.
    if r.rename(&tmp, &dst).is_ok() {
        return Ok(Placed::Replaced);
    }
    let old = root.join(format!(".{name}.old-{}", random_hex()));
    if rename_retry(r, &dst, &old).is_err() {
        discard(&tmp);
        return Err(NOT_PLACED);
    }
    if rename_retry(r, &tmp, &dst).is_err() {
        // Put the old copy back; the destination is never left empty on a path this code
        // controls (a failure here as well is the documented double fault).
        let _ = rename_retry(r, &old, &dst);
        discard(&tmp);
        return Err(NOT_PLACED);
    }
    // Fails while the old copy still runs; GC removes it later.
    let _ = fs::remove_file(&old);
    Ok(Placed::Replaced)
}

/// Writes `bytes` to a new `root\.<name>.new-<16 hex>` and flushes it to disk.
fn write_new(root: &Path, name: &str, bytes: &[u8]) -> io::Result<std::path::PathBuf> {
    let mut last = io::Error::other("no name");
    for _ in 0..4 {
        let tmp = root.join(format!(".{name}.new-{}", random_hex()));
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(mut f) => {
                let done = f.write_all(bytes).and_then(|()| f.sync_all());
                drop(f);
                return match done {
                    Ok(()) => Ok(tmp),
                    Err(e) => {
                        let _ = fs::remove_file(&tmp);
                        Err(e)
                    }
                };
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// Removes `root\name` (a stub of an earlier entry name, or the stub at uninstall) when it is a
/// regular file directly in `root`; a running copy is renamed aside for the GC instead. Returns
/// `false` when it is something else (a directory, a reparse point), which is left alone, or
/// when it could be neither removed nor renamed.
pub(crate) fn remove_stub(root: &Path, name: &str) -> Result<bool, IntegrationError> {
    let path = root.join(name);
    match probe(&path)? {
        Slot::Absent => Ok(true),
        Slot::Other => Ok(false),
        Slot::File => {
            if fs::remove_file(&path).is_ok() {
                return Ok(true);
            }
            let old = root.join(format!(".{name}.old-{}", random_hex()));
            Ok(rename_retry(&mut StdRenamer, &path, &old).is_ok())
        }
    }
}

/// Removes the stub placement's leftovers in the install root `root`: regular files directly in
/// `root` named exactly `.<stub>.old-<16 lowercase hex>` or `.<stub>.new-<16 lowercase hex>`.
/// One that cannot be removed (a copy that still runs) is kept for a later call. Nothing else is
/// touched (no directory, no reparse point, so never `.lunepack` or `app`). Returns how many were
/// removed; an unreadable `root` is an error.
pub fn remove_stub_leftovers(root: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_leftover_name(name) {
            continue;
        }
        let path = root.join(name);
        if matches!(probe(&path), Ok(Slot::File)) && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!("lp-stub-{tag}-{}", random_hex()));
            fs::create_dir(&dir).expect("scratch");
            Scratch(dir)
        }
        fn names(&self) -> BTreeSet<String> {
            fs::read_dir(&self.0)
                .expect("list")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Fails the renames whose 1-based call numbers are in `fail`, with a non-transient error.
    struct Faulty {
        call: usize,
        fail: Vec<usize>,
    }

    impl Renamer for Faulty {
        fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
            self.call += 1;
            if self.fail.contains(&self.call) {
                return Err(io::Error::from_raw_os_error(1));
            }
            fs::rename(from, to)
        }
    }

    #[test]
    fn leftover_names_are_matched_exactly() {
        let hex = "0123456789abcdef";
        for ok in [
            format!(".app.exe.old-{hex}"),
            format!(".app.exe.new-{hex}"),
            format!(".My App ü.exe.old-{hex}"),
            format!(".x.old-{hex}"),
        ] {
            assert!(is_leftover_name(&ok), "{ok}");
        }
        for bad in [
            format!("app.exe.old-{hex}"),
            format!("..old-{hex}"),
            format!(".app.exe.old-{}", "0123456789ABCDEF"),
            format!(".app.exe.old-{}", &hex[..15]),
            format!(".app.exe.old-{hex}0"),
            format!(".app.exe.bak-{hex}"),
            ".lunepack".to_owned(),
            "app".to_owned(),
            format!(".app.exe.old-{hex}.exe"),
        ] {
            assert!(!is_leftover_name(&bad), "{bad}");
        }
    }

    #[test]
    fn a_missing_destination_is_placed_and_a_second_place_changes_nothing() {
        let s = Scratch::new("new");
        assert_eq!(
            place_stub(&s.0, "app.exe", b"v1").expect("place"),
            Placed::Replaced
        );
        assert_eq!(fs::read(s.0.join("app.exe")).expect("read"), b"v1");
        assert_eq!(
            place_stub(&s.0, "app.exe", b"v1").expect("again"),
            Placed::Unchanged
        );
        assert_eq!(s.names(), BTreeSet::from(["app.exe".to_owned()]));
    }

    #[test]
    fn a_directory_at_the_destination_is_a_conflict_and_untouched() {
        let s = Scratch::new("dir");
        fs::create_dir(s.0.join("app.exe")).expect("dir");
        let err = place_stub(&s.0, "app.exe", b"v1").expect_err("conflict");
        assert!(
            matches!(err, IntegrationError::Conflict(IntegrationItem::Stub)),
            "{err:?}"
        );
        assert!(s.0.join("app.exe").is_dir());
        assert_eq!(s.names(), BTreeSet::from(["app.exe".to_owned()]));
    }

    #[test]
    fn a_failure_at_each_rename_restores_or_leaves_the_destination() {
        // (failing calls, the destination's bytes afterwards, whether the placement succeeded)
        // Call 1: tmp → dst (replacing); 2: dst → old; 3: tmp → dst; 4: old → dst (restore).
        let cases: &[(&[usize], &[u8], bool)] = &[
            (&[], b"new", true),
            (&[1], b"new", true),
            (&[1, 2], b"old", false),
            (&[1, 3], b"old", false),
        ];
        for (fail, want, ok) in cases {
            let s = Scratch::new("fault");
            fs::write(s.0.join("app.exe"), b"old").expect("old stub");
            let mut r = Faulty {
                call: 0,
                fail: fail.to_vec(),
            };
            let got = place_with(&mut r, &s.0, "app.exe", b"new");
            assert_eq!(got.is_ok(), *ok, "{fail:?}: {got:?}");
            assert_eq!(
                fs::read(s.0.join("app.exe")).expect("dst"),
                *want,
                "{fail:?}"
            );
            assert_eq!(
                s.names(),
                BTreeSet::from(["app.exe".to_owned()]),
                "{fail:?}: a temporary file is left"
            );
        }
    }

    #[test]
    fn a_new_destination_whose_rename_fails_is_left_absent_with_no_temporary() {
        let s = Scratch::new("absent");
        let mut r = Faulty {
            call: 0,
            fail: vec![1],
        };
        place_with(&mut r, &s.0, "app.exe", b"new").expect_err("fails");
        assert!(s.names().is_empty(), "{:?}", s.names());
    }

    #[test]
    fn leftovers_are_removed_and_nothing_else() {
        let s = Scratch::new("gc");
        let hex = "00000000000000ff";
        for f in [
            format!(".app.exe.old-{hex}"),
            format!(".app.exe.new-{hex}"),
            "app.exe".to_owned(),
            // NTFS ignores case, so the uppercase name must differ from the lowercase one.
            format!(".app.exe.old-{}", "0000000000000ABC"),
        ] {
            fs::write(s.0.join(f), b"x").expect("file");
        }
        fs::create_dir(s.0.join(format!(".dir.old-{hex}"))).expect("dir");
        fs::create_dir_all(s.0.join(".lunepack").join("state")).expect("state");
        fs::create_dir(s.0.join("app")).expect("app");
        assert_eq!(remove_stub_leftovers(&s.0).expect("gc"), 2);
        assert_eq!(
            s.names(),
            BTreeSet::from([
                "app.exe".to_owned(),
                ".app.exe.old-0000000000000ABC".to_owned(),
                format!(".dir.old-{hex}"),
                ".lunepack".to_owned(),
                "app".to_owned(),
            ])
        );
    }

    #[test]
    fn remove_stub_takes_a_file_and_leaves_a_directory() {
        let s = Scratch::new("rm");
        fs::write(s.0.join("old.exe"), b"x").expect("file");
        fs::create_dir(s.0.join("dir.exe")).expect("dir");
        assert!(remove_stub(&s.0, "old.exe").expect("file"));
        assert!(!remove_stub(&s.0, "dir.exe").expect("dir"));
        assert!(remove_stub(&s.0, "absent.exe").expect("absent"));
        assert_eq!(s.names(), BTreeSet::from(["dir.exe".to_owned()]));
    }
}
