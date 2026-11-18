//! The transient-lock retry of `StdFs` on Windows (M7-D12): a rename or a removal that fails
//! because another process holds the file for a moment succeeds once the holder lets go, and fails
//! with the original OS error within the bound when it does not. Empty off Windows, where the retry
//! is the identity (its logic is unit-tested in the crate).

#![cfg(windows)]

use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use lunepack_core::{Fs, FsErrorKind};
use lunepack_fs::StdFs;

const FILE_SHARE_READ: u32 = 1;
const ERROR_SHARING_VIOLATION: i32 = 32;

/// Holds `path` open for reading without `FILE_SHARE_DELETE` (so a rename or a delete of it fails
/// with a sharing violation) until `release` receives a message or `max` passes. Returns once the
/// file is held.
fn hold(path: &Path, max: Duration) -> (mpsc::Sender<()>, thread::JoinHandle<()>) {
    let (release, wait) = mpsc::channel::<()>();
    let (held_tx, held_rx) = mpsc::channel::<()>();
    let path = path.to_owned();
    let handle = thread::spawn(move || {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .expect("hold the file");
        held_tx.send(()).unwrap();
        let _ = wait.recv_timeout(max);
        drop(file);
    });
    held_rx.recv().unwrap();
    (release, handle)
}

/// Releases `path` after `after`.
fn hold_for(path: &Path, after: Duration) -> thread::JoinHandle<()> {
    let (release, handle) = hold(path, Duration::from_secs(30));
    thread::spawn(move || {
        thread::sleep(after);
        let _ = release.send(());
    });
    handle
}

#[test]
fn control_a_held_file_cannot_be_renamed_or_removed_with_plain_std() {
    // The instrument: without it the cases below could pass because the file was never held.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("held.bin");
    fs::write(&file, b"x").unwrap();
    let (release, handle) = hold(&file, Duration::from_secs(30));
    let e = fs::rename(&file, dir.path().join("moved.bin")).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(ERROR_SHARING_VIOLATION), "{e}");
    let e = fs::remove_file(&file).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(ERROR_SHARING_VIOLATION), "{e}");
    release.send(()).unwrap();
    handle.join().unwrap();
    fs::rename(&file, dir.path().join("moved.bin")).unwrap();
}

#[test]
fn a_file_released_after_200_ms_is_renamed_and_removed() {
    let dir = tempfile::tempdir().unwrap();
    let from = dir.path().join("a.bin");
    let to = dir.path().join("b.bin");
    fs::write(&from, b"x").unwrap();
    let holder = hold_for(&from, Duration::from_millis(200));
    let started = Instant::now();
    StdFs.rename(&from, &to).expect("renamed after the release");
    assert!(
        started.elapsed() >= Duration::from_millis(150),
        "it must have waited"
    );
    assert!(started.elapsed() < Duration::from_millis(2500));
    holder.join().unwrap();
    assert!(!from.exists() && to.exists());

    let holder = hold_for(&to, Duration::from_millis(200));
    StdFs.remove_file(&to).expect("removed after the release");
    holder.join().unwrap();
    assert!(!to.exists());
}

#[test]
fn a_file_held_for_5_s_fails_with_the_original_code_within_the_bound() {
    let dir = tempfile::tempdir().unwrap();
    let from = dir.path().join("a.bin");
    fs::write(&from, b"x").unwrap();
    let (release, holder) = hold(&from, Duration::from_secs(30));
    for run in 0..2 {
        let started = Instant::now();
        let e = if run == 0 {
            StdFs.rename(&from, &dir.path().join("b.bin")).unwrap_err()
        } else {
            StdFs.remove_file(&from).unwrap_err()
        };
        let took = started.elapsed();
        assert_eq!(e.os_code(), Some(ERROR_SHARING_VIOLATION), "run {run}: {e}");
        assert!(
            took >= Duration::from_millis(1500),
            "run {run}: gave up after {took:?}"
        );
        assert!(
            took <= Duration::from_millis(2500),
            "run {run}: took {took:?}"
        );
    }
    release.send(()).unwrap();
    holder.join().unwrap();
    assert!(from.exists());
}

#[test]
fn a_missing_file_fails_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let started = Instant::now();
    let e = StdFs
        .rename(&dir.path().join("none"), &dir.path().join("other"))
        .unwrap_err();
    assert_eq!(e.kind, FsErrorKind::NotFound);
    let e = StdFs.remove_file(&dir.path().join("none")).unwrap_err();
    assert_eq!(e.kind, FsErrorKind::NotFound);
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_destination_that_exists_is_still_refused_and_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let from = dir.path().join("a.bin");
    let to = dir.path().join("b.bin");
    fs::write(&from, b"new").unwrap();
    fs::write(&to, b"old").unwrap();
    let e = StdFs.rename(&from, &to).unwrap_err();
    assert_eq!(e.kind, FsErrorKind::AlreadyExists);
    assert_eq!(fs::read(&to).unwrap(), b"old");
}

fn tree_of_200(root: &Path) -> std::path::PathBuf {
    let tree = root.join("tree");
    for d in 0..10 {
        let dir = tree.join(format!("d{d}"));
        fs::create_dir_all(&dir).unwrap();
        for f in 0..19 {
            fs::write(dir.join(format!("f{f}")), b"x").unwrap();
        }
    }
    fs::write(tree.join("d9").join("held"), b"x").unwrap();
    tree
}

#[test]
fn a_tree_released_after_200_ms_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let tree = tree_of_200(dir.path());
    let holder = hold_for(&tree.join("d9").join("held"), Duration::from_millis(200));
    StdFs
        .remove_dir_all_nofollow(&tree)
        .expect("removed after the release");
    holder.join().unwrap();
    assert!(!tree.exists());
}

#[test]
fn a_tree_with_one_file_held_for_5_s_fails_within_the_bound_in_total() {
    let dir = tempfile::tempdir().unwrap();
    let tree = tree_of_200(dir.path());
    let (release, holder) = hold(&tree.join("d9").join("held"), Duration::from_secs(30));
    let started = Instant::now();
    let e = StdFs.remove_dir_all_nofollow(&tree).unwrap_err();
    let took = started.elapsed();
    assert!(took <= Duration::from_millis(2500), "took {took:?}");
    assert!(
        took >= Duration::from_millis(1500),
        "gave up after {took:?}"
    );
    assert_eq!(e.os_code(), Some(ERROR_SHARING_VIOLATION), "{e}");
    release.send(()).unwrap();
    holder.join().unwrap();
    StdFs
        .remove_dir_all_nofollow(&tree)
        .expect("removed once nothing holds it");
    assert!(!tree.exists());
}
