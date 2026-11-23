//! `set_root_umask`: whatever mask the caller (pkexec keeps it) hands a root process, what that
//! process creates afterwards is readable by everyone and writable by its owner only (M11-D7).
//! Its own test binary with one test: the file-creation mask belongs to the whole process.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

fn mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn a_root_process_creates_world_readable_owner_writable_trees_under_any_caller_mask() {
    let dir = std::env::temp_dir().join(format!("lunepack-umask-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    for (n, caller) in [0o000_u32, 0o077, 0o027, 0o022].into_iter().enumerate() {
        // SAFETY: umask(2) has no preconditions and cannot fail; this binary has one test.
        unsafe { libc::umask(caller as libc::mode_t) };
        let before = lunepack_os_linux::set_root_umask();
        assert_eq!(before, caller, "the caller's mask is what comes back");
        // What the engine's filesystem does: no mode of its own, the std defaults.
        let sub = dir.join(format!("d{n}"));
        fs::DirBuilder::new().mode(0o777).create(&sub).unwrap();
        let file = sub.join("f");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o666)
            .open(&file)
            .unwrap();
        assert_eq!(mode(&sub), 0o755, "directory under caller mask {caller:o}");
        assert_eq!(mode(&file), 0o644, "file under caller mask {caller:o}");
    }
    fs::remove_dir_all(&dir).unwrap();
}
