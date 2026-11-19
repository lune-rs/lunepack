//! `StdFs::place`, `exchange`, `create_dir_private` and the xattr-free `copy_file` (M8-D3, D4,
//! D10, D17) on the real filesystem. A binary of its own: these tests start child processes
//! (`hdiutil`, `xattr`, `id`), and a fork inside the contract suite's process can briefly hold a
//! copy of a lock file's descriptor, which made its lock cases flaky.

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;

use lunepack_core::{Fs, FsErrorKind};
use lunepack_fs::StdFs;

fn temp_root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = fs::canonicalize(dir.path()).expect("canonicalize");
    (dir, root)
}

#[cfg(unix)]
mod unix_place {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn place_reports_the_entry_and_its_volume() {
        let (_guard, root) = temp_root();
        let facts = StdFs.place(&root).unwrap();
        assert!(facts.owned_by_caller && facts.writable && !facts.read_only);
        assert!(facts.fs_type.len() <= 15);
        let top = StdFs.place(std::path::Path::new("/")).unwrap();
        assert_ne!(top.inode, 0);
        // A file in the directory is on the same device, with its own inode.
        fs::write(root.join("f"), b"x").unwrap();
        let file = StdFs.place(&root.join("f")).unwrap();
        assert_eq!(file.device, facts.device);
        assert_ne!(file.inode, facts.inode);
        // A directory the caller cannot write is not writable.
        fs::create_dir(root.join("locked")).unwrap();
        fs::set_permissions(root.join("locked"), fs::Permissions::from_mode(0o555)).unwrap();
        let locked = StdFs.place(&root.join("locked")).unwrap();
        assert!(locked.owned_by_caller);
        // Root may or may not write it, by its capabilities (a container drops them); the
        // assertion is for an ordinary user.
        if !euid_is_root() {
            assert!(!locked.writable);
        }
        fs::set_permissions(root.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn euid_is_root() -> bool {
        // `id -u` is the instrument; the test crate holds no unsafe code.
        let out = std::process::Command::new("id").arg("-u").output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim() == "0"
    }

    #[test]
    fn place_of_a_symlink_or_a_missing_path_is_refused() {
        let (_guard, root) = temp_root();
        std::os::unix::fs::symlink(&root, root.join("link")).unwrap();
        assert_eq!(
            StdFs.place(&root.join("link")).unwrap_err().kind,
            FsErrorKind::IsSymlink
        );
        assert_eq!(
            StdFs.place(&root.join("none")).unwrap_err().kind,
            FsErrorKind::NotFound
        );
    }

    #[test]
    fn a_path_with_a_nul_byte_is_an_error_not_a_truncation() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let (_guard, root) = temp_root();
        fs::create_dir(root.join("a")).unwrap();
        // "a\0b" would be read as "a" by a C call that truncated; it must be refused instead.
        let mut bytes = root.join("a").into_os_string().into_vec();
        bytes.extend_from_slice(b"\0b");
        let evil = PathBuf::from(OsString::from_vec(bytes));
        assert_eq!(StdFs.place(&evil).unwrap_err().kind, FsErrorKind::Other);
        assert_eq!(
            StdFs.exchange(&evil, &root.join("a")).unwrap_err().kind,
            if cfg!(target_os = "macos") {
                FsErrorKind::Other
            } else {
                FsErrorKind::Unsupported
            }
        );
        assert!(root.join("a").is_dir());
    }

    #[test]
    fn create_dir_private_makes_one_owner_only_directory() {
        let (_guard, root) = temp_root();
        let dir = root.join("private");
        StdFs.create_dir_private(&dir).unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // An existing directory is reported and never changed.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            StdFs.create_dir_private(&dir).unwrap_err().kind,
            FsErrorKind::AlreadyExists
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            StdFs
                .create_dir_private(&root.join("none/private"))
                .unwrap_err()
                .kind,
            FsErrorKind::NotFound
        );
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::path::Path;
    use std::process::{Command, Stdio};

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn exchange_swaps_two_directories_on_apfs() {
        let (_guard, root) = temp_root();
        let (a, b) = (root.join("a"), root.join("b"));
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        fs::write(a.join("from-a"), b"a").unwrap();
        fs::write(b.join("from-b"), b"b").unwrap();
        let (ia, ib) = (StdFs.place(&a).unwrap(), StdFs.place(&b).unwrap());
        // The temp dir is on the system volume; a swap there must work (APFS), or this Mac's
        // test volume is not what the plan assumed.
        assert_eq!(ia.fs_type, "apfs", "the temp dir is not on APFS");
        StdFs.exchange(&a, &b).unwrap();
        assert_eq!(names(&a), ["from-b"]);
        assert_eq!(names(&b), ["from-a"]);
        // The inodes moved with the contents: the swap is a rename, not a copy.
        assert_eq!(StdFs.place(&a).unwrap().inode, ib.inode);
        assert_eq!(StdFs.place(&b).unwrap().inode, ia.inode);
        // A missing side is NotFound and nothing changes.
        assert_eq!(
            StdFs.exchange(&a, &root.join("none")).unwrap_err().kind,
            FsErrorKind::NotFound
        );
        assert_eq!(
            StdFs.exchange(&root.join("none"), &b).unwrap_err().kind,
            FsErrorKind::NotFound
        );
        assert_eq!(names(&a), ["from-b"]);
    }

    #[test]
    fn exchange_does_not_follow_a_symlink() {
        let (_guard, root) = temp_root();
        fs::create_dir(root.join("real")).unwrap();
        fs::create_dir(root.join("other")).unwrap();
        fs::write(root.join("other/x"), b"x").unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        StdFs
            .exchange(&root.join("link"), &root.join("other"))
            .unwrap();
        // The names swapped; the link is now where `other` was, and still a link to `real`.
        assert!(
            fs::symlink_metadata(root.join("other"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(
            fs::read_link(root.join("other")).unwrap(),
            root.join("real")
        );
        assert_eq!(names(&root.join("link")), ["x"]);
        assert!(names(&root.join("real")).is_empty());
    }

    /// An attached disk image, detached when dropped.
    struct Image {
        mount: PathBuf,
    }

    impl Drop for Image {
        fn drop(&mut self) {
            for force in [false, true] {
                let mut cmd = Command::new("hdiutil");
                cmd.arg("detach");
                if force {
                    cmd.arg("-force");
                }
                let ok = cmd
                    .arg(&self.mount)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if ok {
                    break;
                }
            }
        }
    }

    /// Creates an HFS+ image under `root` and attaches it (hidden from Finder) at `root/mnt`;
    /// `None`, with the reason printed, when `hdiutil` is absent or refuses.
    fn hfs_image(root: &Path, read_only: bool) -> Option<Image> {
        let dmg = root.join("hfs.dmg");
        let mount = root.join("mnt");
        let made = Command::new("hdiutil")
            .args([
                "create",
                "-size",
                "8m",
                "-fs",
                "HFS+",
                "-volname",
                "LunepackFsTest",
            ])
            .arg(&dmg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output();
        match made {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                eprintln!(
                    "skipped: hdiutil create failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                return None;
            }
            Err(e) => {
                eprintln!("skipped: hdiutil is not available: {e}");
                return None;
            }
        }
        fs::create_dir(&mount).unwrap();
        let mut attach = Command::new("hdiutil");
        attach.args([
            "attach",
            "-nobrowse",
            "-noverify",
            "-noautoopen",
            "-mountpoint",
        ]);
        attach.arg(&mount);
        if read_only {
            attach.arg("-readonly");
        }
        let out = attach
            .arg(&dmg)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output();
        match out {
            Ok(o) if o.status.success() => Some(Image { mount }),
            Ok(o) => {
                eprintln!(
                    "skipped: hdiutil attach failed: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                );
                None
            }
            Err(e) => {
                eprintln!("skipped: hdiutil attach failed: {e}");
                None
            }
        }
    }

    #[test]
    fn exchange_on_hfs_plus_is_unsupported_and_changes_nothing() {
        let (_guard, root) = temp_root();
        let Some(image) = hfs_image(&root, false) else {
            return;
        };
        let mount = fs::canonicalize(&image.mount).unwrap();
        let (a, b) = (mount.join("a"), mount.join("b"));
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        fs::write(a.join("from-a"), b"a").unwrap();
        let facts = StdFs.place(&a).unwrap();
        assert!(facts.fs_type.starts_with("hfs"), "{}", facts.fs_type);
        assert_eq!(
            StdFs.exchange(&a, &b).unwrap_err().kind,
            FsErrorKind::Unsupported
        );
        assert_eq!(names(&a), ["from-a"]);
        assert!(names(&b).is_empty());
    }

    #[test]
    fn place_sees_a_read_only_volume() {
        let (_guard, root) = temp_root();
        let Some(image) = hfs_image(&root, true) else {
            return;
        };
        let mount = fs::canonicalize(&image.mount).unwrap();
        let facts = StdFs.place(&mount).unwrap();
        assert!(facts.read_only, "{facts:?}");
        assert!(!facts.writable, "{facts:?}");
        let rw = StdFs.place(&root).unwrap();
        assert_ne!(facts.device, rw.device);
    }

    fn xattrs(path: &Path) -> String {
        let out = Command::new("/usr/bin/xattr").arg(path).output().unwrap();
        assert!(out.status.success(), "xattr failed on a file we made");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn copy_file_drops_extended_attributes_that_std_copy_carries() {
        let (_guard, root) = temp_root();
        let src = root.join("src");
        fs::write(&src, b"payload").unwrap();
        let set = Command::new("/usr/bin/xattr")
            .args(["-w", "com.apple.quarantine", "0081;00000000;Test;"])
            .arg(&src)
            .status()
            .unwrap();
        assert!(set.success());
        assert!(
            xattrs(&src).contains("com.apple.quarantine"),
            "the attribute was not written, so the test would prove nothing"
        );
        // The control: std's copy carries it (probe 8), so the instrument can see an attribute
        // on a copy.
        fs::copy(&src, root.join("std-copy")).unwrap();
        assert!(
            xattrs(&root.join("std-copy")).contains("com.apple.quarantine"),
            "std::fs::copy no longer carries quarantine; revisit M8-D10"
        );
        StdFs.copy_file(&src, &root.join("dst")).unwrap();
        assert_eq!(fs::read(root.join("dst")).unwrap(), b"payload");
        assert_eq!(xattrs(&root.join("dst")).trim(), "");
    }

    #[test]
    fn copy_file_keeps_the_mode_exactly_and_never_overwrites() {
        use std::os::unix::fs::PermissionsExt;
        let (_guard, root) = temp_root();
        let src = root.join("src");
        fs::write(&src, b"run").unwrap();
        for mode in [0o755, 0o700, 0o644, 0o500] {
            fs::set_permissions(&src, fs::Permissions::from_mode(mode)).unwrap();
            let dst = root.join(format!("dst-{mode:o}"));
            StdFs.copy_file(&src, &dst).unwrap();
            assert_eq!(
                fs::metadata(&dst).unwrap().permissions().mode() & 0o7777,
                mode
            );
        }
        assert_eq!(
            StdFs
                .copy_file(&src, &root.join("dst-755"))
                .unwrap_err()
                .kind,
            FsErrorKind::AlreadyExists
        );
        assert_eq!(
            StdFs
                .copy_file(&root.join("none"), &root.join("x"))
                .unwrap_err()
                .kind,
            FsErrorKind::NotFound
        );
        assert!(!root.join("x").exists());
        // A large file crosses the buffer size and arrives whole.
        let big: Vec<u8> = (0..700_000u32).map(|i| (i % 253) as u8).collect();
        fs::write(root.join("big"), &big).unwrap();
        StdFs
            .copy_file(&root.join("big"), &root.join("big2"))
            .unwrap();
        assert_eq!(fs::read(root.join("big2")).unwrap(), big);
    }
}
