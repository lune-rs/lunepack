//! The per-user layout, the discovery rules and the `current` reconcile (M5-D2, M5-D17, P4).

use std::path::{Path, PathBuf};

use lunepack_core::layout::{MAX_TREE_DEPTH, current_target};
use lunepack_core::{
    AppId, CurrentRef, Discovery, FileKind, Fs, FsErrorKind, InstallState, LayoutError, RelPath,
    Scope, Target, UpdateConfig, UserLayout, Version, discover, is_tombstone_of, reconcile_current,
    remove_tombstones, tombstone_name, tree_candidates, version_config_path,
};
use lunepack_testkit::{MemFs, abs_path, sample_update_config};

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn config(entry: &str, version: &str) -> UpdateConfig {
    let mut c = sample_update_config();
    c.install.entry = RelPath::parse(entry).unwrap();
    c.version = v(version);
    c
}

/// `discover` the way the facade drives it: the first candidate of `exe` holding a config is
/// `tree` (given here), at the walk depth `tree_candidates` gives it. A POSIX-form path (`/a`) is
/// made absolute on this platform with `abs_path` (on Windows `/a` has no drive and is not
/// absolute); a Windows form (`C:\a`, `\\?\C:\a`, used by the Windows-only test below) is taken
/// as written.
fn find(exe: &str, tree: &str, config: &UpdateConfig) -> Result<Discovery, LayoutError> {
    let native = |p: &str| {
        if p.starts_with('/') {
            abs_path(p)
        } else {
            PathBuf::from(p)
        }
    };
    let exe = native(exe);
    let want = native(tree);
    let (tree, k) = tree_candidates(&exe)
        .into_iter()
        .find(|(t, _)| *t == want)
        .unwrap_or_else(|| panic!("{} is not a candidate of {}", tree, exe.display()));
    discover(&exe, &tree, k, config)
}

#[test]
fn user_layout_names_the_directories_under_the_root() {
    let r = PathBuf::from("/home/u/.local/share/org.example.hello");
    let l = UserLayout::from_root(r.clone());
    assert_eq!(l.root(), r);
    assert_eq!(l.versions_dir(), r.join("versions"));
    assert_eq!(l.state_dir(), r.join("state"));
    assert_eq!(l.cache_dir(), r.join("cache"));
    assert_eq!(l.logs_dir(), r.join("logs"));
    assert_eq!(l.current_link(), r.join("current"));
    assert_eq!(l.version_dir(&v("1.2.0")), r.join("versions/1.2.0"));
    assert_eq!(l.current_tree(), None);
    assert_eq!(
        version_config_path(&r, &v("1.2.0")),
        r.join("versions/1.2.0/lunepack-update.json")
    );
    assert_eq!(current_target(&v("1.2.0-rc.1")), "versions/1.2.0-rc.1");
}

#[test]
fn tree_candidates_walk_up_from_the_exe_directory() {
    assert_eq!(
        tree_candidates(&abs_path("/a/b/app")),
        vec![
            (abs_path("/a/b"), 0),
            (abs_path("/a"), 1),
            (abs_path("/"), 2),
        ]
    );
    assert_eq!(tree_candidates(&abs_path("/app")), vec![(abs_path("/"), 0)]);
}

#[test]
fn tree_candidates_stop_at_31_and_refuse_a_relative_or_dotted_exe() {
    let mut deep = abs_path("/");
    deep.extend((0..40).map(|i| format!("d{i}")));
    deep.push("app");
    let got = tree_candidates(&deep);
    assert_eq!(got.len(), MAX_TREE_DEPTH + 1);
    assert_eq!(got.last().unwrap().1, MAX_TREE_DEPTH);
    assert_eq!(got[0].0, deep.parent().unwrap());
    assert_eq!(
        got.last().unwrap().0,
        deep.ancestors().nth(MAX_TREE_DEPTH + 1).unwrap()
    );
    // Exactly 31 levels above the exe's directory reaches the root, which is included.
    let mut exact = abs_path("/");
    exact.extend((0..MAX_TREE_DEPTH).map(|i| format!("d{i}")));
    exact.push("app");
    let got = tree_candidates(&exact);
    assert_eq!(got.last().unwrap(), &(abs_path("/"), MAX_TREE_DEPTH));
    for bad in ["app", "bin/app", "./app"] {
        assert!(tree_candidates(Path::new(bad)).is_empty(), "{bad}");
    }
    let dotted = abs_path("/a/../b/app");
    assert!(tree_candidates(&dotted).is_empty(), "{}", dotted.display());
}

const R: &str = "/home/u/.local/share/org.example.hello";

#[test]
fn the_entry_and_the_runtime_beside_it_find_the_installed_tree() {
    for entry in ["app", "bin/app", "a/b/c/app"] {
        let c = config(entry, "1.2.0");
        let tree = format!("{R}/versions/1.2.0");
        let dir = match entry.rsplit_once('/') {
            Some((d, _)) => format!("{tree}/{d}"),
            None => tree.clone(),
        };
        for exe in ["app", "lunepack-runtime", "helper"] {
            let got = find(&format!("{dir}/{exe}"), &tree, &c);
            assert_eq!(
                got.unwrap(),
                Discovery::Installed {
                    root: abs_path(R),
                    version: v("1.2.0"),
                },
                "entry {entry}, exe {exe}"
            );
        }
    }
}

#[test]
fn an_exe_outside_the_entry_directory_is_not_this_tree() {
    let t = format!("{R}/versions/1.2.0");
    let cases = [
        // Above the entry's directory.
        (format!("{t}/a/b/lunepack-runtime"), "a/b/c/app"),
        (format!("{t}/lunepack-runtime"), "bin/app"),
        // Deeper than the entry's directory: the config is found at k 2, not 1.
        (format!("{t}/lib/bin/app"), "bin/app"),
        // The right depth under the wrong component.
        (format!("{t}/sbin/app"), "bin/app"),
        (format!("{t}/Bin/app"), "bin/app"),
        (format!("{t}/a/x/c/app"), "a/b/c/app"),
        // Below the tree with an entry at its root.
        (format!("{t}/bin/app"), "app"),
    ];
    for (exe, entry) in cases {
        assert!(
            matches!(
                find(&exe, &t, &config(entry, "1.2.0")),
                Err(LayoutError::NotThisTree)
            ),
            "exe {exe}, entry {entry}"
        );
    }
}

#[test]
fn a_tree_that_is_not_the_exes_ancestor_is_not_this_tree() {
    let c = config("bin/app", "1.2.0");
    let exe = abs_path("/x/versions/1.2.0/bin/app");
    let got = discover(&exe, &abs_path("/y/versions/1.2.0"), 1, &c);
    assert!(matches!(got, Err(LayoutError::NotThisTree)), "{got:?}");
    let got = discover(Path::new("bin/app"), &abs_path("/x"), 1, &c);
    assert!(matches!(got, Err(LayoutError::NotThisTree)), "{got:?}");
}

#[test]
fn a_tree_not_named_for_its_version_under_versions_is_not_installed() {
    let cases = [
        // A bootstrap tree.
        ("/tmp/boot/hello/bin/app", "/tmp/boot/hello", "1.2.0"),
        // Under another parent.
        ("/opt/old/1.2.0/bin/app", "/opt/old/1.2.0", "1.2.0"),
        (
            "/opt/Versions/1.2.0/bin/app",
            "/opt/Versions/1.2.0",
            "1.2.0",
        ),
        // Named for another version, or only differing in case.
        ("/r/versions/1.2.1/bin/app", "/r/versions/1.2.1", "1.2.0"),
        (
            "/r/versions/1.0.0-rc1/bin/app",
            "/r/versions/1.0.0-rc1",
            "1.0.0-RC1",
        ),
    ];
    for (exe, tree, version) in cases {
        let got = find(exe, tree, &config("bin/app", version));
        assert_eq!(got.unwrap(), Discovery::NotInstalled, "{exe} at {version}");
    }
    // The same text is installed.
    assert_eq!(
        find(
            "/r/versions/1.0.0-RC1/bin/app",
            "/r/versions/1.0.0-RC1",
            &config("bin/app", "1.0.0-RC1")
        )
        .unwrap(),
        Discovery::Installed {
            root: abs_path("/r"),
            version: v("1.0.0-RC1"),
        }
    );
}

#[cfg(windows)]
#[test]
fn windows_forms_are_matched_by_component() {
    let c = config("app.exe", "1.0.0");
    assert_eq!(
        find(r"C:\R\versions\1.0.0\app.exe", r"C:\R\versions\1.0.0", &c).unwrap(),
        Discovery::Installed {
            root: PathBuf::from(r"C:\R"),
            version: v("1.0.0"),
        }
    );
    let c = config("bin/app.exe", "1.0.0");
    assert_eq!(
        find(
            r"\\?\C:\R\versions\1.0.0\bin\app.exe",
            r"\\?\C:\R\versions\1.0.0",
            &c
        )
        .unwrap(),
        Discovery::Installed {
            root: PathBuf::from(r"\\?\C:\R"),
            version: v("1.0.0"),
        }
    );
    assert!(matches!(
        find(
            r"C:\R\versions\1.0.0\sbin\app.exe",
            r"C:\R\versions\1.0.0",
            &c
        ),
        Err(LayoutError::NotThisTree)
    ));
    let roots = tree_candidates(Path::new(r"C:\app.exe"));
    assert_eq!(roots, vec![(PathBuf::from(r"C:\"), 0)]);
}

// ---- reconcile_current --------------------------------------------------------------------------

fn record(current: Option<&str>) -> InstallState {
    let mut s = InstallState::new(
        1,
        AppId::parse("org.example.hello").unwrap(),
        Scope::User,
        [0; 16],
        Target::LinuxX86_64,
    );
    s.current = current.map(|c| CurrentRef {
        version: v(c),
        issued: 1,
    });
    s
}

fn disk() -> (MemFs, PathBuf) {
    let fs = MemFs::new();
    let root = PathBuf::from(R);
    fs.create_dir_all(&root.join("versions/1.0.0")).unwrap();
    (fs, root)
}

#[test]
fn reconcile_creates_and_replaces_the_link_and_leaves_a_right_one() {
    let (fs, root) = disk();
    let link = root.join("current");
    reconcile_current(&fs, &root, &record(Some("1.0.0"))).unwrap();
    assert_eq!(fs.read_link(&link).unwrap(), "versions/1.0.0");
    // A dangling target is fine: the link is derived from the record, never read as truth.
    reconcile_current(&fs, &root, &record(Some("1.1.0"))).unwrap();
    assert_eq!(fs.read_link(&link).unwrap(), "versions/1.1.0");
    let ops = fs.op_count();
    reconcile_current(&fs, &root, &record(Some("1.1.0"))).unwrap();
    assert_eq!(
        fs.op_count() - ops,
        1,
        "only the sync when the link is right"
    );
}

#[test]
fn reconcile_without_a_current_does_nothing() {
    let (fs, root) = disk();
    let ops = fs.op_count();
    reconcile_current(&fs, &root, &record(None)).unwrap();
    assert_eq!(fs.op_count(), ops);
    assert_eq!(fs.symlink_metadata(&root.join("current")).unwrap(), None);
}

#[test]
fn reconcile_refuses_a_file_or_directory_and_deletes_nothing() {
    let (fs, root) = disk();
    let link = root.join("current");
    let mut f = fs.create_new(&link).unwrap();
    f.write_all(b"mine").unwrap();
    f.sync().unwrap();
    drop(f);
    let got = reconcile_current(&fs, &root, &record(Some("1.0.0")));
    assert!(matches!(got, Err(LayoutError::CurrentNotALink)), "{got:?}");
    assert_eq!(fs.read_capped(&link, 100).unwrap(), b"mine");
    fs.remove_file(&link).unwrap();

    fs.create_dir_all(&link.join("inside")).unwrap();
    let got = reconcile_current(&fs, &root, &record(Some("1.0.0")));
    assert!(matches!(got, Err(LayoutError::CurrentNotALink)), "{got:?}");
    assert!(fs.symlink_metadata(&link.join("inside")).unwrap().is_some());
    assert_eq!(
        fs.read_link(&link).unwrap_err().kind,
        FsErrorKind::NotASymlink
    );
}

// ---- tombstones (F18) ------------------------------------------------------------------------

const DATA_HOME: &str = "/home/u/.local/share";

fn app() -> AppId {
    AppId::parse("org.example.hello").unwrap()
}

#[test]
fn a_tombstone_name_is_the_app_id_and_16_hex_digits() {
    let name = tombstone_name(&app(), &[0x00, 0x01, 0x2a, 0x7f, 0x80, 0xab, 0xcd, 0xff]);
    assert_eq!(name, ".org.example.hello.removing-00012a7f80abcdff");
    assert!(is_tombstone_of(&app(), name.as_ref()));
    // R's own name never is one: an app id begins with [a-z0-9].
    assert_eq!(Path::new(R).file_name().unwrap(), "org.example.hello");
    assert!(!is_tombstone_of(&app(), Path::new(R).file_name().unwrap()));
}

#[test]
fn only_the_exact_tombstone_form_of_this_app_id_matches() {
    let other = AppId::parse("org.example").unwrap();
    for name in [
        "org.example.hello",
        ".org.example.hello",
        ".org.example.hello.removing-",
        ".org.example.hello.removing-00012a7f80abcdf",
        ".org.example.hello.removing-00012a7f80abcdff0",
        ".org.example.hello.removing-00012A7F80ABCDFF",
        ".org.example.hello.removing-00012a7f80abcdfg",
        ".org.example.hello.removing-00012a7f80abcdff/x",
        "org.example.hello.removing-00012a7f80abcdff",
        "..org.example.hello.removing-00012a7f80abcdff",
        ".org.example.hello.removing-00012a7f80abcdff.removing-00012a7f80abcdff",
    ] {
        assert!(!is_tombstone_of(&app(), name.as_ref()), "{name}");
    }
    // Another app's tombstone, even one whose id is a prefix of this one's.
    let theirs = tombstone_name(&other, &[1; 8]);
    assert!(!is_tombstone_of(&app(), theirs.as_ref()));
    assert!(!is_tombstone_of(
        &other,
        tombstone_name(&app(), &[1; 8]).as_ref()
    ));
}

#[test]
fn remove_tombstones_removes_only_real_tombstone_directories_without_following_links() {
    let fs = MemFs::new();
    let home = PathBuf::from(DATA_HOME);
    let outside = PathBuf::from("/home/u/keep");
    fs.create_dir_all(&outside).unwrap();
    let mut f = fs.create_new(&outside.join("precious")).unwrap();
    f.write_all(b"mine").unwrap();
    f.sync().unwrap();
    drop(f);

    // A cut-off uninstall's tombstone: part of a tree, with a link pointing outside.
    let t1 = home.join(tombstone_name(&app(), &[1; 8]));
    fs.create_dir_all(&t1.join("versions/1.0.0/bin")).unwrap();
    fs.symlink("/home/u/keep", &t1.join("versions/1.0.0/bin/out"))
        .unwrap();
    // An empty one.
    let t2 = home.join(tombstone_name(&app(), &[2; 8]));
    fs.create_dir_all(&t2).unwrap();
    // What is not ours to remove: R, another app's tombstone, a near miss, a file and a symlink
    // at tombstone names.
    fs.create_dir_all(&PathBuf::from(R).join("state")).unwrap();
    let theirs = home.join(tombstone_name(&AppId::parse("org.other").unwrap(), &[3; 8]));
    fs.create_dir_all(&theirs).unwrap();
    let near = home.join(".org.example.hello.removing-0101");
    fs.create_dir_all(&near).unwrap();
    let file = home.join(tombstone_name(&app(), &[4; 8]));
    let mut f = fs.create_new(&file).unwrap();
    f.write_all(b"x").unwrap();
    f.sync().unwrap();
    drop(f);
    let link = home.join(tombstone_name(&app(), &[5; 8]));
    fs.symlink("/home/u/keep", &link).unwrap();

    remove_tombstones(&fs, &home, &app()).unwrap();

    assert_eq!(fs.symlink_metadata(&t1).unwrap(), None);
    assert_eq!(fs.symlink_metadata(&t2).unwrap(), None);
    assert_eq!(
        fs.read_capped(&outside.join("precious"), 100).unwrap(),
        b"mine"
    );
    let kind = |p: &Path| fs.symlink_metadata(p).unwrap().map(|m| m.kind);
    assert_eq!(kind(&PathBuf::from(R).join("state")), Some(FileKind::Dir));
    assert_eq!(kind(&theirs), Some(FileKind::Dir));
    assert_eq!(kind(&near), Some(FileKind::Dir));
    assert_eq!(kind(&file), Some(FileKind::File));
    assert_eq!(kind(&link), Some(FileKind::Symlink));

    // A second run finds nothing to remove; a missing data home has nothing to remove.
    remove_tombstones(&fs, &home, &app()).unwrap();
    assert_eq!(kind(&theirs), Some(FileKind::Dir));
    remove_tombstones(&fs, Path::new("/nowhere"), &app()).unwrap();
}
