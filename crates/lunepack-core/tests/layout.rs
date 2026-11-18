//! The per-user layout, the discovery rules and the `current` reconcile (M5-D2, M5-D17, P4).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use lunepack_core::layout::{MAX_TREE_DEPTH, current_target};
use lunepack_core::state::commit_raw_payload;
use lunepack_core::{
    AppId, CurrentRef, DirEntryInfo, Discovery, FileKind, FileWrite, Fs, FsError, FsErrorKind,
    InstallState, LayoutError, LayoutScheme, LockGuard, Meta, NameRule, ReadAt, RelPath,
    RootChoice, Scope, Target, UpdateConfig, UserLayout, UserScope, Version, discover,
    ensure_no_foreign_record, is_tombstone_of, reconcile_current, remove_tombstones, resolve_root,
    root_valid_for_uninstall, tombstone_name, tree_candidates, version_config_path,
    windows_name_ok,
};
use lunepack_testkit::{FakeHasher, MemFs, abs_path, sample_update_config};

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
    discover(&exe, &tree, k, config, LayoutScheme::XDG)
}

#[test]
fn user_layout_names_the_directories_under_the_root() {
    let r = PathBuf::from("/home/u/.local/share/org.example.hello");
    let l = UserLayout::from_root(r.clone(), LayoutScheme::XDG);
    assert_eq!(l.root(), r);
    assert_eq!(l.versions_dir(), r.join("versions"));
    assert_eq!(l.state_dir(), r.join("state"));
    assert_eq!(l.cache_dir(), r.join("cache"));
    assert_eq!(l.logs_dir(), r.join("logs"));
    assert_eq!(l.current_link(), Some(r.join("current")));
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
    let got = discover(
        &exe,
        &abs_path("/y/versions/1.2.0"),
        1,
        &c,
        LayoutScheme::XDG,
    );
    assert!(matches!(got, Err(LayoutError::NotThisTree)), "{got:?}");
    let got = discover(
        Path::new("bin/app"),
        &abs_path("/x"),
        1,
        &c,
        LayoutScheme::XDG,
    );
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

// ---- layout schemes (M7-D2, M7-D18 (a)) -----------------------------------------------------------

#[test]
fn the_windows_scheme_names_app_and_dot_lunepack_and_no_current_link() {
    let r = abs_path("/Programs/Hello App");
    let l = UserLayout::from_root(r.clone(), LayoutScheme::WINDOWS);
    assert_eq!(l.versions_dir(), r.join("app"));
    assert_eq!(l.state_dir(), r.join(".lunepack").join("state"));
    assert_eq!(l.cache_dir(), r.join(".lunepack").join("cache"));
    assert_eq!(l.logs_dir(), r.join(".lunepack").join("logs"));
    assert_eq!(l.current_link(), None);
    assert_eq!(l.version_dir(&v("1.2.0")), r.join("app").join("1.2.0"));
    assert_eq!(
        l.version_config_path(&v("1.2.0")),
        r.join("app").join("1.2.0").join("lunepack-update.json")
    );
    // The same root under XDG keeps M5-D2's names (M7-D18 (a)).
    let x = UserLayout::from_root(r.clone(), LayoutScheme::XDG);
    assert_eq!(
        x.version_config_path(&v("1.2.0")),
        version_config_path(&r, &v("1.2.0"))
    );
}

#[test]
fn from_dirs_recognises_each_scheme_and_nothing_else() {
    let r = abs_path("/r");
    for scheme in [LayoutScheme::XDG, LayoutScheme::WINDOWS] {
        let l = UserLayout::from_root(r.clone(), scheme);
        assert_eq!(
            UserLayout::from_dirs(&l.state_dir(), &l.versions_dir()),
            Some(l.clone())
        );
    }
    // Mixed names, or two roots, are no layout.
    assert_eq!(
        UserLayout::from_dirs(&r.join("state"), &r.join("app")),
        None
    );
    assert_eq!(
        UserLayout::from_dirs(&abs_path("/a/state"), &abs_path("/b/versions")),
        None
    );
}

#[test]
fn reconcile_under_the_windows_scheme_projects_nothing() {
    let fs = MemFs::new();
    let root = abs_path("/Programs/Hello App");
    fs.create_dir_all(&root.join("app").join("1.0.0")).unwrap();
    let l = UserLayout::from_root(root.clone(), LayoutScheme::WINDOWS);
    l.reconcile(&fs, &record(Some("1.0.0"))).unwrap();
    assert_eq!(fs.symlink_metadata(&root.join("current")).unwrap(), None);
    // XDG's reconcile through the layout is reconcile_current's.
    let x = UserLayout::from_root(root.clone(), LayoutScheme::XDG);
    fs.create_dir_all(&root.join("versions").join("1.0.0"))
        .unwrap();
    x.reconcile(&fs, &record(Some("1.0.0"))).unwrap();
    assert_eq!(
        fs.read_link(&root.join("current")).unwrap(),
        "versions/1.0.0"
    );
}

/// `discover` under the Windows scheme: the tree's parent must be `app`, and the root is above it.
#[test]
fn discover_under_the_windows_scheme_finds_r_above_app() {
    let c = config("bin/hello.exe", "1.2.0");
    let exe = abs_path("/P/Hello App/app/1.2.0/bin/hello.exe");
    let tree = abs_path("/P/Hello App/app/1.2.0");
    assert_eq!(
        discover(&exe, &tree, 1, &c, LayoutScheme::WINDOWS).unwrap(),
        Discovery::Installed {
            root: abs_path("/P/Hello App"),
            version: v("1.2.0"),
        }
    );
    // A tree under `versions` (XDG's name) is a bootstrap under WINDOWS, and the reverse.
    let exe = abs_path("/P/Hello App/versions/1.2.0/bin/hello.exe");
    let tree = abs_path("/P/Hello App/versions/1.2.0");
    assert_eq!(
        discover(&exe, &tree, 1, &c, LayoutScheme::WINDOWS).unwrap(),
        Discovery::NotInstalled
    );
    let exe = abs_path("/P/Hello App/app/1.2.0/bin/hello.exe");
    let tree = abs_path("/P/Hello App/app/1.2.0");
    assert_eq!(
        discover(&exe, &tree, 1, &c, LayoutScheme::XDG).unwrap(),
        Discovery::NotInstalled
    );
}

// ---- windows_name_ok (M7-D15) -----------------------------------------------------------------

#[test]
fn windows_name_ok_refuses_each_forbidden_character_and_controls() {
    for c in [
        '<', '>', ':', '"', '/', '\\', '|', '?', '*', '\u{1f}', '\u{0}', '\t',
    ] {
        let name = format!("My{c}App");
        assert_eq!(
            windows_name_ok(&name),
            Err(NameRule::ForbiddenChar),
            "{c:?}"
        );
    }
}

#[test]
fn windows_name_ok_refuses_leading_and_trailing_dots_and_spaces() {
    for name in [" Lunegit", ".Lunegit", "Lunegit.", "Lunegit "] {
        assert_eq!(windows_name_ok(name), Err(NameRule::Edge), "{name:?}");
    }
    assert_eq!(windows_name_ok(""), Err(NameRule::Empty));
}

#[test]
fn windows_name_ok_refuses_device_names_by_stem() {
    for name in [
        "con",
        "Con.txt",
        "COM\u{b9}",
        "lpt9 .x",
        "CONIN$",
        "nul",
        "Aux.tar.gz",
        "COM0",
    ] {
        assert_eq!(windows_name_ok(name), Err(NameRule::DeviceName), "{name:?}");
    }
    for name in [
        "COM10",
        "CONSOLE",
        "Lunegit",
        "My App 2",
        "Lunegit.app",
        "x.con",
    ] {
        assert_eq!(windows_name_ok(name), Ok(()), "{name:?}");
    }
}

#[test]
fn windows_name_ok_counts_utf16_units_with_astral_characters_as_two() {
    let at_64 = format!("{}\u{1f600}", "a".repeat(62));
    assert_eq!(at_64.encode_utf16().count(), 64);
    assert_eq!(windows_name_ok(&at_64), Ok(()));
    let at_65 = format!("{}\u{1f600}", "a".repeat(63));
    assert_eq!(at_65.encode_utf16().count(), 65);
    assert_eq!(windows_name_ok(&at_65), Err(NameRule::TooLong));
    // 64 BMP characters of 2 bytes in UTF-8 each are still 64 units.
    assert_eq!(windows_name_ok(&"\u{e4}".repeat(64)), Ok(()));
    assert_eq!(
        windows_name_ok(&"\u{e4}".repeat(65)),
        Err(NameRule::TooLong)
    );
}

// ---- resolve_root (M7-D16, M7-D17 (a)) ---------------------------------------------------------

const NAME: &str = "Hello App";

fn dh() -> PathBuf {
    abs_path("/home/u/AppData/Local/Programs")
}

fn other_app() -> AppId {
    AppId::parse("com.other.app").unwrap()
}

/// A Windows-layout install of `app` at `root`: its state directory with one committed record.
fn install_at(fs: &MemFs, root: &Path, app: &AppId) {
    let l = UserLayout::from_root(root.to_path_buf(), LayoutScheme::WINDOWS);
    fs.create_dir_all(&l.state_dir()).unwrap();
    let store = UserScope {
        dir: l.state_dir(),
        app_id: app.clone(),
    };
    let loaded = store.load(fs, &FakeHasher).unwrap();
    let rec = InstallState::new(1, app.clone(), Scope::User, [7; 16], Target::WindowsX86_64);
    store.commit(fs, &loaded, &rec, &FakeHasher).unwrap();
}

/// A state directory at `root` whose only record is whole (its checksum passes) but invalid.
fn unreadable_at(fs: &MemFs, root: &Path) {
    let dir = UserLayout::from_root(root.to_path_buf(), LayoutScheme::WINDOWS).state_dir();
    fs.create_dir_all(&dir).unwrap();
    commit_raw_payload(fs, &dir, 1, b"{}", &FakeHasher).unwrap();
}

fn put_file(fs: &MemFs, path: &Path) {
    let mut f = fs.create_new(path).unwrap();
    f.write_all(b"x").unwrap();
    f.sync().unwrap();
}

fn resolve(fs: &dyn Fs, name: &str) -> Result<RootChoice, LayoutError> {
    resolve_root(fs, &FakeHasher, &dh(), &app(), name, LayoutScheme::WINDOWS)
}

fn fallback() -> PathBuf {
    dh().join("Hello App (org.example.hello)")
}

#[test]
fn resolve_root_in_an_empty_or_missing_data_home_is_a_new_folder_named_after_the_app() {
    let fs = MemFs::new();
    assert_eq!(
        resolve(&fs, NAME).unwrap(),
        RootChoice::New(dh().join(NAME))
    );
    fs.create_dir_all(&dh()).unwrap();
    assert_eq!(
        resolve(&fs, NAME).unwrap(),
        RootChoice::New(dh().join(NAME))
    );
}

#[test]
fn resolve_root_finds_an_install_by_record_whatever_its_folder_is_named() {
    // A display-name change: the folder keeps its first name.
    let fs = MemFs::new();
    install_at(&fs, &dh().join("Old Name"), &app());
    assert_eq!(
        resolve(&fs, NAME).unwrap(),
        RootChoice::Existing(dh().join("Old Name"))
    );
    // A user-renamed folder.
    let fs = MemFs::new();
    install_at(&fs, &dh().join("Renamed by the user"), &app());
    install_at(&fs, &dh().join(NAME), &other_app());
    assert_eq!(
        resolve(&fs, NAME).unwrap(),
        RootChoice::Existing(dh().join("Renamed by the user"))
    );
}

#[test]
fn resolve_root_refuses_two_folders_with_this_apps_record() {
    let fs = MemFs::new();
    install_at(&fs, &dh().join(NAME), &app());
    install_at(&fs, &dh().join("Copy of Hello App"), &app());
    assert!(matches!(
        resolve(&fs, NAME),
        Err(LayoutError::InstallAmbiguous)
    ));
}

#[test]
fn resolve_root_moves_beside_a_foreign_install_and_refuses_when_both_names_are_taken() {
    let fs = MemFs::new();
    install_at(&fs, &dh().join(NAME), &other_app());
    assert_eq!(resolve(&fs, NAME).unwrap(), RootChoice::New(fallback()));
    install_at(&fs, &fallback(), &other_app());
    let before = fs.op_count();
    assert!(matches!(resolve(&fs, NAME), Err(LayoutError::FolderTaken)));
    assert_eq!(fs.op_count(), before, "resolution writes nothing");
}

#[test]
fn resolve_root_adopts_an_empty_folder_and_skips_a_non_empty_one() {
    let fs = MemFs::new();
    fs.create_dir_all(&dh().join(NAME)).unwrap();
    assert_eq!(
        resolve(&fs, NAME).unwrap(),
        RootChoice::New(dh().join(NAME))
    );
    put_file(&fs, &dh().join(NAME).join("notes.txt"));
    assert_eq!(resolve(&fs, NAME).unwrap(), RootChoice::New(fallback()));
    // An empty folder at the second name is adopted too.
    fs.create_dir_all(&fallback()).unwrap();
    assert_eq!(resolve(&fs, NAME).unwrap(), RootChoice::New(fallback()));
}

#[test]
fn resolve_root_takes_a_file_or_link_at_the_name_as_taken_and_never_follows_it() {
    let fs = MemFs::new();
    fs.create_dir_all(&dh()).unwrap();
    put_file(&fs, &dh().join(NAME));
    assert_eq!(resolve(&fs, NAME).unwrap(), RootChoice::New(fallback()));

    // A link at the name pointing at a real install of this app: not followed, not found.
    let fs = MemFs::new();
    install_at(&fs, &abs_path("/elsewhere/real"), &app());
    fs.create_dir_all(&dh()).unwrap();
    let target = abs_path("/elsewhere/real");
    fs.symlink(target.to_str().unwrap(), &dh().join(NAME))
        .unwrap();
    assert_eq!(resolve(&fs, NAME).unwrap(), RootChoice::New(fallback()));
}

#[test]
fn resolve_root_refuses_an_unreadable_record_in_the_apps_own_folders_only() {
    let fs = MemFs::new();
    unreadable_at(&fs, &dh().join(NAME));
    assert!(matches!(
        resolve(&fs, NAME),
        Err(LayoutError::InstallUnreadable)
    ));
    // Compared ignoring case (a case-insensitive filesystem has one folder for both).
    let fs = MemFs::new();
    unreadable_at(&fs, &dh().join("hello app"));
    assert!(matches!(
        resolve(&fs, NAME),
        Err(LayoutError::InstallUnreadable)
    ));
    let fs = MemFs::new();
    unreadable_at(&fs, &fallback());
    assert!(matches!(
        resolve(&fs, NAME),
        Err(LayoutError::InstallUnreadable)
    ));
    // In an unrelated folder it is skipped.
    let fs = MemFs::new();
    unreadable_at(&fs, &dh().join("Something Else"));
    assert_eq!(
        resolve(&fs, NAME).unwrap(),
        RootChoice::New(dh().join(NAME))
    );
}

#[test]
fn resolve_root_ignores_dot_entries() {
    let fs = MemFs::new();
    let tomb = dh().join(tombstone_name(&app(), &[1; 8]));
    install_at(&fs, &tomb, &app());
    install_at(&fs, &dh().join(".hidden"), &app());
    assert_eq!(
        resolve(&fs, NAME).unwrap(),
        RootChoice::New(dh().join(NAME))
    );
}

#[test]
fn resolve_root_refuses_a_data_home_over_4096_entries() {
    let fs = MemFs::new();
    for i in 0..4096 {
        fs.create_dir_all(&dh().join(format!("d{i}"))).unwrap();
    }
    assert_eq!(
        resolve(&fs, NAME).unwrap(),
        RootChoice::New(dh().join(NAME))
    );
    fs.create_dir_all(&dh().join("d4096")).unwrap();
    assert!(matches!(
        resolve(&fs, NAME),
        Err(LayoutError::TooManyEntries)
    ));
}

#[test]
fn resolve_root_refuses_a_name_that_fails_the_windows_rule() {
    let fs = MemFs::new();
    assert!(matches!(
        resolve(&fs, "CON"),
        Err(LayoutError::NameNotAllowed(NameRule::DeviceName))
    ));
    assert!(matches!(
        resolve(&fs, "a/b"),
        Err(LayoutError::NameNotAllowed(NameRule::ForbiddenChar))
    ));
}

/// Counts `list_dir` calls and passes everything to a [`MemFs`].
struct CountingFs {
    inner: MemFs,
    lists: AtomicUsize,
}

impl Fs for CountingFs {
    fn read_capped(&self, p: &Path, max: u64) -> Result<Vec<u8>, FsError> {
        self.inner.read_capped(p, max)
    }
    fn open_read(&self, p: &Path) -> Result<Box<dyn ReadAt>, FsError> {
        self.inner.open_read(p)
    }
    fn create_new(&self, p: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        self.inner.create_new(p)
    }
    fn open_append(&self, p: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        self.inner.open_append(p)
    }
    fn truncate(&self, p: &Path, len: u64) -> Result<(), FsError> {
        self.inner.truncate(p, len)
    }
    fn rename(&self, a: &Path, b: &Path) -> Result<(), FsError> {
        self.inner.rename(a, b)
    }
    fn remove_file(&self, p: &Path) -> Result<(), FsError> {
        self.inner.remove_file(p)
    }
    fn remove_dir_all_nofollow(&self, p: &Path) -> Result<(), FsError> {
        self.inner.remove_dir_all_nofollow(p)
    }
    fn create_dir_all(&self, p: &Path) -> Result<(), FsError> {
        self.inner.create_dir_all(p)
    }
    fn list_dir(&self, p: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        self.inner.list_dir(p)
    }
    fn symlink_metadata(&self, p: &Path) -> Result<Option<Meta>, FsError> {
        self.inner.symlink_metadata(p)
    }
    fn sync_dir(&self, p: &Path) -> Result<(), FsError> {
        self.inner.sync_dir(p)
    }
    fn copy_file(&self, a: &Path, b: &Path) -> Result<(), FsError> {
        self.inner.copy_file(a, b)
    }
    fn set_exec(&self, p: &Path, exec: bool) -> Result<(), FsError> {
        self.inner.set_exec(p, exec)
    }
    fn symlink(&self, target: &str, p: &Path) -> Result<(), FsError> {
        self.inner.symlink(target, p)
    }
    fn read_link(&self, p: &Path) -> Result<String, FsError> {
        self.inner.read_link(p)
    }
    fn replace_symlink(&self, target: &str, p: &Path) -> Result<(), FsError> {
        self.inner.replace_symlink(target, p)
    }
    fn try_lock(&self, p: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
        self.inner.try_lock(p)
    }
}

#[test]
fn resolve_root_under_xdg_is_the_app_id_folder_with_no_listing() {
    let fs = CountingFs {
        inner: MemFs::new(),
        lists: AtomicUsize::new(0),
    };
    let xdg = |fs: &CountingFs| {
        resolve_root(fs, &FakeHasher, &dh(), &app(), NAME, LayoutScheme::XDG).unwrap()
    };
    assert_eq!(xdg(&fs), RootChoice::New(dh().join("org.example.hello")));
    // Another app's install named like the display name changes nothing under XDG.
    install_at(&fs.inner, &dh().join(NAME), &other_app());
    fs.inner
        .create_dir_all(&dh().join("org.example.hello").join("state"))
        .unwrap();
    fs.lists.store(0, Ordering::SeqCst);
    assert_eq!(
        xdg(&fs),
        RootChoice::Existing(dh().join("org.example.hello"))
    );
    // Even a name the Windows rule refuses: XDG never names a folder after it.
    assert_eq!(
        resolve_root(&fs, &FakeHasher, &dh(), &app(), "CON", LayoutScheme::XDG)
            .unwrap()
            .into_path(),
        dh().join("org.example.hello")
    );
    assert_eq!(fs.lists.load(Ordering::SeqCst), 0);
}

// ---- the uninstall root rule (M5-D10, M7-D16) ---------------------------------------------------

#[test]
fn the_uninstall_root_rule_under_windows_wants_a_real_folder_directly_in_the_data_home() {
    let fs = MemFs::new();
    let w = LayoutScheme::WINDOWS;
    install_at(&fs, &dh().join(NAME), &app());
    install_at(&fs, &dh().join("Copy of Hello App"), &app());
    install_at(&fs, &abs_path("/elsewhere/Hello App"), &app());
    assert!(root_valid_for_uninstall(
        &fs,
        &dh(),
        &dh().join(NAME),
        &app(),
        w
    ));
    // A copied folder is uninstallable on its own.
    assert!(root_valid_for_uninstall(
        &fs,
        &dh(),
        &dh().join("Copy of Hello App"),
        &app(),
        w
    ));
    // Under another parent, the data home itself, a link (a junction's stand-in), a dot name.
    assert!(!root_valid_for_uninstall(
        &fs,
        &dh(),
        &abs_path("/elsewhere/Hello App"),
        &app(),
        w
    ));
    assert!(!root_valid_for_uninstall(&fs, &dh(), &dh(), &app(), w));
    fs.symlink(
        abs_path("/elsewhere/Hello App").to_str().unwrap(),
        &dh().join("Linked"),
    )
    .unwrap();
    assert!(!root_valid_for_uninstall(
        &fs,
        &dh(),
        &dh().join("Linked"),
        &app(),
        w
    ));
    install_at(&fs, &dh().join(".Hidden"), &app());
    assert!(!root_valid_for_uninstall(
        &fs,
        &dh(),
        &dh().join(".Hidden"),
        &app(),
        w
    ));
}

#[test]
fn the_uninstall_root_rule_under_xdg_is_the_derived_root() {
    let fs = MemFs::new();
    let x = LayoutScheme::XDG;
    let r = dh().join("org.example.hello");
    fs.create_dir_all(&r).unwrap();
    fs.create_dir_all(&dh().join("Hello App")).unwrap();
    assert!(root_valid_for_uninstall(&fs, &dh(), &r, &app(), x));
    assert!(!root_valid_for_uninstall(
        &fs,
        &dh(),
        &dh().join("Hello App"),
        &app(),
        x
    ));
    assert!(!root_valid_for_uninstall(&fs, &dh(), &r, &other_app(), x));
}

// ---- the under-lock re-check (M7-D16 rule 3) -----------------------------------------------------

/// Two apps with one display name both resolve the same new folder; the first to take the lock
/// writes its record, and the second, re-checking under the lock, stops writing nothing.
#[test]
fn two_new_resolutions_for_one_name_let_only_the_first_writer_in() {
    let fs = MemFs::new();
    fs.create_dir_all(&dh()).unwrap();
    let a = resolve_root(&fs, &FakeHasher, &dh(), &app(), NAME, LayoutScheme::WINDOWS).unwrap();
    let b = resolve_root(
        &fs,
        &FakeHasher,
        &dh(),
        &other_app(),
        NAME,
        LayoutScheme::WINDOWS,
    )
    .unwrap();
    assert_eq!(a, RootChoice::New(dh().join(NAME)));
    assert_eq!(a, b);
    let state = UserLayout::from_root(a.into_path(), LayoutScheme::WINDOWS).state_dir();
    // The first writer, under the lock.
    ensure_no_foreign_record(&fs, &FakeHasher, &state, &app()).unwrap();
    install_at(&fs, &dh().join(NAME), &app());
    // The second, under the lock.
    let before = fs.op_count();
    assert!(matches!(
        ensure_no_foreign_record(&fs, &FakeHasher, &state, &other_app()),
        Err(LayoutError::ForeignRecord)
    ));
    assert_eq!(fs.op_count(), before);
    // Its own record (or none) passes.
    ensure_no_foreign_record(&fs, &FakeHasher, &state, &app()).unwrap();
}
