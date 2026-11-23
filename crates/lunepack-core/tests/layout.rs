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

/// A first install cut off after it took the lock, before its first record: `root` holds only
/// the state directory with `files` in it.
fn cut_off_at(fs: &MemFs, root: &Path, files: &[&str]) {
    let dir = UserLayout::from_root(root.to_path_buf(), LayoutScheme::WINDOWS).state_dir();
    fs.create_dir_all(&dir).unwrap();
    for name in files {
        put_file(fs, &dir.join(name));
    }
}

#[test]
fn resolve_root_resumes_a_first_install_cut_off_before_its_first_record() {
    // Only the lock: this app's own folder, resumed rather than left beside a second copy.
    let fs = MemFs::new();
    cut_off_at(&fs, &dh().join(NAME), &["lock"]);
    let before = fs.op_count();
    assert_eq!(
        resolve(&fs, NAME).unwrap(),
        RootChoice::New(dh().join(NAME))
    );
    assert_eq!(fs.op_count(), before, "resolution writes nothing");
    // A torn record file next to the lock is still only what a cut-off run leaves.
    let fs = MemFs::new();
    cut_off_at(&fs, &dh().join(NAME), &["lock", "00000000000000000001.rec"]);
    assert_eq!(
        resolve(&fs, NAME).unwrap(),
        RootChoice::New(dh().join(NAME))
    );
    // The same at the second name, when the first is another app's.
    let fs = MemFs::new();
    install_at(&fs, &dh().join(NAME), &other_app());
    cut_off_at(&fs, &fallback(), &["lock"]);
    assert_eq!(resolve(&fs, NAME).unwrap(), RootChoice::New(fallback()));
}

#[test]
fn resolve_root_keeps_a_folder_with_anything_foreign_taken() {
    // A file beside the state directory.
    let fs = MemFs::new();
    cut_off_at(&fs, &dh().join(NAME), &["lock"]);
    put_file(&fs, &dh().join(NAME).join("notes.txt"));
    assert_eq!(resolve(&fs, NAME).unwrap(), RootChoice::New(fallback()));
    // A file beside the state directory's own parent (`.lunepack`).
    let fs = MemFs::new();
    cut_off_at(&fs, &dh().join(NAME), &["lock"]);
    put_file(&fs, &dh().join(NAME).join(".lunepack").join("notes.txt"));
    assert_eq!(resolve(&fs, NAME).unwrap(), RootChoice::New(fallback()));
    // A foreign file in the state directory.
    let fs = MemFs::new();
    cut_off_at(&fs, &dh().join(NAME), &["lock", "notes.txt"]);
    assert_eq!(resolve(&fs, NAME).unwrap(), RootChoice::New(fallback()));
    // Another app's whole record beside the lock is an install, not a leftover.
    let fs = MemFs::new();
    install_at(&fs, &dh().join(NAME), &other_app());
    let state = UserLayout::from_root(dh().join(NAME), LayoutScheme::WINDOWS).state_dir();
    put_file(&fs, &state.join("lock"));
    assert_eq!(resolve(&fs, NAME).unwrap(), RootChoice::New(fallback()));
    // Both names hold a leftover that is not ours to resume: refused as before.
    let fs = MemFs::new();
    cut_off_at(&fs, &dh().join(NAME), &["lock", "notes.txt"]);
    cut_off_at(&fs, &fallback(), &["lock", "notes.txt"]);
    assert!(matches!(resolve(&fs, NAME), Err(LayoutError::FolderTaken)));
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

// ---- macOS bundles (M8-D1, M8-D3, M8-D4, M8-D16, M8-D17) ----------------------------------------

mod bundle {
    use std::io::Write as _;
    use std::path::{Path, PathBuf};

    use lunepack_core::layout::{BUNDLE_ID_FILE, OUT_SLOT, SWAP_SLOT};
    use lunepack_core::{
        AppId, BundleDiscovery, BundleProbe, CurrentRef, FileKind, Fs, FsErrorKind, InstallState,
        LayoutError, LayoutScheme, LocationReason, NameRule, PlaceFacts, RelPath, Scope, Target,
        UpdateConfig, UserLayout, UserScope, Version, check_place, discover_bundle, macos_name_ok,
        read_bundle_identity, reconcile_bundle, resolve_bundle_target, root_valid_for_uninstall,
        set_bundle_pointer, tree_candidates, write_bundle_identity,
    };
    use lunepack_testkit::{
        FakeHasher, MemFs, MemPlace, RecoverMode, abs_path, sample_update_config,
    };

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    fn app() -> AppId {
        sample_update_config().app_id
    }

    fn home() -> PathBuf {
        abs_path("/Users/u")
    }

    fn data_home_of(home: &Path) -> PathBuf {
        home.join("Library").join("Application Support")
    }

    fn data_home() -> PathBuf {
        data_home_of(&home())
    }

    fn apps() -> PathBuf {
        home().join("Applications")
    }

    fn bundle() -> PathBuf {
        apps().join("Hello.app")
    }

    fn layout_in(data_home: &Path) -> UserLayout {
        UserLayout::from_root(data_home.join(app().as_str()), LayoutScheme::MACOS)
    }

    fn layout() -> UserLayout {
        layout_in(&data_home())
    }

    fn mac_config(version: &str) -> UpdateConfig {
        let mut c = sample_update_config();
        c.version = v(version);
        c.target = Target::MacosAarch64;
        c.install.entry = RelPath::parse("Contents/MacOS/hello").unwrap();
        c
    }

    fn put_file(fs: &dyn Fs, path: &Path, bytes: &[u8]) {
        fs.create_dir_all(path.parent().unwrap()).unwrap();
        let mut f = fs.create_new(path).unwrap();
        f.write_all(bytes).unwrap();
        f.sync().unwrap();
    }

    fn config_file(tree: &Path) -> PathBuf {
        tree.join("Contents")
            .join("Resources")
            .join("lunepack-update.json")
    }

    fn put_tree_of(fs: &dyn Fs, tree: &Path, config: &UpdateConfig) {
        put_file(fs, &config_file(tree), &config.to_bytes().unwrap());
        let exe = tree.join("Contents").join("MacOS").join("hello");
        put_file(fs, &exe, config.version.to_string().as_bytes());
    }

    fn put_tree(fs: &dyn Fs, tree: &Path, version: &str) {
        put_tree_of(fs, tree, &mac_config(version));
    }

    /// The version the tree at `path` holds by its own config; `None` when nothing is there.
    fn version_at(fs: &dyn Fs, path: &Path) -> Option<String> {
        match fs.symlink_metadata(path).unwrap() {
            Some(m) if m.kind == FileKind::Dir => {}
            _ => return None,
        }
        let bytes = fs.read_capped(&config_file(path), 1 << 16).ok()?;
        Some(UpdateConfig::parse(&bytes).unwrap().version.to_string())
    }

    fn record(current: &str) -> InstallState {
        let mut s = InstallState::new(1, app(), Scope::User, [0; 16], Target::MacosAarch64);
        s.current = Some(CurrentRef {
            version: v(current),
            issued: 1,
        });
        s
    }

    fn store(fs: &MemFs, l: &UserLayout, rec: &InstallState) {
        let store = UserScope {
            dir: l.state_dir(),
            app_id: app(),
        };
        let loaded = store.load(fs, &FakeHasher).unwrap();
        store.commit(fs, &loaded, rec, &FakeHasher).unwrap();
    }

    /// A macOS install: `R` with its versions and state directories, the apps folder, `R/bundle`
    /// pointing at `Hello.app`, which holds `live` (`None`: not placed yet), and
    /// `versions/<v>` for each of `kept`. The identity is written when the bundle exists.
    fn installed(live: Option<&str>, kept: &[&str]) -> (MemFs, UserLayout) {
        let fs = MemFs::new();
        let l = layout();
        fs.create_dir_all(&l.versions_dir()).unwrap();
        fs.create_dir_all(&l.state_dir()).unwrap();
        fs.create_dir_all(&apps()).unwrap();
        if let Some(version) = live {
            put_tree(&fs, &bundle(), version);
        }
        for version in kept {
            put_tree(&fs, &l.version_dir(&v(version)), version);
        }
        set_bundle_pointer(&fs, &l, &bundle()).unwrap();
        if live.is_some() {
            write_bundle_identity(&fs, &l, &bundle()).unwrap();
        }
        (fs, l)
    }

    /// Every entry of the apps folder and the versions directory with the version its tree holds.
    fn snapshot(fs: &MemFs, l: &UserLayout) -> Vec<(PathBuf, Option<String>)> {
        let mut out = Vec::new();
        for dir in [apps(), l.versions_dir()] {
            let Ok(entries) = fs.list_dir(&dir) else {
                continue;
            };
            for e in entries {
                let path = dir.join(&e.name);
                let held = version_at(fs, &path);
                out.push((path, held));
            }
        }
        out.sort();
        out
    }

    /// The end state of a reconcile to `want`: the bundle holds it, `versions/<previous>` holds
    /// the previous version, no slot is left, the identity is the bundle's and no temporary
    /// identity file is left.
    fn assert_end(fs: &MemFs, l: &UserLayout, want: &str, previous: Option<&str>, what: &str) {
        assert_eq!(
            version_at(fs, &bundle()).as_deref(),
            Some(want),
            "{what}: the bundle"
        );
        if let Some(p) = previous {
            assert_eq!(
                version_at(fs, &l.version_dir(&v(p))).as_deref(),
                Some(p),
                "{what}: versions/{p}"
            );
        }
        assert_eq!(
            version_at(fs, &l.version_dir(&v(want))),
            None,
            "{what}: the current version is in the bundle only"
        );
        for slot in [l.swap_slot(), l.out_slot()] {
            assert_eq!(fs.symlink_metadata(&slot).unwrap(), None, "{what}: a slot");
        }
        let facts = fs.place(&bundle()).unwrap();
        assert_eq!(
            read_bundle_identity(fs, l).unwrap(),
            Some((facts.device, facts.inode)),
            "{what}: the identity"
        );
        assert_eq!(
            fs.symlink_metadata(&l.root().join("bundle.id.tmp"))
                .unwrap(),
            None,
            "{what}: a temporary identity"
        );
    }

    /// Reconciles `rec` over `setup()`'s disk once whole, then once per mutating op cut short at
    /// that op (a crash: the disk as the process left it), followed by a fresh reconcile, and
    /// checks the end state every time. Returns the whole run's op count.
    fn every_cut(
        what: &str,
        setup: &dyn Fn() -> (MemFs, UserLayout),
        rec: &InstallState,
        exchange: bool,
        end: &dyn Fn(&MemFs, &UserLayout, &str),
    ) -> u64 {
        let (fs, l) = setup();
        fs.set_exchange_supported(exchange);
        let start = fs.op_count();
        reconcile_bundle(&fs, &l, rec).unwrap();
        let ops = fs.op_count() - start;
        end(&fs, &l, &format!("{what}: whole"));
        assert!(ops > 0, "{what}: nothing moved");
        for k in 0..ops {
            let (fs, l) = setup();
            fs.set_exchange_supported(exchange);
            fs.crash_after(fs.op_count() + k);
            assert!(
                reconcile_bundle(&fs, &l, rec).is_err(),
                "{what}: the cut at op {k} did not stop it"
            );
            let after = fs.recover(RecoverMode::KeepVolatile);
            reconcile_bundle(&after, &l, rec)
                .unwrap_or_else(|e| panic!("{what}: after the cut at op {k}: {e:?}"));
            end(&after, &l, &format!("{what}: cut at op {k}"));
            // At the end state a reconcile changes nothing and writes nothing.
            let before = after.op_count();
            reconcile_bundle(&after, &l, rec).unwrap();
            assert_eq!(after.op_count(), before, "{what}: cut at op {k}: not idle");
        }
        ops
    }

    #[test]
    fn apply_swaps_the_new_version_in_from_every_cut_on_both_paths() {
        let setup = || installed(Some("1.0.0"), &["2.0.0"]);
        let end = |fs: &MemFs, l: &UserLayout, what: &str| {
            assert_end(fs, l, "2.0.0", Some("1.0.0"), what);
        };
        let swap = every_cut("apply, exchange", &setup, &record("2.0.0"), true, &end);
        let renames = every_cut("apply, two renames", &setup, &record("2.0.0"), false, &end);
        assert!(renames > swap, "the two-rename path makes more moves");
    }

    #[test]
    fn rollback_swaps_the_previous_version_back_from_every_cut_on_both_paths() {
        let setup = || installed(Some("2.0.0"), &["1.0.0"]);
        let end = |fs: &MemFs, l: &UserLayout, what: &str| {
            assert_end(fs, l, "1.0.0", Some("2.0.0"), what);
        };
        every_cut("rollback, exchange", &setup, &record("1.0.0"), true, &end);
        every_cut(
            "rollback, two renames",
            &setup,
            &record("1.0.0"),
            false,
            &end,
        );
    }

    #[test]
    fn the_first_placement_is_one_rename_and_converges_from_every_cut() {
        let setup = || installed(None, &["1.0.0"]);
        let end = |fs: &MemFs, l: &UserLayout, what: &str| {
            assert_end(fs, l, "1.0.0", None, what);
        };
        for exchange in [true, false] {
            every_cut("first placement", &setup, &record("1.0.0"), exchange, &end);
        }
        // The placement renames the tree itself: the bundle is versions/1.0.0's directory.
        let (fs, l) = setup();
        let inode = fs.place(&l.version_dir(&v("1.0.0"))).unwrap().inode;
        reconcile_bundle(&fs, &l, &record("1.0.0")).unwrap();
        assert_eq!(fs.place(&bundle()).unwrap().inode, inode);
    }

    #[test]
    fn a_crash_after_the_swap_before_the_identity_is_healed_by_the_next_reconcile() {
        let (fs, l) = installed(Some("1.0.0"), &["2.0.0"]);
        let old = read_bundle_identity(&fs, &l).unwrap();
        // Run up to the identity write: the moves are done, the identity is the old bundle's.
        let start = fs.op_count();
        reconcile_bundle(&fs, &l, &record("2.0.0")).unwrap();
        let ops = fs.op_count() - start;
        let (fs, l) = installed(Some("1.0.0"), &["2.0.0"]);
        // The identity write is the last five ops (create, write, sync, remove, rename) and a
        // sync: cut at its first.
        fs.crash_after(fs.op_count() + ops - 6);
        assert!(reconcile_bundle(&fs, &l, &record("2.0.0")).is_err());
        let after = fs.recover(RecoverMode::KeepVolatile);
        assert_eq!(version_at(&after, &bundle()).as_deref(), Some("2.0.0"));
        assert_eq!(
            read_bundle_identity(&after, &l).unwrap(),
            old,
            "still the old identity"
        );
        reconcile_bundle(&after, &l, &record("2.0.0")).unwrap();
        assert_end(&after, &l, "2.0.0", Some("1.0.0"), "healed");
        assert_ne!(read_bundle_identity(&after, &l).unwrap(), old);
    }

    #[test]
    fn a_stray_tree_in_the_slot_is_parked_under_its_own_version() {
        let (fs, l) = installed(Some("2.0.0"), &["1.0.0"]);
        put_tree(&fs, &l.swap_slot(), "3.0.0");
        reconcile_bundle(&fs, &l, &record("2.0.0")).unwrap();
        assert_end(&fs, &l, "2.0.0", Some("1.0.0"), "stray");
        assert_eq!(
            version_at(&fs, &l.version_dir(&v("3.0.0"))).as_deref(),
            Some("3.0.0")
        );
    }

    #[test]
    fn a_two_rename_cut_with_the_bundle_empty_is_finished_from_the_slots() {
        // B -> .out done, .swap -> B not yet.
        let (fs, l) = installed(None, &[]);
        put_tree(&fs, &l.out_slot(), "1.0.0");
        put_tree(&fs, &l.swap_slot(), "2.0.0");
        reconcile_bundle(&fs, &l, &record("2.0.0")).unwrap();
        assert_end(&fs, &l, "2.0.0", Some("1.0.0"), "finished");
        // The record rolled back meanwhile: the old tree in .out goes back in.
        let (fs, l) = installed(None, &[]);
        put_tree(&fs, &l.out_slot(), "1.0.0");
        put_tree(&fs, &l.swap_slot(), "2.0.0");
        reconcile_bundle(&fs, &l, &record("1.0.0")).unwrap();
        assert_end(&fs, &l, "1.0.0", Some("2.0.0"), "rolled back");
    }

    #[test]
    fn a_missing_or_foreign_current_tree_is_bundle_missing_and_nothing_moves() {
        let (fs, l) = installed(Some("1.0.0"), &[]);
        let before = snapshot(&fs, &l);
        let got = reconcile_bundle(&fs, &l, &record("2.0.0"));
        assert!(matches!(got, Err(LayoutError::BundleMissing)), "{got:?}");
        assert_eq!(snapshot(&fs, &l), before);

        let (fs, l) = installed(Some("1.0.0"), &[]);
        let mut foreign = mac_config("2.0.0");
        foreign.app_id = AppId::parse("com.other.app").unwrap();
        put_tree_of(&fs, &l.version_dir(&v("2.0.0")), &foreign);
        let before = snapshot(&fs, &l);
        let got = reconcile_bundle(&fs, &l, &record("2.0.0"));
        assert!(matches!(got, Err(LayoutError::BundleMissing)), "{got:?}");
        assert_eq!(snapshot(&fs, &l), before);
    }

    #[test]
    fn a_foreign_tree_at_the_bundle_or_in_a_slot_is_refused_and_nothing_moves() {
        let mut foreign = mac_config("3.0.0");
        foreign.app_id = AppId::parse("com.other.app").unwrap();
        let (fs, l) = installed(Some("1.0.0"), &["2.0.0"]);
        put_tree_of(&fs, &l.swap_slot(), &foreign);
        let before = snapshot(&fs, &l);
        let got = reconcile_bundle(&fs, &l, &record("2.0.0"));
        assert!(matches!(got, Err(LayoutError::ForeignTree)), "{got:?}");
        assert_eq!(snapshot(&fs, &l), before);
    }

    #[test]
    fn parking_onto_an_existing_version_is_duplicate_and_nothing_moves() {
        let (fs, l) = installed(Some("2.0.0"), &["1.0.0"]);
        put_tree(&fs, &l.swap_slot(), "1.0.0");
        let before = snapshot(&fs, &l);
        let got = reconcile_bundle(&fs, &l, &record("2.0.0"));
        assert!(matches!(got, Err(LayoutError::Duplicate)), "{got:?}");
        assert_eq!(snapshot(&fs, &l), before);
    }

    #[test]
    fn a_symlink_where_a_tree_should_be_is_refused_and_nothing_moves() {
        // At the bundle.
        let (fs, l) = installed(None, &["1.0.0"]);
        fs.symlink("../versions-elsewhere", &bundle()).unwrap();
        let before = snapshot(&fs, &l);
        let got = reconcile_bundle(&fs, &l, &record("1.0.0"));
        assert!(matches!(got, Err(LayoutError::NotATree)), "{got:?}");
        assert_eq!(snapshot(&fs, &l), before);
        // In the swap slot.
        let (fs, l) = installed(Some("1.0.0"), &["2.0.0"]);
        fs.symlink("2.0.0", &l.swap_slot()).unwrap();
        let before = snapshot(&fs, &l);
        let got = reconcile_bundle(&fs, &l, &record("2.0.0"));
        assert!(matches!(got, Err(LayoutError::NotATree)), "{got:?}");
        assert_eq!(snapshot(&fs, &l), before);
        // A config inside a tree that is a symlink is never followed: the tree is not the
        // current version's.
        let (fs, l) = installed(Some("1.0.0"), &[]);
        let t = l.version_dir(&v("2.0.0"));
        put_tree(&fs, &home().join("elsewhere"), "2.0.0");
        fs.create_dir_all(&t.join("Contents").join("Resources"))
            .unwrap();
        fs.symlink(
            &config_file(&home().join("elsewhere")).to_string_lossy(),
            &config_file(&t),
        )
        .unwrap();
        let before = snapshot(&fs, &l);
        let got = reconcile_bundle(&fs, &l, &record("2.0.0"));
        assert!(matches!(got, Err(LayoutError::BundleMissing)), "{got:?}");
        assert_eq!(snapshot(&fs, &l), before);
        // The same at the bundle is unreadable.
        let (fs, l) = installed(Some("1.0.0"), &["2.0.0"]);
        fs.remove_file(&config_file(&bundle())).unwrap();
        fs.symlink(
            &config_file(&home().join("elsewhere")).to_string_lossy(),
            &config_file(&bundle()),
        )
        .unwrap();
        let before = snapshot(&fs, &l);
        let got = reconcile_bundle(&fs, &l, &record("2.0.0"));
        assert!(matches!(got, Err(LayoutError::TreeUnreadable)), "{got:?}");
        assert_eq!(snapshot(&fs, &l), before);
    }

    #[test]
    fn an_orphaned_install_is_reported_and_nothing_is_renamed() {
        let (fs, l) = installed(None, &["1.0.0"]);
        put_tree(&fs, &l.swap_slot(), "3.0.0");
        let before = snapshot(&fs, &l);
        let ops = fs.op_count();
        let got = reconcile_bundle(&fs, &l, &record("2.0.0"));
        assert!(matches!(got, Err(LayoutError::Orphaned)), "{got:?}");
        assert_eq!(snapshot(&fs, &l), before);
        assert_eq!(fs.op_count(), ops, "nothing written");
    }

    #[test]
    fn reconcile_without_a_current_version_does_nothing() {
        let (fs, l) = installed(Some("1.0.0"), &["2.0.0"]);
        let ops = fs.op_count();
        let mut rec = record("1.0.0");
        rec.current = None;
        reconcile_bundle(&fs, &l, &rec).unwrap();
        l.reconcile(&fs, &rec).unwrap();
        assert_eq!(fs.op_count(), ops);
    }

    #[test]
    fn the_layout_reconcile_under_macos_is_the_bundle_reconcile() {
        let (fs, l) = installed(Some("1.0.0"), &["2.0.0"]);
        l.reconcile(&fs, &record("2.0.0")).unwrap();
        assert_end(&fs, &l, "2.0.0", Some("1.0.0"), "via UserLayout");
    }

    // ---- the pointer ----------------------------------------------------------------------

    #[test]
    fn a_pointer_that_is_not_a_canonical_app_path_is_refused_not_repaired() {
        let link = layout().bundle_link().unwrap();
        let cases: Vec<(&str, String)> = vec![
            ("relative", "Applications/Hello.app".to_owned()),
            (
                "no .app",
                apps().join("Hello").to_string_lossy().into_owned(),
            ),
            (
                "dot-dot",
                apps()
                    .join("..")
                    .join("Applications")
                    .join("Hello.app")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "only .app",
                apps().join(".app").to_string_lossy().into_owned(),
            ),
            (
                "through a symlink",
                home()
                    .join("Apps")
                    .join("Hello.app")
                    .to_string_lossy()
                    .into_owned(),
            ),
        ];
        for (what, target) in cases {
            let (fs, l) = installed(Some("1.0.0"), &["2.0.0"]);
            fs.symlink("Applications", &home().join("Apps")).unwrap();
            fs.replace_symlink(&target, &link).unwrap();
            let before = snapshot(&fs, &l);
            let got = l.bundle_path(&fs);
            assert!(
                matches!(got, Err(LayoutError::BundlePointer)),
                "{what}: {got:?}"
            );
            let got = reconcile_bundle(&fs, &l, &record("2.0.0"));
            assert!(
                matches!(got, Err(LayoutError::BundlePointer)),
                "{what}: {got:?}"
            );
            assert_eq!(snapshot(&fs, &l), before, "{what}");
            assert_eq!(fs.read_link(&link).unwrap(), target, "{what}: not repaired");
        }
        // A file at R/bundle.
        let (fs, l) = installed(Some("1.0.0"), &[]);
        fs.remove_file(&link).unwrap();
        put_file(&fs, &link, b"x");
        assert!(matches!(
            l.bundle_path(&fs),
            Err(LayoutError::BundlePointer)
        ));
        // set_bundle_pointer refuses a non-canonical bundle and a file in the way.
        assert!(matches!(
            set_bundle_pointer(&fs, &l, &home().join("Apps").join("Hello.app")),
            Err(LayoutError::NotCanonical) | Err(LayoutError::BundlePointer)
        ));
        assert!(matches!(
            set_bundle_pointer(&fs, &l, &bundle()),
            Err(LayoutError::BundlePointer)
        ));
        // A missing pointer with a current version.
        let (fs, l) = installed(Some("1.0.0"), &[]);
        fs.remove_file(&link).unwrap();
        assert_eq!(l.bundle_path(&fs).unwrap(), None);
        assert!(matches!(
            reconcile_bundle(&fs, &l, &record("1.0.0")),
            Err(LayoutError::BundlePointer)
        ));
    }

    #[test]
    fn the_pointer_is_written_once_and_read_back_as_the_bundle() {
        let (fs, l) = installed(Some("1.0.0"), &[]);
        assert_eq!(
            fs.read_link(&l.bundle_link().unwrap()).unwrap(),
            bundle().to_str().unwrap()
        );
        assert_eq!(l.bundle_path(&fs).unwrap(), Some(bundle()));
        assert_eq!(l.current_tree_with(&fs).unwrap(), Some(bundle()));
        // Setting it again only syncs R.
        let ops = fs.op_count();
        set_bundle_pointer(&fs, &l, &bundle()).unwrap();
        assert_eq!(fs.op_count() - ops, 1);
        // Re-pointed after a move.
        let moved = apps().join("Sub").join("Hello.app");
        fs.create_dir_all(moved.parent().unwrap()).unwrap();
        fs.rename(&bundle(), &moved).unwrap();
        set_bundle_pointer(&fs, &l, &moved).unwrap();
        assert_eq!(l.bundle_path(&fs).unwrap(), Some(moved));
    }

    // ---- identity -------------------------------------------------------------------------

    #[test]
    fn the_identity_is_written_through_a_temporary_file_and_only_when_it_changed() {
        let (fs, l) = installed(Some("1.0.0"), &[]);
        let id = l.bundle_id_path().unwrap();
        assert_eq!(id, l.root().join(BUNDLE_ID_FILE));
        let facts = fs.place(&bundle()).unwrap();
        assert_eq!(
            fs.read_capped(&id, 100).unwrap(),
            format!("{} {}", facts.device, facts.inode).into_bytes()
        );
        let ops = fs.op_count();
        write_bundle_identity(&fs, &l, &bundle()).unwrap();
        assert_eq!(fs.op_count(), ops, "the same identity is not written again");
        // Malformed identities identify nothing.
        for bad in [
            &b""[..],
            b"1",
            b"1  2",
            b"01 2",
            b"1 2 ",
            b"-1 2",
            b"1 x",
            b"a b",
        ] {
            fs.remove_file(&id).unwrap();
            put_file(&fs, &id, bad);
            assert_eq!(read_bundle_identity(&fs, &l).unwrap(), None, "{bad:?}");
        }
        // A rewrite replaces it and leaves no temporary file.
        write_bundle_identity(&fs, &l, &bundle()).unwrap();
        assert_eq!(
            read_bundle_identity(&fs, &l).unwrap(),
            Some((facts.device, facts.inode))
        );
        assert_eq!(
            fs.symlink_metadata(&l.root().join("bundle.id.tmp"))
                .unwrap(),
            None
        );
    }

    // ---- check_place (M8-D4) ----------------------------------------------------------------

    fn place(f: impl FnOnce(&mut MemPlace)) -> MemPlace {
        let mut p = MemPlace::default();
        f(&mut p);
        p
    }

    #[test]
    fn check_place_reports_each_reason_and_reconcile_moves_nothing() {
        let cases: Vec<(&str, PathBuf, MemPlace, LocationReason)> = vec![
            (
                "other_volume",
                apps(),
                place(|p| p.device = 2),
                LocationReason::OtherVolume,
            ),
            (
                "not_owned (bundle)",
                bundle(),
                place(|p| p.owned_by_caller = false),
                LocationReason::NotOwned,
            ),
            (
                "not_writable (folder)",
                apps(),
                place(|p| p.writable = false),
                LocationReason::NotWritable,
            ),
            (
                "read_only (folder)",
                apps(),
                place(|p| p.read_only = true),
                LocationReason::ReadOnly,
            ),
            (
                "translocated (folder)",
                apps(),
                place(|p| p.fs_type = "nullfs".to_owned()),
                LocationReason::Translocated,
            ),
        ];
        for (what, at, facts, reason) in cases {
            let (fs, l) = installed(Some("1.0.0"), &["2.0.0"]);
            fs.set_place(&at, facts);
            let got = check_place(&fs, &l, &bundle());
            assert!(
                matches!(got, Err(LayoutError::Location(r)) if r == reason),
                "{what}: {got:?}"
            );
            let before = snapshot(&fs, &l);
            let got = reconcile_bundle(&fs, &l, &record("2.0.0"));
            assert!(
                matches!(got, Err(LayoutError::Location(r)) if r == reason),
                "{what}: {got:?}"
            );
            assert_eq!(snapshot(&fs, &l), before, "{what}");
            // Nothing to move: the place is not checked, the app keeps starting.
            reconcile_bundle(&fs, &l, &record("1.0.0")).unwrap();
        }
        assert_eq!(LocationReason::OtherVolume.as_str(), "other_volume");
        assert_eq!(LocationReason::NotWritable.to_string(), "not_writable");
    }

    #[test]
    fn check_place_reads_a_root_owned_bundle_as_a_machine_install() {
        let (fs, l) = installed(Some("1.0.0"), &["2.0.0"]);
        // M8-D4: root-owned `B` is a machine install by ownership (D10), not `not_owned`.
        fs.set_place(
            &bundle(),
            place(|p| {
                p.owned_by_caller = false;
                p.owned_by_root = true;
            }),
        );
        let got = check_place(&fs, &l, &bundle());
        assert!(matches!(got, Err(LayoutError::MachineBundle)), "{got:?}");
        let before = snapshot(&fs, &l);
        let got = reconcile_bundle(&fs, &l, &record("2.0.0"));
        assert!(matches!(got, Err(LayoutError::MachineBundle)), "{got:?}");
        assert_eq!(snapshot(&fs, &l), before);
        // The caller being root owns it: not a machine refusal.
        fs.set_place(
            &bundle(),
            place(|p| {
                p.owned_by_caller = true;
                p.owned_by_root = true;
            }),
        );
        check_place(&fs, &l, &bundle()).unwrap();
    }

    #[test]
    fn check_place_wants_a_writable_folder_not_an_owned_one() {
        let (fs, l) = installed(Some("1.0.0"), &["2.0.0"]);
        // /Applications: root:admin, group-writable (M8-D4 (a)); the bundle is the caller's.
        fs.set_place(&apps(), place(|p| p.owned_by_caller = false));
        fs.set_place(&bundle(), MemPlace::default());
        check_place(&fs, &l, &bundle()).unwrap();
        reconcile_bundle(&fs, &l, &record("2.0.0")).unwrap();
        assert_end(&fs, &l, "2.0.0", Some("1.0.0"), "admin folder");
    }

    #[test]
    fn check_place_refuses_a_translocated_path_by_its_component() {
        let fs = MemFs::new();
        let l = layout();
        fs.create_dir_all(&l.versions_dir()).unwrap();
        let b = abs_path("/private/var/folders/x/T/AppTranslocation/1234/d/Hello.app");
        fs.create_dir_all(&b).unwrap();
        let got = check_place(&fs, &l, &b);
        assert!(
            matches!(
                got,
                Err(LayoutError::Location(LocationReason::Translocated))
            ),
            "{got:?}"
        );
    }

    // ---- discovery (M8-D1, M8-D4 amended, M8-D17) -------------------------------------------

    fn discover_at(
        fs: &MemFs,
        tree: &Path,
        config: &UpdateConfig,
        facts: &PlaceFacts,
    ) -> Result<BundleDiscovery, LayoutError> {
        discover_in(fs, tree, config, facts, &data_home(), &home())
    }

    fn discover_in(
        fs: &MemFs,
        tree: &Path,
        config: &UpdateConfig,
        facts: &PlaceFacts,
        data_home: &Path,
        home: &Path,
    ) -> Result<BundleDiscovery, LayoutError> {
        let exe = tree.join("Contents").join("MacOS").join("hello");
        let (tree, k) = tree_candidates(&exe)
            .into_iter()
            .find(|(t, _)| t == tree)
            .unwrap();
        discover_bundle(
            fs,
            &FakeHasher,
            &BundleProbe {
                exe: &exe,
                tree: &tree,
                k,
                config,
                facts,
                data_home,
                home,
                system_apps: Path::new(lunepack_core::layout::SYSTEM_APPS_DIR),
            },
        )
    }

    fn discover_real(
        fs: &MemFs,
        tree: &Path,
        version: &str,
    ) -> Result<BundleDiscovery, LayoutError> {
        let facts = fs.place(tree).unwrap();
        discover_at(fs, tree, &mac_config(version), &facts)
    }

    fn installed_as(version: &str) -> BundleDiscovery {
        BundleDiscovery::Installed {
            root: layout().root().to_path_buf(),
            version: v(version),
        }
    }

    #[test]
    fn the_bundle_the_pointer_names_is_installed() {
        let (fs, _) = installed(Some("1.0.0"), &[]);
        assert_eq!(
            discover_real(&fs, &bundle(), "1.0.0").unwrap(),
            installed_as("1.0.0")
        );
    }

    #[test]
    fn an_old_instance_in_its_version_tree_is_installed() {
        let (fs, l) = installed(Some("2.0.0"), &["1.0.0"]);
        assert_eq!(
            discover_real(&fs, &l.version_dir(&v("1.0.0")), "1.0.0").unwrap(),
            installed_as("1.0.0")
        );
        // A tree in the versions directory not named by its version is not an old instance.
        put_tree(&fs, &l.swap_slot(), "1.5.0");
        assert_eq!(
            discover_real(&fs, &l.swap_slot(), "1.5.0").unwrap(),
            BundleDiscovery::NotInstalled
        );
    }

    #[test]
    fn a_bundle_moved_on_its_volume_is_followed_when_its_inode_is_recorded() {
        let (fs, l) = installed(Some("1.0.0"), &[]);
        store(&fs, &l, &record("1.0.0"));
        let moved = apps().join("Sub").join("Hello.app");
        fs.create_dir_all(moved.parent().unwrap()).unwrap();
        fs.rename(&bundle(), &moved).unwrap();
        assert_eq!(
            discover_real(&fs, &moved, "1.0.0").unwrap(),
            BundleDiscovery::MovedFrom {
                root: l.root().to_path_buf(),
                version: v("1.0.0")
            }
        );
        // Not when the record's current version is another one.
        let (fs, l) = installed(Some("1.0.0"), &[]);
        store(&fs, &l, &record("2.0.0"));
        fs.create_dir_all(moved.parent().unwrap()).unwrap();
        fs.rename(&bundle(), &moved).unwrap();
        assert_eq!(
            discover_real(&fs, &moved, "1.0.0").unwrap(),
            BundleDiscovery::NotInstalled
        );
    }

    #[test]
    fn a_copy_with_another_inode_is_not_installed_even_with_the_pointer_dangling() {
        let (fs, l) = installed(Some("1.0.0"), &[]);
        store(&fs, &l, &record("1.0.0"));
        // A re-extracted zip: the same content, a new directory (outside an apps folder, so
        // not adoptable either, M8-D9).
        fs.rename(&bundle(), &home().join("gone")).unwrap();
        let copy = home().join("Downloads").join("Other.app");
        put_tree(&fs, &copy, "1.0.0");
        assert_eq!(
            discover_real(&fs, &copy, "1.0.0").unwrap(),
            BundleDiscovery::NotInstalled
        );
        // A copy while the install is live is never this install either.
        let (fs, l) = installed(Some("1.0.0"), &[]);
        store(&fs, &l, &record("1.0.0"));
        put_tree(&fs, &copy, "1.0.0");
        assert_eq!(
            discover_real(&fs, &copy, "1.0.0").unwrap(),
            BundleDiscovery::NotInstalled
        );
        // No pointer at all (never installed): a development run.
        let fs = MemFs::new();
        put_tree(&fs, &copy, "1.0.0");
        assert_eq!(
            discover_real(&fs, &copy, "1.0.0").unwrap(),
            BundleDiscovery::NotInstalled
        );
    }

    // ---- adoption (M8-D9 (b), Revision 2) ---------------------------------------------------

    fn adoptable() -> BundleDiscovery {
        BundleDiscovery::Adoptable {
            root: layout().root().to_path_buf(),
        }
    }

    /// A second bundle in an apps folder. `/Applications` is a macOS place and the product
    /// compares its bytes literally, so a Windows run (path-neutral fixtures only) uses a second
    /// bundle in the user's apps folder instead.
    fn system_apps_bundle() -> PathBuf {
        if cfg!(windows) {
            apps().join("Other.app")
        } else {
            abs_path("/Applications/Hello.app")
        }
    }

    /// An orphaned install (M8-D16): the record names 1.0.0, the pointer dangles and no tree
    /// holds 1.0.0.
    fn orphaned() -> (MemFs, UserLayout) {
        let (fs, l) = installed(Some("1.0.0"), &[]);
        store(&fs, &l, &record("1.0.0"));
        fs.remove_dir_all_nofollow(&bundle()).unwrap();
        (fs, l)
    }

    #[test]
    fn a_bundle_in_an_apps_folder_with_no_install_root_is_adoptable() {
        for tree in [bundle(), system_apps_bundle()] {
            let fs = MemFs::new();
            put_tree(&fs, &tree, "1.0.0");
            let ops = fs.op_count();
            assert_eq!(
                discover_real(&fs, &tree, "1.0.0").unwrap(),
                adoptable(),
                "{tree:?}"
            );
            // Discovery wrote nothing.
            assert_eq!(fs.op_count(), ops);
        }
    }

    #[test]
    fn a_bundle_over_a_record_with_no_current_version_is_adoptable() {
        let fs = MemFs::new();
        let l = layout();
        fs.create_dir_all(&l.state_dir()).unwrap();
        store(
            &fs,
            &l,
            &InstallState::new(1, app(), Scope::User, [0; 16], Target::MacosAarch64),
        );
        put_tree(&fs, &bundle(), "1.0.0");
        assert_eq!(discover_real(&fs, &bundle(), "1.0.0").unwrap(), adoptable());
    }

    #[test]
    fn a_bundle_over_an_orphaned_record_is_adoptable() {
        // The same version, and another one, dragged in as a new directory. (At the old
        // bundle's own path the pointer names it, which is the step-1 rule for `Installed`.)
        let other = system_apps_bundle();
        for version in ["1.0.0", "1.1.0"] {
            let (fs, _) = orphaned();
            put_tree(&fs, &other, version);
            assert_eq!(
                discover_real(&fs, &other, version).unwrap(),
                adoptable(),
                "{version}"
            );
        }
        // Not orphaned when a version tree still holds the current version.
        let (fs, l) = orphaned();
        put_tree(&fs, &l.version_dir(&v("1.0.0")), "1.0.0");
        put_tree(&fs, &other, "1.1.0");
        assert_eq!(
            discover_real(&fs, &other, "1.1.0").unwrap(),
            BundleDiscovery::NotInstalled
        );
        // Nor when a slot does.
        let (fs, l) = orphaned();
        put_tree(&fs, &l.swap_slot(), "1.0.0");
        put_tree(&fs, &other, "1.1.0");
        assert_eq!(
            discover_real(&fs, &other, "1.1.0").unwrap(),
            BundleDiscovery::NotInstalled
        );
    }

    #[test]
    fn a_bundle_outside_an_apps_folder_is_never_adoptable() {
        for tree in [
            home().join("Desktop").join("Hello.app"),
            home().join(".Trash").join("Hello.app"),
            apps().join("Sub").join("Hello.app"),
            home().join("Downloads").join("Hello.app"),
        ] {
            let fs = MemFs::new();
            put_tree(&fs, &tree, "1.0.0");
            assert_eq!(
                discover_real(&fs, &tree, "1.0.0").unwrap(),
                BundleDiscovery::NotInstalled,
                "{tree:?}"
            );
            // And over an orphaned record.
            let (fs, _) = orphaned();
            put_tree(&fs, &tree, "1.0.0");
            assert_eq!(
                discover_real(&fs, &tree, "1.0.0").unwrap(),
                BundleDiscovery::NotInstalled,
                "{tree:?}"
            );
        }
    }

    #[test]
    fn a_bundle_beside_a_live_install_is_not_installed() {
        let (fs, l) = installed(Some("1.0.0"), &[]);
        store(&fs, &l, &record("1.0.0"));
        let other = abs_path("/Applications/Hello.app");
        put_tree(&fs, &other, "1.0.0");
        assert_eq!(
            discover_real(&fs, &other, "1.0.0").unwrap(),
            BundleDiscovery::NotInstalled
        );
        // A record of another app is never adopted over.
        let fs = MemFs::new();
        let l = layout();
        fs.create_dir_all(&l.state_dir()).unwrap();
        let other = AppId::parse("com.other.app").unwrap();
        let mut foreign = record("1.0.0");
        foreign.app_id = other.clone();
        let loaded =
            lunepack_core::state::load::<InstallState>(&fs, &l.state_dir(), &other, &FakeHasher)
                .unwrap();
        lunepack_core::state::commit(&fs, &l.state_dir(), &loaded, &foreign, &FakeHasher).unwrap();
        put_tree(&fs, &bundle(), "1.0.0");
        assert_eq!(
            discover_real(&fs, &bundle(), "1.0.0").unwrap(),
            BundleDiscovery::NotInstalled
        );
    }

    #[test]
    fn the_location_comes_before_adoption() {
        let fs = MemFs::new();
        put_tree(&fs, &bundle(), "1.0.0");
        fs.set_place(&bundle(), place(|p| p.read_only = true));
        assert!(matches!(
            discover_real(&fs, &bundle(), "1.0.0"),
            Err(LayoutError::Location(LocationReason::ReadOnly))
        ));
    }

    #[test]
    fn a_move_into_an_apps_folder_is_followed_not_adopted() {
        let (fs, l) = installed(Some("1.0.0"), &[]);
        store(&fs, &l, &record("1.0.0"));
        let moved = abs_path("/Applications/Hello.app");
        fs.create_dir_all(moved.parent().unwrap()).unwrap();
        fs.rename(&bundle(), &moved).unwrap();
        let moved_from = BundleDiscovery::MovedFrom {
            root: l.root().to_path_buf(),
            version: v("1.0.0"),
        };
        assert_eq!(discover_real(&fs, &moved, "1.0.0").unwrap(), moved_from);
        // An adoption cut off after its commit, before its pointer: the pointer is missing and
        // the identity names the tree; it is followed the same way.
        fs.remove_file(&l.bundle_link().unwrap()).unwrap();
        assert_eq!(discover_real(&fs, &moved, "1.0.0").unwrap(), moved_from);
    }

    // ---- a bundle replaced at the live bundle's own path (M8-D16 amended, Revision 4) ---------

    /// A live install of 1.0.0 whose bundle the user replaced at its own path by `version` (a new
    /// directory, so a new inode): Finder's Replace, or Trash and drag back.
    fn replaced_by(version: &str) -> (MemFs, UserLayout) {
        let (fs, l) = installed(Some("1.0.0"), &[]);
        store(&fs, &l, &record("1.0.0"));
        let old = fs.place(&bundle()).unwrap().inode;
        fs.remove_dir_all_nofollow(&bundle()).unwrap();
        put_tree(&fs, &bundle(), version);
        assert_ne!(fs.place(&bundle()).unwrap().inode, old, "a new directory");
        (fs, l)
    }

    #[test]
    fn a_newer_bundle_dragged_over_the_live_one_is_adoptable() {
        let (fs, l) = replaced_by("1.2.0");
        assert!(lunepack_core::bundle_replaced(
            &fs,
            &l,
            &record("1.0.0"),
            &bundle()
        ));
        let ops = fs.op_count();
        assert_eq!(discover_real(&fs, &bundle(), "1.2.0").unwrap(), adoptable());
        assert_eq!(fs.op_count(), ops, "discovery wrote nothing");
        // The state reconcile cannot heal (which made the app's start fail before).
        assert!(matches!(
            reconcile_bundle(&fs, &l, &record("1.0.0")),
            Err(LayoutError::BundleMissing)
        ));
    }

    #[test]
    fn a_replaced_bundle_whose_identity_was_already_written_is_still_adoptable() {
        // An adoption cut after its first write (the identity of the new bundle).
        let (fs, l) = replaced_by("1.2.0");
        write_bundle_identity(&fs, &l, &bundle()).unwrap();
        let facts = fs.place(&bundle()).unwrap();
        assert_eq!(
            read_bundle_identity(&fs, &l).unwrap(),
            Some((facts.device, facts.inode))
        );
        assert_eq!(discover_real(&fs, &bundle(), "1.2.0").unwrap(), adoptable());
    }

    #[test]
    fn a_same_version_copy_dragged_back_to_the_live_path_is_installed() {
        let (fs, l) = replaced_by("1.0.0");
        assert!(!lunepack_core::bundle_replaced(
            &fs,
            &l,
            &record("1.0.0"),
            &bundle()
        ));
        assert_eq!(
            discover_real(&fs, &bundle(), "1.0.0").unwrap(),
            installed_as("1.0.0")
        );
        // The reconcile that follows records the new directory.
        reconcile_bundle(&fs, &l, &record("1.0.0")).unwrap();
        let facts = fs.place(&bundle()).unwrap();
        assert_eq!(
            read_bundle_identity(&fs, &l).unwrap(),
            Some((facts.device, facts.inode))
        );
        assert_eq!(version_at(&fs, &bundle()).as_deref(), Some("1.0.0"));
    }

    #[test]
    fn a_bundle_mid_update_is_installed_not_replaced() {
        // The record names 2.0.0; the bundle still holds 1.0.0 and 2.0.0 waits in the version
        // tree, the swap slot or the out slot (an update cut after its record commit).
        for slot in ["versions", "swap", "out"] {
            let (fs, l) = installed(Some("1.0.0"), &[]);
            store(&fs, &l, &record("2.0.0"));
            let at = match slot {
                "versions" => l.version_dir(&v("2.0.0")),
                "swap" => l.swap_slot(),
                _ => l.out_slot(),
            };
            put_tree(&fs, &at, "2.0.0");
            assert!(
                !lunepack_core::bundle_replaced(&fs, &l, &record("2.0.0"), &bundle()),
                "{slot}"
            );
            assert_eq!(
                discover_real(&fs, &bundle(), "1.0.0").unwrap(),
                installed_as("1.0.0"),
                "{slot}"
            );
            reconcile_bundle(&fs, &l, &record("2.0.0")).unwrap_or_else(|e| panic!("{slot}: {e:?}"));
            assert_eq!(
                version_at(&fs, &bundle()).as_deref(),
                Some("2.0.0"),
                "{slot}"
            );
        }
    }

    #[test]
    fn a_replaced_bundle_outside_an_apps_folder_is_not_installed() {
        // The install followed its bundle to the Desktop earlier; there it is replaced.
        let (fs, l) = installed(Some("1.0.0"), &[]);
        store(&fs, &l, &record("1.0.0"));
        let desk = home().join("Desktop").join("Hello.app");
        fs.create_dir_all(desk.parent().unwrap()).unwrap();
        fs.rename(&bundle(), &desk).unwrap();
        set_bundle_pointer(&fs, &l, &desk).unwrap();
        write_bundle_identity(&fs, &l, &desk).unwrap();
        assert_eq!(
            discover_real(&fs, &desk, "1.0.0").unwrap(),
            installed_as("1.0.0")
        );
        fs.remove_dir_all_nofollow(&desk).unwrap();
        put_tree(&fs, &desk, "1.2.0");
        assert_eq!(
            discover_real(&fs, &desk, "1.2.0").unwrap(),
            BundleDiscovery::NotInstalled
        );
    }

    #[test]
    fn a_replaced_bundle_with_an_unreadable_record_stays_installed() {
        // Unreadable: the record's file cut short.
        let (fs, l) = replaced_by("1.2.0");
        for entry in fs.list_dir(&l.state_dir()).unwrap() {
            if entry.name.to_string_lossy().ends_with(".rec") {
                fs.truncate(&l.state_dir().join(&entry.name), 5).unwrap();
            }
        }
        assert_eq!(
            discover_real(&fs, &bundle(), "1.2.0").unwrap(),
            installed_as("1.2.0")
        );
        // Another app's record, written by the core's writer.
        let (fs, l) = installed(Some("1.0.0"), &[]);
        let other = AppId::parse("com.other.app").unwrap();
        let mut foreign = record("1.0.0");
        foreign.app_id = other.clone();
        let loaded =
            lunepack_core::state::load::<InstallState>(&fs, &l.state_dir(), &other, &FakeHasher)
                .unwrap();
        lunepack_core::state::commit(&fs, &l.state_dir(), &loaded, &foreign, &FakeHasher).unwrap();
        fs.remove_dir_all_nofollow(&bundle()).unwrap();
        put_tree(&fs, &bundle(), "1.2.0");
        assert_eq!(
            discover_real(&fs, &bundle(), "1.2.0").unwrap(),
            installed_as("1.2.0")
        );
    }

    #[test]
    fn bundle_replaced_is_false_for_what_it_cannot_judge() {
        let rec = record("1.0.0");
        // The bundle's config cannot be read.
        let (fs, l) = replaced_by("1.2.0");
        fs.remove_file(&config_file(&bundle())).unwrap();
        assert!(!lunepack_core::bundle_replaced(&fs, &l, &rec, &bundle()));
        // A slot holds another app's tree.
        let (fs, l) = replaced_by("1.2.0");
        let mut foreign = mac_config("0.5.0");
        foreign.app_id = AppId::parse("com.other.app").unwrap();
        put_tree_of(&fs, &l.swap_slot(), &foreign);
        assert!(!lunepack_core::bundle_replaced(&fs, &l, &rec, &bundle()));
        // The pointer names another path than the tree asked about.
        let (fs, l) = replaced_by("1.2.0");
        let elsewhere = abs_path("/Applications/Hello.app");
        put_tree(&fs, &elsewhere, "1.2.0");
        assert!(!lunepack_core::bundle_replaced(&fs, &l, &rec, &elsewhere));
        // The bundle is another app's.
        let (fs, l) = replaced_by("1.2.0");
        fs.remove_dir_all_nofollow(&bundle()).unwrap();
        put_tree_of(&fs, &bundle(), &foreign);
        assert!(!lunepack_core::bundle_replaced(&fs, &l, &rec, &bundle()));
        // And nothing was written by any of it.
        let (fs, l) = replaced_by("1.2.0");
        let ops = fs.op_count();
        assert!(lunepack_core::bundle_replaced(&fs, &l, &rec, &bundle()));
        assert_eq!(fs.op_count(), ops);
    }

    #[test]
    fn a_bundle_in_the_trash_is_not_installed() {
        let (fs, l) = installed(Some("1.0.0"), &[]);
        store(&fs, &l, &record("1.0.0"));
        let trashed = home().join(".Trash").join("Hello.app");
        fs.create_dir_all(trashed.parent().unwrap()).unwrap();
        fs.rename(&bundle(), &trashed).unwrap();
        // Its inode is the recorded one; the Trash alone refuses it.
        assert_eq!(
            Some((
                fs.place(&trashed).unwrap().device,
                fs.place(&trashed).unwrap().inode
            )),
            read_bundle_identity(&fs, &l).unwrap()
        );
        assert_eq!(
            discover_real(&fs, &trashed, "1.0.0").unwrap(),
            BundleDiscovery::NotInstalled
        );
    }

    #[test]
    fn a_translocated_running_tree_is_refused_before_the_pointer_is_read() {
        let (fs, l) = installed(Some("1.0.0"), &[]);
        // A pointer that would itself be refused: location comes first.
        let link = l.bundle_link().unwrap();
        fs.remove_file(&link).unwrap();
        put_file(&fs, &link, b"not a link");
        assert!(matches!(
            discover_real(&fs, &bundle(), "1.0.0"),
            Err(LayoutError::BundlePointer)
        ));
        // On a nullfs mount.
        let mut facts = fs.place(&bundle()).unwrap();
        facts.fs_type = "nullfs".to_owned();
        let got = discover_at(&fs, &bundle(), &mac_config("1.0.0"), &facts);
        assert!(
            matches!(
                got,
                Err(LayoutError::Location(LocationReason::Translocated))
            ),
            "{got:?}"
        );
        // Under an AppTranslocation component.
        let t = abs_path("/private/var/folders/x/T/AppTranslocation/1234/d/Hello.app");
        put_tree(&fs, &t, "1.0.0");
        let got = discover_real(&fs, &t, "1.0.0");
        assert!(
            matches!(
                got,
                Err(LayoutError::Location(LocationReason::Translocated))
            ),
            "{got:?}"
        );
    }

    #[test]
    fn a_running_tree_on_a_read_only_volume_is_refused() {
        let (fs, _) = installed(Some("1.0.0"), &[]);
        let dmg = abs_path("/Volumes/Hello/Hello.app");
        put_tree(&fs, &dmg, "1.0.0");
        fs.set_place(&abs_path("/Volumes/Hello"), place(|p| p.read_only = true));
        let got = discover_real(&fs, &dmg, "1.0.0");
        assert!(
            matches!(got, Err(LayoutError::Location(LocationReason::ReadOnly))),
            "{got:?}"
        );
    }

    #[test]
    fn an_exe_outside_the_bundles_entry_directory_is_not_this_tree() {
        let (fs, _) = installed(Some("1.0.0"), &[]);
        let facts = fs.place(&bundle()).unwrap();
        let exe = bundle().join("Contents").join("Helpers").join("hello");
        let (tree, k) = tree_candidates(&exe)
            .into_iter()
            .find(|(t, _)| *t == bundle())
            .unwrap();
        let got = discover_bundle(
            &fs,
            &FakeHasher,
            &BundleProbe {
                exe: &exe,
                tree: &tree,
                k,
                config: &mac_config("1.0.0"),
                facts: &facts,
                data_home: &data_home(),
                home: &home(),
                system_apps: Path::new(lunepack_core::layout::SYSTEM_APPS_DIR),
            },
        );
        assert!(matches!(got, Err(LayoutError::NotThisTree)), "{got:?}");
    }

    // ---- canonical paths (P1) ---------------------------------------------------------------

    #[test]
    fn a_home_reached_through_a_symlink_installs_only_by_its_canonical_path() {
        let fs = MemFs::new();
        // /var -> private/var, as on macOS.
        fs.create_dir_all(&abs_path("/private/var/u")).unwrap();
        fs.symlink("private/var", &abs_path("/var")).unwrap();
        let given = abs_path("/var/u");
        let canonical = abs_path("/private/var/u");
        let dh_given = data_home_of(&given);
        let dh = data_home_of(&canonical);

        // Through the symlink: refused, nothing created.
        assert!(matches!(
            resolve_bundle_target(&fs, &given.join("Applications"), "Hello", &app()),
            Err(LayoutError::NotCanonical)
        ));
        assert_eq!(
            fs.symlink_metadata(&canonical.join("Applications"))
                .unwrap(),
            None
        );
        let l_given = layout_in(&dh_given);
        assert!(matches!(
            set_bundle_pointer(&fs, &l_given, &given.join("Applications").join("Hello.app")),
            Err(LayoutError::NotCanonical)
        ));

        // Canonical: install, discover, uninstall's root rule.
        let l = layout_in(&dh);
        let b =
            resolve_bundle_target(&fs, &canonical.join("Applications"), "Hello", &app()).unwrap();
        assert_eq!(b, canonical.join("Applications").join("Hello.app"));
        put_tree(&fs, &l.version_dir(&v("1.0.0")), "1.0.0");
        set_bundle_pointer(&fs, &l, &b).unwrap();
        reconcile_bundle(&fs, &l, &record("1.0.0")).unwrap();
        assert_eq!(version_at(&fs, &b).as_deref(), Some("1.0.0"));
        let facts = fs.place(&b).unwrap();
        assert_eq!(
            discover_in(&fs, &b, &mac_config("1.0.0"), &facts, &dh, &canonical).unwrap(),
            BundleDiscovery::Installed {
                root: l.root().to_path_buf(),
                version: v("1.0.0")
            }
        );
        assert!(root_valid_for_uninstall(
            &fs,
            &dh,
            l.root(),
            &app(),
            LayoutScheme::MACOS
        ));
    }

    /// The same on a real disk: a temporary directory (under `/var`, a symlink to `/private/var`,
    /// on macOS) with `HOME` given through a symlink of its own, canonicalised as the facade does
    /// (`std::fs::canonicalize`). The disk is reached through a minimal `Fs` over `std` with fixed
    /// volume facts (the real `place` and `exchange` are `lunepack-fs`'s).
    #[cfg(unix)]
    #[test]
    fn a_real_home_reached_through_symlinks_installs_only_by_its_canonical_path() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp =
            std::env::temp_dir().join(format!("lunepack-core-bundle-p1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("home-real")).unwrap();
        std::os::unix::fs::symlink("home-real", tmp.join("home-link")).unwrap();
        let result = std::panic::catch_unwind(|| {
            let fs = real::RealFs;
            let given = tmp.join("home-link");
            let canonical = std::fs::canonicalize(&given).unwrap();
            assert_ne!(given, canonical);
            let dh = data_home_of(&canonical);

            assert!(matches!(
                resolve_bundle_target(&fs, &given.join("Applications"), "Hello", &app()),
                Err(LayoutError::NotCanonical)
            ));
            assert!(matches!(
                set_bundle_pointer(
                    &fs,
                    &layout_in(&data_home_of(&given)),
                    &given.join("Applications").join("Hello.app")
                ),
                Err(LayoutError::NotCanonical)
            ));

            let l = layout_in(&dh);
            let apps = canonical.join("Applications");
            let b = resolve_bundle_target(&fs, &apps, "Hello", &app()).unwrap();
            assert_eq!(b, apps.join("Hello.app"));
            let mode = std::fs::metadata(&apps).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "the apps folder is created owner-only");
            put_tree(&fs, &l.version_dir(&v("1.0.0")), "1.0.0");
            set_bundle_pointer(&fs, &l, &b).unwrap();
            reconcile_bundle(&fs, &l, &record("1.0.0")).unwrap();
            assert_eq!(version_at(&fs, &b).as_deref(), Some("1.0.0"));
            let facts = fs.place(&b).unwrap();
            assert_eq!(
                read_bundle_identity(&fs, &l).unwrap(),
                Some((facts.device, facts.inode))
            );
            let exe = b.join("Contents").join("MacOS").join("hello");
            let (tree, k) = tree_candidates(&exe)
                .into_iter()
                .find(|(t, _)| *t == b)
                .unwrap();
            let found = discover_bundle(
                &fs,
                &FakeHasher,
                &BundleProbe {
                    exe: &exe,
                    tree: &tree,
                    k,
                    config: &mac_config("1.0.0"),
                    facts: &facts,
                    data_home: &dh,
                    home: &canonical,
                    system_apps: Path::new(lunepack_core::layout::SYSTEM_APPS_DIR),
                },
            )
            .unwrap();
            assert_eq!(
                found,
                BundleDiscovery::Installed {
                    root: l.root().to_path_buf(),
                    version: v("1.0.0")
                }
            );
            assert!(root_valid_for_uninstall(
                &fs,
                &dh,
                l.root(),
                &app(),
                LayoutScheme::MACOS
            ));
        });
        let _ = std::fs::remove_dir_all(&tmp);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    /// A minimal `Fs` over `std` for the real-disk test: what the bundle code calls, with fixed
    /// volume facts; everything else is `Unsupported`.
    #[cfg(unix)]
    mod real {
        use std::fs::File;
        use std::io::{self, Write};
        use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
        use std::path::Path;

        use lunepack_core::{
            DirEntryInfo, FileKind, FileWrite, Fs, FsError, FsErrorKind, LockGuard, Meta,
            PlaceFacts, ReadAt,
        };

        pub struct RealFs;

        struct Writer(File);

        impl Write for Writer {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.write(buf)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }

        impl FileWrite for Writer {
            fn sync(&mut self) -> Result<(), FsError> {
                self.0
                    .sync_all()
                    .map_err(|e| FsError::new(FsErrorKind::Other, Path::new("file"), Some(e)))
            }
        }

        fn io(path: &Path) -> impl Fn(io::Error) -> FsError + '_ {
            move |e| FsError::from_io(path, e)
        }

        fn unsupported<T>(path: &Path) -> Result<T, FsError> {
            Err(FsError::new(FsErrorKind::Unsupported, path, None))
        }

        fn kind(t: std::fs::FileType) -> FileKind {
            if t.is_symlink() {
                FileKind::Symlink
            } else if t.is_dir() {
                FileKind::Dir
            } else if t.is_file() {
                FileKind::File
            } else {
                FileKind::Other
            }
        }

        impl Fs for RealFs {
            fn read_capped(&self, path: &Path, max: u64) -> Result<Vec<u8>, FsError> {
                let bytes = std::fs::read(path).map_err(io(path))?;
                if bytes.len() as u64 > max {
                    return Err(FsError::new(FsErrorKind::TooLarge, path, None));
                }
                Ok(bytes)
            }
            fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
                unsupported(path)
            }
            fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
                let f = File::options()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(io(path))?;
                Ok(Box::new(Writer(f)))
            }
            fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
                unsupported(path)
            }
            fn truncate(&self, path: &Path, _len: u64) -> Result<(), FsError> {
                unsupported(path)
            }
            fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
                if std::fs::symlink_metadata(to).is_ok() {
                    return Err(FsError::new(FsErrorKind::AlreadyExists, to, None));
                }
                std::fs::rename(from, to).map_err(io(from))
            }
            fn remove_file(&self, path: &Path) -> Result<(), FsError> {
                std::fs::remove_file(path).map_err(io(path))
            }
            fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), FsError> {
                unsupported(path)
            }
            fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
                std::fs::create_dir_all(path).map_err(io(path))
            }
            fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
                std::fs::read_dir(path)
                    .map_err(io(path))?
                    .map(|e| {
                        let e = e.map_err(io(path))?;
                        Ok(DirEntryInfo {
                            name: e.file_name(),
                            kind: kind(e.file_type().map_err(io(path))?),
                        })
                    })
                    .collect()
            }
            fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError> {
                match std::fs::symlink_metadata(path) {
                    Ok(m) => Ok(Some(Meta {
                        kind: kind(m.file_type()),
                        len: m.len(),
                    })),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(FsError::from_io(path, e)),
                }
            }
            fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
                File::open(path)
                    .and_then(|d| d.sync_all())
                    .map_err(io(path))
            }
            fn copy_file(&self, from: &Path, _to_new: &Path) -> Result<(), FsError> {
                unsupported(from)
            }
            fn set_exec(&self, path: &Path, _exec: bool) -> Result<(), FsError> {
                unsupported(path)
            }
            fn symlink(&self, target: &str, link_path: &Path) -> Result<(), FsError> {
                std::os::unix::fs::symlink(target, link_path).map_err(io(link_path))
            }
            fn read_link(&self, path: &Path) -> Result<String, FsError> {
                let target = std::fs::read_link(path).map_err(io(path))?;
                target
                    .into_os_string()
                    .into_string()
                    .map_err(|_| FsError::new(FsErrorKind::Other, path, None))
            }
            fn replace_symlink(&self, target: &str, link: &Path) -> Result<(), FsError> {
                let temp = link.with_file_name(".lunepack-link-test");
                let _ = std::fs::remove_file(&temp);
                std::os::unix::fs::symlink(target, &temp).map_err(io(link))?;
                std::fs::rename(&temp, link).map_err(io(link))
            }
            fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
                unsupported(path)
            }
            fn place(&self, path: &Path) -> Result<PlaceFacts, FsError> {
                let m = std::fs::symlink_metadata(path).map_err(io(path))?;
                if m.file_type().is_symlink() {
                    return Err(FsError::new(FsErrorKind::IsSymlink, path, None));
                }
                Ok(PlaceFacts {
                    device: m.dev(),
                    inode: m.ino(),
                    read_only: false,
                    fs_type: String::new(),
                    owned_by_caller: true,
                    owned_by_root: false,
                    writable: true,
                })
            }
            fn create_dir_private(&self, path: &Path) -> Result<(), FsError> {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(path)
                    .map_err(io(path))
            }
        }
    }

    // ---- resolve_bundle_target and the name rule (M8-D1) -----------------------------------

    #[test]
    fn resolve_bundle_target_takes_the_name_then_the_fallback_then_refuses() {
        let fs = MemFs::new();
        fs.create_dir_all(&apps()).unwrap();
        assert_eq!(
            resolve_bundle_target(&fs, &apps(), "Hello", &app()).unwrap(),
            bundle()
        );
        // A foreign bundle at the name: never touched, the fallback is used.
        let mut foreign = mac_config("9.0.0");
        foreign.app_id = AppId::parse("com.other.app").unwrap();
        put_tree_of(&fs, &bundle(), &foreign);
        let fallback = apps().join(format!("Hello ({}).app", app().as_str()));
        assert_eq!(
            resolve_bundle_target(&fs, &apps(), "Hello", &app()).unwrap(),
            fallback
        );
        // Both taken (a file or a link counts): refused.
        fs.symlink("Hello.app", &fallback).unwrap();
        assert!(matches!(
            resolve_bundle_target(&fs, &apps(), "Hello", &app()),
            Err(LayoutError::BundleNameTaken)
        ));
        assert_eq!(version_at(&fs, &bundle()).as_deref(), Some("9.0.0"));
    }

    #[test]
    fn an_unacceptable_name_falls_back_to_the_app_id() {
        let fs = MemFs::new();
        fs.create_dir_all(&apps()).unwrap();
        for bad in ["", ".Hidden", "a/b", "a:b", "tab\there", &"x".repeat(201)] {
            assert_eq!(
                resolve_bundle_target(&fs, &apps(), bad, &app()).unwrap(),
                apps().join(format!("{}.app", app().as_str())),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_apps_folder_is_created_private_when_missing_and_left_alone_when_present() {
        let fs = MemFs::new();
        fs.create_dir_all(&home()).unwrap();
        resolve_bundle_target(&fs, &apps(), "Hello", &app()).unwrap();
        assert!(fs.is_private_dir(&apps()), "created 0700");
        let fs = MemFs::new();
        fs.create_dir_all(&apps()).unwrap();
        let ops = fs.op_count();
        resolve_bundle_target(&fs, &apps(), "Hello", &app()).unwrap();
        assert!(
            !fs.is_private_dir(&apps()),
            "an existing folder is not changed"
        );
        assert_eq!(fs.op_count(), ops, "nothing written");
        // A link at the apps folder is not followed.
        let fs = MemFs::new();
        fs.create_dir_all(&home().join("Elsewhere")).unwrap();
        fs.symlink("Elsewhere", &apps()).unwrap();
        assert!(matches!(
            resolve_bundle_target(&fs, &apps(), "Hello", &app()),
            Err(LayoutError::NotCanonical)
        ));
    }

    #[test]
    fn macos_name_ok_applies_the_bundle_name_rule() {
        for ok in [
            "Hello",
            "Hello World",
            "Héllo – 2",
            "a.b",
            "x",
            &"y".repeat(200),
        ] {
            assert_eq!(macos_name_ok(ok), Ok(()), "{ok:?}");
        }
        assert_eq!(macos_name_ok(""), Err(NameRule::Empty));
        assert_eq!(macos_name_ok(&"é".repeat(101)), Err(NameRule::TooLong));
        for bad in ["a/b", "a:b", "a\0b", "a\nb", "a\u{7f}b", "a\u{85}b"] {
            assert_eq!(macos_name_ok(bad), Err(NameRule::ForbiddenChar), "{bad:?}");
        }
        assert_eq!(macos_name_ok(".hidden"), Err(NameRule::Edge));
    }

    // ---- the scheme -------------------------------------------------------------------------

    #[test]
    fn the_macos_scheme_names_its_directories_slots_pointer_and_config() {
        let l = layout();
        let r = data_home().join(app().as_str());
        assert_eq!(l.root(), r);
        assert_eq!(l.versions_dir(), r.join("versions"));
        assert_eq!(l.state_dir(), r.join("state"));
        assert_eq!(l.cache_dir(), r.join("cache"));
        assert_eq!(l.logs_dir(), r.join("logs"));
        assert_eq!(l.current_link(), None);
        assert_eq!(l.bundle_link(), Some(r.join("bundle")));
        assert_eq!(l.bundle_id_path(), Some(r.join("bundle.id")));
        assert_eq!(l.swap_slot(), r.join("versions").join(SWAP_SLOT));
        assert_eq!(l.out_slot(), r.join("versions").join(OUT_SLOT));
        assert_eq!(
            l.version_config_path(&v("1.2.0")),
            config_file(&r.join("versions").join("1.2.0"))
        );
        assert_eq!(
            UserLayout::from_dirs_as(&l.state_dir(), &l.versions_dir(), LayoutScheme::MACOS),
            Some(l.clone())
        );
        // XDG names the same directories and comes first; it has no bundle.
        let xdg = UserLayout::from_dirs(&l.state_dir(), &l.versions_dir()).unwrap();
        assert_eq!(xdg.scheme(), LayoutScheme::XDG);
        assert_eq!(xdg.bundle_link(), None);
        assert_eq!(
            xdg.version_config_path(&v("1.2.0")),
            r.join("versions/1.2.0/lunepack-update.json")
        );
        let fs = MemFs::new();
        assert_eq!(xdg.current_tree_with(&fs).unwrap(), None);
        assert_eq!(l.current_tree_with(&fs).unwrap(), None, "no pointer yet");
    }

    // ---- MemFs: exchange and place ----------------------------------------------------------

    #[test]
    fn memfs_exchange_place_and_inodes_model_a_real_volume() {
        let fs = MemFs::new();
        let (a, b) = (abs_path("/x/a"), abs_path("/y/b"));
        put_file(&fs, &a.join("f"), b"a");
        put_file(&fs, &b.join("g"), b"b");
        let (ia, ib) = (fs.place(&a).unwrap().inode, fs.place(&b).unwrap().inode);
        let ops = fs.op_count();
        fs.exchange(&a, &b).unwrap();
        assert_eq!(fs.op_count() - ops, 1, "one op");
        assert_eq!(fs.read_capped(&a.join("g"), 9).unwrap(), b"b");
        assert_eq!(
            (fs.place(&a).unwrap().inode, fs.place(&b).unwrap().inode),
            (ib, ia)
        );
        // Refusals cost no op.
        let ops = fs.op_count();
        assert_eq!(
            fs.exchange(&a, &abs_path("/x/none")).unwrap_err().kind,
            FsErrorKind::NotFound
        );
        fs.set_exchange_supported(false);
        assert_eq!(
            fs.exchange(&a, &b).unwrap_err().kind,
            FsErrorKind::Unsupported
        );
        assert_eq!(fs.op_count(), ops);
        // Inodes and places survive a restart; the nearest ancestor's place applies.
        fs.set_place(&abs_path("/y"), place(|p| p.device = 7));
        let after = fs.recover(RecoverMode::KeepVolatile);
        assert_eq!(after.place(&a).unwrap().inode, ib);
        assert_eq!(after.place(&b).unwrap().device, 7);
        assert_eq!(after.place(&a).unwrap().device, 1);
        assert_eq!(
            after.exchange(&a, &b).unwrap_err().kind,
            FsErrorKind::Unsupported
        );
        fs.symlink("a", &abs_path("/x/l")).unwrap();
        assert_eq!(
            fs.place(&abs_path("/x/l")).unwrap_err().kind,
            FsErrorKind::IsSymlink
        );
    }
}
