//! `XdgIntegration` on a real file system: golden entry bytes, the environment rules, the unsafe
//! path refusals, ownership of the desktop entry and the command link (a foreign file or link is
//! a conflict and is never touched), stale links, and the testkit's integration suite.
//!
//! Every case runs with `HOME` pointing into its own scratch directory; nothing reads or writes
//! the real home.
#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use lunepack_core::{
    AppId, InstallMeta, IntegrationError, IntegrationItem, IntegrationRequest, OsIntegration,
    RelPath, Scope,
};
use lunepack_os_linux::{XdgEnv, XdgIntegration, xdg_dirs};

/// A canonical scratch directory, removed afterwards.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("lunepack-xdg-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch");
        Scratch(std::fs::canonicalize(&dir).expect("canonicalize scratch"))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn env(home: &Path) -> XdgEnv {
    XdgEnv {
        home: Some(home.as_os_str().to_owned()),
        xdg_data_home: None,
    }
}

fn meta(entry: &str, bin: Option<&str>) -> InstallMeta {
    InstallMeta {
        entry: RelPath::parse(entry).unwrap(),
        name: "Example App".to_owned(),
        comment: None,
        icon: None,
        categories: vec![],
        bin: bin.map(str::to_owned),
        terminal: false,
    }
}

fn request(home: &Path, id: &str, m: InstallMeta) -> IntegrationRequest {
    IntegrationRequest {
        app_id: AppId::parse(id).unwrap(),
        install_root: home.join(".local/share").join(id),
        meta: m,
        stale_bins: vec![],
    }
}

fn desktop(home: &Path, id: &str) -> PathBuf {
    home.join(".local/share/applications")
        .join(format!("{id}.desktop"))
}

fn bin(home: &Path, name: &str) -> PathBuf {
    home.join(".local/bin").join(name)
}

/// Every file (bytes) and link (target) below `root`, for before/after comparisons.
fn snapshot(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).unwrap();
                out.push(format!("{} -> {}", path.display(), target.display()));
            } else if meta.is_dir() {
                walk(&path, out);
            } else {
                let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
                out.push(format!("{} = {text}", path.display()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out.sort();
    out
}

#[test]
fn the_integration_suite_passes() {
    let sandbox = Scratch::new("suite");
    let integration = XdgIntegration::new(env(sandbox.path()));
    lunepack_testkit::run_integration_suite(&integration, sandbox.path());
}

#[test]
fn a_full_entry_has_exactly_these_bytes() {
    let s = Scratch::new("golden-full");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    let mut m = meta("bin/app", Some("example"));
    m.comment = Some("Does examples".to_owned());
    m.icon = Some(RelPath::parse("share/icon.png").unwrap());
    m.categories = vec!["Utility".to_owned(), "Development".to_owned()];
    m.terminal = true;
    let req = request(home, "org.example.app", m);
    integration.apply(Scope::User, &req).unwrap();
    let root = home.join(".local/share/org.example.app");
    let expected = format!(
        "[Desktop Entry]\nType=Application\nVersion=1.5\nName=Example App\nComment=Does examples\n\
         Exec=\"{r}/current/bin/app\"\nIcon={r}/current/share/icon.png\nTerminal=true\n\
         Categories=Utility;Development;\nX-Lunepack-App-Id=org.example.app\n",
        r = root.display()
    );
    let written = std::fs::read_to_string(desktop(home, "org.example.app")).unwrap();
    assert_eq!(written, expected);
    assert_eq!(
        std::fs::read_link(bin(home, "example")).unwrap(),
        root.join("current/bin/app")
    );
}

#[test]
fn a_minimal_entry_has_exactly_these_bytes_and_no_link() {
    let s = Scratch::new("golden-min");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    let req = request(home, "app", meta("app", None));
    integration.apply(Scope::User, &req).unwrap();
    let root = home.join(".local/share/app");
    let expected = format!(
        "[Desktop Entry]\nType=Application\nVersion=1.5\nName=Example App\n\
         Exec=\"{r}/current/app\"\nTerminal=false\nX-Lunepack-App-Id=app\n",
        r = root.display()
    );
    assert_eq!(
        std::fs::read_to_string(desktop(home, "app")).unwrap(),
        expected
    );
    assert!(
        !home.join(".local/bin").exists(),
        "no bin dir without a bin"
    );
}

#[test]
fn a_home_with_a_space_is_allowed() {
    let s = Scratch::new("space");
    let home = s.path().join("my home");
    std::fs::create_dir(&home).unwrap();
    let integration = XdgIntegration::new(env(&home));
    let req = request(&home, "app", meta("bin/app", Some("app")));
    integration.apply(Scope::User, &req).unwrap();
    let written = std::fs::read_to_string(desktop(&home, "app")).unwrap();
    assert!(
        written.contains(&format!(
            "Exec=\"{}/current/bin/app\"\n",
            home.join(".local/share/app").display()
        )),
        "{written}"
    );
}

#[test]
fn a_home_with_an_unsafe_character_is_refused_and_nothing_is_written() {
    for (n, bad) in ["a$b", "a\"b", "a%b", "a\\b", "a`b", "a'b"]
        .iter()
        .enumerate()
    {
        let s = Scratch::new(&format!("unsafe-home-{n}"));
        let home = s.path().join(bad);
        std::fs::create_dir(&home).unwrap();
        let integration = XdgIntegration::new(env(&home));
        let req = request(&home, "app", meta("bin/app", Some("app")));
        let before = snapshot(s.path());
        for result in [
            integration.check(Scope::User, &req),
            integration.apply(Scope::User, &req).map(|_| ()),
        ] {
            let err = result.expect_err(bad);
            assert!(
                matches!(err, IntegrationError::UnsafePath { .. }),
                "{bad}: {err:?}"
            );
            assert!(
                !format!("{err} {err:?}").contains(bad),
                "{bad}: value shown"
            );
        }
        assert_eq!(snapshot(s.path()), before, "{bad}: wrote something");
    }
}

#[test]
fn an_unsafe_data_home_is_refused() {
    let s = Scratch::new("unsafe-data-home");
    let data = s.path().join("d$ata");
    std::fs::create_dir(&data).unwrap();
    let integration = XdgIntegration::new(XdgEnv {
        home: Some(s.path().as_os_str().to_owned()),
        xdg_data_home: Some(data.as_os_str().to_owned()),
    });
    let mut req = request(s.path(), "app", meta("bin/app", None));
    req.install_root = s.path().join("safe-root");
    assert!(matches!(
        integration.check(Scope::User, &req),
        Err(IntegrationError::UnsafePath {
            what: "data home",
            ..
        })
    ));
}

#[test]
fn an_unsafe_entry_path_is_refused() {
    let s = Scratch::new("unsafe-entry");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    let req = request(home, "app", meta("bin/a$b", None));
    assert!(matches!(
        integration.check(Scope::User, &req),
        Err(IntegrationError::UnsafePath {
            what: "executable path",
            ..
        })
    ));
    assert!(snapshot(home).is_empty());
}

#[test]
fn a_relative_xdg_data_home_is_ignored_and_an_absolute_one_is_used() {
    let s = Scratch::new("data-home");
    let home = s.path();
    let relative = xdg_dirs(&XdgEnv {
        home: Some(home.as_os_str().to_owned()),
        xdg_data_home: Some(OsString::from("relative/share")),
    })
    .unwrap();
    assert_eq!(relative.data_home(), home.join(".local/share"));
    for ignored in [OsString::new(), OsString::from_vec(vec![b'/', 0xff, b'x'])] {
        let dirs = xdg_dirs(&XdgEnv {
            home: Some(home.as_os_str().to_owned()),
            xdg_data_home: Some(ignored),
        })
        .unwrap();
        assert_eq!(dirs.data_home(), home.join(".local/share"));
    }
    assert_eq!(
        relative.applications(),
        home.join(".local/share/applications")
    );
    assert_eq!(relative.bin(), home.join(".local/bin"));

    let data = home.join("elsewhere");
    let dirs = xdg_dirs(&XdgEnv {
        home: Some(home.as_os_str().to_owned()),
        xdg_data_home: Some(data.as_os_str().to_owned()),
    })
    .unwrap();
    assert_eq!(dirs.data_home(), data);
    assert_eq!(dirs.applications(), data.join("applications"));
    assert_eq!(dirs.bin(), home.join(".local/bin"));

    // And the integration writes where the dirs say.
    let integration = XdgIntegration::new(XdgEnv {
        home: Some(home.as_os_str().to_owned()),
        xdg_data_home: Some(data.as_os_str().to_owned()),
    });
    let mut req = request(home, "app", meta("bin/app", None));
    req.install_root = data.join("app");
    integration.apply(Scope::User, &req).unwrap();
    assert!(data.join("applications/app.desktop").is_file());
    assert!(!home.join(".local/share").exists());
}

#[test]
fn a_missing_relative_or_non_utf8_home_is_an_error() {
    let s = Scratch::new("home");
    for (what, home) in [
        ("unset", None),
        ("empty", Some(OsString::new())),
        ("relative", Some(OsString::from("home/user"))),
        ("non-utf8", Some(OsString::from_vec(vec![b'/', 0xff]))),
        ("missing dir", Some(s.path().join("nope").into_os_string())),
    ] {
        let env = XdgEnv {
            home,
            xdg_data_home: None,
        };
        assert!(
            matches!(xdg_dirs(&env), Err(IntegrationError::Home)),
            "{what}"
        );
        let integration = XdgIntegration::new(env);
        let req = request(s.path(), "app", meta("bin/app", None));
        for result in [
            integration.check(Scope::User, &req),
            integration.apply(Scope::User, &req).map(|_| ()),
            integration.remove(Scope::User, &req).map(|_| ()),
        ] {
            assert!(matches!(result, Err(IntegrationError::Home)), "{what}");
        }
    }
}

#[test]
fn a_home_reached_through_a_symlink_is_canonicalised() {
    let s = Scratch::new("canon");
    let real = s.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = s.path().join("link");
    symlink(&real, &link).unwrap();
    // A symlinked .local/share too, pointing at another directory.
    std::fs::create_dir_all(real.join(".local")).unwrap();
    std::fs::create_dir(real.join("shared")).unwrap();
    symlink(real.join("shared"), real.join(".local/share")).unwrap();
    let dirs = xdg_dirs(&env(&link)).unwrap();
    assert_eq!(dirs.home(), real);
    assert_eq!(dirs.data_home(), real.join("shared"));
    assert_eq!(dirs.applications(), real.join("shared/applications"));
    for path in [
        dirs.home(),
        dirs.data_home(),
        dirs.applications(),
        dirs.bin(),
    ] {
        assert!(
            path.ancestors()
                .all(|a| !std::fs::symlink_metadata(a).is_ok_and(|m| m.file_type().is_symlink())),
            "a symlink component in {}",
            path.display()
        );
    }
}

#[test]
fn a_foreign_desktop_file_is_a_conflict_and_is_left_alone() {
    let s = Scratch::new("foreign-desktop");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    let path = desktop(home, "app");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    for (what, content) in [
        ("no marker", "[Desktop Entry]\nName=Mine\n".to_owned()),
        (
            "another app's marker",
            "[Desktop Entry]\nX-Lunepack-App-Id=other\n".to_owned(),
        ),
        (
            "a marker prefix only",
            "[Desktop Entry]\nX-Lunepack-App-Id=app2\n".to_owned(),
        ),
        (
            "a marker past the read cap",
            format!(
                "[Desktop Entry]\n{}\nX-Lunepack-App-Id=app\n",
                "#".repeat(70 * 1024)
            ),
        ),
    ] {
        std::fs::write(&path, &content).unwrap();
        let req = request(home, "app", meta("bin/app", Some("app")));
        let before = snapshot(home);
        for result in [
            integration.check(Scope::User, &req),
            integration.apply(Scope::User, &req).map(|_| ()),
        ] {
            assert!(
                matches!(
                    result,
                    Err(IntegrationError::Conflict(IntegrationItem::DesktopEntry))
                ),
                "{what}"
            );
        }
        assert_eq!(snapshot(home), before, "{what}: touched");
        let report = integration.remove(Scope::User, &req).unwrap();
        assert_eq!(report.kept, [IntegrationItem::DesktopEntry], "{what}");
        assert_eq!(snapshot(home), before, "{what}: remove touched it");
    }
}

#[test]
fn a_symlink_or_directory_at_the_desktop_path_is_a_conflict() {
    let s = Scratch::new("desktop-kinds");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    let path = desktop(home, "app");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let marked = home.join("marked.desktop");
    std::fs::write(&marked, "X-Lunepack-App-Id=app\n").unwrap();
    let req = request(home, "app", meta("bin/app", None));

    symlink(&marked, &path).unwrap();
    assert!(matches!(
        integration.check(Scope::User, &req),
        Err(IntegrationError::Conflict(IntegrationItem::DesktopEntry))
    ));
    let report = integration.remove(Scope::User, &req).unwrap();
    assert_eq!(report.kept, [IntegrationItem::DesktopEntry]);
    assert!(std::fs::symlink_metadata(&path).is_ok(), "link removed");
    std::fs::remove_file(&path).unwrap();

    std::fs::create_dir(&path).unwrap();
    assert!(matches!(
        integration.check(Scope::User, &req),
        Err(IntegrationError::Conflict(IntegrationItem::DesktopEntry))
    ));
    let report = integration.remove(Scope::User, &req).unwrap();
    assert_eq!(report.kept, [IntegrationItem::DesktopEntry]);
    assert!(path.is_dir(), "a directory was deleted");
}

#[test]
fn a_foreign_bin_file_or_link_is_a_conflict_and_is_left_alone() {
    let s = Scratch::new("foreign-bin");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    let root = home.join(".local/share/app");
    let link = bin(home, "app");
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    let req = request(home, "app", meta("bin/app", Some("app")));

    // (what, how to plant it)
    type Plant = Box<dyn Fn(&Path)>;
    let cases: Vec<(&str, Plant)> = vec![
        (
            "a regular file",
            Box::new(|p| std::fs::write(p, "#!/bin/sh\n").unwrap()),
        ),
        (
            "a symlink to /usr/bin/x",
            Box::new(|p| symlink("/usr/bin/x", p).unwrap()),
        ),
        (
            "a symlink with a dot-dot after current",
            Box::new({
                let root = root.clone();
                move |p| symlink(root.join("current/../../x"), p).unwrap()
            }),
        ),
        (
            "a symlink to the current link itself",
            Box::new({
                let root = root.clone();
                move |p| symlink(root.join("current"), p).unwrap()
            }),
        ),
        (
            "a symlink to a sibling of current",
            Box::new({
                let root = root.clone();
                move |p| symlink(root.join("currentx/bin/app"), p).unwrap()
            }),
        ),
        (
            "a relative symlink",
            Box::new(|p| symlink("current/bin/app", p).unwrap()),
        ),
        ("a directory", Box::new(|p| std::fs::create_dir(p).unwrap())),
    ];
    for (what, plant) in cases {
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir(&link);
        plant(&link);
        let before = snapshot(home);
        let kind_before = std::fs::symlink_metadata(&link).unwrap().file_type();
        for result in [
            integration.check(Scope::User, &req),
            integration.apply(Scope::User, &req).map(|_| ()),
        ] {
            assert!(
                matches!(
                    result,
                    Err(IntegrationError::Conflict(IntegrationItem::BinLink))
                ),
                "{what}: {result:?}"
            );
        }
        assert_eq!(snapshot(home), before, "{what}: touched");
        assert!(
            !desktop(home, "app").exists(),
            "{what}: a conflict wrote the desktop entry"
        );
        let report = integration.remove(Scope::User, &req).unwrap();
        assert_eq!(report.kept, [IntegrationItem::BinLink], "{what}");
        assert_eq!(snapshot(home), before, "{what}: remove touched it");
        assert_eq!(
            std::fs::symlink_metadata(&link).unwrap().file_type(),
            kind_before,
            "{what}: kind changed"
        );
    }
}

#[test]
fn apply_is_idempotent_and_remove_takes_only_what_it_made() {
    let s = Scratch::new("idempotent");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    let req = request(home, "app", meta("bin/app", Some("app")));
    integration.apply(Scope::User, &req).unwrap();
    let first = snapshot(home);
    let inode = |p: &Path| std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(p).unwrap());
    let ino = inode(&desktop(home, "app"));
    let report = integration.apply(Scope::User, &req).unwrap();
    assert!(report.kept.is_empty());
    assert_eq!(snapshot(home), first);
    assert_eq!(
        inode(&desktop(home, "app")),
        ino,
        "an identical apply rewrote the entry"
    );
    // No temp files are left in either directory.
    for dir in [
        home.join(".local/share/applications"),
        home.join(".local/bin"),
    ] {
        for entry in std::fs::read_dir(dir).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(!name.to_string_lossy().starts_with('.'), "{name:?}");
        }
    }
    // A bystander file in each directory survives remove.
    std::fs::write(home.join(".local/share/applications/other.desktop"), "x").unwrap();
    std::fs::write(home.join(".local/bin/other"), "x").unwrap();
    let report = integration.remove(Scope::User, &req).unwrap();
    assert!(report.kept.is_empty());
    assert!(!desktop(home, "app").exists());
    assert!(std::fs::symlink_metadata(bin(home, "app")).is_err());
    assert!(
        home.join(".local/share/applications/other.desktop")
            .is_file()
    );
    assert!(home.join(".local/bin/other").is_file());
    assert!(home.join(".local/bin").is_dir(), "a directory was deleted");
}

#[test]
fn a_changed_name_refreshes_an_existing_entry() {
    let s = Scratch::new("refresh");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    let mut req = request(home, "app", meta("bin/app", Some("app")));
    integration.apply(Scope::User, &req).unwrap();
    req.meta.name = "Renamed App".to_owned();
    integration.apply(Scope::User, &req).unwrap();
    let written = std::fs::read_to_string(desktop(home, "app")).unwrap();
    assert!(written.contains("Name=Renamed App\n"), "{written}");
    assert!(!written.contains("Example App"));
}

#[test]
fn a_moved_entry_retargets_the_link_and_rewrites_exec() {
    let s = Scratch::new("moved");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    let root = home.join(".local/share/app");
    let old = request(home, "app", meta("bin/app", Some("app")));
    integration.apply(Scope::User, &old).unwrap();
    assert_eq!(
        std::fs::read_link(bin(home, "app")).unwrap(),
        root.join("current/bin/app")
    );
    let new = request(home, "app", meta("app", Some("app")));
    let report = integration.apply(Scope::User, &new).unwrap();
    assert!(report.kept.is_empty());
    assert_eq!(
        std::fs::read_link(bin(home, "app")).unwrap(),
        root.join("current/app")
    );
    let written = std::fs::read_to_string(desktop(home, "app")).unwrap();
    assert!(
        written.contains(&format!("Exec=\"{}/current/app\"\n", root.display())),
        "{written}"
    );
    // Removal still recognises the retargeted link as ours.
    integration.remove(Scope::User, &new).unwrap();
    assert!(std::fs::symlink_metadata(bin(home, "app")).is_err());
}

#[test]
fn a_renamed_bin_removes_the_stale_link_and_keeps_a_foreign_one() {
    let s = Scratch::new("stale");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    let root = home.join(".local/share/app");

    let before = request(home, "app", meta("bin/app", Some("a")));
    integration.apply(Scope::User, &before).unwrap();
    let mut after = request(home, "app", meta("bin/app", Some("b")));
    after.stale_bins = vec!["a".to_owned()];
    let report = integration.apply(Scope::User, &after).unwrap();
    assert!(report.kept.is_empty());
    assert!(
        std::fs::symlink_metadata(bin(home, "a")).is_err(),
        "a stays"
    );
    assert_eq!(
        std::fs::read_link(bin(home, "b")).unwrap(),
        root.join("current/bin/app")
    );

    // A foreign `a` is left in place and reported; `b` is still made.
    std::fs::remove_file(bin(home, "b")).unwrap();
    symlink("/usr/bin/true", bin(home, "a")).unwrap();
    let report = integration.apply(Scope::User, &after).unwrap();
    assert_eq!(report.kept, [IntegrationItem::BinLink]);
    assert_eq!(
        std::fs::read_link(bin(home, "a")).unwrap(),
        PathBuf::from("/usr/bin/true")
    );
    assert!(std::fs::symlink_metadata(bin(home, "b")).is_ok());

    // A stale name that is also the new name is not removed; a bad stale name is refused
    // before anything is written.
    let mut same = after.clone();
    same.stale_bins = vec!["b".to_owned()];
    integration.apply(Scope::User, &same).unwrap();
    assert!(std::fs::symlink_metadata(bin(home, "b")).is_ok());
    let snap = snapshot(home);
    let mut bad = after.clone();
    bad.stale_bins = vec!["../a".to_owned()];
    assert!(matches!(
        integration.apply(Scope::User, &bad),
        Err(IntegrationError::UnsafeField("stale bin"))
    ));
    assert_eq!(snapshot(home), snap);
}

#[test]
fn a_dropped_bin_is_cleaned_through_stale_bins() {
    let s = Scratch::new("dropped");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    integration
        .apply(
            Scope::User,
            &request(home, "app", meta("bin/app", Some("a"))),
        )
        .unwrap();
    let mut next = request(home, "app", meta("bin/app", None));
    next.stale_bins = vec!["a".to_owned()];
    integration.apply(Scope::User, &next).unwrap();
    assert!(std::fs::symlink_metadata(bin(home, "a")).is_err());
}

#[test]
fn unsafe_fields_are_refused_without_writing() {
    let s = Scratch::new("fields");
    let home = s.path();
    let integration = XdgIntegration::new(env(home));
    let good = request(home, "app", meta("bin/app", Some("app")));
    let mut cases: Vec<(&str, IntegrationRequest)> = Vec::new();
    let mut with = |what: &'static str, edit: &dyn Fn(&mut IntegrationRequest)| {
        let mut r = good.clone();
        edit(&mut r);
        cases.push((what, r));
    };
    with("empty name", &|r| r.meta.name = String::new());
    with("a long name", &|r| r.meta.name = "x".repeat(129));
    with("a U+0085 in the name", &|r| {
        r.meta.name = "a\u{85}b".to_owned()
    });
    with("a backslash in the name", &|r| {
        r.meta.name = "a\\nb".to_owned()
    });
    with("leading space", &|r| r.meta.name = " a".to_owned());
    with("a newline in the comment", &|r| {
        r.meta.comment = Some("a\nExec=x".to_owned());
    });
    with("an empty category", &|r| {
        r.meta.categories = vec![String::new()]
    });
    with("17 categories", &|r| {
        r.meta.categories = (0..17).map(|i| format!("C{i}")).collect();
    });
    with("a duplicate category", &|r| {
        r.meta.categories = vec!["A".to_owned(), "A".to_owned()];
    });
    with("a leading dot in bin", &|r| {
        r.meta.bin = Some(".x".to_owned())
    });
    with("a relative install root", &|r| {
        r.install_root = PathBuf::from("relative/app");
    });
    with("a dot-dot install root", &|r| {
        r.install_root = home.join("a/../b");
    });
    for (what, req) in &cases {
        let before = snapshot(home);
        assert!(integration.check(Scope::User, req).is_err(), "{what}");
        assert!(integration.apply(Scope::User, req).is_err(), "{what}");
        assert_eq!(snapshot(home), before, "{what}: wrote something");
    }
    assert!(
        !home.join(".local").exists(),
        "a refusal created directories"
    );
}

#[test]
fn machine_scope_is_unsupported() {
    let s = Scratch::new("machine");
    let integration = XdgIntegration::new(env(s.path()));
    let req = request(s.path(), "app", meta("bin/app", None));
    assert!(matches!(
        integration.check(Scope::Machine, &req),
        Err(IntegrationError::Unsupported)
    ));
    assert!(matches!(
        integration.apply(Scope::Machine, &req),
        Err(IntegrationError::Unsupported)
    ));
    assert!(matches!(
        integration.remove(Scope::Machine, &req),
        Err(IntegrationError::Unsupported)
    ));
}
