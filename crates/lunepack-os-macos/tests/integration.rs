//! `MacIntegration` on a real file system: golden entry bytes, the environment rules, the unsafe
//! refusals, ownership of the entry (a foreign file is a conflict and is never touched), and the
//! testkit's integration suite.
//!
//! Every case runs with `HOME` pointing into its own scratch directory; nothing reads or writes
//! the real home.
#![cfg(target_os = "macos")]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use lunepack_core::{
    AppId, InstallMeta, IntegrationError, IntegrationItem, IntegrationRequest, OsIntegration,
    RelPath, Scope, Version,
};
use lunepack_os_macos::{MacEnv, MacIntegration};
use lunepack_testkit::{SuiteHooks, run_integration_suite_with};

/// A canonical scratch directory, removed afterwards.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("lunepack-macint-{}-{name}", std::process::id()));
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

fn integration(home: &Path) -> MacIntegration {
    MacIntegration::new(MacEnv {
        home: Some(home.as_os_str().to_owned()),
    })
}

fn meta(autostart: bool) -> InstallMeta {
    InstallMeta {
        entry: RelPath::parse("Contents/MacOS/example").unwrap(),
        name: "Example App".to_owned(),
        comment: None,
        icon: None,
        categories: vec![],
        bin: None,
        terminal: false,
        publisher: None,
        file_types: Vec::new(),
        url_schemes: Vec::new(),
        autostart,
    }
}

/// A request for `id` whose live bundle is `bundle`.
fn request(bundle: &Path, id: &str, autostart: bool) -> IntegrationRequest {
    IntegrationRequest {
        app_id: AppId::parse(id).unwrap(),
        install_root: bundle.to_owned(),
        version: Version::parse("1.0.0").unwrap(),
        meta: meta(autostart),
        previous: None,
        stale_bins: vec![],
    }
}

fn agents(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
}

fn entry(home: &Path, id: &str) -> PathBuf {
    agents(home).join(format!("{id}.lunepack.plist"))
}

const GOLDEN: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>acme.tool.lunepack</string>
	<key>ProgramArguments</key>
	<array>
		<string>/Users/someone/Applications/Example App.app/Contents/MacOS/example</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>X-Lunepack-App-Name</key>
	<string>Example App</string>
</dict>
</plist>
"#;

#[test]
fn the_entry_has_golden_bytes_and_mode() {
    let s = Scratch::new("golden");
    let req = request(
        Path::new("/Users/someone/Applications/Example App.app"),
        "acme.tool",
        true,
    );
    let report = integration(s.path()).apply(Scope::User, &req).unwrap();
    assert!(report.kept.is_empty());
    let path = entry(s.path(), "acme.tool");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), GOLDEN);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    // Nothing else was made: the directory holds the entry and no temporary.
    let names: Vec<_> = std::fs::read_dir(agents(s.path()))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, [OsString::from("acme.tool.lunepack.plist")]);
}

#[test]
fn program_arguments_come_from_the_request_not_from_an_existing_file() {
    let s = Scratch::new("request-wins");
    let int = integration(s.path());
    let first = request(Path::new("/Applications/One.app"), "acme.tool", true);
    int.apply(Scope::User, &first).unwrap();
    let second = request(Path::new("/Applications/Two.app"), "acme.tool", true);
    int.apply(Scope::User, &second).unwrap();
    let text = std::fs::read_to_string(entry(s.path(), "acme.tool")).unwrap();
    assert!(text.contains("<string>/Applications/Two.app/Contents/MacOS/example</string>"));
    assert!(!text.contains("One.app"));
}

#[test]
fn strings_are_xml_escaped() {
    let s = Scratch::new("escape");
    let mut req = request(Path::new("/Applications/A&B <x>\"'.app"), "acme.tool", true);
    req.meta.name = "Tom & \"Jerry\" <1>".to_owned();
    integration(s.path()).apply(Scope::User, &req).unwrap();
    let text = std::fs::read_to_string(entry(s.path(), "acme.tool")).unwrap();
    assert!(text.contains(
        "<string>/Applications/A&amp;B &lt;x&gt;&quot;&apos;.app/Contents/MacOS/example</string>"
    ));
    assert!(text.contains("<string>Tom &amp; &quot;Jerry&quot; &lt;1&gt;</string>"));
    // Whatever is in the name, the entry is still ours (its label is intact).
    let report = integration(s.path()).remove(Scope::User, &req).unwrap();
    assert!(report.kept.is_empty());
    assert!(!entry(s.path(), "acme.tool").exists());
}

#[test]
fn declarations_that_macos_takes_from_the_info_plist_make_no_entry() {
    let s = Scratch::new("no-items");
    let mut req = request(Path::new("/Applications/E.app"), "acme.tool", false);
    req.meta.file_types = vec![lunepack_core::FileType {
        ext: "ex".to_owned(),
        mime: "application/x-ex".to_owned(),
        name: "Ex".to_owned(),
    }];
    req.meta.url_schemes = vec!["acme-ex".to_owned()];
    req.meta.bin = Some("ex".to_owned());
    let int = integration(s.path());
    int.check(Scope::User, &req).unwrap();
    let report = int.apply(Scope::User, &req).unwrap();
    assert!(report.kept.is_empty());
    assert!(
        !agents(s.path()).exists(),
        "nothing, not even the directory"
    );
}

#[test]
fn the_environment_must_name_a_usable_home() {
    let req = request(Path::new("/Applications/E.app"), "acme.tool", true);
    let s = Scratch::new("home");
    let file = s.path().join("file");
    std::fs::write(&file, b"x").unwrap();
    for home in [
        None,
        Some(OsString::new()),
        Some(OsString::from("relative/home")),
        Some(s.path().join("missing").into_os_string()),
        Some(file.into_os_string()),
        Some(OsString::from_vec(vec![b'/', 0xFF, b'h'])),
    ] {
        let int = MacIntegration::new(MacEnv { home });
        for result in [
            int.check(Scope::User, &req),
            int.apply(Scope::User, &req).map(|_| ()),
            int.remove(Scope::User, &req).map(|_| ()),
        ] {
            assert!(matches!(result, Err(IntegrationError::Home)), "{result:?}");
        }
    }
}

#[test]
fn a_home_reached_through_a_symlink_is_canonicalised() {
    let s = Scratch::new("symlink-home");
    let real = s.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = s.path().join("link");
    symlink(&real, &link).unwrap();
    let req = request(Path::new("/Applications/E.app"), "acme.tool", true);
    integration(&link).apply(Scope::User, &req).unwrap();
    assert!(entry(&real, "acme.tool").is_file());
}

#[test]
fn an_unusable_bundle_path_or_name_is_refused_and_nothing_is_written() {
    let s = Scratch::new("unsafe");
    let int = integration(s.path());
    let mut cases: Vec<(&str, IntegrationRequest)> = Vec::new();
    let good = request(Path::new("/Applications/E.app"), "acme.tool", true);
    let mut with = |what: &'static str, edit: &dyn Fn(&mut IntegrationRequest)| {
        let mut r = good.clone();
        edit(&mut r);
        cases.push((what, r));
    };
    with("a relative bundle path", &|r| {
        r.install_root = PathBuf::from("Applications/E.app");
    });
    with("dot dot in the bundle path", &|r| {
        r.install_root = PathBuf::from("/Applications/../Evil.app");
    });
    with("a dot in the bundle path", &|r| {
        r.install_root = PathBuf::from("/Applications/./E.app");
    });
    with("a newline in the bundle path", &|r| {
        r.install_root = PathBuf::from("/Applications/SECRET\nE.app");
    });
    with("a non-UTF-8 bundle path", &|r| {
        r.install_root =
            PathBuf::from(OsString::from_vec(b"/Applications/\xFFSECRET.app".to_vec()));
    });
    with("a newline in the name", &|r| {
        r.meta.name = "SECRET\nname".to_owned();
    });
    with("a control character in the name", &|r| {
        r.meta.name = "SECRET\u{7}name".to_owned();
    });
    with("an empty name", &|r| {
        r.meta.name = String::new();
    });
    for (what, req) in &cases {
        for result in [
            int.check(Scope::User, req),
            int.apply(Scope::User, req).map(|_| ()),
        ] {
            let err = result.expect_err(what);
            assert!(
                matches!(err, IntegrationError::UnsafeField(_)),
                "{what}: {err:?}"
            );
            assert!(
                !format!("{err} / {err:?}").contains("SECRET"),
                "{what}: shows the value"
            );
        }
    }
    assert!(!agents(s.path()).exists(), "something was written");
}

#[test]
fn a_foreign_file_at_the_entry_is_a_conflict_and_is_never_touched() {
    let s = Scratch::new("foreign");
    let int = integration(s.path());
    let req = request(Path::new("/Applications/E.app"), "acme.tool", true);
    let path = entry(s.path(), "acme.tool");
    std::fs::create_dir_all(agents(s.path())).unwrap();

    // Another label, no label at all, a binary plist, and a symlink all are foreign.
    let foreign: Vec<(&str, Vec<u8>)> = vec![
        (
            "another label",
            b"<plist><dict><key>Label</key><string>other.job</string></dict></plist>".to_vec(),
        ),
        ("no label", b"hello".to_vec()),
        ("a binary plist", b"bplist00\x00\x01".to_vec()),
        (
            "our label in the wrong key",
            b"<key>Name</key><string>acme.tool.lunepack</string>".to_vec(),
        ),
    ];
    for (what, bytes) in foreign {
        std::fs::write(&path, &bytes).unwrap();
        for result in [
            int.check(Scope::User, &req),
            int.apply(Scope::User, &req).map(|_| ()),
        ] {
            assert!(
                matches!(
                    result,
                    Err(IntegrationError::Conflict(IntegrationItem::Autostart))
                ),
                "{what}: {result:?}"
            );
        }
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{what}: changed");
        let report = int.remove(Scope::User, &req).unwrap();
        assert_eq!(report.kept, vec![IntegrationItem::Autostart], "{what}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{what}: removed");
        // Dropping the declaration does not delete it either.
        let mut bare = req.clone();
        bare.meta.autostart = false;
        let report = int.apply(Scope::User, &bare).unwrap();
        assert_eq!(report.kept, vec![IntegrationItem::Autostart], "{what}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "{what}: dropped");
    }

    // A symlink at the entry is not followed and not replaced, even when it points at our file.
    std::fs::remove_file(&path).unwrap();
    let real = s.path().join("real.plist");
    int.apply(Scope::User, &req).unwrap();
    std::fs::rename(&path, &real).unwrap();
    symlink(&real, &path).unwrap();
    assert!(matches!(
        int.apply(Scope::User, &req),
        Err(IntegrationError::Conflict(IntegrationItem::Autostart))
    ));
    let report = int.remove(Scope::User, &req).unwrap();
    assert_eq!(report.kept, vec![IntegrationItem::Autostart]);
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(real.is_file());
}

#[test]
fn an_entry_with_our_label_is_ours_even_when_its_other_content_differs() {
    let s = Scratch::new("ours");
    let int = integration(s.path());
    let req = request(Path::new("/Applications/E.app"), "acme.tool", true);
    std::fs::create_dir_all(agents(s.path())).unwrap();
    let path = entry(s.path(), "acme.tool");
    // An older version's bytes (another path): ours by label, so it is refreshed, then removed.
    std::fs::write(
        &path,
        "<dict>\n\t<key>Label</key>\n\t<string>acme.tool.lunepack</string>\n\t<key>Old</key>\n</dict>\n",
    )
    .unwrap();
    int.apply(Scope::User, &req).unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("/Applications/E.app/Contents/MacOS/example")
    );
    let report = int.remove(Scope::User, &req).unwrap();
    assert!(report.kept.is_empty());
    assert!(!path.exists());
}

#[test]
fn another_apps_entry_is_left_alone() {
    let s = Scratch::new("two-apps");
    let int = integration(s.path());
    let a = request(Path::new("/Applications/A.app"), "acme.a", true);
    let b = request(Path::new("/Applications/B.app"), "acme.b", true);
    int.apply(Scope::User, &a).unwrap();
    int.apply(Scope::User, &b).unwrap();
    let b_bytes = std::fs::read(entry(s.path(), "acme.b")).unwrap();
    int.remove(Scope::User, &a).unwrap();
    assert!(!entry(s.path(), "acme.a").exists());
    assert_eq!(std::fs::read(entry(s.path(), "acme.b")).unwrap(), b_bytes);
}

#[test]
fn a_launch_agents_directory_that_is_a_symlink_is_refused() {
    let s = Scratch::new("agents-link");
    let elsewhere = s.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::create_dir_all(s.path().join("Library")).unwrap();
    symlink(&elsewhere, agents(s.path())).unwrap();
    let req = request(Path::new("/Applications/E.app"), "acme.tool", true);
    let err = integration(s.path())
        .apply(Scope::User, &req)
        .expect_err("a symlinked directory");
    assert!(matches!(err, IntegrationError::Failed(_)), "{err:?}");
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[test]
fn machine_scope_is_unsupported() {
    let s = Scratch::new("machine");
    let req = request(Path::new("/Applications/E.app"), "acme.tool", true);
    let int = integration(s.path());
    assert!(matches!(
        int.check(Scope::Machine, &req),
        Err(IntegrationError::Unsupported)
    ));
    assert!(matches!(
        int.apply(Scope::Machine, &req),
        Err(IntegrationError::Unsupported)
    ));
    assert!(matches!(
        int.remove(Scope::Machine, &req),
        Err(IntegrationError::Unsupported)
    ));
}

/// The adapter never runs the system's job manager: neither adapter source starts a program
/// other than through the notice's bounded `osascript` (so the entry takes effect at the next
/// sign-in).
#[test]
fn the_integration_starts_no_program() {
    let source = include_str!("../src/integration.rs");
    for needle in ["Command", "spawn(", "launchctl"] {
        assert!(
            !source.contains(needle),
            "integration.rs mentions `{needle}`"
        );
    }
}

#[test]
fn the_shared_integration_suite_passes() {
    let s = Scratch::new("suite");
    let hooks = SuiteHooks {
        entry: "Contents/MacOS/app",
        // Fields this adapter never writes (macOS takes file types and URL schemes from the
        // app's own Info.plist, and the entry holds no command, comment, category or icon).
        not_applicable: &[
            "a newline in the comment",
            "a semicolon in a category",
            "a newline in a category",
            "a slash in bin",
            "dot dot in bin",
            "a semicolon in a mime type",
            "a newline in a mime type",
            "a dot in an extension",
            "an uppercase extension",
            "a newline in a file type name",
            "the same extension twice",
            "a denied URL scheme",
            "a denied ms- URL scheme",
            "a semicolon in a URL scheme",
            // Quotes and percent signs are escaped, not refused, in a property list.
            "a quote in the install root",
            "a percent sign in the install root",
        ],
        ..SuiteHooks::default()
    };
    run_integration_suite_with(&integration(s.path()), s.path(), &hooks);
}
