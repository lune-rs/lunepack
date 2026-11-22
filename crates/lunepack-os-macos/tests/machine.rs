//! The macOS per-machine ports (M11) on a real file system, without root: the testkit's protect,
//! service-channel and integration suites, the protection rule's refusals (an extended ACL
//! included), the policy file's cases (M11-D11), the connector's refusals before any byte
//! (M11-D5), the LaunchDaemon plist byte for byte and the registrar's flow over a fake
//! `launchctl`, launchd activation outside launchd, and the elevation's standing. Ownership by
//! root is stood in for by the test's own uid (each adapter's `for_tests`).
#![cfg(target_os = "macos")]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use lunepack_core::{
    AppId, ConnectError, DirClass, Elevation, ElevationError, IntegrationReport,
    IntegrationRequest, MachinePolicy, OsIntegration, PolicySource, Protect, ProtectError, Scope,
    ServiceConnector, ServiceRegError, ServiceRegistrar, Standing,
};
use lunepack_os_macos::{
    ActivatedListener, ActivationError, FilePolicy, LaunchdRegistrar, MacElevation,
    MacMachineIntegration, MacProtect, UnixConnector, UnixDuplex, daemon_plist, effective_uid,
};
use lunepack_testkit::{SuiteHooks, run_integration_suite_with};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A canonical scratch directory (mode 0755), removed afterwards. Short (under `/tmp`), so a
/// socket path in it fits `sun_path`.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = PathBuf::from(format!(
            "/tmp/lpk-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).expect("create scratch");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        Scratch(fs::canonicalize(&dir).expect("canonicalize scratch"))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn ids(path: &Path) -> (u32, u32) {
    let m = fs::metadata(path).unwrap();
    (m.uid(), m.gid())
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn write(path: &Path, bytes: &[u8]) {
    let mut f = fs::File::create(path).unwrap();
    f.write_all(bytes).unwrap();
}

fn app(id: &str) -> AppId {
    AppId::parse(id).unwrap()
}

// ---- Protect ---------------------------------------------------------------------------------------

fn protect(s: &Scratch) -> MacProtect {
    let (uid, gid) = ids(s.path());
    MacProtect::for_tests(uid, gid, s.path().to_path_buf())
}

#[test]
fn the_protect_suite_passes() {
    let s = Scratch::new("protect-suite");
    let p = protect(&s);
    lunepack_testkit::run_protect_suite(&p, &lunepack_fs_stand_in::Fs, s.path());
}

#[test]
fn created_directories_get_the_exact_mode_whatever_the_umask() {
    let s = Scratch::new("protect-mode");
    let p = protect(&s);
    let tree = s.path().join("tree");
    p.create_dir(&tree, DirClass::MachineTree).unwrap();
    assert_eq!(fs::metadata(&tree).unwrap().mode() & 0o7777, 0o755);
    let admin = tree.join("machine");
    p.create_dir(&admin, DirClass::AdminOnly).unwrap();
    assert_eq!(fs::metadata(&admin).unwrap().mode() & 0o7777, 0o700);
}

#[test]
fn the_protection_rule_refuses_what_others_may_change() {
    let s = Scratch::new("protect-refuse");
    let p = protect(&s);
    let tree = s.path().join("tree");
    p.create_dir(&tree, DirClass::MachineTree).unwrap();
    let child = tree.join("child");
    p.create_dir(&child, DirClass::MachineTree).unwrap();
    chmod(&child, 0o757);
    assert!(matches!(
        p.check(&child, DirClass::MachineTree),
        Err(ProtectError::NotProtected)
    ));
    chmod(&child, 0o755);
    p.check(&child, DirClass::MachineTree).unwrap();
    chmod(&tree, 0o1777);
    assert!(matches!(
        p.check(&child, DirClass::MachineTree),
        Err(ProtectError::NotProtected)
    ));
    chmod(&tree, 0o755);
    let admin = tree.join("admin");
    p.create_dir(&admin, DirClass::AdminOnly).unwrap();
    chmod(&admin, 0o750);
    assert!(matches!(
        p.check(&admin, DirClass::AdminOnly),
        Err(ProtectError::NotProtected)
    ));
    chmod(&admin, 0o700);
    p.check(&admin, DirClass::AdminOnly).unwrap();
    let link = tree.join("link");
    symlink(&admin, &link).unwrap();
    assert!(matches!(
        p.check(&link, DirClass::AdminOnly),
        Err(ProtectError::NotProtected)
    ));
    let (uid, gid) = ids(s.path());
    let stranger = MacProtect::for_tests(uid.wrapping_add(1), gid, s.path().to_path_buf());
    assert!(matches!(
        stranger.check(&child, DirClass::MachineTree),
        Err(ProtectError::NotProtected)
    ));
}

#[test]
fn any_extended_acl_entry_is_refused() {
    let s = Scratch::new("protect-acl");
    let p = protect(&s);
    let tree = s.path().join("tree");
    p.create_dir(&tree, DirClass::MachineTree).unwrap();
    // Even an entry that only denies.
    let status = Command::new("/bin/chmod")
        .arg("+a")
        .arg("everyone deny delete")
        .arg(&tree)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(matches!(
        p.check(&tree, DirClass::MachineTree),
        Err(ProtectError::NotProtected)
    ));
    // An inheritable entry on the parent makes a new directory fail its check: it is removed.
    let status = Command::new("/bin/chmod")
        .arg("+a")
        .arg("everyone allow add_file,directory_inherit")
        .arg(s.path())
        .status()
        .unwrap();
    assert!(status.success());
    let inherits = s.path().join("inherits");
    assert!(p.create_dir(&inherits, DirClass::AdminOnly).is_err());
    assert!(
        !inherits.exists(),
        "the directory that failed its check is removed"
    );
    let _ = Command::new("/bin/chmod").arg("-N").arg(s.path()).status();
    let _ = Command::new("/bin/chmod").arg("-N").arg(&tree).status();
}

/// The testkit's protect suite takes an `Fs` for its scratch files; the real one lives in
/// `lunepack-fs`, which this crate does not depend on, so a minimal stand-in writes them.
mod lunepack_fs_stand_in {
    use std::io::Write;
    use std::path::Path;

    use lunepack_core::{DirEntryInfo, FileWrite, FsError, LockGuard, Meta, ReadAt};

    pub struct Fs;

    struct W(std::fs::File);

    impl Write for W {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    impl FileWrite for W {
        fn sync(&mut self) -> Result<(), FsError> {
            self.0
                .sync_all()
                .map_err(|e| FsError::from_io(Path::new("f"), e))
        }
    }

    fn unsupported(path: &Path) -> FsError {
        FsError::new(lunepack_core::FsErrorKind::Unsupported, path, None)
    }

    impl lunepack_core::Fs for Fs {
        fn read_capped(&self, path: &Path, _: u64) -> Result<Vec<u8>, FsError> {
            Err(unsupported(path))
        }
        fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
            Err(unsupported(path))
        }
        fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map(|f| Box::new(W(f)) as Box<dyn FileWrite>)
                .map_err(|e| FsError::from_io(path, e))
        }
        fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
            Err(unsupported(path))
        }
        fn truncate(&self, path: &Path, _: u64) -> Result<(), FsError> {
            Err(unsupported(path))
        }
        fn rename(&self, from: &Path, _: &Path) -> Result<(), FsError> {
            Err(unsupported(from))
        }
        fn remove_file(&self, path: &Path) -> Result<(), FsError> {
            Err(unsupported(path))
        }
        fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), FsError> {
            std::fs::remove_dir_all(path).map_err(|e| FsError::from_io(path, e))
        }
        fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
            Err(unsupported(path))
        }
        fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
            Err(unsupported(path))
        }
        fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError> {
            Err(unsupported(path))
        }
        fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
            Err(unsupported(path))
        }
        fn copy_file(&self, from: &Path, _: &Path) -> Result<(), FsError> {
            Err(unsupported(from))
        }
        fn set_exec(&self, path: &Path, _: bool) -> Result<(), FsError> {
            Err(unsupported(path))
        }
        fn symlink(&self, _: &str, path: &Path) -> Result<(), FsError> {
            Err(unsupported(path))
        }
        fn read_link(&self, path: &Path) -> Result<String, FsError> {
            Err(unsupported(path))
        }
        fn replace_symlink(&self, _: &str, path: &Path) -> Result<(), FsError> {
            Err(unsupported(path))
        }
        fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
            Err(unsupported(path))
        }
    }
}

// ---- the policy file (M11-D11) --------------------------------------------------------------------

const OFF: MachinePolicy = MachinePolicy {
    self_update_disabled: false,
    no_update_ui: false,
};

#[test]
fn the_policy_file_cases() {
    let s = Scratch::new("policy");
    let (uid, _) = ids(s.path());
    let dir = s.path().join("policy");
    let id = app("org.example.hello");
    let policy = FilePolicy::for_tests(dir.clone(), uid);
    let file = dir.join("org.example.hello.json");

    assert_eq!(policy.read(&id), OFF, "no directory: off");
    fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o755);
    assert_eq!(policy.read(&id), OFF, "no file: off");

    let set = |bytes: &[u8]| {
        let _ = fs::remove_file(&file);
        write(&file, bytes);
        chmod(&file, 0o644);
    };
    set(br#"{"disable_self_update": true}"#);
    assert_eq!(
        policy.read(&id),
        MachinePolicy {
            self_update_disabled: true,
            no_update_ui: false
        }
    );
    set(br#"{"no_update_ui": true, "disable_self_update": false}"#);
    assert_eq!(
        policy.read(&id),
        MachinePolicy {
            self_update_disabled: false,
            no_update_ui: true
        }
    );
    set(b"{}");
    assert_eq!(policy.read(&id), OFF);

    let closed = MachinePolicy::FAIL_CLOSED;
    for (what, bytes) in [
        ("not JSON", &b"disable_self_update=1"[..]),
        (
            "a repeated key",
            br#"{"no_update_ui": true, "no_update_ui": false}"#,
        ),
        (
            "an unknown member",
            br#"{"disable_self_update": false, "x": true}"#,
        ),
        ("a string", br#"{"disable_self_update": "true"}"#),
        ("null", br#"{"no_update_ui": null}"#),
        ("a number", br#"{"no_update_ui": 1}"#),
        ("an array", b"[]"),
        ("trailing data", b"{} {}"),
        ("empty", b""),
    ] {
        set(bytes);
        assert_eq!(policy.read(&id), closed, "{what}");
    }
    let mut big = b"{\"no_update_ui\": false".to_vec();
    big.resize(4096, b' ');
    big.push(b'}');
    set(&big);
    assert_eq!(policy.read(&id), closed, "larger than 4 KiB");

    set(b"{}");
    chmod(&file, 0o664);
    assert_eq!(policy.read(&id), closed, "a group-writable file");
    chmod(&file, 0o646);
    assert_eq!(policy.read(&id), closed, "a world-writable file");
    chmod(&file, 0o644);
    chmod(&dir, 0o775);
    assert_eq!(policy.read(&id), closed, "a group-writable directory");
    chmod(&dir, 0o755);
    assert_eq!(
        FilePolicy::for_tests(dir.clone(), uid.wrapping_add(1)).read(&id),
        closed,
        "a file and directory of another owner"
    );
    fs::remove_file(&file).unwrap();
    let elsewhere = s.path().join("elsewhere.json");
    write(&elsewhere, b"{}");
    symlink(&elsewhere, &file).unwrap();
    assert_eq!(policy.read(&id), closed, "a link");
    fs::remove_file(&file).unwrap();
    fs::create_dir(&file).unwrap();
    assert_eq!(policy.read(&id), closed, "a directory at the file's name");
    fs::remove_dir(&file).unwrap();
    assert_eq!(policy.read(&id), OFF, "absent again");
}

// ---- the connector (M11-D5) -----------------------------------------------------------------------

fn fresh_app() -> AppId {
    app(&format!(
        "suite.app-{}",
        NEXT.fetch_add(1, Ordering::SeqCst)
    ))
}

fn sock(dir: &Path, id: &AppId) -> PathBuf {
    dir.join(format!("lunepack-{}.sock", id.as_str()))
}

#[test]
fn the_service_channel_suite_passes_over_the_socket() {
    let s = Scratch::new("channel");
    let (uid, _) = ids(s.path());
    let dir = s.path().to_path_buf();
    lunepack_testkit::run_service_channel_suite(&|| {
        let id = fresh_app();
        let listener = UnixListener::bind(sock(&dir, &id)).unwrap();
        let connector = UnixConnector::for_tests(dir.clone(), uid, Duration::ZERO);
        let client = connector.connect(&id).expect("connect");
        let (server, _) = listener.accept().unwrap();
        (client, Box::new(UnixDuplex::new(server)))
    });
}

#[test]
fn the_connector_refuses_before_a_byte() {
    let s = Scratch::new("connect");
    let (uid, _) = ids(s.path());
    let dir = s.path().to_path_buf();
    let id = fresh_app();
    let listener = UnixListener::bind(sock(&dir, &id)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let nothing_connected = || {
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "nothing reached the server"
        );
    };
    let stranger = UnixConnector::for_tests(dir.clone(), uid.wrapping_add(1), Duration::ZERO);
    assert!(matches!(
        stranger.connect(&id),
        Err(ConnectError::WrongOwner)
    ));
    nothing_connected();
    chmod(&dir, 0o777);
    let c = UnixConnector::for_tests(dir.clone(), uid, Duration::ZERO);
    assert!(matches!(c.connect(&id), Err(ConnectError::WrongOwner)));
    nothing_connected();
    chmod(&dir, 0o755);
    let other = fresh_app();
    write(&sock(&dir, &other), b"x");
    assert!(matches!(c.connect(&other), Err(ConnectError::WrongOwner)));
    let retrying = UnixConnector::for_tests(dir.clone(), uid, Duration::from_millis(300));
    let started = std::time::Instant::now();
    assert!(matches!(
        retrying.connect(&fresh_app()),
        Err(ConnectError::NotInstalled)
    ));
    assert!(started.elapsed() >= Duration::from_millis(300));
    let dead = fresh_app();
    drop(UnixListener::bind(sock(&dir, &dead)).unwrap());
    assert!(matches!(c.connect(&dead), Err(ConnectError::Disabled)));
    assert!(c.connect(&id).is_ok());
}

#[test]
fn the_production_connector_looks_in_var_run() {
    let r = UnixConnector::new().connect(&app("org.example.never-installed-here"));
    assert!(matches!(
        r,
        Err(ConnectError::NotInstalled | ConnectError::WrongOwner)
    ));
}

#[test]
fn launchd_activation_outside_launchd_is_an_error() {
    assert!(matches!(
        ActivatedListener::from_launchd("lunepack"),
        Err(ActivationError::NotActivated(_) | ActivationError::WrongCount(_))
    ));
    assert!(ActivatedListener::from_launchd("bad\0name").is_err());
}

// ---- the LaunchDaemon and registrar (M11-D4) --------------------------------------------------------

const PLIST_HEAD: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<!-- Written by lunepack; do not edit. -->\n\
<plist version=\"1.0\">\n\
<dict>\n\
\t<key>Label</key>\n\
\t<string>lunepack-org.example.hello</string>\n\
\t<key>ProgramArguments</key>\n\
\t<array>\n\
\t\t<string>/Library/Application Support/lunepack/org.example.hello/.lunepack/machine/lunepack-service</string>\n\
\t</array>\n\
\t<key>Sockets</key>\n\
\t<dict>\n\
\t\t<key>lunepack</key>\n\
\t\t<dict>\n\
\t\t\t<key>SockPathName</key>\n\
\t\t\t<string>/var/run/lunepack-org.example.hello.sock</string>\n\
\t\t\t<key>SockPathMode</key>\n\
\t\t\t<integer>438</integer>\n\
\t\t</dict>\n\
\t</dict>\n";

#[test]
fn the_plist_has_exactly_these_bytes() {
    let id = app("org.example.hello");
    let exec = Path::new(
        "/Library/Application Support/lunepack/org.example.hello/.lunepack/machine/lunepack-service",
    );
    assert_eq!(
        daemon_plist(&id, exec, None).unwrap(),
        format!("{PLIST_HEAD}</dict>\n</plist>\n")
    );
    assert_eq!(
        daemon_plist(&id, exec, Some("org.example.Hello")).unwrap(),
        format!(
            "{PLIST_HEAD}\t<key>AssociatedBundleIdentifiers</key>\n\
             \t<array>\n\
             \t\t<string>org.example.Hello</string>\n\
             \t</array>\n\
             </dict>\n</plist>\n"
        )
    );
}

#[test]
fn plist_strings_are_escaped_and_control_characters_refused() {
    let id = app("org.example.hello");
    let text = daemon_plist(
        &id,
        Path::new("/R & <D>/\"q\"/'a'/lunepack-service"),
        Some("a&b"),
    )
    .unwrap();
    assert!(text.contains(
        "<string>/R &amp; &lt;D&gt;/&quot;q&quot;/&apos;a&apos;/lunepack-service</string>"
    ));
    assert!(text.contains("<string>a&amp;b</string>"));
    assert_eq!(
        daemon_plist(&id, Path::new("/a\nb/lunepack-service"), None),
        None
    );
    assert_eq!(
        daemon_plist(&id, Path::new("/a/lunepack-service"), Some("x\ny")),
        None
    );
}

/// A fake launchctl: it logs each call and keeps the job loaded between `bootstrap` and
/// `bootout` (a file), which `print` answers.
fn fake_launchctl(s: &Scratch) -> (PathBuf, PathBuf) {
    let tool = s.path().join("launchctl");
    let log = s.path().join("launchctl.log");
    let state = s.path().join("loaded");
    write(
        &tool,
        format!(
            "#!/bin/sh\necho \"$*\" >> '{log}'\n\
             case \"$1\" in\n\
             print) [ -f '{state}' ] && exit 0; exit 113;;\n\
             bootstrap) : > '{state}';;\n\
             bootout) /bin/rm -f '{state}';;\n\
             esac\nexit 0\n",
            log = log.display(),
            state = state.display()
        )
        .as_bytes(),
    );
    chmod(&tool, 0o755);
    (tool, log)
}

fn service_binary(path: &Path, exit: i32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    write(path, format!("#!/bin/sh\nexit {exit}\n").as_bytes());
    chmod(path, 0o755);
}

#[test]
fn the_registrar_writes_the_plist_and_switches_the_stable_link() {
    let s = Scratch::new("launchd");
    let (tool, log) = fake_launchctl(&s);
    let daemons = s.path().join("LaunchDaemons");
    fs::create_dir(&daemons).unwrap();
    let reg = LaunchdRegistrar::for_tests(daemons.clone(), tool, Some("org.example.Hello".into()));
    let id = app("org.example.hello");
    let root = s
        .path()
        .join("Library/Application Support/lunepack/org.example.hello");
    let machine = root.join(".lunepack/machine");
    let v1 = machine.join("service/1.0.0/lunepack-service");
    let v2 = machine.join("service/2.0.0/lunepack-service");
    service_binary(&v1, 0);
    service_binary(&v2, 0);
    let plist = daemons.join("lunepack-org.example.hello.plist");

    assert_eq!(reg.image(&id), Ok(None));
    assert_eq!(reg.set_image(&id, &v2), Err(ServiceRegError::NotRegistered));
    reg.register(&id, &v1).unwrap();
    let link = machine.join("lunepack-service");
    assert_eq!(
        fs::read_link(&link).unwrap(),
        PathBuf::from("service/1.0.0/lunepack-service")
    );
    assert_eq!(
        fs::read_to_string(&plist).unwrap(),
        daemon_plist(&id, &link, Some("org.example.Hello")).unwrap()
    );
    assert_eq!(fs::metadata(&plist).unwrap().mode() & 0o777, 0o644);
    let bootstrap = format!("bootstrap system {}", plist.display());
    assert_eq!(
        fs::read_to_string(&log).unwrap(),
        format!("print system/lunepack-org.example.hello\n{bootstrap}\n")
    );
    assert_eq!(reg.image(&id), Ok(Some(v1.clone())));

    // Registering again boots the loaded job out first.
    reg.register(&id, &v1).unwrap();
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.ends_with(&format!(
        "print system/lunepack-org.example.hello\n\
         bootout system/lunepack-org.example.hello\n\
         print system/lunepack-org.example.hello\n\
         {bootstrap}\n"
    )));

    reg.set_image(&id, &v2).unwrap();
    assert_eq!(reg.image(&id), Ok(Some(v2.clone())));
    assert_eq!(
        fs::read_to_string(&log).unwrap(),
        calls,
        "set_image runs no launchctl"
    );
    let other = s
        .path()
        .join("other/.lunepack/machine/service/1.0.0/lunepack-service");
    service_binary(&other, 0);
    assert!(reg.set_image(&id, &other).is_err());
    fs::remove_file(&link).unwrap();
    symlink(&other, &link).unwrap();
    assert!(
        reg.image(&id).is_err(),
        "a link out of the tree is not believed"
    );

    reg.remove(&id).unwrap();
    assert!(!plist.exists());
    assert!(fs::read_to_string(&log).unwrap().ends_with(
        "bootout system/lunepack-org.example.hello\nprint system/lunepack-org.example.hello\n"
    ));
    reg.remove(&id).unwrap();
    assert_eq!(reg.image(&id), Ok(None));
}

#[test]
fn without_a_bundle_id_the_plist_names_none() {
    let s = Scratch::new("launchd-nobundle");
    let (tool, _) = fake_launchctl(&s);
    let reg = LaunchdRegistrar::for_tests(s.path().to_path_buf(), tool, None);
    let id = app("org.example.hello");
    let image = s
        .path()
        .join("R/.lunepack/machine/service/1.0.0/lunepack-service");
    service_binary(&image, 0);
    reg.register(&id, &image).unwrap();
    let text = fs::read_to_string(s.path().join("lunepack-org.example.hello.plist")).unwrap();
    assert!(!text.contains("AssociatedBundleIdentifiers"));
}

#[test]
fn the_self_test_passes_only_on_exit_zero() {
    let s = Scratch::new("selftest");
    let (tool, _) = fake_launchctl(&s);
    let reg = LaunchdRegistrar::for_tests(s.path().to_path_buf(), tool, None);
    let good = s.path().join("good");
    let bad = s.path().join("bad");
    service_binary(&good, 0);
    service_binary(&bad, 3);
    assert_eq!(reg.self_test(&good), Ok(()));
    assert_eq!(reg.self_test(&bad), Err(ServiceRegError::SelfTestFailed));
    assert_eq!(
        reg.self_test(&s.path().join("missing")),
        Err(ServiceRegError::SelfTestFailed)
    );
}

#[test]
fn a_plist_that_is_not_ours_is_not_believed() {
    let s = Scratch::new("foreign-plist");
    let (tool, _) = fake_launchctl(&s);
    let reg = LaunchdRegistrar::for_tests(s.path().to_path_buf(), tool, None);
    write(
        &s.path().join("lunepack-org.example.hello.plist"),
        b"<plist><dict><key>ProgramArguments</key><array><string>/x/lunepack-service</string></array></dict></plist>",
    );
    assert!(reg.image(&app("org.example.hello")).is_err());
}

// ---- elevation (D38 (a)) ----------------------------------------------------------------------------

#[test]
fn the_standing_follows_the_effective_uid_and_there_is_no_prompt() {
    let want = if effective_uid() == 0 {
        Standing::Admin
    } else {
        Standing::Standard
    };
    assert_eq!(MacElevation.standing(), want);
    assert!(matches!(
        MacElevation.run_elevated(Path::new("/bin/sh"), &[]),
        Err(ElevationError::NoAgent)
    ));
}

// ---- the machine autostart (M11-D12) ----------------------------------------------------------------

struct Swapped<'a>(&'a MacMachineIntegration);

fn swap(scope: Scope) -> Scope {
    match scope {
        Scope::User => Scope::Machine,
        Scope::Machine => Scope::User,
    }
}

impl OsIntegration for Swapped<'_> {
    fn check(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<(), lunepack_core::IntegrationError> {
        self.0.check(swap(scope), req)
    }
    fn apply(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, lunepack_core::IntegrationError> {
        self.0.apply(swap(scope), req)
    }
    fn remove(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, lunepack_core::IntegrationError> {
        self.0.remove(swap(scope), req)
    }
}

#[test]
fn the_integration_suite_passes_for_the_machine_scope() {
    let s = Scratch::new("integration");
    let machine = MacMachineIntegration::under(s.path());
    let sandbox = s.path().to_path_buf();
    // Each suite app's machine tree with its bundle pointer, as the engine makes them.
    let stage = |req: &IntegrationRequest| {
        fs::create_dir_all(&req.install_root).unwrap();
        let bundle = sandbox
            .join("Apps")
            .join(format!("{}.app", req.app_id.as_str()));
        symlink(&bundle, req.install_root.join("bundle")).unwrap();
    };
    let ignore = |p: &Path| {
        p.starts_with("Apps") || p.to_str().is_some_and(|t| t.starts_with("suite-install-"))
    };
    let hooks = SuiteHooks {
        entry: "Contents/MacOS/app",
        stage: Some(&stage),
        ignore: Some(&ignore),
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
            "a quote in the install root",
            "a percent sign in the install root",
        ],
        ..SuiteHooks::default()
    };
    run_integration_suite_with(&Swapped(&machine), s.path(), &hooks);
}

#[test]
fn the_machine_entry_starts_the_live_bundle_for_every_user() {
    let s = Scratch::new("integration-paths");
    let machine = MacMachineIntegration::under(s.path());
    let root = s
        .path()
        .join("Library/Application Support/lunepack/org.example.hello");
    fs::create_dir_all(&root).unwrap();
    symlink("/Applications/Hello.app", root.join("bundle")).unwrap();
    let req = IntegrationRequest {
        app_id: app("org.example.hello"),
        install_root: root,
        version: lunepack_core::Version::parse("1.0.0").unwrap(),
        meta: lunepack_core::InstallMeta {
            entry: lunepack_core::RelPath::parse("Contents/MacOS/hello").unwrap(),
            name: "Hello".to_owned(),
            comment: None,
            icon: None,
            categories: Vec::new(),
            bin: None,
            terminal: false,
            publisher: None,
            file_types: Vec::new(),
            url_schemes: Vec::new(),
            autostart: true,
        },
        previous: None,
        stale_bins: Vec::new(),
    };
    machine.apply(Scope::Machine, &req).unwrap();
    let path = s
        .path()
        .join("Library/LaunchAgents/lunepack-org.example.hello.autostart.plist");
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("<string>lunepack-org.example.hello.autostart</string>"));
    assert!(text.contains("<string>/Applications/Hello.app/Contents/MacOS/hello</string>"));
    assert!(text.contains("<string>Aqua</string>"));
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
    assert!(matches!(
        machine.apply(Scope::User, &req),
        Err(lunepack_core::IntegrationError::Unsupported)
    ));
    // A foreign file at the entry's name is a conflict, never replaced.
    let other = IntegrationRequest {
        app_id: app("org.example.other"),
        ..req.clone()
    };
    write(
        &s.path()
            .join("Library/LaunchAgents/lunepack-org.example.other.autostart.plist"),
        b"<plist/>",
    );
    assert!(machine.apply(Scope::Machine, &other).is_err());
    machine.remove(Scope::Machine, &req).unwrap();
    assert!(!path.exists());
}
