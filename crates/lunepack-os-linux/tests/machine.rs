//! The Linux per-machine ports (M11) on a real file system, without root: the testkit's protect,
//! service-channel and integration suites, the protection rule's refusals, the policy file's
//! cases (M11-D11), the connector's refusals before any byte (M11-D5), the systemd units byte for
//! byte and the registrar's flow over a fake `systemctl`, and the pkexec hand-off over a fake
//! `pkexec`. Ownership by root is stood in for by the test's own uid (each adapter's `for_tests`).
#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use lunepack_core::{
    AppId, ConnectError, DirClass, Elevated, Elevation, ElevationError, IntegrationReport,
    IntegrationRequest, MachinePolicy, OsIntegration, PolicySource, Protect, ProtectError, Scope,
    ServiceConnector, ServiceRegError, ServiceRegistrar, Standing,
};
use lunepack_os_linux::{
    FilePolicy, LinuxProtect, MachineIntegration, PkexecElevation, SystemdRegistrar, UnixConnector,
    UnixDuplex, effective_uid, service_unit_text, socket_unit_text,
};

/// A canonical scratch directory (mode 0755), removed afterwards.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir =
            std::env::temp_dir().join(format!("lunepack-machine-{}-{name}", std::process::id()));
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

fn protect(s: &Scratch) -> LinuxProtect {
    let (uid, gid) = ids(s.path());
    LinuxProtect::for_tests(uid, gid, s.path().to_path_buf())
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
    // Writable by others.
    chmod(&child, 0o757);
    assert!(matches!(
        p.check(&child, DirClass::MachineTree),
        Err(ProtectError::NotProtected)
    ));
    chmod(&child, 0o755);
    p.check(&child, DirClass::MachineTree).unwrap();
    // An ancestor writable by others, with the sticky bit too.
    chmod(&tree, 0o1777);
    assert!(matches!(
        p.check(&child, DirClass::MachineTree),
        Err(ProtectError::NotProtected)
    ));
    chmod(&tree, 0o755);
    // Admin-only allows nothing for group or others.
    let admin = tree.join("admin");
    p.create_dir(&admin, DirClass::AdminOnly).unwrap();
    chmod(&admin, 0o750);
    assert!(matches!(
        p.check(&admin, DirClass::AdminOnly),
        Err(ProtectError::NotProtected)
    ));
    chmod(&admin, 0o700);
    p.check(&admin, DirClass::AdminOnly).unwrap();
    // A link is never a protected directory, even to one.
    let link = tree.join("link");
    symlink(&admin, &link).unwrap();
    assert!(matches!(
        p.check(&link, DirClass::AdminOnly),
        Err(ProtectError::NotProtected)
    ));
    // A directory of another owner (the adapter's owner is someone else here).
    let (uid, gid) = ids(s.path());
    let stranger = LinuxProtect::for_tests(uid.wrapping_add(1), gid, s.path().to_path_buf());
    assert!(matches!(
        stranger.check(&child, DirClass::MachineTree),
        Err(ProtectError::NotProtected)
    ));
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

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn fresh_app() -> AppId {
    app(&format!(
        "suite.app-{}",
        NEXT.fetch_add(1, Ordering::SeqCst)
    ))
}

#[test]
fn the_service_channel_suite_passes_over_the_socket() {
    let s = Scratch::new("channel");
    let (uid, _) = ids(s.path());
    let dir = s.path().to_path_buf();
    lunepack_testkit::run_service_channel_suite(&|| {
        let id = fresh_app();
        let listener = UnixListener::bind(dir.join(format!("{}.sock", id.as_str()))).unwrap();
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
    let sock = dir.join(format!("{}.sock", id.as_str()));
    let listener = UnixListener::bind(&sock).unwrap();
    listener.set_nonblocking(true).unwrap();
    let nothing_connected = || {
        assert!(
            matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "nothing reached the server"
        );
    };

    // A socket (and folder) of another owner than the service's: untrusted.
    let stranger = UnixConnector::for_tests(dir.clone(), uid.wrapping_add(1), Duration::ZERO);
    assert!(matches!(
        stranger.connect(&id),
        Err(ConnectError::WrongOwner)
    ));
    nothing_connected();

    // A folder others may write.
    chmod(&dir, 0o777);
    let c = UnixConnector::for_tests(dir.clone(), uid, Duration::ZERO);
    assert!(matches!(c.connect(&id), Err(ConnectError::WrongOwner)));
    nothing_connected();
    chmod(&dir, 0o755);

    // Anything but a socket at the path.
    let other = fresh_app();
    write(&dir.join(format!("{}.sock", other.as_str())), b"x");
    assert!(matches!(c.connect(&other), Err(ConnectError::WrongOwner)));

    // No socket: not installed, after the retry.
    let retrying = UnixConnector::for_tests(dir.clone(), uid, Duration::from_millis(300));
    let started = std::time::Instant::now();
    assert!(matches!(
        retrying.connect(&fresh_app()),
        Err(ConnectError::NotInstalled)
    ));
    assert!(started.elapsed() >= Duration::from_millis(300));

    // A socket nobody listens on: disabled.
    let dead = fresh_app();
    drop(UnixListener::bind(dir.join(format!("{}.sock", dead.as_str()))).unwrap());
    assert!(matches!(c.connect(&dead), Err(ConnectError::Disabled)));

    // The real one connects, and the peer (this process) is the owner.
    assert!(c.connect(&id).is_ok());
}

#[test]
fn the_production_connector_looks_in_run_lunepack() {
    // No socket of this id exists there: not installed (or untrusted where the folder is not
    // root's), never a connection.
    let r = UnixConnector::new().connect(&app("org.example.never-installed-here"));
    assert!(matches!(
        r,
        Err(ConnectError::NotInstalled | ConnectError::WrongOwner)
    ));
}

// ---- the systemd units and registrar (M11-D4) -----------------------------------------------------

#[test]
fn the_units_have_exactly_these_bytes() {
    let id = app("org.example.hello");
    assert_eq!(
        socket_unit_text(&id),
        "# Written by lunepack; do not edit.\n\
         [Unit]\n\
         Description=lunepack update service socket of org.example.hello\n\
         \n\
         [Socket]\n\
         ListenStream=/run/lunepack/org.example.hello.sock\n\
         SocketMode=0666\n\
         SocketUser=root\n\
         SocketGroup=root\n\
         DirectoryMode=0755\n\
         Accept=no\n\
         \n\
         [Install]\n\
         WantedBy=sockets.target\n"
    );
    assert_eq!(
        service_unit_text(
            &id,
            Path::new("/opt/org.example.hello/.lunepack/machine/lunepack-service")
        )
        .unwrap(),
        "# Written by lunepack; do not edit.\n\
         [Unit]\n\
         Description=lunepack update service of org.example.hello\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart=/opt/org.example.hello/.lunepack/machine/lunepack-service\n\
         NoNewPrivileges=yes\n\
         ProtectHome=yes\n\
         PrivateTmp=yes\n\
         RestrictAddressFamilies=AF_UNIX\n\
         UMask=0022\n"
    );
}

#[test]
fn every_app_id_character_needs_no_escape_and_other_paths_are_refused() {
    // The app id charset is [a-z0-9._-]: the units carry it verbatim.
    let id = app("a.b_c-9");
    let exec = Path::new("/opt/a.b_c-9/.lunepack/machine/lunepack-service");
    let text = service_unit_text(&id, exec).unwrap();
    assert!(text.contains("ExecStart=/opt/a.b_c-9/.lunepack/machine/lunepack-service\n"));
    assert!(socket_unit_text(&id).contains("ListenStream=/run/lunepack/a.b_c-9.sock\n"));
    for bad in [
        "/opt/a b/x",
        "/opt/a%b/x",
        "/opt/a\\b/x",
        "/opt/a$b/x",
        "/opt/a;b/x",
        "/opt/a\"b/x",
        "/opt/a\nb/x",
    ] {
        assert_eq!(service_unit_text(&id, Path::new(bad)), None, "{bad:?}");
    }
}

/// A fake systemctl that appends its arguments to `log`, one call per line.
fn fake_systemctl(s: &Scratch) -> (PathBuf, PathBuf) {
    let tool = s.path().join("systemctl");
    let log = s.path().join("systemctl.log");
    write(
        &tool,
        format!("#!/bin/sh\necho \"$*\" >> '{}'\n", log.display()).as_bytes(),
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
fn the_registrar_writes_the_units_and_switches_the_stable_link() {
    let s = Scratch::new("systemd");
    let (tool, log) = fake_systemctl(&s);
    let units = s.path().join("units");
    fs::create_dir(&units).unwrap();
    let reg = SystemdRegistrar::for_tests(units.clone(), tool);
    let id = app("org.example.hello");
    let root = s.path().join("opt").join("org.example.hello");
    let machine = root.join(".lunepack/machine");
    let v1 = machine.join("service/1.0.0/lunepack-service");
    let v2 = machine.join("service/2.0.0/lunepack-service");
    service_binary(&v1, 0);
    service_binary(&v2, 0);

    assert_eq!(reg.image(&id), Ok(None), "nothing registered");
    assert_eq!(reg.set_image(&id, &v2), Err(ServiceRegError::NotRegistered));
    reg.register(&id, &v1).unwrap();
    let link = machine.join("lunepack-service");
    assert_eq!(
        fs::read_link(&link).unwrap(),
        PathBuf::from("service/1.0.0/lunepack-service"),
        "a relative link"
    );
    assert_eq!(
        fs::read_to_string(units.join("lunepack-org.example.hello.socket")).unwrap(),
        socket_unit_text(&id)
    );
    assert_eq!(
        fs::read_to_string(units.join("lunepack-org.example.hello.service")).unwrap(),
        service_unit_text(&id, &link).unwrap()
    );
    assert_eq!(
        fs::read_to_string(&log).unwrap(),
        "daemon-reload\nenable --now lunepack-org.example.hello.socket\n"
    );
    assert_eq!(reg.image(&id), Ok(Some(v1.clone())));

    // The switch: a new link renamed over the stable one; the units are untouched.
    reg.set_image(&id, &v2).unwrap();
    assert_eq!(reg.image(&id), Ok(Some(v2.clone())));
    assert_eq!(
        fs::read_to_string(&log).unwrap().lines().count(),
        2,
        "set_image runs no systemctl"
    );
    // Another install's image is refused.
    let other = s
        .path()
        .join("opt/other/.lunepack/machine/service/1.0.0/lunepack-service");
    service_binary(&other, 0);
    assert!(reg.set_image(&id, &other).is_err());
    // A link that points out of the tree is not believed.
    fs::remove_file(&link).unwrap();
    symlink(&other, &link).unwrap();
    assert!(reg.image(&id).is_err());

    reg.remove(&id).unwrap();
    assert!(!units.join("lunepack-org.example.hello.socket").exists());
    assert!(!units.join("lunepack-org.example.hello.service").exists());
    let calls = fs::read_to_string(&log).unwrap();
    assert!(calls.ends_with(
        "disable --now lunepack-org.example.hello.socket lunepack-org.example.hello.service\n\
         daemon-reload\n"
    ));
    // Removing what is not there is fine and runs nothing.
    reg.remove(&id).unwrap();
    assert_eq!(fs::read_to_string(&log).unwrap(), calls);
    assert_eq!(reg.image(&id), Ok(None));
}

#[test]
fn the_self_test_passes_only_on_exit_zero() {
    let s = Scratch::new("selftest");
    let (tool, _) = fake_systemctl(&s);
    let reg = SystemdRegistrar::for_tests(s.path().to_path_buf(), tool);
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
fn a_unit_that_is_not_ours_is_not_believed() {
    let s = Scratch::new("foreign-unit");
    let (tool, _) = fake_systemctl(&s);
    let reg = SystemdRegistrar::for_tests(s.path().to_path_buf(), tool);
    let id = app("org.example.hello");
    write(
        &s.path().join("lunepack-org.example.hello.service"),
        b"[Service]\nExecStart=/tmp/x/lunepack-service\n",
    );
    assert!(reg.image(&id).is_err());
}

// ---- pkexec (M11-D9) ------------------------------------------------------------------------------

fn fake_pkexec(s: &Scratch, body: &str) -> PathBuf {
    let tool = s
        .path()
        .join(format!("pkexec-{}", NEXT.fetch_add(1, Ordering::SeqCst)));
    write(&tool, format!("#!/bin/sh\n{body}\n").as_bytes());
    chmod(&tool, 0o755);
    tool
}

fn started(e: Result<Elevated, ElevationError>) -> Box<dyn lunepack_core::ElevatedChild> {
    match e {
        Ok(Elevated::Started(child)) => child,
        other => panic!("not started: {other:?}"),
    }
}

#[test]
fn pkexec_pipes_stdout_and_maps_its_exit_codes() {
    let s = Scratch::new("pkexec");
    let sh = Path::new("/bin/sh");
    // pkexec runs the program: its stdout is the caller's pipe, its code passes through.
    let pass = PkexecElevation::for_tests(fake_pkexec(&s, "exec \"$@\""));
    let args = ["-c".to_owned(), "echo line one; exit 7".to_owned()];
    let mut child = started(pass.run_elevated(sh, &args));
    let mut out = String::new();
    std::io::Read::read_to_string(&mut child.take_output().unwrap(), &mut out).unwrap();
    assert_eq!(out, "line one\n");
    assert!(child.take_output().is_none(), "taken once");
    assert_eq!(child.wait(), Ok(7));

    let declined = PkexecElevation::for_tests(fake_pkexec(&s, "exit 126"));
    assert_eq!(
        started(declined.run_elevated(sh, &[])).wait(),
        Err(ElevationError::Declined)
    );
    let no_agent = PkexecElevation::for_tests(fake_pkexec(&s, "exit 127"));
    assert_eq!(
        started(no_agent.run_elevated(sh, &[])).wait(),
        Err(ElevationError::NoAgent)
    );
    let missing = PkexecElevation::for_tests(s.path().join("no-such-pkexec"));
    assert!(matches!(
        missing.run_elevated(sh, &[]),
        Err(ElevationError::NoAgent)
    ));
    assert!(matches!(
        pass.run_elevated(Path::new("relative"), &[]),
        Err(ElevationError::Failed(_))
    ));
}

#[test]
fn the_standing_follows_the_effective_uid() {
    let want = if effective_uid() == 0 {
        Standing::Admin
    } else {
        Standing::Standard
    };
    assert_eq!(PkexecElevation::new().standing(), want);
}

// ---- the machine integration (M11-D12) -------------------------------------------------------------

/// Runs the per-user integration suite against the machine adapter: the suite's user scope is the
/// machine scope here, and its "machine scope is unsupported" checks reach the adapter's refusal
/// of the user scope.
struct Swapped<'a>(&'a MachineIntegration);

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
    let machine = MachineIntegration::under(s.path());
    lunepack_testkit::run_integration_suite(&Swapped(&machine), s.path());
}

#[test]
fn the_machine_entries_go_to_usr_local_and_etc() {
    let s = Scratch::new("integration-paths");
    let machine = MachineIntegration::under(s.path());
    let root = PathBuf::from("/opt/org.example.hello");
    let req = IntegrationRequest {
        app_id: app("org.example.hello"),
        install_root: root,
        version: lunepack_core::Version::parse("1.0.0").unwrap(),
        meta: lunepack_core::InstallMeta {
            entry: lunepack_core::RelPath::parse("bin/hello").unwrap(),
            name: "Hello".to_owned(),
            comment: None,
            icon: None,
            categories: Vec::new(),
            bin: Some("hello".to_owned()),
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
    let desktop = fs::read_to_string(
        s.path()
            .join("usr/local/share/applications/org.example.hello.desktop"),
    )
    .unwrap();
    assert!(desktop.contains("Exec=\"/opt/org.example.hello/current/bin/hello\""));
    assert_eq!(
        fs::read_link(s.path().join("usr/local/bin/hello")).unwrap(),
        PathBuf::from("/opt/org.example.hello/current/bin/hello")
    );
    assert!(
        s.path()
            .join("etc/xdg/autostart/org.example.hello.desktop")
            .is_file()
    );
    // A foreign entry at the desktop entry's name is refused, never replaced.
    let other = IntegrationRequest {
        app_id: app("org.example.other"),
        ..req.clone()
    };
    write(
        &s.path()
            .join("usr/local/share/applications/org.example.other.desktop"),
        b"[Desktop Entry]\n",
    );
    assert!(machine.apply(Scope::Machine, &other).is_err());
    assert!(matches!(
        machine.apply(Scope::User, &req),
        Err(lunepack_core::IntegrationError::Unsupported)
    ));
    machine.remove(Scope::Machine, &req).unwrap();
    assert!(!s.path().join("usr/local/bin/hello").exists());
}
