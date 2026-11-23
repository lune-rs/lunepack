//! `WindowsProtect`, the descriptor reader and the token queries against the real system (M10-D9,
//! M10 step 7).
//!
//! Most rows create protected directories, which needs administrator rights (the owner of the
//! descriptor is Administrators). A run without them asserts the typed refusal of `create_dir`
//! instead of skipping: see [`admin_or_assert_refused`]. Every directory the rows make lives under
//! a unique temporary folder (or, for one row, directly under Program Files) that a guard removes.
//!
//! The bad directories start from a valid one made by `WindowsProtect` and change exactly one
//! thing with `icacls` (the row first checks the valid one passes), so each failure names its
//! cause.
#![cfg(windows)]

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use lunepack_core::{
    DirClass, DirEntryInfo, FileWrite, Fs, FsError, FsErrorKind, LockGuard, Meta, PlaceFacts,
    Protect, ProtectError, ReadAt, Standing,
};
use lunepack_os_windows::{
    ACE_ALLOWED, Ace, CheckError, READ_CLASS, SID_ADMINISTRATORS, SID_ALL_APP_PACKAGES,
    SID_CREATOR_OWNER, SID_EVERYONE, SID_SYSTEM, SID_TRUSTED_INSTALLER, SID_USERS, WindowsProtect,
    check_dir, current_user_sid, local_app_data, program_files, read_descriptor, standing,
};
use lunepack_testkit::run_protect_suite;

// ---- helpers -------------------------------------------------------------------------------------

/// A unique folder under the temp directory, removed (with everything under it) when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lp-sec-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        assert!(!dir.exists(), "scratch dir exists: {dir:?}");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Removes a directory created for a row, when dropped.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn is_admin() -> bool {
    standing() != Standing::Standard
}

/// `true` when the process may create protected directories. Without administrator rights it
/// asserts instead what such a run must see (the typed refusal of `create_dir`, and no directory
/// left behind) and returns `false`, so the caller returns: a run without rights is never a
/// silent skip.
fn admin_or_assert_refused() -> bool {
    if is_admin() {
        return true;
    }
    let scratch = Scratch::new("refused");
    for class in [DirClass::MachineTree, DirClass::AdminOnly] {
        let dir = scratch.join("d");
        let refused = WindowsProtect.create_dir(&dir, class);
        assert!(
            matches!(refused, Err(ProtectError::Os(_))),
            "a run without administrator rights must be refused with Os(_): {refused:?}"
        );
        assert!(!dir.exists(), "a refused create_dir left a directory");
    }
    eprintln!("not an administrator: asserted the typed refusal of create_dir instead");
    false
}

fn icacls(dir: &Path, args: &[&str]) {
    let out = Command::new("icacls")
        .arg(dir)
        .args(args)
        .output()
        .expect("icacls");
    assert!(
        out.status.success(),
        "icacls {args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A valid protected directory, made by the adapter, that the row then spoils.
fn valid_dir(scratch: &Scratch, name: &str, class: DirClass) -> PathBuf {
    let dir = scratch.join(name);
    WindowsProtect.create_dir(&dir, class).expect("create_dir");
    check_dir(&dir, class).expect("a freshly created directory passes");
    dir
}

fn sorted(mut entries: Vec<Ace>) -> Vec<Ace> {
    entries.sort_by(|a, b| a.sid.cmp(&b.sid));
    entries
}

/// A filesystem for `run_protect_suite` with just what the suite calls (a real file create and a
/// recursive remove); everything else is refused. The adapter crate may not depend on `lunepack-fs`.
struct HostFs;

struct HostFile(std::fs::File);

impl Write for HostFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl FileWrite for HostFile {
    fn sync(&mut self) -> Result<(), FsError> {
        self.0
            .sync_all()
            .map_err(|e| FsError::from_io(Path::new("file"), e).during("sync"))
    }
}

fn unsupported<T>(path: &Path) -> Result<T, FsError> {
    Err(FsError::new(FsErrorKind::Unsupported, path, None))
}

impl Fs for HostFs {
    fn read_capped(&self, path: &Path, _max: u64) -> Result<Vec<u8>, FsError> {
        unsupported(path)
    }
    fn open_read(&self, path: &Path) -> Result<Box<dyn ReadAt>, FsError> {
        unsupported(path)
    }
    fn create_new(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map(|f| Box::new(HostFile(f)) as Box<dyn FileWrite>)
            .map_err(|e| FsError::from_io(path, e).during("create_new"))
    }
    fn open_append(&self, path: &Path) -> Result<Box<dyn FileWrite>, FsError> {
        unsupported(path)
    }
    fn truncate(&self, path: &Path, _len: u64) -> Result<(), FsError> {
        unsupported(path)
    }
    fn rename(&self, from: &Path, _to: &Path) -> Result<(), FsError> {
        unsupported(from)
    }
    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        unsupported(path)
    }
    fn remove_dir_all_nofollow(&self, path: &Path) -> Result<(), FsError> {
        std::fs::remove_dir_all(path)
            .map_err(|e| FsError::from_io(path, e).during("remove_dir_all"))
    }
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        unsupported(path)
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntryInfo>, FsError> {
        unsupported(path)
    }
    fn symlink_metadata(&self, path: &Path) -> Result<Option<Meta>, FsError> {
        unsupported(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        unsupported(path)
    }
    fn copy_file(&self, from: &Path, _to_new: &Path) -> Result<(), FsError> {
        unsupported(from)
    }
    fn set_exec(&self, path: &Path, _exec: bool) -> Result<(), FsError> {
        unsupported(path)
    }
    fn symlink(&self, _target: &str, link_path: &Path) -> Result<(), FsError> {
        unsupported(link_path)
    }
    fn read_link(&self, path: &Path) -> Result<String, FsError> {
        unsupported(path)
    }
    fn replace_symlink(&self, _target: &str, link: &Path) -> Result<(), FsError> {
        unsupported(link)
    }
    fn try_lock(&self, path: &Path) -> Result<Option<Box<dyn LockGuard>>, FsError> {
        unsupported(path)
    }
    fn place(&self, path: &Path) -> Result<PlaceFacts, FsError> {
        unsupported(path)
    }
}

// ---- the rows ------------------------------------------------------------------------------------

#[test]
fn the_protect_suite_passes() {
    if !admin_or_assert_refused() {
        return;
    }
    let scratch = Scratch::new("suite");
    run_protect_suite(&WindowsProtect, &HostFs, &scratch.0);
}

#[test]
fn a_created_directory_reads_back_with_the_owner_and_entries_of_its_class() {
    if !admin_or_assert_refused() {
        return;
    }
    let scratch = Scratch::new("readback");
    let all = 0x001F_01FF; // FILE_ALL_ACCESS
    let read_exec = 0x0012_00A9; // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
    let inherit = 0x03; // OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    let entry = |sid: &str, mask: u32| Ace {
        kind: ACE_ALLOWED,
        sid: sid.to_owned(),
        mask,
        flags: inherit,
    };

    let tree = valid_dir(&scratch, "tree", DirClass::MachineTree);
    let d = read_descriptor(&tree).expect("read tree");
    assert_eq!(d.owner, SID_ADMINISTRATORS);
    assert_eq!(
        sorted(d.entries.expect("a DACL")),
        sorted(vec![
            entry(SID_SYSTEM, all),
            entry(SID_ADMINISTRATORS, all),
            entry(SID_USERS, read_exec),
            entry(SID_ALL_APP_PACKAGES, read_exec),
        ])
    );

    let admin = valid_dir(&scratch, "admin", DirClass::AdminOnly);
    let d = read_descriptor(&admin).expect("read admin");
    assert_eq!(d.owner, SID_ADMINISTRATORS);
    assert_eq!(
        sorted(d.entries.expect("a DACL")),
        sorted(vec![entry(SID_SYSTEM, all), entry(SID_ADMINISTRATORS, all)])
    );

    // Through the `Protect` port too.
    WindowsProtect
        .check(&tree, DirClass::MachineTree)
        .expect("port check");
    WindowsProtect
        .check(&admin, DirClass::AdminOnly)
        .expect("port check");
    // A machine-tree directory is not admin-only: Users can read it.
    assert!(matches!(
        WindowsProtect.check(&tree, DirClass::AdminOnly),
        Err(ProtectError::NotProtected)
    ));
}

#[test]
fn create_dir_on_an_existing_path_fails_and_leaves_its_descriptor() {
    if !admin_or_assert_refused() {
        return;
    }
    let scratch = Scratch::new("exists");
    let dir = valid_dir(&scratch, "d", DirClass::AdminOnly);
    let before = read_descriptor(&dir).expect("read");
    for class in [DirClass::MachineTree, DirClass::AdminOnly] {
        assert!(matches!(
            WindowsProtect.create_dir(&dir, class),
            Err(ProtectError::Exists)
        ));
    }
    assert_eq!(read_descriptor(&dir).expect("read again"), before);

    // An existing directory made by someone else keeps its (wide) descriptor, a file is `Exists`.
    let plain = scratch.join("plain");
    std::fs::create_dir(&plain).expect("plain dir");
    let plain_before = read_descriptor(&plain).expect("read plain");
    assert!(matches!(
        WindowsProtect.create_dir(&plain, DirClass::MachineTree),
        Err(ProtectError::Exists)
    ));
    assert_eq!(read_descriptor(&plain).expect("read plain"), plain_before);
    let file = scratch.join("file");
    std::fs::write(&file, b"x").expect("file");
    assert!(matches!(
        WindowsProtect.create_dir(&file, DirClass::AdminOnly),
        Err(ProtectError::Exists)
    ));
    assert_eq!(std::fs::read(&file).expect("file"), b"x");
}

#[test]
fn check_fails_for_each_way_a_directory_can_be_spoiled() {
    if !admin_or_assert_refused() {
        return;
    }
    let scratch = Scratch::new("spoiled");
    let user = format!("*{}", current_user_sid().expect("current user sid"));

    // Owned by the current user (an unprivileged process shares the SID).
    let dir = valid_dir(&scratch, "owner", DirClass::MachineTree);
    icacls(&dir, &["/setowner", &user]);
    assert_eq!(
        check_dir(&dir, DirClass::MachineTree),
        Err(CheckError::Owner)
    );
    assert!(matches!(
        WindowsProtect.check(&dir, DirClass::MachineTree),
        Err(ProtectError::NotProtected)
    ));

    // (name, icacls grant, class, expected). Each starts from a valid directory.
    let rows: [(&str, String, DirClass, CheckError); 5] = [
        (
            "users-modify",
            format!("*{SID_USERS}:(OI)(CI)M"),
            DirClass::MachineTree,
            CheckError::ForeignWrite,
        ),
        (
            "everyone-wdac",
            format!("*{SID_EVERYONE}:(WDAC)"),
            DirClass::MachineTree,
            CheckError::ForeignWrite,
        ),
        (
            "inherit-only-users-write",
            format!("*{SID_USERS}:(OI)(CI)(IO)(W)"),
            DirClass::MachineTree,
            CheckError::ForeignWrite,
        ),
        (
            "inherit-only-creator-owner",
            format!("*{SID_CREATOR_OWNER}:(OI)(CI)(IO)(F)"),
            DirClass::MachineTree,
            CheckError::ForeignWrite,
        ),
        (
            "admin-only-users-read",
            format!("*{SID_USERS}:(RX)"),
            DirClass::AdminOnly,
            CheckError::ForeignAccess,
        ),
    ];
    for (name, grant, class, expected) in rows {
        let dir = valid_dir(&scratch, name, class);
        icacls(&dir, &["/grant", &grant]);
        assert_eq!(check_dir(&dir, class), Err(expected), "{name}");
    }

    // A junction to a valid directory is not a real directory.
    let target = valid_dir(&scratch, "target", DirClass::MachineTree);
    let junction = scratch.join("junction");
    let made = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .output()
        .expect("mklink");
    assert!(made.status.success(), "mklink failed");
    assert_eq!(
        check_dir(&junction, DirClass::MachineTree),
        Err(CheckError::NotDirectory)
    );
    check_dir(&target, DirClass::MachineTree).expect("the target itself is fine");
}

#[test]
fn check_names_a_missing_path_a_file_and_a_junction() {
    let scratch = Scratch::new("shapes");
    assert_eq!(
        check_dir(&scratch.join("missing"), DirClass::MachineTree),
        Err(CheckError::NotFound)
    );
    assert!(matches!(
        WindowsProtect.check(&scratch.join("missing"), DirClass::MachineTree),
        Err(ProtectError::NotFound)
    ));
    let file = scratch.join("file");
    std::fs::write(&file, b"x").expect("file");
    assert_eq!(
        check_dir(&file, DirClass::AdminOnly),
        Err(CheckError::NotDirectory)
    );
    let plain = scratch.join("plain");
    std::fs::create_dir(&plain).expect("plain");
    let junction = scratch.join("junction");
    let made = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&plain)
        .output()
        .expect("mklink");
    assert!(made.status.success(), "mklink failed");
    assert_eq!(
        check_dir(&junction, DirClass::MachineTree),
        Err(CheckError::NotDirectory)
    );
}

/// Known answer of the reader on a real, complex DACL: Program Files.
#[test]
fn the_reader_on_program_files_and_the_rule_agree() {
    let pf = program_files().expect("program files");
    let d = read_descriptor(&pf).expect("read Program Files");
    for ace in d.entries.as_ref().expect("Program Files has a DACL") {
        eprintln!(
            "Program Files ACE: kind {} sid {} mask {:#010x} flags {:#04x}",
            ace.kind, ace.sid, ace.mask, ace.flags
        );
    }
    eprintln!("Program Files owner: {}", d.owner);
    let entries = d.entries.as_ref().expect("a DACL");
    assert!(
        entries.iter().any(|a| a.sid == SID_TRUSTED_INSTALLER),
        "the reader returned no TrustedInstaller entry for Program Files"
    );
    assert!(
        entries.iter().any(|a| a.sid == SID_SYSTEM),
        "the reader returned no LocalSystem entry for Program Files"
    );
    let outside_write = entries.iter().any(|a| {
        a.kind == ACE_ALLOWED
            && ![SID_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER].contains(&a.sid.as_str())
            && a.mask & !READ_CLASS != 0
    });
    eprintln!("a write-class allow entry for a SID outside T: {outside_write}");
    let checked = check_dir(&pf, DirClass::MachineTree);
    if outside_write {
        assert_eq!(checked, Err(CheckError::ForeignWrite));
    } else {
        // M10-D9's premise (an inheritable CREATOR OWNER full-control entry) would be wrong on
        // this Windows version: the entries are printed above for the report.
        assert_eq!(checked, Ok(()), "{checked:?}");
        eprintln!("PREMISE: Program Files carries no write-class entry outside T here");
    }
    // The same through the port.
    assert_eq!(
        WindowsProtect.check(&pf, DirClass::MachineTree).is_ok(),
        !outside_write
    );
}

#[test]
fn directories_made_directly_under_program_files_pass_and_are_removed() {
    if !admin_or_assert_refused() {
        return;
    }
    let pf = program_files().expect("program files");
    let tree = pf.join(format!("lunepack-sec-test-{}-tree", std::process::id()));
    let admin = pf.join(format!("lunepack-sec-test-{}-admin", std::process::id()));
    let _tree = RemoveOnDrop(tree.clone());
    let _admin = RemoveOnDrop(admin.clone());
    WindowsProtect
        .create_dir(&tree, DirClass::MachineTree)
        .expect("create under Program Files");
    WindowsProtect
        .create_dir(&admin, DirClass::AdminOnly)
        .expect("create under Program Files");
    WindowsProtect
        .check(&tree, DirClass::MachineTree)
        .expect("tree passes");
    WindowsProtect
        .check(&admin, DirClass::AdminOnly)
        .expect("admin-only passes");
    // What the inheritance of Program Files might have added shows in the read-back entries: only
    // the descriptor's own entries are there.
    let d = read_descriptor(&tree).expect("read");
    assert_eq!(d.owner, SID_ADMINISTRATORS);
    assert_eq!(d.entries.expect("DACL").len(), 4);
}

#[test]
fn the_token_queries_agree_with_the_system() {
    let user = current_user_sid().expect("current user sid");
    let whoami = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .expect("whoami");
    assert!(whoami.status.success());
    let text = String::from_utf8_lossy(&whoami.stdout);
    assert!(
        text.contains(&format!("\"{user}\"")),
        "whoami says {text:?}, the reader says {user}"
    );
    assert!(user.starts_with("S-1-5-"), "{user}");

    // The instrument first: the PowerShell role query on a name no token holds.
    let ps = |script: &str| {
        let out = Command::new("powershell")
            .env_remove("PSModulePath")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .expect("powershell");
        assert!(out.status.success(), "powershell failed");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    assert_eq!(
        ps(
            "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('S-1-5-32-9999')"
        ),
        "False",
        "INVALID: the role query says True for a group no token holds"
    );
    let in_role = ps(
        "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
    ) == "True";
    let got = standing();
    eprintln!("standing: {got:?}; Administrators role enabled: {in_role}");
    assert_eq!(in_role, got != Standing::Standard, "{got:?}");
}

#[test]
fn the_known_folders_come_from_the_shell_and_the_module_reads_no_environment() {
    for path in [program_files().expect("pf"), local_app_data().expect("lad")] {
        assert!(path.is_absolute() && path.is_dir(), "{path:?}");
    }
    // The machine's folder is not the per-user one.
    assert_ne!(
        program_files().unwrap(),
        local_app_data().unwrap().join("Programs")
    );
    for (name, source) in [
        ("security.rs", include_str!("../src/security.rs")),
        ("shell.rs", include_str!("../src/shell.rs")),
    ] {
        for needle in ["env::var", "std::env", "env!(", "option_env"] {
            // The tests of `shell.rs` run in this crate's own process and may read none either.
            assert!(
                !source.contains(needle),
                "{name} reads the environment: {needle}"
            );
        }
    }
}
