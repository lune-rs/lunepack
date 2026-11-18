//! The Windows per-user [`OsIntegration`] (M7 step 6, part 1): the launcher stub at the install
//! root (M7-D8), the "Apps & features" uninstall entry (M7-D15, M7-D16) and the hidden
//! `.lunepack` directory (M7-D19). Part 2 (M7 step 7) adds the Start-menu shortcut, file types,
//! URL schemes and autostart.
//!
//! Rules:
//!
//! - **Paths inside `R` come from the layout** (`UserLayout::from_root(R, LayoutScheme::WINDOWS)`);
//!   `R`'s own name is never derived or checked here, so a renamed or display-name folder works.
//! - **Every registry path and hive comes from one [`WinScope`]**, so a per-machine scope (M10) is
//!   a second value, not new logic.
//! - **Only what is ours is changed.** The uninstall key `<uninstall>\<app id>` is ours when it
//!   carries `LunepackAppId` = the app id; any other key there is a `Conflict` for `check` and
//!   `apply` and is left (and reported) by `remove`. A directory or reparse point where the stub
//!   goes is a `Conflict`.
//! - **Nothing is escaped, everything unsafe is refused.** A control character in any string
//!   written, or a `"` or `%` in `R`, is refused (`UnsafeField`) before anything is written. Every
//!   command value quotes the stub path.
//!
//! Errors never show a path or a value from the metadata.

use std::path::{Component, Path, PathBuf, Prefix};

use lunepack_core::{
    IntegrationError, IntegrationItem, IntegrationReport, IntegrationRequest, LayoutScheme,
    OsIntegration, STUB_FILE, Scope, UserLayout, windows_name_ok,
};

use crate::registry::{self, Hive, Key, Value};
use crate::stub_place::{self, Slot};

/// The per-user uninstall entries' parent key, relative to `HKEY_CURRENT_USER`.
pub const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";

/// The marker value of an uninstall key lunepack made: its data is the app id.
pub const MARKER_VALUE: &str = "LunepackAppId";

/// The reserved stub argument that starts the current version's uninstall (M7-D7).
const UNINSTALL_ARG: &str = "--lunepack-uninstall";

/// Where one install scope's registry entries go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinScope {
    hive: Hive,
    uninstall: String,
}

impl WinScope {
    /// The current user: `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`.
    pub fn current_user() -> WinScope {
        WinScope {
            hive: Hive::CurrentUser,
            uninstall: UNINSTALL_KEY.to_owned(),
        }
    }

    /// The current user's layout moved under `HKCU\<prefix>` (for tests and tools: the
    /// uninstall entries go to `HKCU\<prefix>\Software\Microsoft\Windows\CurrentVersion\Uninstall`).
    /// `None` when `prefix` is empty, has an empty component, a `/` or a control character.
    pub fn with_registry_prefix(prefix: &str) -> Option<WinScope> {
        let ok = !prefix.is_empty()
            && prefix.split('\\').all(|c| !c.is_empty())
            && !prefix.chars().any(|c| c.is_control() || c == '/');
        ok.then(|| WinScope {
            hive: Hive::CurrentUser,
            uninstall: format!(r"{prefix}\{UNINSTALL_KEY}"),
        })
    }

    fn entry_key(&self, app_id: &str) -> String {
        format!(r"{}\{app_id}", self.uninstall)
    }
}

/// The Windows [`OsIntegration`]. Per-machine scope is `Unsupported` until M10.
#[derive(Debug, Clone)]
pub struct WindowsIntegration {
    user: WinScope,
}

impl WindowsIntegration {
    /// An integration whose per-user entries go where `user` says.
    pub fn new(user: WinScope) -> WindowsIntegration {
        WindowsIntegration { user }
    }

    /// The real per-user integration ([`WinScope::current_user`]).
    pub fn current_user() -> WindowsIntegration {
        WindowsIntegration::new(WinScope::current_user())
    }

    fn scope(&self, scope: Scope) -> Result<&WinScope, IntegrationError> {
        match scope {
            Scope::User => Ok(&self.user),
            _ => Err(IntegrationError::Unsupported),
        }
    }
}

/// A request resolved, after every check that writes nothing.
struct Prepared<'a> {
    hive: Hive,
    root: PathBuf,
    layout: UserLayout,
    key: String,
    stub_name: &'a str,
    /// The stub's directories below the version tree (the entry's directory).
    entry_dirs: Vec<&'a str>,
    /// The previous version's stub name, when it differs from `stub_name`.
    stale_stub: Option<&'a str>,
    strings: Vec<(&'static str, String)>,
    publisher: Option<String>,
}

impl OsIntegration for WindowsIntegration {
    fn check(&self, scope: Scope, req: &IntegrationRequest) -> Result<(), IntegrationError> {
        let p = prepare(self.scope(scope)?, req)?;
        check_conflicts(&p, req.app_id.as_str())
    }

    fn apply(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        let p = prepare(self.scope(scope)?, req)?;
        check_conflicts(&p, req.app_id.as_str())?;
        let bytes = read_source(&p, req)?;

        // The stub first: the uninstall entry's commands point at it.
        stub_place::place_stub(&p.root, p.stub_name, &bytes)?;
        write_entry(&p, req.app_id.as_str())?;

        let mut report = IntegrationReport::default();
        if let Some(old) = p.stale_stub
            && !stub_place::remove_stub(&p.root, old)?
        {
            report.kept.push(IntegrationItem::Stub);
        }
        hide(&p.root.join(".lunepack"));
        Ok(report)
    }

    fn remove(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        let p = prepare(self.scope(scope)?, req)?;
        let mut report = IntegrationReport::default();
        match Key::open(p.hive, &p.key, false).map_err(|_| READ_FAILED)? {
            None => {}
            Some(key) if owned(&key, req.app_id.as_str())? => {
                drop(key);
                registry::delete_tree(p.hive, &p.key)
                    .map_err(|_| IntegrationError::Failed("the uninstall entry was not removed"))?;
            }
            Some(_) => report.kept.push(IntegrationItem::UninstallEntry),
        }
        if !stub_place::remove_stub(&p.root, p.stub_name)? {
            report.kept.push(IntegrationItem::Stub);
        }
        Ok(report)
    }
}

const READ_FAILED: IntegrationError =
    IntegrationError::Failed("the uninstall entry could not be read");
const WRITE_FAILED: IntegrationError =
    IntegrationError::Failed("the uninstall entry was not written");

fn prepare<'a>(
    scope: &WinScope,
    req: &'a IntegrationRequest,
) -> Result<Prepared<'a>, IntegrationError> {
    let root = install_root(&req.install_root)?;
    let root_text = root
        .to_str()
        .ok_or(IntegrationError::Failed("the install root is not usable"))?;
    let meta = &req.meta;

    let mut parts: Vec<&str> = meta.entry.components().collect();
    let stub_name = parts.pop().ok_or(IntegrationError::UnsafeField("entry"))?;
    if windows_name_ok(stub_name).is_err() {
        return Err(IntegrationError::UnsafeField("entry"));
    }
    let stale_stub = match &req.previous {
        Some(prev) => prev
            .entry
            .components()
            .last()
            .filter(|old| windows_name_ok(old).is_ok() && !same_name(old, stub_name)),
        None => None,
    };

    let text_ok = |s: &str| !s.is_empty() && !s.chars().any(char::is_control);
    if !text_ok(&meta.name) {
        return Err(IntegrationError::UnsafeField("name"));
    }
    if meta.publisher.as_deref().is_some_and(|p| !text_ok(p)) {
        return Err(IntegrationError::UnsafeField("publisher"));
    }
    let version = req.version.to_string();
    if !text_ok(&version) {
        return Err(IntegrationError::UnsafeField("version"));
    }

    let stub_path = format!(r"{root_text}\{stub_name}");
    let strings = vec![
        ("DisplayName", meta.name.clone()),
        ("DisplayVersion", version),
        ("DisplayIcon", format!("{stub_path},0")),
        ("InstallLocation", root_text.to_owned()),
        (
            "UninstallString",
            format!("\"{stub_path}\" {UNINSTALL_ARG}"),
        ),
        (
            "QuietUninstallString",
            format!("\"{stub_path}\" {UNINSTALL_ARG} /S"),
        ),
    ];
    Ok(Prepared {
        hive: scope.hive,
        layout: UserLayout::from_root(root.clone(), LayoutScheme::WINDOWS),
        root,
        key: scope.entry_key(req.app_id.as_str()),
        stub_name,
        entry_dirs: parts,
        stale_stub,
        strings,
        publisher: meta.publisher.clone(),
    })
}

/// Whether two file names name the same file on NTFS (case-insensitive).
fn same_name(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// The install root as a plain absolute path: a drive (`C:\…`, a `\\?\C:\…` prefix is dropped) or
/// a UNC share, then plain names only; at least one name. A `"`, a `%` or a control character
/// anywhere is refused, since the root goes into quoted command values.
fn install_root(root: &Path) -> Result<PathBuf, IntegrationError> {
    const BAD: IntegrationError =
        IntegrationError::Failed("the install root is not a plain absolute path");
    let text = root.to_str().ok_or(BAD)?;
    if text.chars().any(|c| c.is_control() || c == '"' || c == '%') {
        return Err(IntegrationError::UnsafeField("install_root"));
    }
    let mut comps = root.components();
    let mut out = match comps.next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => format!("{}:", char::from(d)),
            Prefix::UNC(server, share) => format!(
                r"\\{}\{}",
                server.to_str().ok_or(BAD)?,
                share.to_str().ok_or(BAD)?
            ),
            _ => return Err(BAD),
        },
        _ => return Err(BAD),
    };
    if comps.next() != Some(Component::RootDir) {
        return Err(BAD);
    }
    let mut names = 0;
    for c in comps {
        match c {
            Component::Normal(name) => {
                out.push('\\');
                out.push_str(name.to_str().ok_or(BAD)?);
                names += 1;
            }
            _ => return Err(BAD),
        }
    }
    if names == 0 {
        return Err(BAD);
    }
    Ok(PathBuf::from(out))
}

fn owned(key: &Key, app_id: &str) -> Result<bool, IntegrationError> {
    Ok(key.get(MARKER_VALUE).map_err(|_| READ_FAILED)? == Some(Value::Str(app_id.to_owned())))
}

/// What `apply` would refuse because something foreign is in the way.
fn check_conflicts(p: &Prepared<'_>, app_id: &str) -> Result<(), IntegrationError> {
    if let Some(key) = Key::open(p.hive, &p.key, false).map_err(|_| READ_FAILED)?
        && !owned(&key, app_id)?
    {
        return Err(IntegrationError::Conflict(IntegrationItem::UninstallEntry));
    }
    if stub_place::probe(&p.root.join(p.stub_name))? == Slot::Other {
        return Err(IntegrationError::Conflict(IntegrationItem::Stub));
    }
    Ok(())
}

/// The current version's stub, `R\app\<version>\<entry dir>\lunepack-stub.exe`, read whole; every
/// directory on the way and the file itself must be real (no reparse point).
fn read_source(p: &Prepared<'_>, req: &IntegrationRequest) -> Result<Vec<u8>, IntegrationError> {
    const MISSING: IntegrationError = IntegrationError::Failed("stub missing");
    let mut dir = p.layout.versions_dir();
    if !stub_place::is_real_dir(&dir) {
        return Err(MISSING);
    }
    dir = p.layout.version_dir(&req.version);
    if !stub_place::is_real_dir(&dir) {
        return Err(MISSING);
    }
    for name in &p.entry_dirs {
        dir.push(name);
        if !stub_place::is_real_dir(&dir) {
            return Err(MISSING);
        }
    }
    let src = dir.join(STUB_FILE);
    if stub_place::probe(&src)? != Slot::File {
        return Err(MISSING);
    }
    stub_place::read_capped(&src).map_err(|_| MISSING)
}

/// Creates or refreshes the uninstall entry; a value already right is not rewritten.
fn write_entry(p: &Prepared<'_>, app_id: &str) -> Result<(), IntegrationError> {
    let key = Key::create(p.hive, &p.key).map_err(|_| WRITE_FAILED)?;
    // The marker first, so a key this run created is recognised as ours by a retry.
    ensure_str(&key, MARKER_VALUE, app_id)?;
    for (name, value) in &p.strings {
        ensure_str(&key, name, value)?;
    }
    match &p.publisher {
        Some(publisher) => ensure_str(&key, "Publisher", publisher)?,
        None => key.delete_value("Publisher").map_err(|_| WRITE_FAILED)?,
    }
    for name in ["NoModify", "NoRepair"] {
        if key.get(name).map_err(|_| READ_FAILED)? != Some(Value::Dword(1)) {
            key.set_dword(name, 1).map_err(|_| WRITE_FAILED)?;
        }
    }
    Ok(())
}

fn ensure_str(key: &Key, name: &str, value: &str) -> Result<(), IntegrationError> {
    if key.get(name).map_err(|_| READ_FAILED)? != Some(Value::Str(value.to_owned())) {
        key.set_str(name, value).map_err(|_| WRITE_FAILED)?;
    }
    Ok(())
}

/// Sets `FILE_ATTRIBUTE_HIDDEN` on `dir` when it is a real directory (M7-D19). Best effort: a
/// reparse point is left alone, and a failure is not an error (the workspace has no log sink in
/// the adapters; nothing reads the attribute).
#[allow(unsafe_code)]
fn hide(dir: &Path) {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_SYSTEM,
        FILE_ATTRIBUTE_TEMPORARY, GetFileAttributesW, INVALID_FILE_ATTRIBUTES, SetFileAttributesW,
    };
    if !stub_place::is_real_dir(dir) {
        return;
    }
    let wide: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` is a NUL-terminated buffer that outlives the call.
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES || attrs & FILE_ATTRIBUTE_HIDDEN != 0 {
        return;
    }
    let settable = FILE_ATTRIBUTE_ARCHIVE
        | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
        | FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_READONLY
        | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_TEMPORARY;
    // SAFETY: as above; the attributes are a plain flags value.
    let _ =
        unsafe { SetFileAttributesW(wide.as_ptr(), (attrs & settable) | FILE_ATTRIBUTE_HIDDEN) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use lunepack_core::{AppId, InstallMeta, RelPath, Version};
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN;

    fn hex() -> String {
        use std::hash::{BuildHasher as _, Hasher as _};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u32(std::process::id());
        format!("{:016x}", h.finish())
    }

    /// A scratch registry prefix `HKCU\Software\lunepack-test-<hex>` and a scratch install root
    /// (a folder named like a display name) holding a version tree with a stub.
    struct Sandbox {
        prefix: String,
        scope: WinScope,
        parent: PathBuf,
        root: PathBuf,
    }

    impl Sandbox {
        fn new() -> Sandbox {
            let tag = hex();
            let prefix = format!(r"Software\lunepack-test-{tag}");
            let parent = std::env::temp_dir().join(format!("lp-int-{tag}"));
            let root = parent.join("My App ü (x)");
            std::fs::create_dir_all(root.join(".lunepack").join("state")).expect("state dir");
            let s = Sandbox {
                scope: WinScope::with_registry_prefix(&prefix).expect("prefix"),
                prefix,
                parent,
                root,
            };
            s.stage("1.0.0", "bin", b"stub-1");
            s
        }

        fn stage(&self, version: &str, dir: &str, bytes: &[u8]) {
            let d = self.root.join("app").join(version).join(dir);
            std::fs::create_dir_all(&d).expect("tree");
            std::fs::write(d.join(STUB_FILE), bytes).expect("stub");
        }

        fn integration(&self) -> WindowsIntegration {
            WindowsIntegration::new(self.scope.clone())
        }

        fn request(&self, version: &str, entry: &str, name: &str) -> IntegrationRequest {
            IntegrationRequest {
                app_id: AppId::parse("test.app").expect("id"),
                install_root: self.root.clone(),
                version: Version::parse(version).expect("version"),
                meta: InstallMeta {
                    entry: RelPath::parse(entry).expect("entry"),
                    name: name.to_owned(),
                    comment: None,
                    icon: None,
                    categories: Vec::new(),
                    bin: None,
                    terminal: false,
                    publisher: None,
                    file_types: Vec::new(),
                    url_schemes: Vec::new(),
                    autostart: false,
                },
                previous: None,
                stale_bins: Vec::new(),
            }
        }

        fn key_path(&self) -> String {
            self.scope.entry_key("test.app")
        }

        fn values(&self) -> Option<Vec<(&'static str, Option<Value>)>> {
            let key = Key::open(Hive::CurrentUser, &self.key_path(), false).expect("open")?;
            Some(
                [
                    "DisplayName",
                    "DisplayVersion",
                    "Publisher",
                    "DisplayIcon",
                    "InstallLocation",
                    "UninstallString",
                    "QuietUninstallString",
                    "NoModify",
                    "NoRepair",
                    MARKER_VALUE,
                ]
                .into_iter()
                .map(|n| (n, key.get(n).expect("get")))
                .collect(),
            )
        }

        fn value(&self, name: &str) -> Option<Value> {
            Key::open(Hive::CurrentUser, &self.key_path(), false)
                .expect("open")?
                .get(name)
                .expect("get")
        }

        /// Removes the registry prefix and the folder, and asserts the prefix is gone.
        fn finish(self) {
            registry::delete_tree(Hive::CurrentUser, &self.prefix).expect("delete test root");
            assert!(
                Key::open(Hive::CurrentUser, &self.prefix, false)
                    .expect("open")
                    .is_none(),
                "the test registry root is still there"
            );
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = registry::delete_tree(Hive::CurrentUser, &self.prefix);
            let _ = std::fs::remove_dir_all(&self.parent);
        }
    }

    fn s(v: &str) -> Option<Value> {
        Some(Value::Str(v.to_owned()))
    }

    /// `CommandLineToArgvW`, the system's own split of a command line.
    #[allow(unsafe_code)]
    fn split(cmd: &str) -> Vec<String> {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::UI::Shell::CommandLineToArgvW;
        let wide: Vec<u16> = std::ffi::OsStr::new(cmd)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut n = 0i32;
        // SAFETY: `wide` is NUL-terminated and outlives the call; `n` is a valid out pointer.
        let argv = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut n) };
        assert!(!argv.is_null(), "split failed");
        let mut out = Vec::new();
        for i in 0..usize::try_from(n).expect("count") {
            // SAFETY: `argv` holds `n` valid NUL-terminated strings (the call succeeded).
            let arg = unsafe {
                let p = *argv.add(i);
                let mut len = 0;
                while *p.add(len) != 0 {
                    len += 1;
                }
                String::from_utf16(std::slice::from_raw_parts(p, len)).expect("utf16")
            };
            out.push(arg);
        }
        // SAFETY: `argv` is the single allocation `CommandLineToArgvW` returned, freed once.
        unsafe { LocalFree(argv.cast()) };
        out
    }

    #[test]
    fn apply_places_the_stub_and_writes_the_entry_and_a_second_apply_changes_nothing() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let req = sb.request("1.0.0", "bin/app.exe", "My App");
        w.check(Scope::User, &req).expect("check");
        assert!(sb.values().is_none(), "check wrote something");
        let report = w.apply(Scope::User, &req).expect("apply");
        assert!(report.kept.is_empty());

        let stub = sb.root.join("app.exe");
        assert_eq!(std::fs::read(&stub).expect("stub"), b"stub-1");
        let root = sb.root.to_str().expect("utf-8");
        let stub_text = format!(r"{root}\app.exe");
        let want = vec![
            ("DisplayName", s("My App")),
            ("DisplayVersion", s("1.0.0")),
            ("Publisher", None),
            ("DisplayIcon", s(&format!("{stub_text},0"))),
            ("InstallLocation", s(root)),
            (
                "UninstallString",
                s(&format!("\"{stub_text}\" --lunepack-uninstall")),
            ),
            (
                "QuietUninstallString",
                s(&format!("\"{stub_text}\" --lunepack-uninstall /S")),
            ),
            ("NoModify", Some(Value::Dword(1))),
            ("NoRepair", Some(Value::Dword(1))),
            (MARKER_VALUE, s("test.app")),
        ];
        assert_eq!(sb.values().expect("entry"), want);

        let mtime = std::fs::metadata(&stub)
            .expect("meta")
            .modified()
            .expect("mtime");
        std::thread::sleep(std::time::Duration::from_millis(50));
        let report = w.apply(Scope::User, &req).expect("apply again");
        assert!(report.kept.is_empty());
        assert_eq!(
            sb.values().expect("entry"),
            want,
            "a second apply changed a value"
        );
        assert_eq!(
            std::fs::metadata(&stub)
                .expect("meta")
                .modified()
                .expect("mtime"),
            mtime,
            "a second apply rewrote the stub"
        );
        assert_eq!(
            stub_place::remove_stub_leftovers(&sb.root).expect("gc"),
            0,
            "a leftover was made"
        );

        // A publisher appears and goes again.
        let mut with_publisher = req.clone();
        with_publisher.meta.publisher = Some("Acme Ü".to_owned());
        w.apply(Scope::User, &with_publisher).expect("publisher");
        assert_eq!(sb.value("Publisher"), s("Acme Ü"));
        w.apply(Scope::User, &req).expect("no publisher");
        assert_eq!(sb.value("Publisher"), None);

        // remove takes the entry and the stub; a second remove is fine.
        let report = w.remove(Scope::User, &req).expect("remove");
        assert!(report.kept.is_empty());
        assert!(sb.values().is_none(), "the entry is left");
        assert!(!stub.exists(), "the stub is left");
        w.remove(Scope::User, &req).expect("remove again");
        sb.finish();
    }

    #[test]
    fn the_commands_split_to_the_quoted_stub_path_and_the_argument() {
        let sb = Sandbox::new();
        let req = sb.request("1.0.0", "bin/app.exe", "My App");
        sb.integration().apply(Scope::User, &req).expect("apply");
        let stub = sb.root.join("app.exe");
        let stub = stub.to_str().expect("utf-8");
        assert!(stub.contains("My App ü (x)"), "{stub}");
        let Some(Value::Str(cmd)) = sb.value("UninstallString") else {
            panic!("no uninstall string");
        };
        assert_eq!(split(&cmd), [stub, "--lunepack-uninstall"]);
        let Some(Value::Str(quiet)) = sb.value("QuietUninstallString") else {
            panic!("no quiet uninstall string");
        };
        assert_eq!(split(&quiet), [stub, "--lunepack-uninstall", "/S"]);
        sb.finish();
    }

    #[test]
    fn a_foreign_key_is_a_conflict_and_is_left_alone() {
        let sb = Sandbox::new();
        let key = Key::create(Hive::CurrentUser, &sb.key_path()).expect("foreign key");
        key.set_str("DisplayName", "Someone else").expect("value");
        drop(key);
        let w = sb.integration();
        let req = sb.request("1.0.0", "bin/app.exe", "My App");
        for result in [
            w.check(Scope::User, &req),
            w.apply(Scope::User, &req).map(|_| ()),
        ] {
            assert!(
                matches!(
                    result,
                    Err(IntegrationError::Conflict(IntegrationItem::UninstallEntry))
                ),
                "{result:?}"
            );
        }
        assert!(!sb.root.join("app.exe").exists(), "apply placed the stub");
        let report = w.remove(Scope::User, &req).expect("remove");
        assert_eq!(report.kept, [IntegrationItem::UninstallEntry]);
        assert_eq!(sb.value("DisplayName"), s("Someone else"));
        assert_eq!(sb.value(MARKER_VALUE), None);
        sb.finish();
    }

    #[test]
    fn a_new_display_name_rewrites_the_entry_and_leaves_the_folder() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let first = sb.request("1.0.0", "bin/app.exe", "My App");
        w.apply(Scope::User, &first).expect("apply");
        sb.stage("2.0.0", "bin", b"stub-2");
        let mut second = sb.request("2.0.0", "bin/app.exe", "My Renamed App");
        second.previous = Some(first.meta.clone());
        w.apply(Scope::User, &second).expect("apply renamed");
        assert_eq!(sb.value("DisplayName"), s("My Renamed App"));
        assert_eq!(sb.value("DisplayVersion"), s("2.0.0"));
        assert_eq!(
            sb.value("InstallLocation"),
            s(sb.root.to_str().expect("utf-8"))
        );
        assert_eq!(
            std::fs::read(sb.root.join("app.exe")).expect("stub"),
            b"stub-2"
        );
        assert!(sb.root.ends_with("My App ü (x)") && sb.root.is_dir());
        sb.finish();
    }

    #[test]
    fn a_changed_entry_name_removes_the_old_stub_and_keeps_a_foreign_one() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let first = sb.request("1.0.0", "bin/old.exe", "My App");
        w.apply(Scope::User, &first).expect("apply");
        assert!(sb.root.join("old.exe").is_file());
        sb.stage("2.0.0", "bin", b"stub-2");
        let mut second = sb.request("2.0.0", "bin/new.exe", "My App");
        second.previous = Some(first.meta.clone());
        let report = w.apply(Scope::User, &second).expect("apply new name");
        assert!(report.kept.is_empty());
        assert!(!sb.root.join("old.exe").exists(), "the old stub is left");
        assert_eq!(
            std::fs::read(sb.root.join("new.exe")).expect("new"),
            b"stub-2"
        );

        // A directory under the earlier name is not ours to remove.
        std::fs::create_dir(sb.root.join("old.exe")).expect("dir");
        let report = w.apply(Scope::User, &second).expect("apply again");
        assert_eq!(report.kept, [IntegrationItem::Stub]);
        assert!(sb.root.join("old.exe").is_dir());

        // A name differing only in case is the same file, never removed.
        let mut third = sb.request("2.0.0", "bin/New.exe", "My App");
        third.previous = Some(second.meta.clone());
        w.apply(Scope::User, &third).expect("case change");
        assert_eq!(
            std::fs::read(sb.root.join("new.exe")).expect("new"),
            b"stub-2"
        );
        sb.finish();
    }

    #[test]
    fn a_missing_source_fails_before_any_change() {
        let sb = Sandbox::new();
        let req = sb.request("3.0.0", "bin/app.exe", "My App");
        let err = sb
            .integration()
            .apply(Scope::User, &req)
            .expect_err("missing");
        assert!(
            matches!(err, IntegrationError::Failed("stub missing")),
            "{err:?}"
        );
        assert!(sb.values().is_none(), "the entry was written");
        assert!(!sb.root.join("app.exe").exists());
        sb.finish();
    }

    #[test]
    fn the_state_dir_is_hidden_after_apply() {
        let sb = Sandbox::new();
        let dot = sb.root.join(".lunepack");
        let before = std::fs::metadata(&dot).expect("meta").file_attributes();
        assert_eq!(before & FILE_ATTRIBUTE_HIDDEN, 0);
        let req = sb.request("1.0.0", "bin/app.exe", "My App");
        sb.integration().apply(Scope::User, &req).expect("apply");
        let after = std::fs::metadata(&dot).expect("meta").file_attributes();
        assert_ne!(after & FILE_ATTRIBUTE_HIDDEN, 0, "not hidden");
        assert!(dot.join("state").is_dir());
        sb.finish();
    }

    #[test]
    fn unsafe_values_and_machine_scope_are_refused_and_write_nothing() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let good = sb.request("1.0.0", "bin/app.exe", "My App");
        let mut cases: Vec<(&str, IntegrationRequest)> = Vec::new();
        let mut with = |what: &'static str, edit: &dyn Fn(&mut IntegrationRequest)| {
            let mut r = good.clone();
            edit(&mut r);
            cases.push((what, r));
        };
        with("a newline in the name", &|r| {
            r.meta.name = "SECRET\nx".to_owned()
        });
        with("a tab in the publisher", &|r| {
            r.meta.publisher = Some("SECRET\tx".to_owned());
        });
        with("a quote in the root", &|r| {
            r.install_root = sb.parent.join("SECRET\"x");
        });
        with("a percent sign in the root", &|r| {
            r.install_root = sb.parent.join("SECRET%x%");
        });
        with("a relative root", &|r| {
            r.install_root = PathBuf::from("SECRET")
        });
        with("a parent component in the root", &|r| {
            r.install_root = sb.root.join("..").join("SECRET");
        });
        // The path rules already refuse a device name; the Windows name rule adds a length cap.
        with("a stub name over 64 UTF-16 units", &|r| {
            let long = format!("bin/SECRET{}.exe", "a".repeat(60));
            r.meta.entry = RelPath::parse(&long).expect("entry");
        });
        for (what, req) in &cases {
            for result in [
                w.check(Scope::User, req),
                w.apply(Scope::User, req).map(|_| ()),
            ] {
                let err = result.expect_err(what);
                assert!(
                    !format!("{err} {err:?}").contains("SECRET"),
                    "{what}: {err:?}"
                );
            }
        }
        for result in [
            w.check(Scope::Machine, &good),
            w.apply(Scope::Machine, &good).map(|_| ()),
            w.remove(Scope::Machine, &good).map(|_| ()),
        ] {
            assert!(
                matches!(result, Err(IntegrationError::Unsupported)),
                "{result:?}"
            );
        }
        assert!(sb.values().is_none(), "something was written");
        assert!(!sb.root.join("app.exe").exists());
        sb.finish();
    }

    #[test]
    fn a_verbatim_root_is_written_without_its_prefix() {
        assert_eq!(
            install_root(Path::new(r"\\?\C:\Users\u\Programs\My App")).expect("root"),
            PathBuf::from(r"C:\Users\u\Programs\My App")
        );
        assert_eq!(
            install_root(Path::new(r"C:/Users/u/Programs/My App/")).expect("root"),
            PathBuf::from(r"C:\Users\u\Programs\My App")
        );
        assert_eq!(
            install_root(Path::new(r"\\server\share\My App")).expect("unc"),
            PathBuf::from(r"\\server\share\My App")
        );
        for bad in [r"C:\", r"\\.\pipe\x", r"C:relative", r"\no-drive"] {
            assert!(install_root(Path::new(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_registry_prefix_is_validated() {
        assert!(WinScope::with_registry_prefix(r"Software\lunepack-test-1").is_some());
        for bad in ["", r"a\\b", r"\a", "a/b", "a\nb"] {
            assert!(WinScope::with_registry_prefix(bad).is_none(), "{bad:?}");
        }
    }
}
