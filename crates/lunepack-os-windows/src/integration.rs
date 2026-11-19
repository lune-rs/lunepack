//! The Windows per-user [`OsIntegration`] (M7 steps 6 and 7): the launcher stub at the install
//! root (M7-D8), the "Apps & features" uninstall entry (M7-D15, M7-D16), the hidden `.lunepack`
//! directory (M7-D19), the Start-menu shortcut with the app user model id (M7-D9, M7-D15), and
//! the file types, URL schemes and autostart the app declares (M7-D3, in [`crate::classes`]).
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
//!   goes is a `Conflict`. A Start-menu shortcut is ours when its app user model id is the app id
//!   and its target is `R\<stub>`; a registry declaration is ours by its marker or its exact value.
//! - **Nothing is escaped, everything unsafe is refused.** A control character in any string
//!   written, or a `"` or `%` in `R`, is refused (`UnsafeField`) before anything is written. Every
//!   command value quotes the stub path.
//!
//! Errors never show a path or a value from the metadata.

use std::path::{Component, Path, PathBuf, Prefix};

use lunepack_core::update_config::{
    MAX_EXT_BYTES, MAX_FILE_TYPE_NAME_CHARS, MAX_FILE_TYPES, MAX_SCHEME_BYTES, MAX_URL_SCHEMES,
    is_denied_url_scheme,
};
use lunepack_core::{
    InstallMeta, IntegrationError, IntegrationItem, IntegrationReport, IntegrationRequest,
    LayoutScheme, OsIntegration, STUB_FILE, Scope, UserLayout, windows_name_ok,
};

use crate::classes::{self, Decls, FileTypeDecl};
use crate::registry::{self, Hive, Key, Value};
use crate::shortcut::{self, LinkInfo, LinkSpec};
use crate::stub_place::{self, Slot};

/// The per-user uninstall entries' parent key, relative to `HKEY_CURRENT_USER`.
pub const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";

/// The per-user autostart key, relative to `HKEY_CURRENT_USER`.
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// The classes key, relative to `HKEY_CURRENT_USER` (written) and to `HKEY_LOCAL_MACHINE` (read).
const CLASSES_KEY: &str = r"Software\Classes";

/// Under a [`WinScope::with_registry_prefix`] root, the folder standing in for `HKLM` (read only).
const MACHINE_PREFIX: &str = "Machine";

/// The marker value of a key lunepack made (the uninstall key, a ProgID, a scheme): its data is
/// the app id.
pub const MARKER_VALUE: &str = "LunepackAppId";

/// The reserved stub argument that starts the current version's uninstall (M7-D7).
const UNINSTALL_ARG: &str = "--lunepack-uninstall";

/// Where one install scope's registry entries and Start-menu shortcut go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinScope {
    hive: Hive,
    uninstall: String,
    classes: String,
    /// The per-machine classes root, read only: what another program registered for all users
    /// (a scheme or ProgID there is a conflict, not ours to shadow). `None` reads none.
    machine_classes: Option<(Hive, String)>,
    run: String,
    /// The Start-menu programs folder; `None` asks the shell (`FOLDERID_Programs`).
    programs: Option<PathBuf>,
    /// Whether a change to an association tells the shell (`SHCNE_ASSOCCHANGED`).
    notify: bool,
}

impl WinScope {
    /// The current user: `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall` and `Run`,
    /// `HKCU\Software\Classes`, and the user's Start-menu programs folder.
    pub fn current_user() -> WinScope {
        WinScope {
            hive: Hive::CurrentUser,
            uninstall: UNINSTALL_KEY.to_owned(),
            classes: CLASSES_KEY.to_owned(),
            machine_classes: Some((Hive::LocalMachine, CLASSES_KEY.to_owned())),
            run: RUN_KEY.to_owned(),
            programs: None,
            notify: true,
        }
    }

    /// The current user's layout moved under `HKCU\<prefix>` (for tests and tools: the uninstall
    /// entries go to `HKCU\<prefix>\Software\Microsoft\Windows\CurrentVersion\Uninstall`, the
    /// classes to `HKCU\<prefix>\Software\Classes`, the `Run` value to `...\Run`), and the shell
    /// is not told of association changes, and a folder `HKCU\<prefix>\Machine\Software\Classes`
    /// stands in for the per-machine classes the check reads (what another program registered
    /// for all users). `None` when `prefix` is empty, has an empty component,
    /// a `/` or a control character. The shortcut still goes to the real Start menu unless
    /// [`WinScope::with_start_menu`] moves it.
    pub fn with_registry_prefix(prefix: &str) -> Option<WinScope> {
        let ok = !prefix.is_empty()
            && prefix.split('\\').all(|c| !c.is_empty())
            && !prefix.chars().any(|c| c.is_control() || c == '/');
        ok.then(|| WinScope {
            hive: Hive::CurrentUser,
            uninstall: format!(r"{prefix}\{UNINSTALL_KEY}"),
            classes: format!(r"{prefix}\{CLASSES_KEY}"),
            machine_classes: Some((
                Hive::CurrentUser,
                format!(r"{prefix}\{MACHINE_PREFIX}\{CLASSES_KEY}"),
            )),
            run: format!(r"{prefix}\{RUN_KEY}"),
            programs: None,
            notify: false,
        })
    }

    /// This scope with the Start-menu shortcut going to `dir` (for tests and tools).
    #[must_use]
    pub fn with_start_menu(mut self, dir: PathBuf) -> WinScope {
        self.programs = Some(dir);
        self
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
    scope: &'a WinScope,
    root: PathBuf,
    layout: UserLayout,
    entry_path: String,
    stub_name: &'a str,
    /// The stub's directories below the version tree (the entry's directory).
    entry_dirs: Vec<&'a str>,
    /// The previous version's stub name, when it differs from `stub_name`.
    stale_stub: Option<&'a str>,
    /// `R\<stub name>`, as written into commands.
    stub_text: String,
    /// `R\<stale stub name>`.
    stale_stub_text: Option<String>,
    strings: Vec<(&'static str, String)>,
    publisher: Option<String>,
    /// The Start-menu shortcut's path, and that of the previous name's shortcut when it differs.
    lnk: PathBuf,
    old_lnk: Option<PathBuf>,
    decls: Decls,
}

impl Prepared<'_> {
    fn hive(&self) -> Hive {
        self.scope.hive
    }

    /// The `Run` values that are lunepack's: the command for the current and for the earlier stub.
    fn run_ours(&self) -> Vec<String> {
        std::iter::once(&self.stub_text)
            .chain(&self.stale_stub_text)
            .map(|stub| format!("\"{stub}\""))
            .collect()
    }

    fn classes_ctx<'b>(
        &'b self,
        app_id: &'b str,
        name: &'b str,
        run_ours: &'b [String],
    ) -> classes::Ctx<'b> {
        classes::Ctx {
            hive: self.hive(),
            classes: &self.scope.classes,
            machine: self
                .scope
                .machine_classes
                .as_ref()
                .map(|(hive, path)| (*hive, path.as_str())),
            run: &self.scope.run,
            app_id,
            name,
            stub: &self.stub_text,
            run_ours,
        }
    }

    /// The targets a shortcut of this app may have: the current stub and an earlier one.
    fn targets(&self) -> Vec<&str> {
        std::iter::once(self.stub_text.as_str())
            .chain(self.stale_stub_text.as_deref())
            .collect()
    }
}

impl OsIntegration for WindowsIntegration {
    fn check(&self, scope: Scope, req: &IntegrationRequest) -> Result<(), IntegrationError> {
        let p = prepare(self.scope(scope)?, req)?;
        check_conflicts(&p, req)
    }

    fn apply(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        let p = prepare(self.scope(scope)?, req)?;
        check_conflicts(&p, req)?;
        let bytes = read_source(&p, req)?;
        let app_id = req.app_id.as_str();

        // The stub first: the uninstall entry's commands, the shortcut and the declarations all
        // point at it.
        stub_place::place_stub(&p.root, p.stub_name, &bytes)?;
        write_entry(&p, app_id)?;

        let mut report = IntegrationReport::default();
        write_shortcut(&p, app_id)?;
        if let Some(old) = &p.old_lnk {
            match link_state(old, app_id, &p.targets())? {
                LinkState::Foreign => report.kept.push(IntegrationItem::Shortcut),
                LinkState::Ours(_) => {
                    stub_place::remove_file_retrying(old).map_err(|_| SHORTCUT_NOT_REMOVED)?;
                }
                LinkState::Absent => {}
            }
        }
        let run_ours = p.run_ours();
        let ctx = p.classes_ctx(app_id, &req.meta.name, &run_ours);
        let changed = classes::apply(&ctx, &p.decls, &mut report)?;
        if let Some(old) = p.stale_stub
            && !stub_place::remove_stub(&p.root, old)?
        {
            report.kept.push(IntegrationItem::Stub);
        }
        hide(&p.root.join(".lunepack"));
        if changed && p.scope.notify {
            classes::notify_associations_changed();
        }
        Ok(report)
    }

    fn remove(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        let p = prepare(self.scope(scope)?, req)?;
        let app_id = req.app_id.as_str();
        let mut report = IntegrationReport::default();
        match link_state(&p.lnk, app_id, &p.targets())? {
            LinkState::Foreign => report.kept.push(IntegrationItem::Shortcut),
            LinkState::Ours(_) => {
                stub_place::remove_file_retrying(&p.lnk).map_err(|_| SHORTCUT_NOT_REMOVED)?;
            }
            LinkState::Absent => {}
        }
        let run_ours = p.run_ours();
        let ctx = p.classes_ctx(app_id, &req.meta.name, &run_ours);
        let changed = classes::remove(&ctx, &p.decls, &mut report)?;
        match Key::open(p.hive(), &p.entry_path, false).map_err(|_| READ_FAILED)? {
            None => {}
            Some(entry) if owned(&entry, app_id)? => {
                drop(entry);
                registry::delete_tree(p.hive(), &p.entry_path)
                    .map_err(|_| IntegrationError::Failed("the uninstall entry was not removed"))?;
            }
            Some(_) => report.kept.push(IntegrationItem::UninstallEntry),
        }
        if !stub_place::remove_stub(&p.root, p.stub_name)? {
            report.kept.push(IntegrationItem::Stub);
        }
        if changed && p.scope.notify {
            classes::notify_associations_changed();
        }
        Ok(report)
    }
}

const READ_FAILED: IntegrationError =
    IntegrationError::Failed("the uninstall entry could not be read");
const WRITE_FAILED: IntegrationError =
    IntegrationError::Failed("the uninstall entry was not written");
const SHORTCUT_NOT_READ: IntegrationError =
    IntegrationError::Failed("the Start-menu shortcut could not be read");
const SHORTCUT_NOT_WRITTEN: IntegrationError =
    IntegrationError::Failed("the Start-menu shortcut was not written");
const SHORTCUT_NOT_REMOVED: IntegrationError =
    IntegrationError::Failed("the Start-menu shortcut was not removed");

fn prepare<'a>(
    scope: &'a WinScope,
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

    if !text_ok(&meta.name) || windows_name_ok(&meta.name).is_err() {
        return Err(IntegrationError::UnsafeField("name"));
    }
    if meta.publisher.as_deref().is_some_and(|p| !text_ok(p)) {
        return Err(IntegrationError::UnsafeField("publisher"));
    }
    let version = req.version.to_string();
    if !text_ok(&version) {
        return Err(IntegrationError::UnsafeField("version"));
    }
    let decls = declarations(req)?;

    let programs = match &scope.programs {
        Some(dir) => dir.clone(),
        None => crate::start_menu_programs()
            .map_err(|_| IntegrationError::Failed("the Start-menu folder is not available"))?,
    };
    let lnk = programs.join(format!("{}.lnk", meta.name));
    let old_lnk = req.previous.as_ref().and_then(|prev| {
        (text_ok(&prev.name)
            && windows_name_ok(&prev.name).is_ok()
            && !same_name(&prev.name, &meta.name))
        .then(|| programs.join(format!("{}.lnk", prev.name)))
    });

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
        scope,
        layout: UserLayout::from_root(root.clone(), LayoutScheme::WINDOWS),
        entry_path: scope.entry_key(req.app_id.as_str()),
        stub_text: stub_path,
        stale_stub_text: stale_stub.map(|old| format!(r"{root_text}\{old}")),
        root,
        stub_name,
        entry_dirs: parts,
        stale_stub,
        strings,
        publisher: meta.publisher.clone(),
        lnk,
        old_lnk,
        decls,
    })
}

/// A text value that goes into the registry or a shortcut: non-empty, no control character.
fn text_ok(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(char::is_control)
}

/// `[a-z0-9]{1,16}`.
fn ext_ok(ext: &str) -> bool {
    (1..=MAX_EXT_BYTES).contains(&ext.len())
        && ext
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// `[a-z][a-z0-9+.-]{0,31}`, none of the deny-list.
fn scheme_ok(scheme: &str) -> bool {
    (1..=MAX_SCHEME_BYTES).contains(&scheme.len())
        && scheme.as_bytes()[0].is_ascii_lowercase()
        && scheme.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'.' | b'-')
        })
        && !is_denied_url_scheme(scheme)
}

fn file_type_decl(app_id: &str, ft: &lunepack_core::FileType) -> Option<FileTypeDecl> {
    let name_chars = ft.name.chars().count();
    (ext_ok(&ft.ext) && text_ok(&ft.name) && (1..=MAX_FILE_TYPE_NAME_CHARS).contains(&name_chars))
        .then(|| FileTypeDecl {
            ext: ft.ext.clone(),
            progid: format!("{app_id}.{}", ft.ext),
            name: ft.name.clone(),
        })
}

/// What the request declares (checked: a bad field is refused, naming the field only) and what
/// the previous version declared that this one does not (an item that does not pass the same
/// rules is not ours to remove and is skipped).
fn declarations(req: &IntegrationRequest) -> Result<Decls, IntegrationError> {
    const FILE_TYPES: IntegrationError = IntegrationError::UnsafeField("file_types");
    const URL_SCHEMES: IntegrationError = IntegrationError::UnsafeField("url_schemes");
    let app_id = req.app_id.as_str();
    let meta: &InstallMeta = &req.meta;
    if meta.file_types.len() > MAX_FILE_TYPES {
        return Err(FILE_TYPES);
    }
    let mut file_types: Vec<FileTypeDecl> = Vec::new();
    for ft in &meta.file_types {
        let decl = file_type_decl(app_id, ft).ok_or(FILE_TYPES)?;
        if file_types.iter().any(|d| d.ext == decl.ext) {
            return Err(FILE_TYPES);
        }
        file_types.push(decl);
    }
    if meta.url_schemes.len() > MAX_URL_SCHEMES {
        return Err(URL_SCHEMES);
    }
    let mut schemes: Vec<String> = Vec::new();
    for scheme in &meta.url_schemes {
        if !scheme_ok(scheme) || schemes.contains(scheme) {
            return Err(URL_SCHEMES);
        }
        schemes.push(scheme.clone());
    }
    let (mut stale_file_types, mut stale_schemes) = (Vec::new(), Vec::new());
    if let Some(prev) = &req.previous {
        stale_file_types = prev
            .file_types
            .iter()
            .filter_map(|ft| file_type_decl(app_id, ft))
            .filter(|d| !file_types.iter().any(|now| now.ext == d.ext))
            .collect();
        stale_schemes = prev
            .url_schemes
            .iter()
            .filter(|s| scheme_ok(s) && !schemes.contains(s))
            .cloned()
            .collect();
    }
    Ok(Decls {
        file_types,
        schemes,
        autostart: meta.autostart,
        stale_file_types,
        stale_schemes,
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
fn check_conflicts(p: &Prepared<'_>, req: &IntegrationRequest) -> Result<(), IntegrationError> {
    let app_id = req.app_id.as_str();
    if let Some(key) = Key::open(p.hive(), &p.entry_path, false).map_err(|_| READ_FAILED)?
        && !owned(&key, app_id)?
    {
        return Err(IntegrationError::Conflict(IntegrationItem::UninstallEntry));
    }
    if stub_place::probe(&p.root.join(p.stub_name))? == Slot::Other {
        return Err(IntegrationError::Conflict(IntegrationItem::Stub));
    }
    if matches!(
        link_state(&p.lnk, app_id, &p.targets())?,
        LinkState::Foreign
    ) {
        return Err(IntegrationError::Conflict(IntegrationItem::Shortcut));
    }
    let run_ours = p.run_ours();
    classes::check(&p.classes_ctx(app_id, &req.meta.name, &run_ours), &p.decls)
}

/// What is at a shortcut's path.
enum LinkState {
    Absent,
    /// A shortcut with this app's id and one of its stubs as target.
    Ours(LinkInfo),
    /// Anything else: a file that is no shortcut, a shortcut of another app, a directory.
    Foreign,
}

/// Whether `text` (a path as read from a shortcut) and `path` name the same place: equal ignoring
/// case and a trailing separator, else equal once both are canonical.
fn same_path(text: &str, path: &str) -> bool {
    let norm = |s: &str| s.replace('/', "\\").trim_end_matches('\\').to_lowercase();
    if norm(text) == norm(path) {
        return true;
    }
    match (std::fs::canonicalize(text), std::fs::canonicalize(path)) {
        (Ok(a), Ok(b)) => norm(&a.to_string_lossy()) == norm(&b.to_string_lossy()),
        _ => false,
    }
}

fn link_state(path: &Path, app_id: &str, targets: &[&str]) -> Result<LinkState, IntegrationError> {
    match stub_place::probe(path).map_err(|_| SHORTCUT_NOT_READ)? {
        Slot::Absent => Ok(LinkState::Absent),
        Slot::Other => Ok(LinkState::Foreign),
        Slot::File => match shortcut::read(path).map_err(|_| SHORTCUT_NOT_READ)? {
            Some(info)
                if info.aumid.as_deref() == Some(app_id)
                    && targets.iter().any(|t| same_path(&info.target, t)) =>
            {
                Ok(LinkState::Ours(info))
            }
            _ => Ok(LinkState::Foreign),
        },
    }
}

/// Creates the shortcut, or rewrites it when it is ours and differs from what it should hold.
fn write_shortcut(p: &Prepared<'_>, app_id: &str) -> Result<(), IntegrationError> {
    let root_text = p.root.to_string_lossy();
    let spec = LinkSpec {
        target: Path::new(&p.stub_text),
        working_dir: &p.root,
        icon: Path::new(&p.stub_text),
        aumid: app_id,
    };
    if let LinkState::Ours(info) = link_state(&p.lnk, app_id, &p.targets())?
        && same_path(&info.target, &p.stub_text)
        && same_path(&info.working_dir, &root_text)
        && same_path(&info.icon, &p.stub_text)
        && info.icon_index == 0
    {
        return Ok(());
    }
    if let Some(dir) = p.lnk.parent() {
        std::fs::create_dir_all(dir).map_err(|_| SHORTCUT_NOT_WRITTEN)?;
    }
    shortcut::write(&p.lnk, &spec).map_err(|_| SHORTCUT_NOT_WRITTEN)
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
    let key = Key::create(p.hive(), &p.entry_path).map_err(|_| WRITE_FAILED)?;
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
    use lunepack_core::{AppId, FileType, InstallMeta, RelPath, Version};
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
            let programs = parent.join("Programs");
            let s = Sandbox {
                scope: WinScope::with_registry_prefix(&prefix)
                    .expect("prefix")
                    .with_start_menu(programs),
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

        /// `HKCU\<prefix>\Software\Classes`.
        fn classes(&self) -> String {
            format!(r"{}\Software\Classes", self.prefix)
        }

        /// The value `name` of the key `<classes>\<path>`; `None` when the key or value is absent.
        fn class_value(&self, path: &str, name: &str) -> Option<Value> {
            Key::open(
                Hive::CurrentUser,
                &format!(r"{}\{path}", self.classes()),
                false,
            )
            .expect("open")?
            .get(name)
            .expect("get")
        }

        fn class_exists(&self, path: &str) -> bool {
            Key::open(
                Hive::CurrentUser,
                &format!(r"{}\{path}", self.classes()),
                false,
            )
            .expect("open")
            .is_some()
        }

        /// The `Run` value `test.app`.
        fn run_value(&self) -> Option<Value> {
            Key::open(
                Hive::CurrentUser,
                &format!(
                    r"{}\Software\Microsoft\Windows\CurrentVersion\Run",
                    self.prefix
                ),
                false,
            )
            .expect("open")?
            .get("test.app")
            .expect("get")
        }

        /// A key under `<classes>` made by "another app": a value and no marker.
        fn foreign_class(&self, path: &str, name: &str, value: &str) {
            let key = Key::create(Hive::CurrentUser, &format!(r"{}\{path}", self.classes()))
                .expect("foreign key");
            key.set_str(name, value).expect("value");
        }

        /// A key under the stand-in for `HKLM\Software\Classes` (read only to the code under
        /// test): `name` = `value`, so a key made by "another program" for all users.
        fn machine_class(&self, path: &str, name: &str, value: &str) {
            let key = Key::create(
                Hive::CurrentUser,
                &format!(r"{}\Machine\Software\Classes\{path}", self.prefix),
            )
            .expect("machine key");
            key.set_str(name, value).expect("value");
        }

        fn lnk(&self, name: &str) -> PathBuf {
            self.parent.join("Programs").join(format!("{name}.lnk"))
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

    fn declaring_request(sb: &Sandbox) -> IntegrationRequest {
        let mut req = sb.request("1.0.0", "bin/app.exe", "My App");
        req.meta.file_types = vec![
            FileType {
                ext: "suite".to_owned(),
                mime: "application/x-suite".to_owned(),
                name: "Suite document".to_owned(),
            },
            FileType {
                ext: "suiteb".to_owned(),
                mime: "application/x-suite-b".to_owned(),
                name: "Suite B document".to_owned(),
            },
        ];
        req.meta.url_schemes = vec!["suite-app".to_owned()];
        req.meta.autostart = true;
        req
    }

    #[test]
    fn the_shortcut_is_written_read_back_and_left_alone_by_a_second_apply() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let req = sb.request("1.0.0", "bin/app.exe", "My App");
        w.check(Scope::User, &req).expect("check");
        assert!(!sb.lnk("My App").exists(), "check wrote the shortcut");
        w.apply(Scope::User, &req).expect("apply");

        let stub = sb.root.join("app.exe");
        let info = shortcut::read(&sb.lnk("My App"))
            .expect("read")
            .expect("a shortcut");
        assert!(same_path(&info.target, stub.to_str().expect("utf-8")));
        assert!(same_path(
            &info.working_dir,
            sb.root.to_str().expect("utf-8")
        ));
        assert!(same_path(&info.icon, stub.to_str().expect("utf-8")));
        assert_eq!(info.icon_index, 0);
        assert_eq!(info.aumid.as_deref(), Some("test.app"));

        let before = std::fs::read(sb.lnk("My App")).expect("bytes");
        std::thread::sleep(std::time::Duration::from_millis(50));
        w.apply(Scope::User, &req).expect("apply again");
        assert_eq!(
            std::fs::read(sb.lnk("My App")).expect("bytes"),
            before,
            "a second apply rewrote the shortcut"
        );
        assert_eq!(
            std::fs::read_dir(sb.parent.join("Programs"))
                .expect("list")
                .count(),
            1,
            "a temporary name is left"
        );

        let report = w.remove(Scope::User, &req).expect("remove");
        assert!(report.kept.is_empty());
        assert!(!sb.lnk("My App").exists(), "the shortcut is left");
        w.remove(Scope::User, &req).expect("remove again");
        sb.finish();
    }

    #[test]
    fn the_shortcut_works_on_a_thread_whose_com_mode_is_another() {
        use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoUninitialize};
        let sb = Sandbox::new();
        let w = sb.integration();
        let req = sb.request("1.0.0", "bin/app.exe", "My App");
        std::thread::scope(|scope| {
            scope.spawn(|| {
                #[allow(unsafe_code)]
                // SAFETY: no pointer arguments; balanced by `CoUninitialize` below on this thread.
                let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
                assert!(hr.is_ok(), "{hr:?}");
                w.apply(Scope::User, &req).expect("apply on an MTA thread");
                w.remove(Scope::User, &req).expect("remove");
                // SAFETY: balances the `CoInitializeEx` above; the adapter must not have undone it.
                #[allow(unsafe_code)]
                unsafe {
                    CoUninitialize()
                };
            });
        });
        sb.finish();
    }

    #[test]
    fn a_foreign_shortcut_is_a_conflict_and_is_kept_and_reported() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let req = sb.request("1.0.0", "bin/app.exe", "My App");
        std::fs::create_dir_all(sb.parent.join("Programs")).expect("programs");

        // A file that is no shortcut at all, then a real shortcut of another app.
        std::fs::write(sb.lnk("My App"), b"not a shortcut").expect("file");
        for round in 0..2 {
            for result in [
                w.check(Scope::User, &req),
                w.apply(Scope::User, &req).map(|_| ()),
            ] {
                assert!(
                    matches!(
                        result,
                        Err(IntegrationError::Conflict(IntegrationItem::Shortcut))
                    ),
                    "round {round}: {result:?}"
                );
            }
            let report = w.remove(Scope::User, &req).expect("remove");
            assert_eq!(report.kept, [IntegrationItem::Shortcut], "round {round}");
            if round == 0 {
                std::fs::remove_file(sb.lnk("My App")).expect("clear");
                let other = sb.root.join("other.exe");
                std::fs::write(&other, b"x").expect("target");
                shortcut::write(
                    &sb.lnk("My App"),
                    &LinkSpec {
                        target: &other,
                        working_dir: &sb.root,
                        icon: &other,
                        aumid: "someone.else",
                    },
                )
                .expect("foreign shortcut");
            }
        }
        let foreign = shortcut::read(&sb.lnk("My App"))
            .expect("read")
            .expect("shortcut");
        assert_eq!(foreign.aumid.as_deref(), Some("someone.else"));
        assert!(!sb.root.join("app.exe").exists(), "apply placed the stub");
        assert!(sb.values().is_none(), "something was written");
        sb.finish();
    }

    #[test]
    fn a_new_name_moves_the_shortcut_and_a_foreign_old_one_stays() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let first = sb.request("1.0.0", "bin/app.exe", "My App");
        w.apply(Scope::User, &first).expect("apply");
        sb.stage("2.0.0", "bin", b"stub-2");
        let mut second = sb.request("2.0.0", "bin/app.exe", "My Renamed App");
        second.previous = Some(first.meta.clone());
        let report = w.apply(Scope::User, &second).expect("renamed");
        assert!(report.kept.is_empty());
        assert!(!sb.lnk("My App").exists(), "the old shortcut is left");
        assert!(sb.lnk("My Renamed App").is_file());

        // The old name taken by someone else's file: kept and reported on the next move.
        std::fs::write(sb.lnk("My App"), b"theirs").expect("foreign");
        let mut third = sb.request("2.0.0", "bin/app.exe", "Third Name");
        third.previous = Some(second.meta.clone());
        let report = w.apply(Scope::User, &third).expect("third");
        assert!(report.kept.is_empty(), "{:?}", report.kept);
        assert!(!sb.lnk("My Renamed App").exists());
        let mut back = sb.request("2.0.0", "bin/app.exe", "Third Name");
        let mut prev = back.meta.clone();
        prev.name = "My App".to_owned();
        back.previous = Some(prev);
        let report = w.apply(Scope::User, &back).expect("old name is foreign");
        assert_eq!(report.kept, [IntegrationItem::Shortcut]);
        assert_eq!(std::fs::read(sb.lnk("My App")).expect("kept"), b"theirs");
        sb.finish();
    }

    #[test]
    fn declarations_are_written_read_back_and_removed() {
        let sb = Sandbox::new();
        let w = sb.integration();
        // Someone else's extension key with its own default value must survive.
        sb.foreign_class(".suite", "", "other.file");
        sb.foreign_class(".suite\\OpenWithProgids", "other.file", "");
        let req = declaring_request(&sb);
        w.check(Scope::User, &req).expect("check");
        assert!(!sb.class_exists("test.app.suite"), "check wrote");
        let report = w.apply(Scope::User, &req).expect("apply");
        assert!(report.kept.is_empty());

        let stub = sb.root.join("app.exe");
        let stub = stub.to_str().expect("utf-8");
        let command = format!("\"{stub}\" \"%1\"");
        for (ext, name) in [("suite", "Suite document"), ("suiteb", "Suite B document")] {
            let progid = format!("test.app.{ext}");
            assert_eq!(sb.class_value(&progid, MARKER_VALUE), s("test.app"));
            assert_eq!(sb.class_value(&progid, "FriendlyTypeName"), s(name));
            assert_eq!(
                sb.class_value(&format!(r"{progid}\DefaultIcon"), ""),
                s(&format!("{stub},0"))
            );
            assert_eq!(
                sb.class_value(&format!(r"{progid}\shell\open\command"), ""),
                s(&command)
            );
            assert_eq!(
                sb.class_value(&format!(r".{ext}\OpenWithProgids"), &progid),
                s("")
            );
        }
        // The extension keys' default values are never written: `.suiteb` had none, and
        // `.suite`'s is the other app's.
        assert_eq!(sb.class_value(".suiteb", ""), None);
        assert_eq!(
            sb.class_value(".suite", ""),
            s("other.file"),
            "default changed"
        );
        assert_eq!(
            sb.class_value(r".suite\OpenWithProgids", "other.file"),
            s("")
        );
        assert_eq!(sb.class_value("suite-app", MARKER_VALUE), s("test.app"));
        assert_eq!(sb.class_value("suite-app", "URL Protocol"), s(""));
        assert_eq!(
            sb.class_value("suite-app", ""),
            s("URL:My App"),
            "the scheme's description"
        );
        assert_eq!(
            sb.class_value(r"suite-app\shell\open\command", ""),
            s(&command)
        );
        assert_eq!(sb.run_value(), s(&format!("\"{stub}\"")));

        // Idempotent: a second apply changes no value.
        let before = reg_export(&sb);
        w.apply(Scope::User, &req).expect("apply again");
        assert_eq!(reg_export(&sb), before, "a second apply changed a value");

        let report = w.remove(Scope::User, &req).expect("remove");
        assert!(report.kept.is_empty(), "{:?}", report.kept);
        for ext in ["suite", "suiteb"] {
            assert!(!sb.class_exists(&format!("test.app.{ext}")));
            assert_eq!(
                sb.class_value(
                    &format!(r".{ext}\OpenWithProgids"),
                    &format!("test.app.{ext}")
                ),
                None
            );
        }
        assert!(!sb.class_exists(".suiteb"), "an empty key we made is left");
        assert_eq!(sb.class_value(".suite", ""), s("other.file"));
        assert_eq!(
            sb.class_value(r".suite\OpenWithProgids", "other.file"),
            s(""),
            "someone else's Open-with entry was removed"
        );
        assert!(!sb.class_exists("suite-app"));
        assert_eq!(sb.run_value(), None);
        w.remove(Scope::User, &req).expect("remove again");
        sb.finish();
    }

    /// `reg.exe export` of the scratch prefix, an instrument independent of the adapter's own
    /// registry code (value order and last-write times are not in a `.reg` file).
    fn reg_export(sb: &Sandbox) -> String {
        let out = std::env::temp_dir().join(format!("lp-export-{}.reg", hex()));
        let status = std::process::Command::new("reg.exe")
            .args(["export", &format!(r"HKCU\{}", sb.prefix)])
            .arg(&out)
            .arg("/y")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("reg.exe");
        assert!(
            status.success(),
            "INVALID: reg.exe cannot export the prefix"
        );
        let bytes = std::fs::read(&out).expect("export");
        let _ = std::fs::remove_file(&out);
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        String::from_utf16_lossy(&units)
    }

    #[test]
    fn foreign_declarations_are_conflicts_and_are_left_alone() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let req = declaring_request(&sb);

        // A ProgID, a scheme and a Run value that are not ours, one kind at a time.
        let cases: [(&str, IntegrationItem); 3] = [
            ("test.app.suite", IntegrationItem::FileType),
            ("suite-app", IntegrationItem::UrlScheme),
            ("run", IntegrationItem::Autostart),
        ];
        for (where_, item) in cases {
            if where_ == "run" {
                let run = Key::create(
                    Hive::CurrentUser,
                    &format!(
                        r"{}\Software\Microsoft\Windows\CurrentVersion\Run",
                        sb.prefix
                    ),
                )
                .expect("run key");
                run.set_str("test.app", r#""C:\Other\thing.exe""#)
                    .expect("foreign run value");
            } else {
                sb.foreign_class(where_, "Theirs", "yes");
            }
            for result in [
                w.check(Scope::User, &req),
                w.apply(Scope::User, &req).map(|_| ()),
            ] {
                match result {
                    Err(IntegrationError::Conflict(got)) => assert_eq!(got, item, "{where_}"),
                    other => panic!("{where_}: {other:?}"),
                }
            }
            assert!(sb.values().is_none(), "{where_}: apply wrote something");
            let report = w.remove(Scope::User, &req).expect("remove");
            assert_eq!(report.kept, [item], "{where_}");
            // Cleared for the next kind.
            if where_ == "run" {
                let run = Key::open(
                    Hive::CurrentUser,
                    &format!(
                        r"{}\Software\Microsoft\Windows\CurrentVersion\Run",
                        sb.prefix
                    ),
                    true,
                )
                .expect("open")
                .expect("run key");
                assert_eq!(
                    run.get("test.app").expect("get"),
                    s(r#""C:\Other\thing.exe""#),
                    "remove deleted a foreign value"
                );
                run.delete_value("test.app").expect("clear");
            } else {
                assert_eq!(sb.class_value(where_, "Theirs"), s("yes"), "{where_}");
                registry::delete_tree(Hive::CurrentUser, &format!(r"{}\{where_}", sb.classes()))
                    .expect("clear");
            }
        }
        sb.finish();
    }

    #[test]
    fn a_scheme_or_progid_registered_per_machine_by_another_program_is_a_conflict() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let req = declaring_request(&sb);

        let cases: [(&str, IntegrationItem); 2] = [
            ("test.app.suite", IntegrationItem::FileType),
            ("suite-app", IntegrationItem::UrlScheme),
        ];
        for (where_, item) in cases {
            sb.machine_class(where_, "Theirs", "yes");
            for result in [
                w.check(Scope::User, &req),
                w.apply(Scope::User, &req).map(|_| ()),
            ] {
                match result {
                    Err(IntegrationError::Conflict(got)) => assert_eq!(got, item, "{where_}"),
                    other => panic!("{where_}: {other:?}"),
                }
            }
            assert!(sb.values().is_none(), "{where_}: apply wrote something");
            assert!(!sb.class_exists(where_), "{where_}: a user key was made");
            // Remove only reads the user's keys: nothing of ours, nothing reported, theirs stays.
            let report = w.remove(Scope::User, &req).expect("remove");
            assert!(report.kept.is_empty(), "{where_}: {:?}", report.kept);
            registry::delete_tree(
                Hive::CurrentUser,
                &format!(r"{}\Machine\Software\Classes\{where_}", sb.prefix),
            )
            .expect("clear");
        }
        // With nothing per machine it applies.
        w.apply(Scope::User, &req).expect("apply");
        sb.finish();
    }

    #[test]
    fn per_machine_keys_that_shadow_nothing_do_not_conflict() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let req = declaring_request(&sb);
        // An extension's own key (its handler) is never shadowed: only `OpenWithProgids` is added.
        sb.machine_class(".suite", "", "other.file");
        // A per-machine key of this app's own (M10) carries the marker.
        sb.machine_class("suite-app", MARKER_VALUE, "test.app");
        w.check(Scope::User, &req).expect("check");
        w.apply(Scope::User, &req).expect("apply");
        // A per-machine key that appeared after our own user key was made does not turn an
        // update into a conflict.
        sb.machine_class("test.app.suiteb", "Theirs", "yes");
        w.apply(Scope::User, &req).expect("second apply");
        sb.finish();
    }

    #[test]
    fn dropped_declarations_go_away_when_ours_and_stay_when_not() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let full = declaring_request(&sb);
        w.apply(Scope::User, &full).expect("apply");

        // Someone replaced one of ours: their ProgID of that name is kept and reported.
        let mut bare = sb.request("1.0.0", "bin/app.exe", "My App");
        bare.previous = Some(full.meta.clone());
        registry::delete_tree(
            Hive::CurrentUser,
            &format!(r"{}\test.app.suiteb", sb.classes()),
        )
        .expect("drop");
        sb.foreign_class("test.app.suiteb", "Theirs", "yes");
        let report = w.apply(Scope::User, &bare).expect("apply bare");
        assert_eq!(report.kept, [IntegrationItem::FileType]);
        assert_eq!(sb.class_value("test.app.suiteb", "Theirs"), s("yes"));
        assert!(!sb.class_exists("test.app.suite"));
        assert!(!sb.class_exists("suite-app"));
        assert_eq!(sb.run_value(), None, "autostart is left");
        assert!(sb.values().is_some(), "the uninstall entry is gone");

        // The same again changes nothing and reports the same.
        let report = w.apply(Scope::User, &bare).expect("apply bare again");
        assert_eq!(report.kept, [IntegrationItem::FileType]);
        sb.finish();
    }

    #[test]
    fn a_changed_stub_name_rewrites_the_commands() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let mut first = declaring_request(&sb);
        first.meta.entry = RelPath::parse("bin/old.exe").expect("entry");
        w.apply(Scope::User, &first).expect("apply");
        sb.stage("2.0.0", "bin", b"stub-2");
        let mut second = declaring_request(&sb);
        second.version = Version::parse("2.0.0").expect("version");
        second.meta.entry = RelPath::parse("bin/new.exe").expect("entry");
        second.previous = Some(first.meta.clone());
        let report = w.apply(Scope::User, &second).expect("apply");
        assert!(report.kept.is_empty(), "{:?}", report.kept);
        let new = sb.root.join("new.exe");
        let new = new.to_str().expect("utf-8");
        assert_eq!(
            sb.class_value(r"test.app.suite\shell\open\command", ""),
            s(&format!("\"{new}\" \"%1\""))
        );
        assert_eq!(sb.run_value(), s(&format!("\"{new}\"")));
        let info = shortcut::read(&sb.lnk("My App"))
            .expect("read")
            .expect("shortcut");
        assert!(same_path(&info.target, new));
        sb.finish();
    }

    #[test]
    fn unsafe_declarations_are_refused_and_write_nothing() {
        let sb = Sandbox::new();
        let w = sb.integration();
        let good = declaring_request(&sb);
        let mut cases: Vec<(&str, IntegrationRequest)> = Vec::new();
        let mut with = |what: &'static str, edit: &dyn Fn(&mut IntegrationRequest)| {
            let mut r = good.clone();
            edit(&mut r);
            cases.push((what, r));
        };
        with("a backslash in an extension", &|r| {
            r.meta.file_types[0].ext = "SECRET\\x".to_owned();
        });
        with("an uppercase extension", &|r| {
            r.meta.file_types[0].ext = "SECRET".to_owned();
        });
        with("the same extension twice", &|r| {
            r.meta.file_types[1].ext = r.meta.file_types[0].ext.clone();
        });
        with("a newline in a file type name", &|r| {
            r.meta.file_types[0].name = "SECRET\nx".to_owned();
        });
        with("a denied scheme", &|r| {
            r.meta.url_schemes = vec!["https".to_owned()];
        });
        with("a backslash in a scheme", &|r| {
            r.meta.url_schemes = vec!["secret\\x".to_owned()];
        });
        with("a name Windows cannot use", &|r| {
            r.meta.name = "SECRET:name".to_owned();
        });
        for (what, req) in &cases {
            for result in [
                w.check(Scope::User, req),
                w.apply(Scope::User, req).map(|_| ()),
            ] {
                let err = result.expect_err(what);
                assert!(
                    !format!("{err} {err:?}").to_lowercase().contains("secret"),
                    "{what}: {err:?}"
                );
            }
        }
        assert!(sb.values().is_none(), "something was written");
        assert!(!sb.lnk("My App").exists());
        assert!(!sb.class_exists("test.app.suite"));
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
