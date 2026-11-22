//! XDG desktop integration for a per-user install: a `.desktop` entry in
//! `<data home>/applications`, when the app declares one a command link in `$HOME/.local/bin`
//! (M5-D2, M5-D10 as amended) and, when it declares file types, URL schemes or autostart, a
//! `MimeType=` line in the entry and an autostart entry in `<config home>/autostart` (M7-D3).
//!
//! Safety rules, in order of importance:
//!
//! - **Nothing is escaped, everything unsafe is refused.** The entry's `Exec` and `Icon` hold an
//!   absolute path built from the install root and a tree path. A path (and the home and data
//!   home it sits under) that holds a character [`desktop_safe_path`] refuses is an
//!   `UnsafePath` error from `check` and `apply`, and nothing is written. So the quoted `Exec`
//!   value never needs an escape. Text fields are re-validated here, since this adapter does
//!   not trust its caller.
//! - **Only what lunepack made is replaced or removed.** The desktop entry is ours when it is a
//!   regular file carrying the line `X-Lunepack-App-Id=<app id>`; a command link is ours when it
//!   is a symlink whose target lies under `<install root>/current/` and has no `..` component;
//!   the autostart entry is ours under the same marker as the desktop entry.
//!   Anything else at those paths is a `Conflict` on `check` and `apply`, and is left (and
//!   reported) by `remove` and for stale links. Nothing here deletes a directory.
//! - **Entries go through `<install root>/current`**, so a version flip needs no rewrite.
//!
//! Errors never show a path or a value from the metadata.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use lunepack_core::{
    InstallMeta, IntegrationError, IntegrationItem, IntegrationReport, IntegrationRequest,
    OsIntegration, Scope, desktop_safe_path, update_config::is_denied_url_scheme,
};

/// The most bytes of an existing desktop entry that are read to look for the marker.
const MARKER_READ_CAP: u64 = 64 * 1024;

/// The marker's key: the entry carries `X-Lunepack-App-Id=<app id>`.
const MARKER_KEY: &str = "X-Lunepack-App-Id=";

/// The environment variables the layout depends on, passed in so tests need not touch the
/// process's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XdgEnv {
    /// `HOME`.
    pub home: Option<OsString>,
    /// `XDG_DATA_HOME`.
    pub xdg_data_home: Option<OsString>,
    /// `XDG_CONFIG_HOME` (where the autostart directory is).
    pub xdg_config_home: Option<OsString>,
}

impl XdgEnv {
    /// The process's own `HOME` and `XDG_DATA_HOME`.
    pub fn from_process() -> XdgEnv {
        XdgEnv {
            home: std::env::var_os("HOME"),
            xdg_data_home: std::env::var_os("XDG_DATA_HOME"),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
        }
    }
}

/// The directories a per-user install uses, all canonical (no symlink component) and absolute.
/// They need not exist yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdgDirs {
    home: PathBuf,
    data_home: PathBuf,
    applications: PathBuf,
    bin: PathBuf,
    autostart: PathBuf,
}

impl XdgDirs {
    /// The user's home.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The data home: `XDG_DATA_HOME` when it is set, non-empty, absolute and UTF-8, else
    /// `$HOME/.local/share`. The install root is `<data home>/<app id>` (M5-D2).
    pub fn data_home(&self) -> &Path {
        &self.data_home
    }

    /// `<data home>/applications`, where desktop entries go.
    pub fn applications(&self) -> &Path {
        &self.applications
    }

    /// `$HOME/.local/bin`, where command links go.
    pub fn bin(&self) -> &Path {
        &self.bin
    }

    /// `<config home>/autostart`, where the start-at-sign-in entry goes (`XDG_CONFIG_HOME` when it
    /// is set, non-empty, absolute and UTF-8, else `$HOME/.config`).
    pub fn autostart(&self) -> &Path {
        &self.autostart
    }
}

/// Works out the directories from `env`.
///
/// `HOME` must be set, absolute and UTF-8 and name a directory that exists, else
/// [`IntegrationError::Home`]. `XDG_DATA_HOME` is used only when it is set, non-empty, absolute
/// and UTF-8 (the specification calls a relative value invalid, so it is ignored). Every path is
/// canonicalised: the part that exists is resolved through [`fs::canonicalize`], and the part
/// that does not must be plain names. Nothing is created.
pub fn xdg_dirs(env: &XdgEnv) -> Result<XdgDirs, IntegrationError> {
    let raw_home = env.home.as_ref().ok_or(IntegrationError::Home)?;
    let raw_home = raw_home.to_str().ok_or(IntegrationError::Home)?;
    if raw_home.is_empty() || !Path::new(raw_home).is_absolute() {
        return Err(IntegrationError::Home);
    }
    let home = fs::canonicalize(raw_home).map_err(|_| IntegrationError::Home)?;
    if !home.is_dir() {
        return Err(IntegrationError::Home);
    }
    let data_home = match env
        .xdg_data_home
        .as_ref()
        .and_then(|v| v.to_str())
        .filter(|v| !v.is_empty() && Path::new(v).is_absolute())
    {
        Some(v) => resolve(Path::new(v))?,
        None => resolve(&home.join(".local").join("share"))?,
    };
    let applications = resolve(&data_home.join("applications"))?;
    let bin = resolve(&home.join(".local").join("bin"))?;
    let config_home = match env
        .xdg_config_home
        .as_ref()
        .and_then(|v| v.to_str())
        .filter(|v| !v.is_empty() && Path::new(v).is_absolute())
    {
        Some(v) => resolve(Path::new(v))?,
        None => resolve(&home.join(".config"))?,
    };
    let autostart = resolve(&config_home.join("autostart"))?;
    Ok(XdgDirs {
        home,
        data_home,
        applications,
        bin,
        autostart,
    })
}

/// Canonicalises the longest existing prefix of an absolute `path` and appends the rest, which
/// must be plain names (no `..`).
fn resolve(path: &Path) -> Result<PathBuf, IntegrationError> {
    let mut tail: Vec<OsString> = Vec::new();
    let mut probe = path;
    loop {
        match fs::canonicalize(probe) {
            Ok(mut base) => {
                for part in tail.iter().rev() {
                    base.push(part);
                }
                return Ok(base);
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let name = probe
                    .file_name()
                    .ok_or(IntegrationError::Failed("a directory path is not usable"))?;
                tail.push(name.to_owned());
                probe = probe
                    .parent()
                    .ok_or(IntegrationError::Failed("a directory path is not usable"))?;
            }
            Err(_) => return Err(IntegrationError::Failed("a directory is not usable")),
        }
    }
}

/// The Linux per-user [`OsIntegration`]: an XDG desktop entry, a command link and an autostart
/// entry. Per-machine scope is `Unsupported` here ([`MachineIntegration`] serves it).
#[derive(Debug, Clone)]
pub struct XdgIntegration {
    env: XdgEnv,
}

impl XdgIntegration {
    /// An integration that reads its layout from `env` on every call.
    pub fn new(env: XdgEnv) -> XdgIntegration {
        XdgIntegration { env }
    }

    /// An integration over the process's own environment.
    pub fn from_process_env() -> XdgIntegration {
        XdgIntegration::new(XdgEnv::from_process())
    }
}

/// What a request resolves to, after every check that writes nothing.
struct Prepared {
    dirs: XdgDirs,
    root: PathBuf,
    desktop_path: PathBuf,
    content: String,
    /// The link path and its target, when the app declares a command.
    bin: Option<(PathBuf, String)>,
    /// Links of names the previous version used.
    stale: Vec<PathBuf>,
    /// The autostart entry's path and, when the app declares autostart, its content (else the
    /// entry is removed when it is ours).
    autostart: (PathBuf, Option<String>),
}

impl OsIntegration for XdgIntegration {
    fn check(&self, scope: Scope, req: &IntegrationRequest) -> Result<(), IntegrationError> {
        self.prepare(scope, req).map(|_| ())
    }

    fn apply(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        apply_prepared(self.prepare(scope, req)?, req)
    }

    fn remove(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        if scope != Scope::User {
            return Err(IntegrationError::Unsupported);
        }
        remove_with(xdg_dirs(&self.env)?, req)
    }
}

/// `apply` over what [`prepare_with`] resolved.
fn apply_prepared(
    p: Prepared,
    req: &IntegrationRequest,
) -> Result<IntegrationReport, IntegrationError> {
    ensure_dir(p.dirs.applications())?;
    if p.bin.is_some() || !p.stale.is_empty() {
        ensure_dir(p.dirs.bin())?;
    }

    // The desktop entry first: a failure after it leaves a valid entry and a retry finishes
    // the rest.
    let name = file_name(&p.desktop_path)?;
    let unchanged = match probe(&p.desktop_path)? {
        Slot::File => read_capped(&p.desktop_path).is_ok_and(|bytes| bytes == p.content.as_bytes()),
        _ => false,
    };
    if !unchanged {
        write_atomic(p.dirs.applications(), name, p.content.as_bytes())?;
    }

    if let Some((link, target)) = &p.bin {
        let current = match probe(link)? {
            Slot::Symlink(t) => t.to_str() == Some(target.as_str()),
            _ => false,
        };
        if !current {
            replace_symlink(target, link)?;
        }
    }

    let mut report = IntegrationReport::default();
    let (autostart_path, autostart_content) = &p.autostart;
    match autostart_content {
        Some(content) => {
            ensure_dir(p.dirs.autostart())?;
            let unchanged = match probe(autostart_path)? {
                Slot::File => {
                    read_capped(autostart_path).is_ok_and(|bytes| bytes == content.as_bytes())
                }
                _ => false,
            };
            if !unchanged {
                write_atomic(
                    p.dirs.autostart(),
                    file_name(autostart_path)?,
                    content.as_bytes(),
                )?;
            }
        }
        None => remove_autostart(autostart_path, req.app_id.as_str(), &mut report)?,
    }
    for link in &p.stale {
        match probe(link)? {
            Slot::Absent => {}
            Slot::Symlink(t) if is_ours(&t, &p.root) => {
                fs::remove_file(link).map_err(|_| {
                    IntegrationError::Failed("a stale command link was not removed")
                })?;
            }
            _ => report.kept.push(IntegrationItem::BinLink),
        }
    }
    sync_dir(p.dirs.bin());
    sync_dir(p.dirs.autostart());
    Ok(report)
}

/// `remove` with the directories `dirs`.
fn remove_with(
    dirs: XdgDirs,
    req: &IntegrationRequest,
) -> Result<IntegrationReport, IntegrationError> {
    let root = check_root(&req.install_root)?;
    let mut report = IntegrationReport::default();

    let desktop_path = dirs
        .applications()
        .join(format!("{}.desktop", req.app_id.as_str()));
    match probe(&desktop_path)? {
        Slot::Absent => {}
        Slot::File if has_marker(&desktop_path, req.app_id.as_str()) => {
            fs::remove_file(&desktop_path)
                .map_err(|_| IntegrationError::Failed("the desktop entry was not removed"))?;
        }
        _ => report.kept.push(IntegrationItem::DesktopEntry),
    }

    if let Some(bin) = &req.meta.bin {
        if !bin_ok(bin) {
            return Err(IntegrationError::UnsafeField("bin"));
        }
        let link = dirs.bin().join(bin);
        match probe(&link)? {
            Slot::Absent => {}
            Slot::Symlink(t) if is_ours(&t, &root) => {
                fs::remove_file(&link)
                    .map_err(|_| IntegrationError::Failed("the command link was not removed"))?;
            }
            _ => report.kept.push(IntegrationItem::BinLink),
        }
    }
    let autostart_path = dirs
        .autostart()
        .join(format!("{}.desktop", req.app_id.as_str()));
    remove_autostart(&autostart_path, req.app_id.as_str(), &mut report)?;
    sync_dir(dirs.applications());
    sync_dir(dirs.bin());
    sync_dir(dirs.autostart());
    Ok(report)
}

/// Removes the autostart entry when it is ours (a regular file with the marker); reports a foreign
/// one as kept; an absent one is fine.
fn remove_autostart(
    path: &Path,
    app_id: &str,
    report: &mut IntegrationReport,
) -> Result<(), IntegrationError> {
    match probe(path)? {
        Slot::Absent => {}
        Slot::File if has_marker(path, app_id) => {
            fs::remove_file(path)
                .map_err(|_| IntegrationError::Failed("the autostart entry was not removed"))?;
        }
        _ => report.kept.push(IntegrationItem::Autostart),
    }
    Ok(())
}

impl XdgIntegration {
    /// Every check that writes nothing: scope, environment, paths, fields, conflicts.
    fn prepare(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<Prepared, IntegrationError> {
        if scope != Scope::User {
            return Err(IntegrationError::Unsupported);
        }
        prepare_with(xdg_dirs(&self.env)?, req)
    }
}

/// Every check that writes nothing, with the directories `dirs`: paths, fields, conflicts.
fn prepare_with(dirs: XdgDirs, req: &IntegrationRequest) -> Result<Prepared, IntegrationError> {
    let root = check_root(&req.install_root)?;
    let meta = &req.meta;

    let current = root.join("current");
    let exec_path = current.join(meta.entry.as_str());
    let exec = path_str(&exec_path, "executable path")?;
    let icon = match &meta.icon {
        Some(icon) => Some(path_str(&current.join(icon.as_str()), "icon path")?.to_owned()),
        None => None,
    };
    // The home and the data home sit under every path the entry and the link refer to; a
    // hostile one is refused here (FORMAT.md 13.5), not escaped.
    for (what, path) in [("home", dirs.home()), ("data home", dirs.data_home())] {
        path_str(path, what)?;
    }
    check_fields(meta)?;
    for stale in &req.stale_bins {
        if !bin_ok(stale) {
            return Err(IntegrationError::UnsafeField("stale bin"));
        }
    }

    let content = entry_bytes(req.app_id.as_str(), meta, exec, icon.as_deref(), false);
    let desktop_path = dirs
        .applications()
        .join(format!("{}.desktop", req.app_id.as_str()));
    match probe(&desktop_path)? {
        Slot::Absent => {}
        Slot::File if has_marker(&desktop_path, req.app_id.as_str()) => {}
        _ => return Err(IntegrationError::Conflict(IntegrationItem::DesktopEntry)),
    }
    let autostart_path = dirs
        .autostart()
        .join(format!("{}.desktop", req.app_id.as_str()));
    let autostart_content = if meta.autostart {
        match probe(&autostart_path)? {
            Slot::Absent => {}
            Slot::File if has_marker(&autostart_path, req.app_id.as_str()) => {}
            _ => return Err(IntegrationError::Conflict(IntegrationItem::Autostart)),
        }
        Some(entry_bytes(
            req.app_id.as_str(),
            meta,
            exec,
            icon.as_deref(),
            true,
        ))
    } else {
        None
    };

    let bin = match &meta.bin {
        Some(name) => {
            let link = dirs.bin().join(name);
            match probe(&link)? {
                Slot::Absent => {}
                Slot::Symlink(t) if is_ours(&t, &root) => {}
                _ => return Err(IntegrationError::Conflict(IntegrationItem::BinLink)),
            }
            Some((link, exec.to_owned()))
        }
        None => None,
    };
    let stale = req
        .stale_bins
        .iter()
        .filter(|name| Some(*name) != meta.bin.as_ref())
        .map(|name| dirs.bin().join(name))
        .collect();

    Ok(Prepared {
        dirs,
        root,
        desktop_path,
        content,
        bin,
        stale,
        autostart: (autostart_path, autostart_content),
    })
}

// ---- the per-machine integration (M11-D12) -------------------------------------------------------

/// The Linux per-machine [`OsIntegration`] (M11-D12), run as root by the engine: the desktop
/// entry in `/usr/local/share/applications`, the command link in `/usr/local/bin` and the
/// autostart entry in `/etc/xdg/autostart`, each through `R/current`, under the per-user rules
/// (an entry that is not this app's is refused, never replaced). The package manager's
/// `/usr/share` and `/usr/bin` are never touched. Per-user scope is `Unsupported`.
#[derive(Debug, Clone)]
pub struct MachineIntegration {
    dirs: XdgDirs,
}

impl Default for MachineIntegration {
    fn default() -> Self {
        MachineIntegration::new()
    }
}

impl MachineIntegration {
    /// The system's directories.
    pub fn new() -> MachineIntegration {
        MachineIntegration::under(Path::new("/"))
    }

    /// The same directories under `prefix` (tests use a scratch directory; `/` is the system).
    pub fn under(prefix: &Path) -> MachineIntegration {
        let share = prefix.join("usr/local/share");
        MachineIntegration {
            dirs: XdgDirs {
                home: prefix.to_path_buf(),
                applications: share.join("applications"),
                data_home: share,
                bin: prefix.join("usr/local/bin"),
                autostart: prefix.join("etc/xdg/autostart"),
            },
        }
    }

    fn dirs(&self, scope: Scope) -> Result<XdgDirs, IntegrationError> {
        if scope != Scope::Machine {
            return Err(IntegrationError::Unsupported);
        }
        Ok(self.dirs.clone())
    }
}

impl OsIntegration for MachineIntegration {
    fn check(&self, scope: Scope, req: &IntegrationRequest) -> Result<(), IntegrationError> {
        prepare_with(self.dirs(scope)?, req).map(|_| ())
    }

    fn apply(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        apply_prepared(prepare_with(self.dirs(scope)?, req)?, req)
    }

    fn remove(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        remove_with(self.dirs(scope)?, req)
    }
}

/// The install root: absolute, UTF-8, and plain components only.
fn check_root(root: &Path) -> Result<PathBuf, IntegrationError> {
    const BAD: IntegrationError =
        IntegrationError::Failed("the install root is not a plain absolute path");
    if !root.is_absolute() || root.to_str().is_none() {
        return Err(BAD);
    }
    if root
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(BAD);
    }
    // Rebuild from components so a trailing or doubled separator is gone.
    Ok(root.components().collect())
}

/// `path` as `&str`, refused when it holds a character a desktop entry cannot carry.
fn path_str<'a>(path: &'a Path, what: &'static str) -> Result<&'a str, IntegrationError> {
    let text = path
        .to_str()
        .ok_or(IntegrationError::Failed("a path is not UTF-8"))?;
    desktop_safe_path(text).map_err(|reason| IntegrationError::UnsafePath { what, reason })?;
    Ok(text)
}

// ---- field checks (the same rules as the update-config reader; this adapter does not trust its caller) ----

fn text_ok(text: &str, min: usize, max: usize) -> bool {
    let count = text.chars().count();
    if count < min || count > max {
        return false;
    }
    if text
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\\'))
    {
        return false;
    }
    let edge = |c: Option<char>| c.is_some_and(char::is_whitespace);
    !(edge(text.chars().next()) || edge(text.chars().next_back()))
}

fn bin_ok(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !text.starts_with(['-', '.'])
}

fn category_ok(text: &str) -> bool {
    (1..=64).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn check_fields(meta: &InstallMeta) -> Result<(), IntegrationError> {
    if !text_ok(&meta.name, 1, 128) {
        return Err(IntegrationError::UnsafeField("name"));
    }
    if meta.comment.as_deref().is_some_and(|c| !text_ok(c, 0, 512)) {
        return Err(IntegrationError::UnsafeField("comment"));
    }
    let mut seen = std::collections::BTreeSet::new();
    if meta.categories.len() > 16
        || meta
            .categories
            .iter()
            .any(|c| !category_ok(c) || !seen.insert(c.as_str()))
    {
        return Err(IntegrationError::UnsafeField("categories"));
    }
    if meta.bin.as_deref().is_some_and(|b| !bin_ok(b)) {
        return Err(IntegrationError::UnsafeField("bin"));
    }
    let mut exts = std::collections::BTreeSet::new();
    if meta.file_types.len() > 32
        || meta.file_types.iter().any(|t| {
            !ext_ok(&t.ext)
                || !mime_ok(&t.mime)
                || !text_ok(&t.name, 1, 128)
                || !exts.insert(t.ext.as_str())
        })
    {
        return Err(IntegrationError::UnsafeField("file_types"));
    }
    let mut schemes = std::collections::BTreeSet::new();
    if meta.url_schemes.len() > 8
        || meta
            .url_schemes
            .iter()
            .any(|s| !scheme_ok(s) || !schemes.insert(s.as_str()))
    {
        return Err(IntegrationError::UnsafeField("url_schemes"));
    }
    Ok(())
}

fn ext_ok(text: &str) -> bool {
    (1..=16).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// `type/subtype`, each side `[A-Za-z0-9!#$&^_.+-]{1,127}`: no `;`, so a value cannot add an item
/// to the `MimeType=` list.
fn mime_ok(text: &str) -> bool {
    let side = |s: &str| {
        (1..=127).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
    };
    text.split_once('/')
        .is_some_and(|(kind, sub)| side(kind) && side(sub))
}

fn scheme_ok(text: &str) -> bool {
    (1..=32).contains(&text.len())
        && text.as_bytes()[0].is_ascii_lowercase()
        && text.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'.' | b'-')
        })
        && !is_denied_url_scheme(text)
}

// ---- the entry ----

/// The entry's bytes (Desktop Entry Specification 1.5), exactly as in the step contract. Every
/// value here has been checked by the caller, so none is escaped.
///
/// The menu entry (`autostart` false) carries `MimeType=` when the app declares file types or URL
/// schemes, and then `%U` after the command so the file manager or browser can pass what it opens;
/// the autostart entry never does (nothing is passed at sign-in).
fn entry_bytes(
    app_id: &str,
    meta: &InstallMeta,
    exec: &str,
    icon: Option<&str>,
    autostart: bool,
) -> String {
    let mimes = if autostart {
        Vec::new()
    } else {
        mime_list(meta)
    };
    let mut out = String::from("[Desktop Entry]\nType=Application\nVersion=1.5\n");
    out.push_str(&format!("Name={}\n", meta.name));
    if let Some(comment) = &meta.comment {
        out.push_str(&format!("Comment={comment}\n"));
    }
    let args = if mimes.is_empty() { "" } else { " %U" };
    out.push_str(&format!("Exec=\"{exec}\"{args}\n"));
    if let Some(icon) = icon {
        out.push_str(&format!("Icon={icon}\n"));
    }
    out.push_str(&format!("Terminal={}\n", meta.terminal));
    if !meta.categories.is_empty() {
        out.push_str("Categories=");
        for c in &meta.categories {
            out.push_str(c);
            out.push(';');
        }
        out.push('\n');
    }
    if !mimes.is_empty() {
        out.push_str("MimeType=");
        for m in &mimes {
            out.push_str(m);
            out.push(';');
        }
        out.push('\n');
    }
    out.push_str(&format!("{MARKER_KEY}{app_id}\n"));
    out
}

/// The `MimeType=` items: each file type's mime (once, in declaration order), then
/// `x-scheme-handler/<scheme>` for each URL scheme. No default handler is claimed (M7-D3).
fn mime_list(meta: &InstallMeta) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in &meta.file_types {
        if !out.contains(&t.mime) {
            out.push(t.mime.clone());
        }
    }
    out.extend(
        meta.url_schemes
            .iter()
            .map(|s| format!("x-scheme-handler/{s}")),
    );
    out
}

// ---- inspection (lstat; nothing here follows a final symlink) ----

enum Slot {
    Absent,
    File,
    Symlink(PathBuf),
    Other,
}

fn probe(path: &Path) -> Result<Slot, IntegrationError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => fs::read_link(path)
            .map(Slot::Symlink)
            .map_err(|_| IntegrationError::Failed("a link cannot be read")),
        Ok(m) if m.file_type().is_file() => Ok(Slot::File),
        Ok(_) => Ok(Slot::Other),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Slot::Absent),
        Err(_) => Err(IntegrationError::Failed("an entry cannot be inspected")),
    }
}

/// A command link is ours when its target lies strictly under `<root>/current/` and holds no
/// `..` component. The entry may move between versions, so the exact target is not required.
fn is_ours(target: &Path, root: &Path) -> bool {
    let prefix = root.join("current");
    target.starts_with(&prefix)
        && target.components().count() > prefix.components().count()
        && !target
            .components()
            .any(|c| matches!(c, Component::ParentDir))
}

/// The first [`MARKER_READ_CAP`] bytes of a regular file, not following a final symlink.
fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(MARKER_READ_CAP).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Whether the file carries the line `X-Lunepack-App-Id=<app id>` in its first 64 KiB. A file
/// that cannot be read is not ours.
fn has_marker(path: &Path, app_id: &str) -> bool {
    let marker = format!("{MARKER_KEY}{app_id}");
    read_capped(path)
        .map(|bytes| {
            bytes
                .split(|&b| b == b'\n')
                .any(|line| line == marker.as_bytes())
        })
        .unwrap_or(false)
}

// ---- writing ----

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_name(name: &str) -> String {
    format!(
        ".{name}.lunepack-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn file_name(path: &Path) -> Result<&str, IntegrationError> {
    path.file_name()
        .and_then(|n| n.to_str())
        .ok_or(IntegrationError::Failed("a path has no file name"))
}

/// Creates `dir` and its missing parents, then checks that the result is canonical: no symlink
/// component, so nothing below it can lead outside.
fn ensure_dir(dir: &Path) -> Result<(), IntegrationError> {
    fs::create_dir_all(dir)
        .map_err(|_| IntegrationError::Failed("a directory cannot be created"))?;
    match fs::canonicalize(dir) {
        Ok(real) if real == dir => Ok(()),
        _ => Err(IntegrationError::Failed("a directory is not canonical")),
    }
}

/// Writes `bytes` to `<dir>/<name>` through a synced temp file and a rename in the same
/// directory, then syncs the directory.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), IntegrationError> {
    let tmp = dir.join(temp_name(name));
    let written = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, dir.join(name))
    })();
    match written {
        Ok(()) => {
            sync_dir(dir);
            Ok(())
        }
        Err(_) => {
            let _ = fs::remove_file(&tmp);
            Err(IntegrationError::Failed(
                "the desktop entry cannot be written",
            ))
        }
    }
}

/// Atomically makes `link` a symlink to `target`: a temp link in the same directory, renamed
/// over. The caller has checked that `link` is absent or ours.
fn replace_symlink(target: &str, link: &Path) -> Result<(), IntegrationError> {
    let dir = link
        .parent()
        .ok_or(IntegrationError::Failed("a path has no directory"))?;
    let tmp = dir.join(temp_name(file_name(link)?));
    let made = symlink(target, &tmp).and_then(|()| fs::rename(&tmp, link));
    match made {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = fs::remove_file(&tmp);
            Err(IntegrationError::Failed(
                "the command link cannot be written",
            ))
        }
    }
}

/// Best effort: a directory that cannot be synced does not fail the operation.
fn sync_dir(dir: &Path) {
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
}
