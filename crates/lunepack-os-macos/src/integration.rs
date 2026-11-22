//! [`MacIntegration`]: the start-at-sign-in entry of a per-user macOS install (M8-D12 (a)).
//!
//! An app that declares `autostart = true` gets one LaunchAgent property list,
//! `~/Library/LaunchAgents/<app id>.lunepack.plist`, whose `Label` is `<app id>.lunepack` and
//! whose `ProgramArguments` is `[<B>/<install.entry>]`: `B` is the live bundle, which the request
//! carries as [`IntegrationRequest::install_root`] on macOS (the bundle lives outside the data
//! home `R`, and the adopt and install orders write this entry before `R/bundle` exists), and the
//! entry is the request's, never read back from an existing file. `RunAtLoad` is set and
//! `LimitLoadToSessionType` is `Aqua`. The entry is never loaded: nothing here starts, bootstraps
//! or queries the system's job manager, so it takes effect at the next sign-in.
//!
//! Nothing else is created. `file_types` and `url_schemes` produce no item: macOS reads them from
//! the app's own `Info.plist`. The desktop-entry and command-link items have no macOS meaning.
//!
//! Rules, in order of importance:
//!
//! - **Only what lunepack made is replaced or removed.** A file is ours when it is a regular file
//!   (a symlink is not followed) whose `Label` is this app's. Anything else at the entry's path is
//!   a `Conflict` on `check` and `apply`, and is left (and reported) by `remove`.
//! - **Deterministic bytes, nothing unescaped.** Strings go into the property list XML-escaped;
//!   a path or name with a control character, a relative or non-canonical bundle path, or a path
//!   that is not UTF-8 is refused (`UnsafeField`) before anything is written. The display name is
//!   kept in an `X-Lunepack-App-Name` key (the system ignores keys it does not know).
//! - **Written atomically**: a synced temporary file in the same directory (mode 0644) is renamed
//!   over the entry.
//!
//! Errors never show a path or a value from the metadata.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use lunepack_core::{
    IntegrationError, IntegrationItem, IntegrationReport, IntegrationRequest, OsIntegration, Scope,
};

/// The most bytes of an existing entry that are read to look for the label.
const READ_CAP: u64 = 64 * 1024;

/// What the label of an app's entry is: `<app id>.lunepack`.
fn label_of(app_id: &str) -> String {
    format!("{app_id}.lunepack")
}

/// The environment the layout depends on, passed in so tests need not touch the process's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacEnv {
    /// `HOME`.
    pub home: Option<OsString>,
}

impl MacEnv {
    /// The process's own `HOME`.
    pub fn from_process() -> MacEnv {
        MacEnv {
            home: std::env::var_os("HOME"),
        }
    }
}

/// The macOS [`OsIntegration`]: the LaunchAgent entry for autostart. Per-machine scope is
/// `Unsupported`.
#[derive(Debug, Clone)]
pub struct MacIntegration {
    env: MacEnv,
}

impl MacIntegration {
    /// An integration that reads `HOME` from `env` on every call.
    pub fn new(env: MacEnv) -> MacIntegration {
        MacIntegration { env }
    }

    /// An integration over the process's own environment.
    pub fn from_process_env() -> MacIntegration {
        MacIntegration::new(MacEnv::from_process())
    }
}

/// What a request resolves to, after every check that writes nothing.
struct Prepared {
    /// `<home>/Library/LaunchAgents`.
    dir: PathBuf,
    /// The entry's file name.
    file: String,
    /// The entry's path.
    path: PathBuf,
    /// The entry's label.
    label: String,
    /// The entry's bytes, when the app declares autostart (else the entry is removed when ours).
    content: Option<String>,
}

impl OsIntegration for MacIntegration {
    fn check(&self, scope: Scope, req: &IntegrationRequest) -> Result<(), IntegrationError> {
        self.prepare(scope, req).map(|_| ())
    }

    fn apply(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        apply_prepared(self.prepare(scope, req)?)
    }

    fn remove(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        if scope != Scope::User {
            return Err(IntegrationError::Unsupported);
        }
        let dir = launch_agents(&self.env)?;
        remove_in(&dir, &label_of(req.app_id.as_str()))
    }
}

/// Removes the entry `<label>.plist` in `dir` when it is ours.
fn remove_in(dir: &Path, label: &str) -> Result<IntegrationReport, IntegrationError> {
    let path = dir.join(format!("{label}.plist"));
    let mut report = IntegrationReport::default();
    remove_entry(&path, label, &mut report)?;
    sync_dir(dir);
    Ok(report)
}

/// `apply` over what a `prepare` resolved.
fn apply_prepared(p: Prepared) -> Result<IntegrationReport, IntegrationError> {
    let mut report = IntegrationReport::default();
    match &p.content {
        Some(content) => {
            ensure_dir(&p.dir)?;
            let unchanged = match probe(&p.path)? {
                Slot::File => read_capped(&p.path).is_ok_and(|b| b == content.as_bytes()),
                _ => false,
            };
            if !unchanged {
                write_atomic(&p.dir, &p.file, content.as_bytes())?;
            }
        }
        None => remove_entry(&p.path, &p.label, &mut report)?,
    }
    Ok(report)
}

impl MacIntegration {
    /// Every check that writes nothing: scope, environment, paths, fields, conflicts.
    fn prepare(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<Prepared, IntegrationError> {
        if scope != Scope::User {
            return Err(IntegrationError::Unsupported);
        }
        let dir = launch_agents(&self.env)?;
        let bundle = check_bundle(&req.install_root)?;
        let exec = bundle.join(req.meta.entry.as_str());
        let exec = plain_text(&exec, "executable path")?;
        let name = text_ok(&req.meta.name, "name")?;
        let label = label_of(req.app_id.as_str());
        let file = format!("{label}.plist");
        let path = dir.join(&file);

        let content = if req.meta.autostart {
            match probe(&path)? {
                Slot::Absent => {}
                Slot::File if is_ours(&path, &label) => {}
                _ => return Err(IntegrationError::Conflict(IntegrationItem::Autostart)),
            }
            Some(plist_bytes(&label, exec, name))
        } else {
            None
        };
        Ok(Prepared {
            dir,
            file,
            path,
            label,
            content,
        })
    }
}

/// `<home>/Library/LaunchAgents` for the environment's `HOME`, which must be set, absolute, UTF-8
/// and an existing directory (else [`IntegrationError::Home`]); canonicalised. The directory
/// itself need not exist.
fn launch_agents(env: &MacEnv) -> Result<PathBuf, IntegrationError> {
    let raw = env.home.as_ref().ok_or(IntegrationError::Home)?;
    let raw = raw.to_str().ok_or(IntegrationError::Home)?;
    if raw.is_empty() || !Path::new(raw).is_absolute() {
        return Err(IntegrationError::Home);
    }
    let home = fs::canonicalize(raw).map_err(|_| IntegrationError::Home)?;
    if !home.is_dir() {
        return Err(IntegrationError::Home);
    }
    plain_text(&home, "home")?;
    Ok(home.join("Library").join("LaunchAgents"))
}

/// The bundle path from the request: absolute and made of plain names only (no `.`, `..`, empty
/// or trailing-slash segment, judged on the text because `Path` drops a `.` segment), as the core
/// hands it over canonical.
fn check_bundle(path: &Path) -> Result<PathBuf, IntegrationError> {
    let text = plain_text(path, "install_root")?;
    let plain = path.is_absolute()
        && text
            .split('/')
            .skip(1)
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..");
    if !plain {
        return Err(IntegrationError::UnsafeField("install_root"));
    }
    Ok(path.to_owned())
}

/// `path` as text that can go into the property list: UTF-8 without a control character.
fn plain_text<'a>(path: &'a Path, what: &'static str) -> Result<&'a str, IntegrationError> {
    path.to_str()
        .ok_or(IntegrationError::UnsafeField(what))
        .and_then(|s| text_ok(s, what))
}

fn text_ok<'a>(text: &'a str, what: &'static str) -> Result<&'a str, IntegrationError> {
    if text.is_empty() || text.chars().any(char::is_control) {
        Err(IntegrationError::UnsafeField(what))
    } else {
        Ok(text)
    }
}

/// XML text: the five markup characters escaped.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// The text [`escape`] wrote back: exactly the five entities it writes are read, and any other
/// `&` is `None` (not a text this crate wrote).
pub(crate) fn unescape(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let (entity, c) = [
            ("&amp;", '&'),
            ("&lt;", '<'),
            ("&gt;", '>'),
            ("&quot;", '"'),
            ("&apos;", '\''),
        ]
        .into_iter()
        .find(|(e, _)| rest.starts_with(e))?;
        out.push(c);
        rest = &rest[entity.len()..];
    }
    out.push_str(rest);
    Some(out)
}

/// The entry's bytes: fixed layout, tabs for indentation, one trailing newline.
fn plist_bytes(label: &str, exec: &str, name: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{label}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>{exec}</string>\n\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>LimitLoadToSessionType</key>\n\
         \t<string>Aqua</string>\n\
         \t<key>X-Lunepack-App-Name</key>\n\
         \t<string>{name}</string>\n\
         </dict>\n\
         </plist>\n",
        label = escape(label),
        exec = escape(exec),
        name = escape(name),
    )
}

// ---- the per-machine autostart (M11-D12) ----------------------------------------------------

/// The macOS per-machine [`OsIntegration`] (M11-D12), run as root by the engine: the start-at-
/// sign-in entry for every user, `/Library/LaunchAgents/lunepack-<app id>.autostart.plist`
/// (label `lunepack-<app id>.autostart`, mode 0644, the per-user entry's bytes), whose program is
/// `<B>/<install.entry>` with `B` the live bundle `R/bundle` names (the request's install root is
/// the machine tree `R`). No shortcut: the bundle in the apps folder is the entry. Only an entry
/// with this label is replaced or removed. Per-user scope is `Unsupported`.
#[derive(Debug, Clone)]
pub struct MacMachineIntegration {
    dir: PathBuf,
}

impl Default for MacMachineIntegration {
    fn default() -> Self {
        MacMachineIntegration::new()
    }
}

impl MacMachineIntegration {
    /// The system's `/Library/LaunchAgents`.
    pub fn new() -> MacMachineIntegration {
        MacMachineIntegration::under(Path::new("/"))
    }

    /// `<prefix>/Library/LaunchAgents` (tests use a scratch directory; `/` is the system).
    pub fn under(prefix: &Path) -> MacMachineIntegration {
        MacMachineIntegration {
            dir: prefix.join("Library").join("LaunchAgents"),
        }
    }

    /// The machine label of `app_id`'s entry.
    pub fn label(app_id: &str) -> String {
        format!("lunepack-{app_id}.autostart")
    }

    fn prepare(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<Prepared, IntegrationError> {
        if scope != Scope::Machine {
            return Err(IntegrationError::Unsupported);
        }
        let root = check_bundle(&req.install_root)?;
        let label = MacMachineIntegration::label(req.app_id.as_str());
        let file = format!("{label}.plist");
        let path = self.dir.join(&file);
        let name = text_ok(&req.meta.name, "name")?;
        let content = if req.meta.autostart {
            // `R/bundle` is an absolute link to the live bundle (FORMAT 17); read, never followed.
            let bundle = fs::read_link(root.join(lunepack_core::layout::BUNDLE_LINK))
                .map_err(|_| IntegrationError::Failed("the bundle pointer cannot be read"))?;
            let bundle = check_bundle(&bundle)?;
            let exec = bundle.join(req.meta.entry.as_str());
            let exec = plain_text(&exec, "executable path")?;
            match probe(&path)? {
                Slot::Absent => {}
                Slot::File if is_ours(&path, &label) => {}
                _ => return Err(IntegrationError::Conflict(IntegrationItem::Autostart)),
            }
            Some(plist_bytes(&label, exec, name))
        } else {
            None
        };
        Ok(Prepared {
            dir: self.dir.clone(),
            file,
            path,
            label,
            content,
        })
    }
}

impl OsIntegration for MacMachineIntegration {
    fn check(&self, scope: Scope, req: &IntegrationRequest) -> Result<(), IntegrationError> {
        self.prepare(scope, req).map(|_| ())
    }

    fn apply(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        apply_prepared(self.prepare(scope, req)?)
    }

    fn remove(
        &self,
        scope: Scope,
        req: &IntegrationRequest,
    ) -> Result<IntegrationReport, IntegrationError> {
        if scope != Scope::Machine {
            return Err(IntegrationError::Unsupported);
        }
        remove_in(
            &self.dir,
            &MacMachineIntegration::label(req.app_id.as_str()),
        )
    }
}

// ---- what is at a path ----

enum Slot {
    Absent,
    File,
    /// A symlink, a directory or anything else.
    Other,
}

fn probe(path: &Path) -> Result<Slot, IntegrationError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => Ok(Slot::File),
        Ok(_) => Ok(Slot::Other),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(Slot::Absent),
        Err(_) => Err(IntegrationError::Failed("an entry cannot be inspected")),
    }
}

/// The first [`READ_CAP`] bytes of a regular file, not following a final symlink.
fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(READ_CAP).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Whether the file's `Label` is `label`: the key `Label` followed by a `<string>` holding exactly
/// that text. A file that cannot be read is not ours.
fn is_ours(path: &Path, label: &str) -> bool {
    const KEY: &[u8] = b"<key>Label</key>";
    let Ok(bytes) = read_capped(path) else {
        return false;
    };
    let wanted = format!("<string>{}</string>", escape(label));
    let mut from = 0;
    while let Some(at) = find(&bytes[from..], KEY) {
        let rest = &bytes[from + at + KEY.len()..];
        let skip = rest.iter().take_while(|b| b.is_ascii_whitespace()).count();
        if rest[skip..].starts_with(wanted.as_bytes()) {
            return true;
        }
        from += at + KEY.len();
    }
    false
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Removes the entry when it is ours; reports a foreign one as kept; an absent one is fine.
fn remove_entry(
    path: &Path,
    label: &str,
    report: &mut IntegrationReport,
) -> Result<(), IntegrationError> {
    match probe(path)? {
        Slot::Absent => {}
        Slot::File if is_ours(path, label) => {
            fs::remove_file(path)
                .map_err(|_| IntegrationError::Failed("the autostart entry was not removed"))?;
        }
        _ => report.kept.push(IntegrationItem::Autostart),
    }
    Ok(())
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

/// Creates the directory when it is missing and requires it to be canonical (no symlink in its
/// path), so the temporary file and the rename land where the entry goes.
fn ensure_dir(dir: &Path) -> Result<(), IntegrationError> {
    fs::create_dir_all(dir)
        .map_err(|_| IntegrationError::Failed("a directory cannot be created"))?;
    match fs::canonicalize(dir) {
        Ok(real) if real == dir => Ok(()),
        _ => Err(IntegrationError::Failed("a directory is not canonical")),
    }
}

/// Writes `bytes` to `<dir>/<name>` through a synced temporary file (mode 0644) and a rename in
/// the same directory, then syncs the directory.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), IntegrationError> {
    let tmp = dir.join(temp_name(name));
    let written = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)?;
        // The creation mode went through the umask; the entry is 0644 whatever it is.
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
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
                "the autostart entry cannot be written",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_covers_the_five_markup_characters() {
        assert_eq!(escape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(escape("plain/Path 1.app"), "plain/Path 1.app");
    }

    #[test]
    fn the_label_is_the_app_id_and_a_suffix() {
        assert_eq!(label_of("acme.tool"), "acme.tool.lunepack");
    }
}
