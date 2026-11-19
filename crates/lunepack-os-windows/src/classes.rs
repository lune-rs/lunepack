//! The registry declarations of an app (M7-D3), all under `HKCU\Software\Classes` and the per-user
//! `Run` key, none of them a default handler:
//!
//! - a file type is an "Open with" candidate: the ProgID key `<app id>.<ext>` (`FriendlyTypeName`,
//!   `DefaultIcon`, `shell\open\command`, the marker) and the value `<app id>.<ext>` (empty) in
//!   `.<ext>\OpenWithProgids`. The `.<ext>` key's own default value and `UserChoice` are never
//!   read or written;
//! - a URL scheme is the key `<scheme>` (`URL Protocol`, `DefaultIcon`, `shell\open\command`, the
//!   marker);
//! - autostart is the `Run` value `<app id>`.
//!
//! The merged `HKEY_CLASSES_ROOT` view lets a per-user key shadow a per-machine one, so a ProgID or
//! scheme key that another program registered per machine (`HKLM\Software\Classes`, read only
//! here) and that this app would create under `HKCU` is a `Conflict` too, unless it is marked as
//! this app's. An existing `.<ext>` key needs no such check: only a value in its `OpenWithProgids`
//! is added, and its default value (the handler) stays visible through the merge.
//!
//! A key is lunepack's when it holds `LunepackAppId` = the app id; a `Run` value is lunepack's when
//! its data is exactly one of the commands lunepack writes. Anything else is a `Conflict` for
//! `check` and `apply`, and is left (and reported) by `remove`. Errors never show a value.

use lunepack_core::{IntegrationError, IntegrationItem, IntegrationReport};

use crate::integration::MARKER_VALUE;
use crate::registry::{self, Hive, Key, Value};

const READ_FAILED: IntegrationError =
    IntegrationError::Failed("a registry declaration could not be read");
const WRITE_FAILED: IntegrationError =
    IntegrationError::Failed("a registry declaration was not written");

/// One declared file type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileTypeDecl {
    /// The extension without its dot.
    pub ext: String,
    /// The ProgID, `<app id>.<ext>`.
    pub progid: String,
    /// The display name.
    pub name: String,
}

/// What an app declares, and what its previous version declared that this one no longer does.
#[derive(Debug, Clone, Default)]
pub(crate) struct Decls {
    pub file_types: Vec<FileTypeDecl>,
    pub schemes: Vec<String>,
    pub autostart: bool,
    pub stale_file_types: Vec<FileTypeDecl>,
    pub stale_schemes: Vec<String>,
}

/// Where and as whom the declarations are written.
#[derive(Clone, Copy)]
pub(crate) struct Ctx<'a> {
    pub hive: Hive,
    /// The key path of `Software\Classes`.
    pub classes: &'a str,
    /// The per-machine classes root another program may have registered a scheme or ProgID in,
    /// read only: its hive and `Software\Classes` path.
    pub machine: Option<(Hive, &'a str)>,
    /// The key path of `...\CurrentVersion\Run`.
    pub run: &'a str,
    pub app_id: &'a str,
    /// The display name (`FriendlyTypeName`, the scheme's description).
    pub name: &'a str,
    /// `R\<stub>`, plain.
    pub stub: &'a str,
    /// Every `Run` value data that is lunepack's (the command for the current stub name and for
    /// an earlier one).
    pub run_ours: &'a [String],
}

impl Ctx<'_> {
    fn icon(&self) -> String {
        format!("{},0", self.stub)
    }

    fn open_command(&self) -> String {
        format!("\"{}\" \"%1\"", self.stub)
    }

    /// The `Run` value's data for the current stub.
    pub(crate) fn run_command(&self) -> String {
        format!("\"{}\"", self.stub)
    }

    fn class_key(&self, name: &str) -> String {
        format!(r"{}\{name}", self.classes)
    }

    fn openwith_key(&self, ext: &str) -> String {
        format!(r"{}\.{ext}\OpenWithProgids", self.classes)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    Absent,
    Ours,
    Foreign,
}

fn state(ctx: &Ctx<'_>, path: &str) -> Result<State, IntegrationError> {
    Ok(
        match Key::open(ctx.hive, path, false).map_err(|_| READ_FAILED)? {
            None => State::Absent,
            Some(key) => {
                if key.get(MARKER_VALUE).map_err(|_| READ_FAILED)?
                    == Some(Value::Str(ctx.app_id.to_owned()))
                {
                    State::Ours
                } else {
                    State::Foreign
                }
            }
        },
    )
}

/// The state of the class key `name` as the user would see it through the merged view: this
/// user's own key, else (when there is none) the per-machine one. A key of the machine's that
/// carries this app's marker is not foreign (M10's per-machine scope).
fn merged_state(ctx: &Ctx<'_>, name: &str) -> Result<State, IntegrationError> {
    let user = state(ctx, &ctx.class_key(name))?;
    if user != State::Absent {
        return Ok(user);
    }
    let Some((hive, classes)) = ctx.machine else {
        return Ok(State::Absent);
    };
    let machine = Ctx { hive, ..*ctx };
    Ok(match state(&machine, &format!(r"{classes}\{name}"))? {
        State::Foreign => State::Foreign,
        State::Absent | State::Ours => State::Absent,
    })
}

/// Whether the `Run` value is there and not lunepack's.
fn run_foreign(ctx: &Ctx<'_>) -> Result<bool, IntegrationError> {
    let Some(key) = Key::open(ctx.hive, ctx.run, false).map_err(|_| READ_FAILED)? else {
        return Ok(false);
    };
    Ok(match key.get(ctx.app_id).map_err(|_| READ_FAILED)? {
        None => false,
        Some(Value::Str(data)) => !ctx.run_ours.contains(&data),
        Some(_) => true,
    })
}

/// What `apply` would refuse: a key or value of these kinds that is not lunepack's. Writes
/// nothing.
pub(crate) fn check(ctx: &Ctx<'_>, decls: &Decls) -> Result<(), IntegrationError> {
    for ft in &decls.file_types {
        if merged_state(ctx, &ft.progid)? == State::Foreign {
            return Err(IntegrationError::Conflict(IntegrationItem::FileType));
        }
    }
    for scheme in &decls.schemes {
        if merged_state(ctx, scheme)? == State::Foreign {
            return Err(IntegrationError::Conflict(IntegrationItem::UrlScheme));
        }
    }
    if decls.autostart && run_foreign(ctx)? {
        return Err(IntegrationError::Conflict(IntegrationItem::Autostart));
    }
    Ok(())
}

/// Creates or refreshes the declarations and removes what the previous version declared and this
/// one does not (each only when it is lunepack's, else reported in `report.kept`). Returns whether
/// an association key changed, so the caller tells the shell.
pub(crate) fn apply(
    ctx: &Ctx<'_>,
    decls: &Decls,
    report: &mut IntegrationReport,
) -> Result<bool, IntegrationError> {
    let mut changed = false;
    for ft in &decls.file_types {
        changed |= write_progid(ctx, ft)?;
    }
    for scheme in &decls.schemes {
        changed |= write_scheme(ctx, scheme)?;
    }
    for ft in &decls.stale_file_types {
        match remove_progid(ctx, ft)? {
            Removed::Nothing => {}
            Removed::Done => changed = true,
            Removed::Kept => report.kept.push(IntegrationItem::FileType),
        }
    }
    for scheme in &decls.stale_schemes {
        match remove_scheme(ctx, scheme)? {
            Removed::Nothing => {}
            Removed::Done => changed = true,
            Removed::Kept => report.kept.push(IntegrationItem::UrlScheme),
        }
    }
    if decls.autostart {
        write_run(ctx)?;
    } else if remove_run(ctx)? == Removed::Kept {
        report.kept.push(IntegrationItem::Autostart);
    }
    Ok(changed)
}

/// Removes every declaration of `decls` that is lunepack's; the rest is left and reported.
pub(crate) fn remove(
    ctx: &Ctx<'_>,
    decls: &Decls,
    report: &mut IntegrationReport,
) -> Result<bool, IntegrationError> {
    let mut changed = false;
    for ft in decls.file_types.iter().chain(&decls.stale_file_types) {
        match remove_progid(ctx, ft)? {
            Removed::Nothing => {}
            Removed::Done => changed = true,
            Removed::Kept => report.kept.push(IntegrationItem::FileType),
        }
    }
    for scheme in decls.schemes.iter().chain(&decls.stale_schemes) {
        match remove_scheme(ctx, scheme)? {
            Removed::Nothing => {}
            Removed::Done => changed = true,
            Removed::Kept => report.kept.push(IntegrationItem::UrlScheme),
        }
    }
    if remove_run(ctx)? == Removed::Kept {
        report.kept.push(IntegrationItem::Autostart);
    }
    Ok(changed)
}

#[derive(Debug, PartialEq, Eq)]
enum Removed {
    /// There was nothing of ours.
    Nothing,
    /// Something of ours was removed.
    Done,
    /// Something was there that is not ours; it stays.
    Kept,
}

/// Creates `path` (and parents) when absent; returns the key and whether it was created.
fn open_or_create(ctx: &Ctx<'_>, path: &str) -> Result<(Key, bool), IntegrationError> {
    let existed = Key::open(ctx.hive, path, false)
        .map_err(|_| WRITE_FAILED)?
        .is_some();
    let key = Key::create(ctx.hive, path).map_err(|_| WRITE_FAILED)?;
    Ok((key, !existed))
}

fn ensure(key: &Key, name: &str, value: &str) -> Result<bool, IntegrationError> {
    key.ensure_str(name, value).map_err(|_| WRITE_FAILED)
}

/// The two subkeys every class has: `DefaultIcon` and `shell\open\command`.
fn write_class_body(ctx: &Ctx<'_>, class: &str) -> Result<bool, IntegrationError> {
    let mut changed = false;
    let (icon, made) = open_or_create(ctx, &format!(r"{class}\DefaultIcon"))?;
    changed |= made;
    changed |= ensure(&icon, "", &ctx.icon())?;
    let (command, made) = open_or_create(ctx, &format!(r"{class}\shell\open\command"))?;
    changed |= made;
    changed |= ensure(&command, "", &ctx.open_command())?;
    Ok(changed)
}

fn write_progid(ctx: &Ctx<'_>, ft: &FileTypeDecl) -> Result<bool, IntegrationError> {
    let class = ctx.class_key(&ft.progid);
    let (key, mut changed) = open_or_create(ctx, &class)?;
    // The marker first, so a key this run made is recognised as ours by a retry.
    changed |= ensure(&key, MARKER_VALUE, ctx.app_id)?;
    changed |= ensure(&key, "FriendlyTypeName", &ft.name)?;
    changed |= write_class_body(ctx, &class)?;
    let (open_with, made) = open_or_create(ctx, &ctx.openwith_key(&ft.ext))?;
    changed |= made;
    changed |= ensure(&open_with, &ft.progid, "")?;
    Ok(changed)
}

fn write_scheme(ctx: &Ctx<'_>, scheme: &str) -> Result<bool, IntegrationError> {
    let class = ctx.class_key(scheme);
    let (key, mut changed) = open_or_create(ctx, &class)?;
    changed |= ensure(&key, MARKER_VALUE, ctx.app_id)?;
    changed |= ensure(&key, "", &format!("URL:{}", ctx.name))?;
    changed |= ensure(&key, "URL Protocol", "")?;
    changed |= write_class_body(ctx, &class)?;
    Ok(changed)
}

fn write_run(ctx: &Ctx<'_>) -> Result<(), IntegrationError> {
    let (key, _) = open_or_create(ctx, ctx.run)?;
    ensure(&key, ctx.app_id, &ctx.run_command())?;
    Ok(())
}

fn remove_progid(ctx: &Ctx<'_>, ft: &FileTypeDecl) -> Result<Removed, IntegrationError> {
    let class = ctx.class_key(&ft.progid);
    match state(ctx, &class)? {
        State::Absent => Ok(Removed::Nothing),
        State::Foreign => Ok(Removed::Kept),
        State::Ours => {
            let open_with = ctx.openwith_key(&ft.ext);
            if let Some(key) = Key::open(ctx.hive, &open_with, true).map_err(|_| WRITE_FAILED)? {
                key.delete_value(&ft.progid).map_err(|_| WRITE_FAILED)?;
            }
            registry::delete_tree(ctx.hive, &class).map_err(|_| WRITE_FAILED)?;
            // The keys this made for the extension go when nothing else lives in them.
            registry::delete_if_empty(ctx.hive, &open_with).map_err(|_| WRITE_FAILED)?;
            registry::delete_if_empty(ctx.hive, &format!(r"{}\.{}", ctx.classes, ft.ext))
                .map_err(|_| WRITE_FAILED)?;
            Ok(Removed::Done)
        }
    }
}

fn remove_scheme(ctx: &Ctx<'_>, scheme: &str) -> Result<Removed, IntegrationError> {
    let class = ctx.class_key(scheme);
    match state(ctx, &class)? {
        State::Absent => Ok(Removed::Nothing),
        State::Foreign => Ok(Removed::Kept),
        State::Ours => {
            registry::delete_tree(ctx.hive, &class).map_err(|_| WRITE_FAILED)?;
            Ok(Removed::Done)
        }
    }
}

fn remove_run(ctx: &Ctx<'_>) -> Result<Removed, IntegrationError> {
    let Some(key) = Key::open(ctx.hive, ctx.run, true).map_err(|_| READ_FAILED)? else {
        return Ok(Removed::Nothing);
    };
    match key.get(ctx.app_id).map_err(|_| READ_FAILED)? {
        None => Ok(Removed::Nothing),
        Some(Value::Str(data)) if ctx.run_ours.contains(&data) => {
            key.delete_value(ctx.app_id).map_err(|_| WRITE_FAILED)?;
            Ok(Removed::Done)
        }
        Some(_) => Ok(Removed::Kept),
    }
}

/// Tells the shell that associations changed (`SHCNE_ASSOCCHANGED`), so Explorer re-reads them.
#[allow(unsafe_code)]
pub(crate) fn notify_associations_changed() {
    use windows_sys::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};
    // SAFETY: `SHCNE_ASSOCCHANGED` takes no item pointers; both are null, as the API documents for
    // this event.
    unsafe {
        SHChangeNotify(
            SHCNE_ASSOCCHANGED as i32,
            SHCNF_IDLIST,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn telling_the_shell_returns() {
        // The call has no result to read; it must come back (it does not wait for Explorer).
        super::notify_associations_changed();
    }
}
