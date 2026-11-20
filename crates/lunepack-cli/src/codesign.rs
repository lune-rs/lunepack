//! The OS sign stage of C2 stage 2 (M9 step 3): [`OsCodeSign`] runs the developer's argv templates
//! (`[codesign.<os>]`, M9-D1/M9-D2) over the items of a sign plan, inner to outer, through the
//! bounded runner ([`crate::tool`]), and checks after every call that the item really is in a
//! signed form. For a `macos-*` bundle it then verifies, notarizes (with a zip of the signed tree or
//! the bundle itself) and staples, and checks that the staple ticket (`Contents/CodeResources`) is
//! in the tree, so the hash stage that follows covers it (M9-D5).
//!
//! What this module may print: `code-sign: <relative path>` per item, and on failure the
//! template's key, the item's relative path and the runner's error text (the program's file name,
//! its status and the redacted tail of its standard error). Never an expanded argv, never an
//! environment variable's value.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use lunepack_core::codesign::PLAN_HEAD_BYTES;
use lunepack_core::{
    ArgvTemplate, CodeSign, Error, ExpandCtx, SignItem, SignKind, macho_slices_signed, pe_is_signed,
};

use crate::config::CodeSignSection;
use crate::pipeline::{Found, walk};
use crate::tool;
use crate::zip;

/// The staple ticket's place in a bundle (probe, M9-D5): a regular file stapler writes.
const TICKET: &str = "Contents/CodeResources";

/// Where a signed nested bundle keeps its `_CodeSignature` directory, by bundle layout: the flat
/// layout of an app or plug-in, a versioned framework (through `Versions/Current`, a symlink the
/// check follows) and the shallow layouts.
const SIGNATURE_DIRS: [&str; 5] = [
    "Contents/_CodeSignature",
    "Versions/Current/_CodeSignature",
    "Versions/Current/Resources/_CodeSignature",
    "Resources/_CodeSignature",
    "_CodeSignature",
];

/// A refused or failed sign stage. The text names paths and template keys, never an argv.
#[derive(Debug)]
struct StageError(String);

impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StageError {}

fn fail<T>(text: String) -> Result<T, StageError> {
    Err(StageError(text))
}

type EnvLookup = Box<dyn Fn(&str) -> Option<OsString> + Send + Sync>;

/// The OS code-signing hook (M9-D4, M9-D5), wired by `pack` when the target's OS has a
/// `[codesign.<os>]` section.
pub struct OsCodeSign {
    section: CodeSignSection,
    /// The bundle directory's name inside the notarization zip: `<bundle name>.app`.
    bundle_name: String,
    env: EnvLookup,
}

impl OsCodeSign {
    /// The hook for `section`; `bundle_name` is `<name>.app`, the directory name a notarization
    /// zip holds the tree under. `{env:}` values come from the process environment.
    pub fn new(section: CodeSignSection, bundle_name: String) -> OsCodeSign {
        OsCodeSign::with_env(
            section,
            bundle_name,
            Box::new(|name| std::env::var_os(name)),
        )
    }

    /// Like [`OsCodeSign::new`] with another source of `{env:}` values (tests).
    pub fn with_env(section: CodeSignSection, bundle_name: String, env: EnvLookup) -> OsCodeSign {
        OsCodeSign {
            section,
            bundle_name,
            env,
        }
    }

    /// The template of `key` for an item of `kind`.
    fn template_for(&self, kind: SignKind) -> (&'static str, &ArgvTemplate) {
        match kind {
            SignKind::PeFile | SignKind::MachOFile => ("sign", &self.section.sign),
            SignKind::NestedBundle => ("sign_bundle", &self.section.sign_bundle),
            SignKind::OuterBundle => ("sign_outer", &self.section.sign_outer),
        }
    }

    /// Every `{env:}` variable of the templates this run will use must be set and non-empty before
    /// any tool runs (M9-D1).
    fn check_env(&self, plan: &[SignItem]) -> Result<(), StageError> {
        let mut used: Vec<(&'static str, &ArgvTemplate)> = Vec::new();
        for item in plan {
            used.push(self.template_for(item.kind));
        }
        let outer = plan.iter().any(|i| i.kind == SignKind::OuterBundle);
        if !plan.is_empty()
            && let Some(t) = &self.section.verify
        {
            used.push(("verify", t));
        }
        if outer {
            for (key, t) in [
                ("notarize", &self.section.notarize),
                ("staple", &self.section.staple),
            ] {
                if let Some(t) = t {
                    used.push((key, t));
                }
            }
        }
        let mut seen = BTreeSet::new();
        for (key, template) in used {
            for name in template.env_names() {
                if !seen.insert((key, name)) {
                    continue;
                }
                if (self.env)(name).is_none_or(|v| v.is_empty()) {
                    return fail(format!(
                        "[codesign] {key}: the environment variable {name} is unset or empty"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Expands `template` for `path` and runs it. The error names the template's `key` and the
    /// item's `shown` path.
    fn run_template(
        &self,
        key: &str,
        shown: &str,
        template: &ArgvTemplate,
        ctx: &ExpandCtx<'_>,
        timeout: Duration,
    ) -> Result<(), StageError> {
        let expanded = template
            .expand(ctx, &|name| (self.env)(name))
            .map_err(|e| StageError(format!("code-sign: {shown}: {key}: {e}")))?;
        tool::run_tool(&expanded.argv, timeout, &expanded.redact)
            .map(drop)
            .map_err(|e| StageError(format!("code-sign: {shown}: {key} failed: {e}")))
    }

    fn run(&self, root: &Path, plan: &[SignItem]) -> Result<(), StageError> {
        let root = absolute(root)?;
        self.check_env(plan)?;
        let section = &self.section;
        for item in plan {
            let (key, template) = self.template_for(item.kind);
            let shown = if item.path.is_none() {
                self.bundle_name.as_str()
            } else {
                item.rel()
            };
            let at = match &item.path {
                Some(rel) => root.join(rel.as_str()),
                None => root.clone(),
            };
            say(&format!("code-sign: {shown}"));
            let ctx = ExpandCtx {
                path: &at,
                bundle: None,
                zip: None,
            };
            self.run_template(key, shown, template, &ctx, section.timeout)?;
            if !is_signed(&root, item, &at)
                .map_err(|e| StageError(format!("code-sign: cannot read {shown}: {e}")))?
            {
                return fail(format!("code-sign: {shown} is not signed after {key}"));
            }
            // A Windows signature is checked per file; a macOS bundle once, after `sign_outer`.
            if item.kind == SignKind::PeFile
                && let Some(verify) = &section.verify
            {
                self.run_template("verify", shown, verify, &ctx, section.timeout)?;
            }
            if item.kind == SignKind::OuterBundle {
                if let Some(verify) = &section.verify {
                    self.run_template("verify", shown, verify, &ctx, section.timeout)?;
                }
                self.notarize_and_staple(&root, &at)?;
            }
        }
        Ok(())
    }

    /// M9-D5: `notarize` (a zip of the signed tree, or the bundle), then `staple` on the bundle,
    /// then the ticket check. Nothing happens without a `notarize` template (the config refuses
    /// one without `staple`).
    fn notarize_and_staple(&self, root: &Path, bundle: &Path) -> Result<(), StageError> {
        let section = &self.section;
        let (Some(notarize), Some(staple)) = (&section.notarize, &section.staple) else {
            return Ok(());
        };
        let shown = self.bundle_name.as_str();
        say(&format!("code-sign: {shown}: notarize"));
        let zip_path = root.parent().map(|p| p.join("lunepack-notarize.zip"));
        let result = (|| {
            let zip = if notarize.uses_zip() {
                let at = zip_path
                    .clone()
                    .ok_or_else(|| StageError("code-sign: the work dir has no parent".into()))?;
                write_tree_zip(root, &self.bundle_name, &at)
                    .map_err(|e| StageError(format!("code-sign: cannot zip {shown}: {e:#}")))?;
                Some(at)
            } else {
                None
            };
            let ctx = ExpandCtx {
                path: bundle,
                bundle: Some(root),
                zip: zip.as_deref(),
            };
            self.run_template("notarize", shown, notarize, &ctx, section.notarize_timeout)
        })();
        // The zip is a copy of the tree: it never outlives the call, success or not.
        if let Some(at) = &zip_path {
            let _ = fs::remove_file(at);
        }
        result?;
        say(&format!("code-sign: {shown}: staple"));
        let ctx = ExpandCtx {
            path: bundle,
            bundle: Some(root),
            zip: None,
        };
        self.run_template("staple", shown, staple, &ctx, section.timeout)?;
        let ticket = root.join(TICKET);
        match fs::symlink_metadata(&ticket) {
            Ok(meta) if meta.file_type().is_file() => Ok(()),
            _ => fail(format!(
                "code-sign: {shown}: staple left no ticket ({TICKET} is not a regular file)"
            )),
        }
    }
}

impl CodeSign for OsCodeSign {
    fn sign_tree(&self, root: &Path, plan: &[SignItem]) -> Result<(), Error> {
        self.run(root, plan)
            .map_err(|e| Error::CodeSign(Box::new(e)))
    }
}

/// One progress line; a closed stdout is not a reason to stop signing.
fn say(line: &str) {
    let _ = writeln!(io::stdout().lock(), "{line}");
}

fn absolute(path: &Path) -> Result<PathBuf, StageError> {
    std::path::absolute(path)
        .map_err(|e| StageError(format!("code-sign: cannot resolve the work dir: {e}")))
}

/// Whether `item` (at `at`) is in a signed form (M9-D3): a PE with a certificate table, a Mach-O
/// whose every slice has a code signature, a bundle with its `_CodeSignature/CodeResources`.
fn is_signed(root: &Path, item: &SignItem, at: &Path) -> io::Result<bool> {
    match item.kind {
        SignKind::PeFile => {
            let file = File::open(at)?;
            let len = file.metadata()?.len();
            let mut head = Vec::new();
            file.take(PLAN_HEAD_BYTES as u64).read_to_end(&mut head)?;
            Ok(pe_is_signed(&head, len))
        }
        SignKind::MachOFile => Ok(macho_slices_signed(&fs::read(at)?)),
        SignKind::NestedBundle => Ok(SIGNATURE_DIRS
            .iter()
            .any(|dir| is_regular(&at.join(dir).join("CodeResources")))),
        SignKind::OuterBundle => Ok(is_regular(
            &root.join("Contents/_CodeSignature/CodeResources"),
        )),
    }
}

/// A regular file, symlinks followed (a framework's `Versions/Current` is one).
fn is_regular(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file())
}

/// Writes the tree at `root` to the new file `out` as a zip holding it under `bundle_name`
/// (M9-D5): what `notarytool submit` takes. Entries are the tree's own, in path order; links stay
/// links; exec bits are kept.
pub fn write_tree_zip(root: &Path, bundle_name: &str, out: &Path) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .with_context(|| format!("cannot create {}", out.display()))?;
    let mut writer = zip::Writer::new(io::BufWriter::new(file));
    writer.add(bundle_name, zip::Kind::Dir)?;
    for (path, full, kind, meta) in walk(root)? {
        let name = format!("{bundle_name}/{}", path.as_str());
        match kind {
            Found::Dir => writer.add(&name, zip::Kind::Dir)?,
            Found::Symlink => {
                let target = fs::read_link(&full)
                    .with_context(|| format!("cannot read {}", full.display()))?;
                let target = target
                    .to_str()
                    .with_context(|| format!("the target of {} is not UTF-8", full.display()))?;
                writer.add(&name, zip::Kind::Symlink { target })?;
            }
            Found::File => {
                let data =
                    fs::read(&full).with_context(|| format!("cannot read {}", full.display()))?;
                writer.add(
                    &name,
                    zip::Kind::File {
                        data: &data,
                        exec: is_exec(&meta),
                    },
                )?;
            }
        }
    }
    writer.finish()?.flush().context("cannot write the zip")?;
    Ok(())
}

#[cfg(unix)]
fn is_exec(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_exec(_meta: &fs::Metadata) -> bool {
    false
}
