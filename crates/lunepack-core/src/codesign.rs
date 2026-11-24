//! OS code signing, the pure part (M9): the argv templates a developer's signing tools are run
//! through (M9-D1), the sign plan of a release tree (M9-D4) and the checks that a file really holds
//! an OS signature after a tool ran (M9-D3).
//!
//! Nothing here runs a process or touches the file system: the packager reads the tree into
//! [`PlanEntry`] values, asks [`sign_plan`] what to sign in which order, expands each item's
//! [`ArgvTemplate`] and runs the result itself.
//!
//! Errors name an element index, a placeholder or an environment variable's *name*; no error ever
//! carries a template's literal text or an expanded value.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::Path;

use crate::error::PublisherError;
use crate::path::RelPath;
use crate::pe::{PeError, PeHeaders};
use crate::target::Target;
use crate::update_config::PublisherPolicy;

// ---- argv templates (M9-D1) ------------------------------------------------------------------------

/// What a template is for. Only a [`TemplateRole::Notarize`] template may name `{bundle}` or
/// `{zip}`; every role may name `{path}` and `{env:NAME}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateRole {
    /// Signs one item (`sign`, `sign_bundle`, `sign_outer`, `sign_installer`).
    Sign,
    /// Verifies a signed object (`verify`).
    Verify,
    /// Submits a bundle or disk image for notarization (`notarize`).
    Notarize,
    /// Staples the notarization ticket (`staple`).
    Staple,
}

/// Why a template was refused at load or could not be expanded. Never carries a template's text or
/// an expanded value; an environment variable's name is shown (it passed the name rule).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TemplateError {
    /// The template has no element.
    #[error("the template is empty")]
    Empty,
    /// An element is the empty string.
    #[error("element {index} is empty")]
    EmptyElement {
        /// Zero-based element index.
        index: usize,
    },
    /// A `{` or `}` that is not part of a placeholder filling the whole element.
    #[error("element {index} has a brace outside a whole-element placeholder")]
    Brace {
        /// Zero-based element index.
        index: usize,
    },
    /// `{...}` naming no placeholder this grammar defines.
    #[error("element {index} is an unknown placeholder")]
    UnknownPlaceholder {
        /// Zero-based element index.
        index: usize,
    },
    /// `{env:NAME}` whose name does not match `[A-Z_][A-Z0-9_]*`.
    #[error("element {index} names an environment variable outside [A-Z_][A-Z0-9_]*")]
    EnvName {
        /// Zero-based element index.
        index: usize,
    },
    /// `{path}`, `{bundle}` or `{zip}` as the program (element 0).
    #[error("element {index} is a path placeholder in the program position")]
    PathAsProgram {
        /// Zero-based element index (always 0).
        index: usize,
    },
    /// `{bundle}` or `{zip}` in a template that is not a notarize template.
    #[error("element {index} is {placeholder}, which only a notarize template takes")]
    NotInRole {
        /// Zero-based element index.
        index: usize,
        /// The placeholder.
        placeholder: &'static str,
    },
    /// `{env:NAME}` whose variable is unset or empty at expansion.
    #[error("environment variable {name} is unset or empty")]
    EnvUnset {
        /// The variable's name.
        name: String,
    },
    /// The caller gave no value for a placeholder the template names.
    #[error("element {index}: no value for {placeholder}")]
    NoValue {
        /// Zero-based element index.
        index: usize,
        /// The placeholder.
        placeholder: &'static str,
    },
    /// A path placeholder's value is not absolute (it could then be read as an option).
    #[error("element {index}: the value of {placeholder} is not an absolute path")]
    NotAbsolute {
        /// Zero-based element index.
        index: usize,
        /// The placeholder.
        placeholder: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Element {
    Literal(String),
    Path,
    Bundle,
    Zip,
    Env(String),
}

/// A parsed argv template (M9-D1): a non-empty list of elements, each either literal text with no
/// brace at all or exactly one placeholder filling the whole element: `{path}`, `{bundle}` and
/// `{zip}` (notarize only), `{env:NAME}`. A path placeholder is never the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgvTemplate {
    role: TemplateRole,
    elements: Vec<Element>,
}

/// The values of the path placeholders for one expansion. Every given path must be absolute.
#[derive(Debug, Clone, Copy)]
pub struct ExpandCtx<'a> {
    /// `{path}`: the item being processed.
    pub path: &'a Path,
    /// `{bundle}`: the bundle directory (notarize).
    pub bundle: Option<&'a Path>,
    /// `{zip}`: a zip of the bundle (notarize).
    pub zip: Option<&'a Path>,
}

/// An expanded template: the argv to run, and the environment values it holds, by variable name,
/// so the caller can replace each in any tool output it shows (M9-D3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expanded {
    /// The program and its arguments.
    pub argv: Vec<OsString>,
    /// Every `{env:NAME}` value put into `argv`, once per name, in name order.
    pub redact: Vec<(String, OsString)>,
}

impl ArgvTemplate {
    /// Parses `elements` as a template for `role` (M9-D1). Every refusal names the element index.
    pub fn parse<S: AsRef<str>>(
        role: TemplateRole,
        elements: &[S],
    ) -> Result<ArgvTemplate, TemplateError> {
        if elements.is_empty() {
            return Err(TemplateError::Empty);
        }
        let mut out = Vec::with_capacity(elements.len());
        for (index, text) in elements.iter().enumerate() {
            let element = parse_element(text.as_ref(), index)?;
            match element {
                Element::Bundle | Element::Zip if role != TemplateRole::Notarize => {
                    let placeholder = if element == Element::Bundle {
                        "{bundle}"
                    } else {
                        "{zip}"
                    };
                    return Err(TemplateError::NotInRole { index, placeholder });
                }
                Element::Path | Element::Bundle | Element::Zip if index == 0 => {
                    return Err(TemplateError::PathAsProgram { index });
                }
                _ => {}
            }
            out.push(element);
        }
        Ok(ArgvTemplate {
            role,
            elements: out,
        })
    }

    /// The role the template was parsed for.
    pub fn role(&self) -> TemplateRole {
        self.role
    }

    /// Whether the template names `{zip}` (the packager writes the zip only for a template that
    /// does).
    pub fn uses_zip(&self) -> bool {
        self.elements.contains(&Element::Zip)
    }

    /// The names of the environment variables the template reads, once each, in name order.
    pub fn env_names(&self) -> Vec<&str> {
        let names: BTreeSet<&str> = self
            .elements
            .iter()
            .filter_map(|e| match e {
                Element::Env(name) => Some(name.as_str()),
                _ => None,
            })
            .collect();
        names.into_iter().collect()
    }

    /// Expands the template: path placeholders from `ctx` (each must be given and absolute),
    /// `{env:NAME}` from `env` (unset or empty is an error naming the variable).
    pub fn expand(
        &self,
        ctx: &ExpandCtx<'_>,
        env: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Expanded, TemplateError> {
        let mut argv = Vec::with_capacity(self.elements.len());
        let mut redact: BTreeMap<String, OsString> = BTreeMap::new();
        for (index, element) in self.elements.iter().enumerate() {
            let value = match element {
                Element::Literal(text) => OsString::from(text),
                Element::Path => path_value(Some(ctx.path), index, "{path}")?,
                Element::Bundle => path_value(ctx.bundle, index, "{bundle}")?,
                Element::Zip => path_value(ctx.zip, index, "{zip}")?,
                Element::Env(name) => {
                    let value = env(name)
                        .filter(|v| !v.is_empty())
                        .ok_or_else(|| TemplateError::EnvUnset { name: name.clone() })?;
                    redact.insert(name.clone(), value.clone());
                    value
                }
            };
            argv.push(value);
        }
        Ok(Expanded {
            argv,
            redact: redact.into_iter().collect(),
        })
    }
}

fn path_value(
    path: Option<&Path>,
    index: usize,
    placeholder: &'static str,
) -> Result<OsString, TemplateError> {
    let path = path.ok_or(TemplateError::NoValue { index, placeholder })?;
    if !path.is_absolute() {
        return Err(TemplateError::NotAbsolute { index, placeholder });
    }
    Ok(path.as_os_str().to_owned())
}

fn parse_element(text: &str, index: usize) -> Result<Element, TemplateError> {
    if text.is_empty() {
        return Err(TemplateError::EmptyElement { index });
    }
    if !text.contains(['{', '}']) {
        return Ok(Element::Literal(text.to_owned()));
    }
    let inner = text
        .strip_prefix('{')
        .and_then(|t| t.strip_suffix('}'))
        .filter(|t| !t.contains(['{', '}']))
        .ok_or(TemplateError::Brace { index })?;
    match inner {
        "path" => Ok(Element::Path),
        "bundle" => Ok(Element::Bundle),
        "zip" => Ok(Element::Zip),
        _ => match inner.strip_prefix("env:") {
            Some(name) if env_name_ok(name) => Ok(Element::Env(name.to_owned())),
            Some(_) => Err(TemplateError::EnvName { index }),
            None => Err(TemplateError::UnknownPlaceholder { index }),
        },
    }
}

/// `[A-Z_][A-Z0-9_]*`.
fn env_name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

// ---- the sign plan (M9-D4) -------------------------------------------------------------------------

/// How many bytes of each file a [`PlanEntry`] should carry: enough for any PE header and section
/// table [`PeHeaders::parse`] accepts, and for a Mach-O magic.
pub const PLAN_HEAD_BYTES: usize = 64 * 1024;

/// What one entry of the tree is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanEntryKind {
    /// A directory.
    Dir,
    /// A symbolic link; never signed, never followed.
    Symlink,
    /// A regular file.
    File {
        /// Its first `min(len, PLAN_HEAD_BYTES)` bytes.
        head: Vec<u8>,
        /// Its length.
        len: u64,
        /// [`pe::has_pe_signature`](crate::pe::has_pe_signature) for this file, answered by the
        /// caller (which may read past `head`): a file whose headers do not parse is a PE the plan
        /// cannot sign when this is true, and is not a PE otherwise. Setting it false for a file
        /// that is a PE leaves that file unsigned.
        pe_signature: bool,
    },
}

/// One entry of the tree the plan is made for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEntry {
    /// The path under the tree root.
    pub path: RelPath,
    /// What it is.
    pub kind: PlanEntryKind,
}

/// What a [`SignItem`] is, which also picks the template that signs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignKind {
    /// A Windows PE file without a certificate table (`sign`).
    PeFile,
    /// A loose Mach-O file of a macOS bundle (`sign`).
    MachOFile,
    /// A bundle nested under the bundle's `Contents/` (`sign_bundle`).
    NestedBundle,
    /// The bundle itself, the tree root (`sign_outer`).
    OuterBundle,
}

/// One thing to sign, in plan order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignItem {
    /// The path under the tree root; `None` for [`SignKind::OuterBundle`], the root itself.
    pub path: Option<RelPath>,
    /// What it is.
    pub kind: SignKind,
}

impl SignItem {
    /// The path text; empty for the tree root.
    pub fn rel(&self) -> &str {
        self.path.as_ref().map_or("", RelPath::as_str)
    }
}

/// Why no plan could be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignPlanError {
    /// A file with a PE signature whose headers the reader refuses: it would be left unsigned.
    #[error("{path} is a malformed PE image: {what}")]
    MalformedPe {
        /// The file.
        path: RelPath,
        /// What is wrong.
        what: &'static str,
    },
    /// A macOS plan was asked for without the bundle's main executable.
    #[error("a macOS sign plan needs the bundle's main executable")]
    NoMainExecutable,
}

/// The bundle directory suffixes signed as nested bundles (M9-D4), compared ASCII
/// case-insensitively.
const BUNDLE_SUFFIXES: [&str; 6] = [".app", ".framework", ".appex", ".xpc", ".bundle", ".plugin"];

/// The items to OS-sign in `entries` (a release tree of `target`), inner to outer (M9-D4).
///
/// - Windows: every PE file (by header) without a certificate table, deepest first, then by path
///   bytes. A signed PE, a non-PE file of any name and every directory are left out.
/// - macOS: for each nested bundle (a directory under `Contents/` named `*.app`, `*.framework`,
///   `*.appex`, `*.xpc`, `*.bundle` or `*.plugin`), deepest first then by path bytes: the loose
///   Mach-O files whose innermost enclosing bundle it is, then the bundle; then the outer bundle's
///   own loose Mach-O files except `main_exe`; then the outer bundle (the tree root). Within a
///   bundle, files are deepest first, then by path bytes. `main_exe` (the bundle's
///   `CFBundleExecutable` path) is required.
/// - Linux: nothing.
///
/// Symlinks are never items. The result depends only on `entries`' contents, not their order.
pub fn sign_plan(
    target: Target,
    entries: &[PlanEntry],
    main_exe: Option<&RelPath>,
) -> Result<Vec<SignItem>, SignPlanError> {
    if target.is_windows() {
        windows_plan(entries)
    } else if target.is_macos() {
        macos_plan(entries, main_exe.ok_or(SignPlanError::NoMainExecutable)?)
    } else {
        Ok(Vec::new())
    }
}

fn depth(path: &RelPath) -> usize {
    path.components().count()
}

/// Deepest first, then by path bytes.
fn deepest_first(a: &RelPath, b: &RelPath) -> std::cmp::Ordering {
    depth(b).cmp(&depth(a)).then_with(|| a.cmp(b))
}

fn windows_plan(entries: &[PlanEntry]) -> Result<Vec<SignItem>, SignPlanError> {
    let mut files = Vec::new();
    for entry in entries {
        let PlanEntryKind::File {
            head,
            len,
            pe_signature,
        } = &entry.kind
        else {
            continue;
        };
        match PeHeaders::parse(head, *len) {
            Ok(headers) => {
                if !security_in_file(&headers, *len) {
                    files.push(entry.path.clone());
                }
            }
            Err(PeError::NotPe) => {}
            Err(PeError::Malformed(what)) => {
                if *pe_signature {
                    return Err(SignPlanError::MalformedPe {
                        path: entry.path.clone(),
                        what,
                    });
                }
            }
        }
    }
    files.sort_by(deepest_first);
    files.dedup();
    Ok(files
        .into_iter()
        .map(|path| SignItem {
            path: Some(path),
            kind: SignKind::PeFile,
        })
        .collect())
}

fn is_nested_bundle(path: &RelPath) -> bool {
    if !path.as_str().starts_with("Contents/") {
        return false;
    }
    let Some(name) = path.components().last() else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    BUNDLE_SUFFIXES
        .iter()
        .any(|s| lower.len() > s.len() && lower.ends_with(s))
}

fn macos_plan(entries: &[PlanEntry], main_exe: &RelPath) -> Result<Vec<SignItem>, SignPlanError> {
    let bundles: BTreeSet<&RelPath> = entries
        .iter()
        .filter(|e| matches!(e.kind, PlanEntryKind::Dir) && is_nested_bundle(&e.path))
        .map(|e| &e.path)
        .collect();
    // Loose Mach-O files by their innermost enclosing nested bundle (`None`: the outer bundle).
    let mut loose: BTreeMap<Option<&RelPath>, Vec<RelPath>> = BTreeMap::new();
    for entry in entries {
        let PlanEntryKind::File { head, .. } = &entry.kind else {
            continue;
        };
        if !is_macho(head) {
            continue;
        }
        let owner = innermost_bundle(&entry.path, &bundles);
        if owner.is_none() && entry.path == *main_exe {
            continue;
        }
        loose.entry(owner).or_default().push(entry.path.clone());
    }
    let mut order: Vec<&RelPath> = bundles.iter().copied().collect();
    order.sort_by(|a, b| deepest_first(a, b));
    let mut plan = Vec::new();
    for owner in order.into_iter().map(Some).chain([None]) {
        if let Some(mut files) = loose.remove(&owner) {
            files.sort_by(deepest_first);
            files.dedup();
            plan.extend(files.into_iter().map(|path| SignItem {
                path: Some(path),
                kind: SignKind::MachOFile,
            }));
        }
        plan.push(match owner {
            Some(bundle) => SignItem {
                path: Some(bundle.clone()),
                kind: SignKind::NestedBundle,
            },
            None => SignItem {
                path: None,
                kind: SignKind::OuterBundle,
            },
        });
    }
    Ok(plan)
}

/// The deepest bundle of `bundles` that is a proper ancestor of `path`.
fn innermost_bundle<'a>(path: &RelPath, bundles: &BTreeSet<&'a RelPath>) -> Option<&'a RelPath> {
    let text = path.as_str();
    text.match_indices('/')
        .rev()
        .find_map(|(at, _)| bundles.iter().find(|b| b.as_str() == &text[..at]).copied())
}

// ---- signed-form checks (M9-D3) --------------------------------------------------------------------

/// Whether a PE image of `len` bytes, whose prefix is `head`, has a certificate table: its security
/// data directory is non-zero (offset and size) and lies inside the file. False for anything the PE
/// reader refuses. Total on any input.
pub fn pe_is_signed(head: &[u8], len: u64) -> bool {
    PeHeaders::parse(head, len).is_ok_and(|h| security_in_file(&h, len))
}

fn security_in_file(headers: &PeHeaders, len: u64) -> bool {
    let dir = headers.security();
    dir.address != 0 && dir.size != 0 && u64::from(dir.address) + u64::from(dir.size) <= len
}

const LC_CODE_SIGNATURE: u32 = 0x1d;
const MAX_FAT_SLICES: u32 = 20;

fn rd32(bytes: &[u8], at: usize, big: bool) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(if big {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    })
}

fn rd64(bytes: &[u8], at: usize, big: bool) -> Option<u64> {
    let raw: [u8; 8] = bytes.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(if big {
        u64::from_be_bytes(raw)
    } else {
        u64::from_le_bytes(raw)
    })
}

/// A thin Mach-O magic: `(big endian, 64-bit)`.
fn thin_magic(bytes: &[u8]) -> Option<(bool, bool)> {
    match bytes.get(..4)? {
        [0xFE, 0xED, 0xFA, 0xCE] => Some((true, false)),
        [0xFE, 0xED, 0xFA, 0xCF] => Some((true, true)),
        [0xCE, 0xFA, 0xED, 0xFE] => Some((false, false)),
        [0xCF, 0xFA, 0xED, 0xFE] => Some((false, true)),
        _ => None,
    }
}

/// A universal header: `(big endian, 64-bit arch entries, slice count)`, the count in 1..=20 and
/// the whole arch table present (a Java class file's version puts its count far above 20).
fn fat_header(bytes: &[u8]) -> Option<(bool, bool, usize)> {
    let (big, wide) = match bytes.get(..4)? {
        [0xCA, 0xFE, 0xBA, 0xBE] => (true, false),
        [0xCA, 0xFE, 0xBA, 0xBF] => (true, true),
        [0xBE, 0xBA, 0xFE, 0xCA] => (false, false),
        [0xBF, 0xBA, 0xFE, 0xCA] => (false, true),
        _ => return None,
    };
    let count = rd32(bytes, 4, big)?;
    if !(1..=MAX_FAT_SLICES).contains(&count) {
        return None;
    }
    let stride = if wide { 32 } else { 20 };
    let table_end = 8 + count as usize * stride;
    (bytes.len() >= table_end).then_some((big, wide, count as usize))
}

/// Whether `head` (the file's first [`PLAN_HEAD_BYTES`] bytes) starts like a Mach-O file, thin or
/// universal, of any architecture.
pub fn is_macho(head: &[u8]) -> bool {
    thin_magic(head).is_some() || fat_header(head).is_some()
}

/// Whether every slice of the Mach-O file `bytes` (thin, or universal with 32- or 64-bit arch
/// entries; either byte order) has an `LC_CODE_SIGNATURE` whose data range is non-empty and lies
/// inside the slice. False for anything that is not a well-formed Mach-O. Total on any input.
pub fn macho_slices_signed(bytes: &[u8]) -> bool {
    let Some((big, wide, count)) = fat_header(bytes) else {
        return thin_signed(bytes);
    };
    let stride = if wide { 32 } else { 20 };
    (0..count).all(|i| {
        let at = 8 + i * stride;
        let range = if wide {
            rd64(bytes, at + 8, big).zip(rd64(bytes, at + 16, big))
        } else {
            rd32(bytes, at + 8, big)
                .zip(rd32(bytes, at + 12, big))
                .map(|(o, s)| (u64::from(o), u64::from(s)))
        };
        range
            .and_then(|(offset, size)| {
                let start = usize::try_from(offset).ok()?;
                let end = start.checked_add(usize::try_from(size).ok()?)?;
                bytes.get(start..end)
            })
            .is_some_and(thin_signed)
    })
}

/// One thin slice: every load command well formed, and an `LC_CODE_SIGNATURE` among them whose
/// data lies inside the slice.
fn thin_signed(slice: &[u8]) -> bool {
    let Some((big, wide)) = thin_magic(slice) else {
        return false;
    };
    let header: usize = if wide { 32 } else { 28 };
    let (Some(ncmds), Some(sizeofcmds)) = (rd32(slice, 16, big), rd32(slice, 20, big)) else {
        return false;
    };
    let Some(end) = header.checked_add(sizeofcmds as usize) else {
        return false;
    };
    if end > slice.len() {
        return false;
    }
    let mut at = header;
    let mut signed = false;
    for _ in 0..ncmds {
        // Every command is at least 8 bytes, so this loop ends within `sizeofcmds / 8` rounds.
        let (Some(cmd), Some(size)) = (rd32(slice, at, big), rd32(slice, at + 4, big)) else {
            return false;
        };
        let size = size as usize;
        let Some(next) = at.checked_add(size) else {
            return false;
        };
        if size < 8 || next > end {
            return false;
        }
        if cmd == LC_CODE_SIGNATURE {
            if size < 16 {
                return false;
            }
            let (Some(off), Some(len)) = (rd32(slice, at + 8, big), rd32(slice, at + 12, big))
            else {
                return false;
            };
            if off != 0 && len != 0 && u64::from(off) + u64::from(len) <= slice.len() as u64 {
                signed = true;
            }
        }
        at = next;
    }
    signed
}

// ---- the publisher policy (M9-D9) ------------------------------------------------------------------

/// What a publisher check found when it did not simply say "same publisher" (or "not applicable"):
/// the closed set of reasons a refusal or a warning can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublisherOutcome {
    /// Signed by another publisher than the installed version.
    Different,
    /// The installed version is not signed: no baseline.
    InstalledUnsigned,
    /// The installed version's signature does not verify.
    InstalledInvalid,
    /// The candidate is not signed.
    CandidateUnsigned,
    /// The candidate's signature does not verify.
    CandidateInvalid,
    /// The operating system could not answer.
    Os,
}

impl PublisherOutcome {
    /// The stable code text: `different`, `installed_unsigned`, `installed_invalid`,
    /// `candidate_unsigned`, `candidate_invalid` or `os`.
    pub const fn code(self) -> &'static str {
        match self {
            PublisherOutcome::Different => "different",
            PublisherOutcome::InstalledUnsigned => "installed_unsigned",
            PublisherOutcome::InstalledInvalid => "installed_invalid",
            PublisherOutcome::CandidateUnsigned => "candidate_unsigned",
            PublisherOutcome::CandidateInvalid => "candidate_invalid",
            PublisherOutcome::Os => "os",
        }
    }
}

/// What the policy makes of a check's result (M9-D9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The update goes on. `Some` is a finding to report (a `tracing` warning and the `publisher`
    /// member of the result); `None` is "same publisher", "not applicable" or "no check ran".
    Proceed(Option<PublisherOutcome>),
    /// The update is refused for `reason`. `mark_bad` is set only when the finding is about the
    /// candidate's own bytes or signature: then the version is marked bad in the same state
    /// commit, so it is never offered again.
    Refuse {
        /// Why.
        reason: PublisherOutcome,
        /// Whether the candidate version is marked bad.
        mark_bad: bool,
    },
}

/// The policy decision over a check's `result` (M9-D9), total over every pair:
///
/// | result | `off` | `warn` | `enforce` |
/// |---|---|---|---|
/// | same publisher, not applicable | proceed | proceed | proceed |
/// | installed unsigned | proceed | proceed, report | proceed, report (no baseline yet) |
/// | different, candidate unsigned, candidate invalid | proceed | proceed, report | refuse, mark bad |
/// | installed invalid, os | proceed | proceed, report | refuse, mark nothing (a local fault) |
pub fn decide(policy: PublisherPolicy, result: Result<bool, PublisherError>) -> Decision {
    let found = match result {
        Ok(true) | Err(PublisherError::NotApplicable) => None,
        Ok(false) => Some(PublisherOutcome::Different),
        Err(PublisherError::InstalledUnsigned) => Some(PublisherOutcome::InstalledUnsigned),
        Err(PublisherError::InstalledInvalid) => Some(PublisherOutcome::InstalledInvalid),
        Err(PublisherError::CandidateUnsigned) => Some(PublisherOutcome::CandidateUnsigned),
        Err(PublisherError::CandidateInvalid) => Some(PublisherOutcome::CandidateInvalid),
        // `PublisherError` is non-exhaustive: anything this table does not know is a local fault.
        Err(_) => Some(PublisherOutcome::Os),
    };
    let Some(found) = found else {
        return Decision::Proceed(None);
    };
    match policy {
        PublisherPolicy::Off => Decision::Proceed(None),
        PublisherPolicy::Warn => Decision::Proceed(Some(found)),
        PublisherPolicy::Enforce => match found {
            PublisherOutcome::InstalledUnsigned => Decision::Proceed(Some(found)),
            PublisherOutcome::Different
            | PublisherOutcome::CandidateUnsigned
            | PublisherOutcome::CandidateInvalid => Decision::Refuse {
                reason: found,
                mark_bad: true,
            },
            PublisherOutcome::InstalledInvalid | PublisherOutcome::Os => Decision::Refuse {
                reason: found,
                mark_bad: false,
            },
        },
    }
}
