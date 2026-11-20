//! The packing pipeline of C2, stages 1 to 4 and the layout of stage 5: assemble (a copy of the
//! input in a work dir), code-sign, hash, pack. Each stage is a function, called in that order by
//! [`build`]; nothing after the hash stage reads the tree except by re-reading a file and comparing
//! it with the hash stage's SHA-256.
//!
//! Parallelism lives only in the pack stage ([`pack_jobs`]): workers take job indices in order from
//! a shared counter, a memory gate admits a job only when its estimate fits the budget (or nothing
//! else runs), and each result lands in the slot of its index. Everything after reads the slots in
//! index order, so neither the worker count nor the scheduling reaches the output bytes.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};

use anyhow::{Context, Result, anyhow, bail};
use lunepack_core::path::MAX_PATH_DEPTH;
use lunepack_core::update_config::{
    MACOS_CODE_SIGNATURE_DIR, MACOS_HELPER_APP, MACOS_HELPER_ICON, MACOS_HELPER_INFO_PLIST,
    MACOS_HELPER_UI, MACOS_INFO_PLIST, MACOS_INSTALLER_PAYLOAD, RUNTIME_FILE, RUNTIME_FILE_WINDOWS,
    UI_FILE, UI_FILE_WINDOWS, config_path, runtime_file, ui_file,
};
use lunepack_core::{
    CodeSign, Codec, CodecId, Encoder, EntryKind, Hasher, InstallMeta, ManifestDocument,
    PackedFile, RelPath, ReleaseLayout, STUB_FILE, Sha256Digest, Target, UPDATE_CONFIG_FILE,
    pack_file, validate_tree,
};

/// Fixed per-job allowance on top of the input, output and encoder estimates: 16 MiB of slack for
/// the decoder of the round trip and allocator overhead, 1 MiB for the decoder's fixed state.
const JOB_OVERHEAD: u64 = 16 * 1024 * 1024 + 1024 * 1024;

/// Read size of the hash stage.
const CHUNK: usize = 64 * 1024;

/// Every codec an encoder may be asked for; the estimate takes the largest of them.
const ENCODED_CODECS: [CodecId; 4] = [
    CodecId::Lzma2,
    CodecId::BcjX86Lzma2,
    CodecId::BcjArm64Lzma2,
    CodecId::Bcj2,
];

/// One entry of the hashed tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemKind {
    /// A directory.
    Dir,
    /// A symlink and its link text.
    Symlink(String),
    /// A regular file.
    File {
        /// Bytes read.
        size: u64,
        /// SHA-256 of the bytes read.
        sha256: Sha256Digest,
        /// Executable bit (Unix mode `& 0o111`; always false on other hosts).
        exec: bool,
    },
}

/// One path of the tree with what the hash stage found there.
#[derive(Debug, Clone)]
pub struct Item {
    /// The path relative to the tree's root.
    pub path: RelPath,
    /// What it is.
    pub kind: ItemKind,
}

/// The kind of a directory entry, without following symlinks; specials are an error.
enum Found {
    Dir,
    File,
    Symlink,
}

fn found(path: &Path) -> Result<(Found, fs::Metadata)> {
    let meta =
        fs::symlink_metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    let ft = meta.file_type();
    let kind = if ft.is_dir() {
        Found::Dir
    } else if ft.is_file() {
        Found::File
    } else if ft.is_symlink() {
        Found::Symlink
    } else {
        bail!(
            "{} is a special file (fifo, socket or device); only files, directories and symlinks can be packed",
            path.display()
        );
    };
    Ok((kind, meta))
}

/// The names in `dir`, sorted by bytes; a name that is not UTF-8 is an error.
fn names(dir: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("cannot list {}", dir.display()))? {
        let entry = entry.with_context(|| format!("cannot list {}", dir.display()))?;
        let name = entry.file_name().into_string().map_err(|_| {
            anyhow!(
                "a name in {} is not UTF-8 and cannot be packed",
                dir.display()
            )
        })?;
        out.push(name);
    }
    out.sort();
    Ok(out)
}

fn link_text(path: &Path) -> Result<String> {
    let link = fs::read_link(path).with_context(|| format!("cannot read {}", path.display()))?;
    link.into_os_string()
        .into_string()
        .map_err(|_| anyhow!("the target of {} is not UTF-8", path.display()))
}

#[cfg(unix)]
fn make_symlink(text: &str, at: &Path) -> Result<()> {
    std::os::unix::fs::symlink(text, at).with_context(|| format!("cannot create {}", at.display()))
}

#[cfg(not(unix))]
fn make_symlink(_text: &str, at: &Path) -> Result<()> {
    bail!(
        "{} is a symlink; symlinks are packed only on Unix hosts",
        at.display()
    )
}

/// What a pack with `[update]` adds to the tree (M5-D7): the runtime beside the entry, the UI
/// binary beside it when `--ui` is given (M6), the Windows stub beside it for a `windows-*` target
/// (M7), and the update configuration at its fixed place (FORMAT.md 13.1). For a `macos-*` target
/// the UI is the executable of the helper app `Contents/Helpers/lunepack-update.app`, with its
/// `Info.plist` and, optionally, its icon (M8-D6).
pub struct UpdatePlan<'a> {
    /// The target of the pack.
    pub target: Target,
    /// The install metadata, which names the entry and the icon.
    pub install: &'a InstallMeta,
    /// The runtime's bytes, already checked against the target.
    pub runtime: &'a [u8],
    /// The UI binary's bytes, already checked against the target; absent without `--ui`.
    pub ui: Option<&'a [u8]>,
    /// The stamped Windows launcher stub (M7-D14), placed beside the entry as
    /// [`STUB_FILE`]; `Some` exactly for a `windows-*` target.
    pub stub: Option<&'a [u8]>,
    /// The update configuration's canonical bytes.
    pub config: &'a [u8],
    /// The helper app's `Info.plist` bytes (M8-D6); `Some` exactly for a `macos-*` target with
    /// `--ui`.
    pub helper_plist: Option<&'a [u8]>,
    /// The helper app's `.icns` bytes, already checked; only with `helper_plist`.
    pub helper_icon: Option<&'a [u8]>,
}

/// One file `pack` places into the assembled tree, or finds already placed in a signed bundle.
struct Placement<'a> {
    /// The path relative to the tree.
    path: String,
    bytes: &'a [u8],
    exec: bool,
}

/// Every file `plan` places, in the order they are written and, for a signed bundle, compared.
fn placements<'a>(plan: &UpdatePlan<'a>) -> Vec<Placement<'a>> {
    let dir = parent_of(plan.install.entry.as_str());
    let beside = |name: &str| {
        if dir.is_empty() {
            name.to_owned()
        } else {
            format!("{dir}/{name}")
        }
    };
    let mut out = vec![Placement {
        path: beside(runtime_file(plan.target)),
        bytes: plan.runtime,
        exec: true,
    }];
    if plan.target.is_macos() {
        out.push(Placement {
            path: config_path(plan.target).to_owned(),
            bytes: plan.config,
            exec: false,
        });
        if let (Some(ui), Some(plist)) = (plan.ui, plan.helper_plist) {
            out.push(Placement {
                path: MACOS_HELPER_UI.to_owned(),
                bytes: ui,
                exec: true,
            });
            out.push(Placement {
                path: MACOS_HELPER_INFO_PLIST.to_owned(),
                bytes: plist,
                exec: false,
            });
            if let Some(icon) = plan.helper_icon {
                out.push(Placement {
                    path: MACOS_HELPER_ICON.to_owned(),
                    bytes: icon,
                    exec: false,
                });
            }
        }
        return out;
    }
    if let Some(ui) = plan.ui {
        out.push(Placement {
            path: beside(ui_file(plan.target)),
            bytes: ui,
            exec: true,
        });
    }
    if let Some(stub) = plan.stub {
        out.push(Placement {
            path: beside(STUB_FILE),
            bytes: stub,
            exec: true,
        });
    }
    out.push(Placement {
        path: config_path(plan.target).to_owned(),
        bytes: plan.config,
        exec: false,
    });
    out
}

/// The directory part of a tree path (`""` for a path at the root).
fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// Whether the input at `input` is a code-signed `macos-*` bundle: it holds
/// `Contents/_CodeSignature` (M8-D8). `pack` then never modifies it.
pub fn is_signed_bundle(input: &Path, target: Target) -> bool {
    target.is_macos() && fs::symlink_metadata(input.join(MACOS_CODE_SIGNATURE_DIR)).is_ok()
}

/// Fails when the input holds a name the update setup reserves (M5-D17): the configuration's file
/// name at any depth, so nothing can shadow the root's in the nearest-ancestor discovery, or the
/// runtime's or the UI's name (either form) in the entry's directory. The UI's name is reserved
/// whether or not `--ui` is given, since the runtime starts a UI from its own directory. Names
/// compare ignoring ASCII case, as a case-insensitive file system would.
///
/// For a `macos-*` target the helper app's directory and the installer payload's path are reserved
/// as well (M8-D6, M8-D7). A signed bundle (M8-D8) legitimately holds the files `pack` would
/// place, so exactly those paths are let through, and with `--ui` everything inside the helper app
/// (its own signature among it); [`place_update`] then compares the placed files.
pub fn check_reserved(input: &Path, plan: &UpdatePlan<'_>) -> Result<()> {
    let entry_dir = parent_of(plan.install.entry.as_str());
    let target = plan.target;
    let placed: Vec<String> = if is_signed_bundle(input, target) {
        placements(plan).into_iter().map(|p| p.path).collect()
    } else {
        Vec::new()
    };
    // Exact text: a path that differs only in case from a placed one is still reserved.
    let is_placed = |text: &str| placed.iter().any(|p| p == text);
    let helper_signed = placed.iter().any(|p| p == MACOS_HELPER_UI);
    for (path, ..) in walk(input)? {
        let text = path.as_str();
        if is_placed(text) {
            continue;
        }
        let name = text.rsplit_once('/').map_or(text, |(_, name)| name);
        if name.eq_ignore_ascii_case(UPDATE_CONFIG_FILE) {
            bail!(
                "the input tree holds {text:?}; the name {UPDATE_CONFIG_FILE} is reserved for the update configuration at any depth"
            );
        }
        // The stub's name is the entry directory's, as the runtime's; for a Windows target it is
        // kept free at any depth, so no file of the tree can be taken for a launcher (M7-D8).
        if target.is_windows() && name.eq_ignore_ascii_case(STUB_FILE) {
            bail!(
                "the input tree holds {text:?}; the name {STUB_FILE} is reserved for the launcher stub of a Windows target"
            );
        }
        if target.is_macos() {
            for (reserved, what) in [
                (MACOS_HELPER_APP, "the update window's helper app"),
                (MACOS_INSTALLER_PAYLOAD, "the installer app's payload"),
            ] {
                if helper_signed && reserved == MACOS_HELPER_APP {
                    continue;
                }
                let under = text.len() > reserved.len()
                    && text.as_bytes()[reserved.len()] == b'/'
                    && text[..reserved.len()].eq_ignore_ascii_case(reserved);
                if text.eq_ignore_ascii_case(reserved) || under {
                    bail!(
                        "the input tree holds {text:?}; the path {reserved} is reserved for {what}"
                    );
                }
            }
        }
        if parent_of(text) == entry_dir {
            for (reserved, what) in [
                ([RUNTIME_FILE, RUNTIME_FILE_WINDOWS], "the runtime"),
                ([UI_FILE, UI_FILE_WINDOWS], "the UI"),
            ] {
                if reserved.iter().any(|r| name.eq_ignore_ascii_case(r)) {
                    bail!(
                        "the input tree holds {text:?}; the name {} is reserved for {what} beside the entry",
                        reserved[0]
                    );
                }
            }
        }
    }
    Ok(())
}

/// Fails unless `rel` names a regular file in `tree`, reached through real directories only (a
/// symlink on the way would make the last `lstat` say nothing about the path).
pub(crate) fn regular_file_in(tree: &Path, rel: &RelPath, field: &str) -> Result<fs::Metadata> {
    let count = rel.components().count();
    let mut at = tree.to_path_buf();
    for (i, component) in rel.components().enumerate() {
        at.push(component);
        let meta = fs::symlink_metadata(&at)
            .map_err(|_| anyhow!("{field} is not a file of the input tree"))?;
        let last = i + 1 == count;
        let ok = if last {
            meta.file_type().is_file()
        } else {
            meta.file_type().is_dir()
        };
        if !ok {
            bail!(
                "{field} is not a regular file of the input tree, or is reached through a symlink"
            );
        }
        if last {
            return Ok(meta);
        }
    }
    bail!("{field} is empty")
}

#[cfg(unix)]
fn write_new(path: &Path, bytes: &[u8], exec: bool) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if exec { 0o755 } else { 0o644 })
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(not(unix))]
fn write_new(path: &Path, bytes: &[u8], _exec: bool) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("cannot write {}", path.display()))
}

/// Creates the directories above `rel` in `tree`, one at a time through real directories only: a
/// component that exists as anything but a directory (a symlink included) is refused, so a write
/// can never be redirected out of the tree.
fn ensure_dirs(tree: &Path, rel: &str) -> Result<()> {
    let mut at = tree.to_path_buf();
    for component in parent_of(rel).split('/').filter(|c| !c.is_empty()) {
        at.push(component);
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => {
                bail!("{rel} cannot be placed: a directory on its path is not a real directory")
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&at).with_context(|| format!("cannot create {}", at.display()))?
            }
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!("cannot read {}", at.display())));
            }
        }
    }
    Ok(())
}

/// The first of `list` that a signed `macos-*` bundle at `tree` does not hold byte for byte
/// (M8-D8): missing, not a regular file, another size or content, or another exec bit.
fn first_unplaced(tree: &Path, list: &[Placement<'_>]) -> Result<Option<String>> {
    for p in list {
        let at = tree.join(&p.path);
        let rel = RelPath::parse(&p.path).context("internal error: a placement is not a path")?;
        let Ok(meta) = regular_file_in(tree, &rel, "placement") else {
            return Ok(Some(p.path.clone()));
        };
        if meta.len() != p.bytes.len() as u64 {
            return Ok(Some(p.path.clone()));
        }
        #[cfg(unix)]
        if is_exec(&meta) != p.exec {
            return Ok(Some(p.path.clone()));
        }
        let have = fs::read(&at).with_context(|| format!("cannot read {}", at.display()))?;
        if have != p.bytes {
            return Ok(Some(p.path.clone()));
        }
    }
    Ok(None)
}

/// Checks the entry and icon in the assembled tree at `tree`, then places the runtime, and the UI
/// when given, beside the entry and the update configuration at its fixed path (M5-D7). Runs after
/// `assemble` and before code signing, so every file is signed, hashed and packed like the app's own.
///
/// For a `macos-*` target the entry must be `Contents/MacOS/<file>` and `Contents/Info.plist` a
/// regular file; the UI goes into the helper app (M8-D6). A signed bundle (M8-D8) is never
/// written to: every file `pack` would place must already be there byte for byte, or this fails
/// naming the first path that is not.
pub fn place_update(tree: &Path, plan: &UpdatePlan<'_>) -> Result<()> {
    let install = plan.install;
    let meta = regular_file_in(tree, &install.entry, "install.entry")?;
    // The exec bit of a Windows target means nothing; elsewhere the entry must carry it.
    #[cfg(unix)]
    if !plan.target.is_windows() && !is_exec(&meta) {
        bail!("install.entry is not marked executable in the input tree");
    }
    #[cfg(not(unix))]
    let _ = meta;
    if let Some(icon) = &install.icon {
        regular_file_in(tree, icon, "install.icon")?;
    }
    if plan.target.is_macos() {
        let plist = RelPath::parse(MACOS_INFO_PLIST).context("internal error: a bundle path")?;
        regular_file_in(tree, &plist, MACOS_INFO_PLIST).map_err(|_| {
            anyhow!("a macos-* input must hold {MACOS_INFO_PLIST} as a regular file")
        })?;
    }
    let list = placements(plan);
    if is_signed_bundle(tree, plan.target) {
        if let Some(path) = first_unplaced(tree, &list)? {
            bail!(
                "the input bundle is code-signed ({MACOS_CODE_SIGNATURE_DIR}) and {path} is missing or differs from what pack would place; \
                 pack never modifies a signed bundle: run `lunepack pack --assemble <dir>` with the same options, sign the assembled bundle, and pack that"
            );
        }
        return Ok(());
    }
    for p in &list {
        ensure_dirs(tree, &p.path)?;
        write_new(&tree.join(&p.path), p.bytes, p.exec)?;
    }
    Ok(())
}

/// `pack --assemble` (M8-D8): writes the tree stage 1 and the update placement would produce to the
/// new directory `dest` and nothing else, so a signing tool can sign it before it is packed. The
/// input must not be signed. An existing `dest` is refused; a failure removes the `dest` this call
/// created.
pub fn assemble_bundle(input: &Path, dest: &Path, plan: &UpdatePlan<'_>) -> Result<()> {
    if !input.is_dir() {
        bail!("--input {} is not a directory", input.display());
    }
    if is_signed_bundle(input, plan.target) {
        bail!(
            "--input holds {MACOS_CODE_SIGNATURE_DIR}: a signed bundle is packed as it is, nothing is assembled"
        );
    }
    check_reserved(input, plan)?;
    fs::create_dir(dest).with_context(|| format!("cannot create {}", dest.display()))?;
    let built = copy_dir(input, dest, 0).and_then(|()| place_update(dest, plan));
    if built.is_err() {
        // `dest` did not exist a moment ago: `create_dir` above made it.
        let _ = fs::remove_dir_all(dest);
    }
    built
}

/// Stage 1: copies the tree at `input` into `dest` (which must not exist): files (with their
/// permissions), directories, and symlinks as links on Unix. A special file is refused; a hard link
/// is copied as a file.
pub fn assemble(input: &Path, dest: &Path) -> Result<()> {
    if !input.is_dir() {
        bail!("--input {} is not a directory", input.display());
    }
    fs::create_dir(dest).with_context(|| format!("cannot create {}", dest.display()))?;
    copy_dir(input, dest, 0)
}

fn copy_dir(from: &Path, to: &Path, depth: usize) -> Result<()> {
    if depth >= MAX_PATH_DEPTH {
        bail!(
            "{} is nested more than {MAX_PATH_DEPTH} levels deep",
            from.display()
        );
    }
    for name in names(from)? {
        let (src, dst) = (from.join(&name), to.join(&name));
        match found(&src)?.0 {
            Found::Dir => {
                fs::create_dir(&dst).with_context(|| format!("cannot create {}", dst.display()))?;
                copy_dir(&src, &dst, depth + 1)?;
            }
            Found::File => {
                fs::copy(&src, &dst).with_context(|| format!("cannot copy {}", src.display()))?;
            }
            Found::Symlink => make_symlink(&link_text(&src)?, &dst)?,
        }
    }
    Ok(())
}

/// Every path under `root`, sorted by path bytes, with what it is.
fn walk(root: &Path) -> Result<Vec<(RelPath, PathBuf, Found, fs::Metadata)>> {
    let mut out = Vec::new();
    walk_into(root, "", &mut out, 0)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk_into(
    dir: &Path,
    prefix: &str,
    out: &mut Vec<(RelPath, PathBuf, Found, fs::Metadata)>,
    depth: usize,
) -> Result<()> {
    if depth >= MAX_PATH_DEPTH {
        bail!(
            "{} is nested more than {MAX_PATH_DEPTH} levels deep",
            dir.display()
        );
    }
    for name in names(dir)? {
        let rel = format!("{prefix}{name}");
        let full = dir.join(&name);
        let path = RelPath::parse(&rel).with_context(|| format!("{rel:?} cannot be packed"))?;
        let (kind, meta) = found(&full)?;
        let is_dir = matches!(kind, Found::Dir);
        out.push((path, full.clone(), kind, meta));
        if is_dir {
            walk_into(&full, &format!("{rel}/"), out, depth + 1)?;
        }
    }
    Ok(())
}

/// The code-signing order (C2 stage 2): the files under `root`, deepest first, then by path bytes.
pub fn sign_order(root: &Path) -> Result<Vec<RelPath>> {
    let mut files: Vec<RelPath> = walk(root)?
        .into_iter()
        .filter(|(_, _, kind, _)| matches!(kind, Found::File))
        .map(|(path, ..)| path)
        .collect();
    files.sort_by(|a, b| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then_with(|| a.cmp(b))
    });
    Ok(files)
}

#[cfg(unix)]
fn is_exec(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_exec(_meta: &fs::Metadata) -> bool {
    false
}

/// SHA-256 and length of the file at `path`, streamed through `hasher`.
fn hash_file(path: &Path, hasher: &dyn Hasher) -> Result<(u64, Sha256Digest)> {
    let mut file = File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut state = hasher.sha256_start();
    let mut buf = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if n == 0 {
            break;
        }
        state.update(&buf[..n]);
        size += n as u64;
    }
    Ok((size, state.finalize()))
}

/// Stage 3: walks the tree at `root` into items sorted by path bytes, with each file's size,
/// SHA-256 and exec bit, then checks the tree rules for `target` before anything is encoded.
pub fn hash_tree(root: &Path, target: Target, hasher: &dyn Hasher) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    for (path, full, kind, meta) in walk(root)? {
        let kind = match kind {
            Found::Dir => ItemKind::Dir,
            Found::Symlink => ItemKind::Symlink(link_text(&full)?),
            Found::File => {
                let (size, sha256) = hash_file(&full, hasher)?;
                ItemKind::File {
                    size,
                    sha256,
                    exec: is_exec(&meta),
                }
            }
        };
        items.push(Item { path, kind });
    }
    validate_tree(
        items.iter().map(|i| {
            let kind = match &i.kind {
                ItemKind::Dir => EntryKind::Dir,
                ItemKind::Symlink(link) => EntryKind::Symlink { target: link },
                ItemKind::File { .. } => EntryKind::File,
            };
            (&i.path, kind)
        }),
        target,
    )
    .context("the input tree cannot be packed")?;
    Ok(items)
}

/// One file to encode: the first of its (size, SHA-256) in path order.
#[derive(Debug, Clone)]
pub struct Job {
    /// Where to read it.
    pub file: PathBuf,
    /// Its path in the tree, for messages.
    pub path: RelPath,
    /// Size from the hash stage.
    pub size: u64,
    /// SHA-256 from the hash stage.
    pub sha256: Sha256Digest,
}

/// The memory one job may need, in bytes: the input, twice the input for the best candidate
/// `pack_file` keeps while the next one runs (a frame is kept only when shorter than the input,
/// and `LzmaCodec`'s buffer is at most twice the input from 65 bytes up; below that it fits
/// [`JOB_OVERHEAD`]), the largest `encode_memory` of any codec (one running `encode` call, its
/// intermediate and output buffers included), and [`JOB_OVERHEAD`]. The largest over all codecs
/// bounds the largest over the file's own candidates, which are known only once its bytes are
/// read.
pub fn estimate(size: u64, encoder: &dyn Encoder) -> u64 {
    let state = ENCODED_CODECS
        .iter()
        .map(|c| encoder.encode_memory(*c, size))
        .max()
        .unwrap_or(0);
    size.saturating_mul(3)
        .saturating_add(state)
        .saturating_add(JOB_OVERHEAD)
}

/// The memory gate: admits a job while `in_use + est <= budget`, or when nothing else is admitted
/// (a job over the whole budget still runs, alone).
struct Gate {
    in_use: Mutex<u64>,
    freed: Condvar,
    budget: u64,
}

/// An admitted job's share of the budget; returned on drop, so an error or a panic gives it back.
struct Permit<'a> {
    gate: &'a Gate,
    est: u64,
}

impl Gate {
    fn admit(&self, est: u64) -> Permit<'_> {
        let mut in_use = self.in_use.lock().unwrap_or_else(PoisonError::into_inner);
        while *in_use != 0 && in_use.saturating_add(est) > self.budget {
            in_use = self
                .freed
                .wait(in_use)
                .unwrap_or_else(PoisonError::into_inner);
        }
        *in_use = in_use.saturating_add(est);
        Permit { gate: self, est }
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut in_use = self
            .gate
            .in_use
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *in_use = in_use.saturating_sub(self.est);
        self.gate.freed.notify_all();
    }
}

fn run_job(
    job: &Job,
    encoder: &dyn Encoder,
    codec: &dyn Codec,
    hasher: &dyn Hasher,
) -> Result<PackedFile> {
    let bytes = fs::read(&job.file).with_context(|| format!("cannot read {}", job.path))?;
    if bytes.len() as u64 != job.size || hasher.sha256(&bytes) != job.sha256 {
        bail!("{}: file changed after hashing", job.path);
    }
    pack_file(&bytes, encoder, codec, hasher).with_context(|| format!("cannot pack {}", job.path))
}

/// Stage 4: encodes `jobs` on up to `workers` threads within `budget` bytes (see [`estimate`]).
///
/// Workers take indices in order; a taken job always runs to the end, and once any job fails no
/// further job is taken. Results are kept by index, so the output does not depend on `workers` or
/// on timing, and the error returned is the lowest-index one: every index below a failed one was
/// taken before it, and so ran.
pub fn pack_jobs(
    jobs: &[Job],
    workers: usize,
    budget: u64,
    encoder: &dyn Encoder,
    codec: &dyn Codec,
    hasher: &dyn Hasher,
) -> Result<Vec<PackedFile>> {
    let gate = Gate {
        in_use: Mutex::new(0),
        freed: Condvar::new(),
        budget,
    };
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let slots: Mutex<Vec<Option<Result<PackedFile>>>> =
        Mutex::new((0..jobs.len()).map(|_| None).collect());
    let threads = workers.clamp(1, jobs.len().max(1));
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::AcqRel);
                    let Some(job) = jobs.get(i) else { break };
                    let permit = gate.admit(estimate(job.size, encoder));
                    let result = run_job(job, encoder, codec, hasher);
                    drop(permit);
                    if result.is_err() {
                        stop.store(true, Ordering::Release);
                    }
                    slots.lock().unwrap_or_else(PoisonError::into_inner)[i] = Some(result);
                }
            });
        }
    });
    let slots = slots.into_inner().unwrap_or_else(PoisonError::into_inner);
    let mut out = Vec::with_capacity(jobs.len());
    for (i, slot) in slots.into_iter().enumerate() {
        match slot {
            Some(Ok(packed)) => out.push(packed),
            Some(Err(e)) => return Err(e),
            // Only possible after an error, which is returned first, at a lower index.
            None => bail!("internal error: job {i} did not run"),
        }
    }
    Ok(out)
}

/// What [`build`] reports.
#[derive(Debug, Default)]
pub struct Report {
    /// File entries.
    pub files: usize,
    /// Directory entries.
    pub dirs: usize,
    /// Symlink entries.
    pub symlinks: usize,
    /// Bytes of all file entries.
    pub input_bytes: u64,
    /// Distinct non-empty files encoded.
    pub unique: usize,
    /// File entries per codec id (`none` for empty files).
    pub per_codec: BTreeMap<&'static str, usize>,
    /// Candidates dropped: the path, the codec and the reason.
    pub dropped: Vec<(String, CodecId, String)>,
}

/// Settings of [`build`].
pub struct Settings<'a> {
    /// Encoder threads.
    pub workers: usize,
    /// Memory budget of the pack stage, in bytes.
    pub budget: u64,
    /// The code-signing hook.
    pub code_sign: &'a dyn CodeSign,
    /// The encoder.
    pub encoder: &'a dyn Encoder,
    /// The decoder of the round trip.
    pub codec: &'a dyn Codec,
    /// SHA-256.
    pub hasher: &'a dyn Hasher,
    /// The runtime and update configuration to place after assemble, when `[update]` is set.
    pub update: Option<UpdatePlan<'a>>,
}

/// The unsigned result of stages 1 to 5.
pub struct Built {
    /// The manifest payload's document.
    pub manifest: ManifestDocument,
    /// The pack bytes.
    pub pack: Vec<u8>,
    /// Counts for the output.
    pub report: Report,
}

/// Runs C2 stages 1 to 4 in order over `input`, with `work` (an existing, empty directory) as the
/// work dir, then lays out the release (stage 5 without the signature) with `issued`. `say`
/// receives one line per stage.
pub fn build(
    input: &Path,
    work: &Path,
    layout: ReleaseLayout,
    target: Target,
    issued: u64,
    set: &Settings<'_>,
    say: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<Built> {
    let tree = work.join("tree");
    if let Some(plan) = &set.update
        && input.is_dir()
    {
        check_reserved(input, plan)?;
    }
    assemble(input, &tree)?;
    say(&format!("assemble: copied {}", input.display()))?;
    if let Some(plan) = &set.update {
        place_update(&tree, plan)?;
        say("update: placed the runtime and the update config")?;
    }

    let order = sign_order(&tree)?;
    set.code_sign
        .sign_tree(&tree, &order)
        .context("code signing failed")?;
    say(&format!("code-sign: {} file(s)", order.len()))?;

    let items = hash_tree(&tree, target, set.hasher)?;
    let mut report = Report::default();
    let mut jobs = Vec::new();
    let mut index: HashMap<(u64, [u8; 32]), usize> = HashMap::new();
    let mut job_of = Vec::with_capacity(items.len());
    for item in &items {
        let mut job = None;
        match &item.kind {
            ItemKind::Dir => report.dirs += 1,
            ItemKind::Symlink(_) => report.symlinks += 1,
            ItemKind::File { size, sha256, .. } => {
                report.files += 1;
                report.input_bytes = report.input_bytes.saturating_add(*size);
                if *size > 0 {
                    let key = (*size, *sha256.as_bytes());
                    let i = *index.entry(key).or_insert_with(|| {
                        jobs.push(Job {
                            file: tree.join(item.path.as_str()),
                            path: item.path.clone(),
                            size: *size,
                            sha256: *sha256,
                        });
                        jobs.len() - 1
                    });
                    job = Some(i);
                }
            }
        }
        job_of.push(job);
    }
    report.unique = jobs.len();
    say(&format!(
        "hash: {} file(s), {} dir(s), {} symlink(s), {} bytes",
        report.files, report.dirs, report.symlinks, report.input_bytes
    ))?;

    let packed = pack_jobs(
        &jobs,
        set.workers,
        set.budget,
        set.encoder,
        set.codec,
        set.hasher,
    )?;
    say(&format!(
        "pack: {} distinct file(s) encoded on {} worker(s)",
        jobs.len(),
        set.workers.clamp(1, jobs.len().max(1))
    ))?;
    for (job, p) in jobs.iter().zip(&packed) {
        for (codec, reason) in &p.dropped {
            report
                .dropped
                .push((job.path.as_str().to_owned(), *codec, reason.clone()));
        }
    }

    // Each frame is dropped right after its last user is added, so the peak stays near one copy
    // of the frames (the layout holds its own).
    let mut last_use = vec![0usize; jobs.len()];
    for (pos, job) in job_of.iter().enumerate() {
        if let Some(j) = job {
            last_use[*j] = pos;
        }
    }
    let mut packed: Vec<Option<PackedFile>> = packed.into_iter().map(Some).collect();
    let mut layout = layout;
    for (pos, (item, job)) in items.into_iter().zip(job_of).enumerate() {
        match item.kind {
            ItemKind::Dir => layout.add_dir(item.path)?,
            ItemKind::Symlink(link) => layout.add_symlink(item.path, &link)?,
            ItemKind::File { size, sha256, exec } => {
                let codec = match job {
                    None => {
                        let empty = PackedFile {
                            size,
                            sha256,
                            frame: None,
                            dropped: Vec::new(),
                        };
                        layout.add_file(item.path, exec, &empty)?;
                        "none"
                    }
                    Some(j) => {
                        let p = packed[j]
                            .as_ref()
                            .context("internal error: a frame was used after its last user")?;
                        let id = p.frame.as_ref().map_or("none", |f| f.codec.id());
                        layout.add_file(item.path, exec, p)?;
                        if last_use[j] == pos {
                            packed[j] = None;
                        }
                        id
                    }
                };
                *report.per_codec.entry(codec).or_default() += 1;
            }
        }
    }
    let (manifest, pack) = layout.finish(issued, set.hasher)?;
    Ok(Built {
        manifest,
        pack,
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lunepack_codec_lzma::LzmaCodec;
    use lunepack_core::{AppId, Error};
    use lunepack_crypto::Sha256Hasher;

    /// Rewrites one file in place and records the order it was given.
    struct Rewrite {
        path: &'static str,
        bytes: &'static [u8],
        seen: Mutex<Vec<String>>,
    }

    impl CodeSign for Rewrite {
        fn sign_tree(&self, root: &Path, order: &[RelPath]) -> Result<(), Error> {
            *self.seen.lock().unwrap() = order.iter().map(|p| p.as_str().to_owned()).collect();
            fs::write(root.join(self.path), self.bytes).expect("rewrite");
            Ok(())
        }
    }

    fn file_sha(manifest: &ManifestDocument, path: &str) -> Sha256Digest {
        manifest
            .entries
            .iter()
            .find(|e| e.path.as_str() == path)
            .and_then(|e| e.sha256)
            .expect("file entry")
    }

    #[test]
    fn code_sign_runs_between_assemble_and_hash() {
        let input = tempfile::tempdir().unwrap();
        fs::create_dir_all(input.path().join("sub/deeper")).unwrap();
        fs::write(input.path().join("app.bin"), b"original bytes of the app").unwrap();
        fs::write(input.path().join("sub/lib.bin"), b"a library").unwrap();
        fs::write(input.path().join("sub/deeper/x.bin"), b"deep").unwrap();
        let work = tempfile::tempdir().unwrap();
        let sign = Rewrite {
            path: "app.bin",
            bytes: b"the signed app, longer than before",
            seen: Mutex::new(Vec::new()),
        };
        let set = Settings {
            workers: 2,
            budget: 1 << 30,
            code_sign: &sign,
            encoder: &LzmaCodec,
            codec: &LzmaCodec,
            hasher: &Sha256Hasher,
            update: None,
        };
        let layout = ReleaseLayout::new(
            AppId::parse("org.example.app").unwrap(),
            "1.0.0",
            Target::LinuxX86_64,
        )
        .unwrap();
        let built = build(
            input.path(),
            work.path(),
            layout,
            Target::LinuxX86_64,
            1_800_000_000,
            &set,
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            file_sha(&built.manifest, "app.bin"),
            Sha256Hasher.sha256(b"the signed app, longer than before")
        );
        assert_eq!(
            file_sha(&built.manifest, "sub/lib.bin"),
            Sha256Hasher.sha256(b"a library")
        );
        // Deepest first, then by path.
        assert_eq!(
            *sign.seen.lock().unwrap(),
            ["sub/deeper/x.bin", "sub/lib.bin", "app.bin"]
        );
        // The input itself is never touched.
        assert_eq!(
            fs::read(input.path().join("app.bin")).unwrap(),
            b"original bytes of the app"
        );
    }

    #[test]
    fn gate_admits_a_job_over_the_budget_alone() {
        let gate = Gate {
            in_use: Mutex::new(0),
            freed: Condvar::new(),
            budget: 10,
        };
        let big = gate.admit(100);
        assert_eq!(*gate.in_use.lock().unwrap(), 100);
        drop(big);
        let a = gate.admit(4);
        let b = gate.admit(6);
        assert_eq!(*gate.in_use.lock().unwrap(), 10);
        drop((a, b));
        assert_eq!(*gate.in_use.lock().unwrap(), 0);
    }
}
