//! The work directory of a push (P-D6, P-D7): store objects downloaded into a release directory
//! layout, a release's `<version>/` files read from the release directories, and the uploads.
//!
//! Every path a signed document names becomes a [`StoreKey`] under the prefix before it is read
//! or written, and is joined under the work directory only through [`under`].

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use lunepack_core::{
    CheckedRef, FeedTargetEntry, Hasher, ObjectStore, StoreError, StoreKey, VerifiedKeySet,
    verify_manifest,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use super::fetch::{under, write_file};

/// The key `<prefix>/<rel>`; an error names the relative path only.
pub fn key(prefix: &str, rel: &str) -> Result<StoreKey> {
    StoreKey::new(prefix, rel).map_err(|e| anyhow!("{rel}: not a usable object key: {e}"))
}

/// What a reader of the object is told it is.
pub fn content_type(rel: &str) -> &'static str {
    if rel.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

/// `get` with an error that names the key (never a credential: [`StoreError`] holds none).
pub fn get(store: &dyn ObjectStore, key: &StoreKey, cap: u64) -> Result<Option<Vec<u8>>> {
    store.get(key, cap).map_err(Into::into)
}

/// One file of the release being pushed: where it is, and its length and SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFile {
    /// The file in a release directory.
    pub path: PathBuf,
    /// Its length.
    pub len: u64,
    /// Its SHA-256.
    pub sha256: [u8; 32],
}

/// Streams `path` through SHA-256.
pub fn hash_file(path: &Path) -> Result<LocalFile> {
    let mut file = File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut state = Sha256Hasher.sha256_start();
    let mut buf = vec![0u8; 64 * 1024];
    let mut len = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if n == 0 {
            break;
        }
        len += n as u64;
        state.update(&buf[..n]);
    }
    Ok(LocalFile {
        path: path.to_owned(),
        len,
        sha256: *state.finalize().as_bytes(),
    })
}

/// Every regular file under `<dir>/<version>/`, by its path relative to `dir` (`/`-separated). A
/// symlink or other special file is refused; a missing folder is an error.
pub fn version_files(dir: &Path, version: &str) -> Result<BTreeMap<String, LocalFile>> {
    let root = dir.join(version);
    if !root.is_dir() {
        bail!(
            "{} has no {version}/ folder: pack the release into it first",
            dir.display()
        );
    }
    let mut out = BTreeMap::new();
    let mut stack = vec![(root, version.to_owned())];
    while let Some((at, rel)) = stack.pop() {
        for entry in fs::read_dir(&at).with_context(|| format!("cannot list {}", at.display()))? {
            let entry = entry.with_context(|| format!("cannot list {}", at.display()))?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| anyhow!("{}: a file name that is not UTF-8", at.display()))?;
            let child = format!("{rel}/{name}");
            let kind = entry
                .file_type()
                .with_context(|| format!("cannot read {}", entry.path().display()))?;
            if kind.is_dir() {
                stack.push((entry.path(), child));
            } else if kind.is_file() {
                out.insert(child, hash_file(&entry.path())?);
            } else {
                bail!("{}: not a regular file", entry.path().display());
            }
        }
    }
    Ok(out)
}

/// The objects of one listed release target: its manifest, pack and delta files, by relative path.
pub fn objects_of(manifest_path: &str, pack: &CheckedRef, deltas: &[&CheckedRef]) -> Vec<String> {
    let mut out = vec![manifest_path.to_owned(), pack.path().to_owned()];
    out.extend(deltas.iter().map(|d| d.path().to_owned()));
    out
}

/// Downloads `rel` (exactly the bytes `reference` names) from the public store into `work`.
fn download_checked(
    store: &dyn ObjectStore,
    prefix: &str,
    work: &Path,
    reference: &CheckedRef,
) -> Result<()> {
    let rel = reference.path();
    let k = key(prefix, rel)?;
    let bytes = get(store, &k, reference.size())?
        .ok_or_else(|| anyhow!("{k}: listed, but the store has no such object"))?;
    reference
        .check_bytes(&bytes, &Sha256Hasher)
        .with_context(|| format!("{k} does not match the document that lists it"))?;
    write_file(&under(work, rel)?, &bytes)
}

/// Downloads one retained release target (P-D7): the manifest through the feed's reference,
/// verified under `keys`, then its pack and every delta file, each checked against the manifest.
/// Returns the relative paths of its objects.
pub fn download_target(
    store: &dyn ObjectStore,
    prefix: &str,
    work: &Path,
    keys: &VerifiedKeySet,
    entry: &FeedTargetEntry,
) -> Result<Vec<String>> {
    let reference = entry.reference();
    let rel = reference.path();
    let k = key(prefix, rel)?;
    let bytes = get(store, &k, reference.size())?
        .ok_or_else(|| anyhow!("{k}: listed, but the store has no such object"))?;
    let manifest = verify_manifest(keys, entry, &bytes, &Sha256Hasher, &Ed25519Verifier)
        .with_context(|| format!("{k} does not verify"))?;
    write_file(&under(work, rel)?, &bytes)?;
    download_checked(store, prefix, work, manifest.pack())?;
    let deltas: Vec<&CheckedRef> = manifest.deltas().iter().map(|d| d.file()).collect();
    for d in &deltas {
        download_checked(store, prefix, work, d)?;
    }
    Ok(objects_of(rel, manifest.pack(), &deltas))
}

/// One object to upload.
#[derive(Debug, Clone)]
pub struct Upload {
    /// Where it goes.
    pub key: StoreKey,
    /// Its path relative to the prefix.
    pub rel: String,
    /// The local file.
    pub file: LocalFile,
}

/// Whether the store already holds exactly `up`'s bytes (`Some(true)`), other bytes
/// (`Some(false)`) or nothing (`None`).
pub fn existing(store: &dyn ObjectStore, up: &Upload) -> Result<Option<bool>> {
    match store.get(&up.key, up.file.len) {
        Ok(None) => Ok(None),
        Ok(Some(bytes)) => Ok(Some(
            bytes.len() as u64 == up.file.len
                && Sha256Hasher.sha256(&bytes).as_bytes() == &up.file.sha256,
        )),
        Err(StoreError::TooLarge { .. }) => Ok(Some(false)),
        Err(e) => Err(e.into()),
    }
}

/// Uploads `up` from its file.
pub fn put_file(store: &dyn ObjectStore, up: &Upload) -> Result<()> {
    let mut file = File::open(&up.file.path)
        .with_context(|| format!("cannot read {}", up.file.path.display()))?;
    store.put(
        &up.key,
        &mut file,
        up.file.len,
        up.file.sha256,
        content_type(&up.rel),
    )?;
    Ok(())
}

/// Uploads `bytes` to `key`.
pub fn put_bytes(store: &dyn ObjectStore, key: &StoreKey, rel: &str, bytes: &[u8]) -> Result<()> {
    let sha = *Sha256Hasher.sha256(bytes).as_bytes();
    store.put(
        key,
        &mut io::Cursor::new(bytes),
        bytes.len() as u64,
        sha,
        content_type(rel),
    )?;
    Ok(())
}

/// The relative paths in `files` no entry of `referenced` names.
pub fn unreferenced<'a>(
    files: impl IntoIterator<Item = &'a String>,
    referenced: &BTreeSet<String>,
) -> Vec<String> {
    files
        .into_iter()
        .filter(|f| !referenced.contains(*f))
        .cloned()
        .collect()
}
