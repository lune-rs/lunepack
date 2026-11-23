//! Opening a release directory (C2): the trust chain a writer starts from. The compiled-in root of
//! the config is walked forward through `root-<k>.json` files, and `keys.json` is verified under
//! the walked root.
//!
//! Callers that write pass a time-skipping reading (`ClockReading::read(clock, Some(u64::MAX))`,
//! M3-D9) so an expired key set can still be replaced; callers that only read pass the real one.

use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use lunepack_core::{
    AppId, ClockReading, FeedTargetEntry, Hasher, Limits, RollbackFloor, Target, TrustedRoot,
    VerifiedEntry, VerifiedKeySet, VerifiedManifest, Verifier, Version, advance_root, verify_feed,
    verify_key_set, verify_manifest, verify_payload_manifest,
};

use crate::cmd_verify::{channel_of, feed_file_names};
use crate::config::Config;
use crate::pipeline::{BaseFile, BaseRelease};

/// What a release directory's trust chain yields.
pub struct Opened {
    /// The root after the walk.
    pub root: TrustedRoot,
    /// The version of `root` (the `k` of the last `root-<k>.json`, or the config's version).
    pub root_doc_k: u64,
    /// The key set under `root`, when `keys.json` exists.
    pub keys: Option<VerifiedKeySet>,
}

/// The path of `root-<k>.json`.
pub fn root_path(dir: &Path, k: u64) -> PathBuf {
    dir.join(format!("root-{k}.json"))
}

/// The path of `keys.json`.
pub fn keys_path(dir: &Path) -> PathBuf {
    dir.join("keys.json")
}

/// Reads a file of at most `cap` bytes; `None` if it does not exist.
pub fn read_capped(path: &Path, cap: u64) -> Result<Option<Vec<u8>>> {
    // Classified before opening: Windows cannot open a directory, and a FIFO blocks on open.
    if let Ok(meta) = fs::metadata(path)
        && !meta.is_file()
    {
        bail!("{} is not a regular file", path.display());
    }
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() as u64 > cap {
        bail!("{} is over {cap} bytes", path.display());
    }
    Ok(Some(bytes))
}

/// Opens `dir`: builds the trusted root from `cfg`, walks `root-<k>.json` for `k = version + 1,
/// +2, ...` while the file exists (a gap ends the walk; a file that does not verify fails it), then
/// verifies `keys.json` when present, with the floors at zero.
pub fn open(
    dir: &Path,
    cfg: &Config,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
    reading: &ClockReading,
) -> Result<Opened> {
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    let mut root = cfg.trusted_root(hasher, verifier)?;
    loop {
        let k = root.version() + 1;
        let path = root_path(dir, k);
        let Some(bytes) = read_capped(&path, Limits::V1.root_doc_bytes)? else {
            break;
        };
        root = advance_root(&root, &bytes, hasher, verifier)
            .with_context(|| format!("{} does not verify", path.display()))?;
    }
    let path = keys_path(dir);
    let keys = match read_capped(&path, Limits::V1.keys_doc_bytes)? {
        None => None,
        Some(bytes) => Some(
            verify_key_set(
                &root,
                &bytes,
                &RollbackFloor::default(),
                reading,
                hasher,
                verifier,
            )
            .with_context(|| format!("{} does not verify", path.display()))?,
        ),
    };
    let root_doc_k = root.version();
    Ok(Opened {
        root,
        root_doc_k,
        keys,
    })
}

/// The most bases one pack uses: the format's cap on deltas per manifest (FORMAT.md 4).
pub const MAX_BASES: usize = 16;

/// What [`select_bases`] needs to know about the release being packed.
pub struct BaseQuery<'a> {
    /// The release directory.
    pub dir: &'a Path,
    /// Its verified key set.
    pub keys: &'a VerifiedKeySet,
    /// The app id.
    pub app_id: &'a AppId,
    /// The new release's version: only versions of lower precedence are bases.
    pub version: &'a Version,
    /// The target.
    pub target: Target,
    /// `--deltas`: bases per feed, or in all when no feed is usable; 0 for none.
    pub per_feed: usize,
    /// The writer's time, for the key windows of a manifest read with no feed.
    pub now: u64,
    /// The time-skipping reading pack uses for the documents it reads (M3-D9).
    pub skip: &'a ClockReading,
}

/// How a base's manifest is reached: through a verified feed's entry, or with no feed.
enum Via {
    Feed(FeedTargetEntry),
    NoFeed(Version),
}

/// The bases of a new release (M12-D3), highest first, each opened and verified; one line per
/// ignored feed and per skipped base is pushed to `lines`.
///
/// Candidates are the version directories of lower precedence than the new version that hold
/// `<target>.manifest.json`. Every `feed-<channel>.json` is opened with [`verify_feed`] under the
/// time-skipping reading (a feed whose only fault is its expiry is used: a base choice is not a
/// trust decision); a feed that fails otherwise is ignored. With at least one usable feed the
/// bases are the union of each feed's `per_feed` highest candidates for this target; with none,
/// the `per_feed` highest candidates. The union is capped at the [`MAX_BASES`] highest.
///
/// A base's manifest is verified the way `verify` does, through the feed's entry, or with no feed
/// the way an installer does ([`verify_payload_manifest`], release keys valid at `now`); its pack
/// must have the manifest's size and SHA-256. A base that fails either is skipped.
pub fn select_bases(
    q: &BaseQuery<'_>,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
    lines: &mut Vec<String>,
) -> Result<Vec<BaseRelease>> {
    if q.per_feed == 0 {
        return Ok(Vec::new());
    }
    let manifest_name = format!("{}.manifest.json", q.target.as_str());
    let mut candidates: BTreeMap<String, Version> = BTreeMap::new();
    for entry in fs::read_dir(q.dir).with_context(|| format!("cannot list {}", q.dir.display()))? {
        let entry = entry.with_context(|| format!("cannot list {}", q.dir.display()))?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(version) = Version::parse(&name) else {
            continue;
        };
        if version < *q.version && entry.path().join(&manifest_name).is_file() {
            candidates.insert(name, version);
        }
    }

    // Text -> (precedence, how to reach it); the first feed (in file-name order) to list a text
    // names its entry.
    let mut chosen: BTreeMap<String, (Version, Via)> = BTreeMap::new();
    let mut usable = 0usize;
    for file in feed_file_names(q.dir)? {
        let feed = (|| -> Result<_> {
            let channel = channel_of(&file)?;
            let bytes = read_capped(&q.dir.join(&file), Limits::V1.feed_doc_bytes)?
                .with_context(|| format!("{file} does not exist"))?;
            Ok(verify_feed(
                q.keys,
                &bytes,
                q.app_id,
                &channel,
                &RollbackFloor::default(),
                q.skip,
                verifier,
            )?)
        })();
        let feed = match feed {
            Ok(feed) => feed,
            Err(e) => {
                lines.push(format!("delta: feed {file} ignored: {e:#}"));
                continue;
            }
        };
        usable += 1;
        let mut listed: Vec<(Version, String, FeedTargetEntry)> = Vec::new();
        for (i, release) in feed.releases().iter().enumerate() {
            let text = release.version_text();
            let Some(version) = candidates.get(text) else {
                continue;
            };
            if let Some(entry) = feed.target_entry(i, q.target) {
                listed.push((version.clone(), text.to_owned(), entry));
            }
        }
        listed.sort_by(|a, b| b.0.cmp(&a.0));
        for (version, text, entry) in listed.into_iter().take(q.per_feed) {
            chosen.entry(text).or_insert((version, Via::Feed(entry)));
        }
    }
    if usable == 0 {
        let mut all: Vec<(&String, &Version)> = candidates.iter().collect();
        all.sort_by(|a, b| b.1.cmp(a.1));
        for (text, version) in all.into_iter().take(q.per_feed) {
            chosen.insert(
                text.clone(),
                (version.clone(), Via::NoFeed(version.clone())),
            );
        }
    }
    let mut order: Vec<(String, Version, Via)> = chosen
        .into_iter()
        .map(|(t, (v, via))| (t, v, via))
        .collect();
    order.sort_by(|a, b| b.1.cmp(&a.1));
    order.truncate(MAX_BASES);

    let mut out = Vec::new();
    for (text, _, via) in order {
        match open_base(q, &text, &via, &manifest_name, hasher, verifier) {
            Ok(base) => out.push(base),
            Err(e) => lines.push(format!("delta: base {text} skipped: {e:#}")),
        }
    }
    Ok(out)
}

/// Opens one base: its manifest verified, its pack's size and SHA-256 checked by streaming.
fn open_base(
    q: &BaseQuery<'_>,
    text: &str,
    via: &Via,
    manifest_name: &str,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<BaseRelease> {
    let manifest: VerifiedManifest = match via {
        Via::Feed(entry) => {
            let reference = entry.reference();
            let bytes = read_capped(&q.dir.join(reference.path()), reference.size())?
                .with_context(|| format!("{} does not exist", reference.path()))?;
            verify_manifest(q.keys, entry, &bytes, hasher, verifier)
                .with_context(|| format!("{} does not verify", reference.path()))?
        }
        Via::NoFeed(version) => {
            let rel = format!("{text}/{manifest_name}");
            let bytes = read_capped(&q.dir.join(&rel), Limits::V1.manifest_doc_bytes)?
                .with_context(|| format!("{rel} does not exist"))?;
            verify_payload_manifest(q.keys, (version, q.target), &bytes, q.now, hasher, verifier)
                .with_context(|| format!("{rel} does not verify"))?
        }
    };
    let pack_ref = manifest.pack();
    let pack = q.dir.join(pack_ref.path());
    let mut file = File::open(&pack).with_context(|| format!("cannot read {}", pack_ref.path()))?;
    let mut state = hasher.sha256_start();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("cannot read {}", pack_ref.path()))?;
        if n == 0 {
            break;
        }
        state.update(&buf[..n]);
        size += n as u64;
        if size > pack_ref.size() {
            break;
        }
    }
    if size != pack_ref.size() || state.finalize() != pack_ref.sha256() {
        bail!("{} does not match its manifest", pack_ref.path());
    }
    let mut files = BTreeMap::new();
    for e in manifest.entries() {
        if let VerifiedEntry::File {
            path,
            size,
            sha256,
            frame: Some(frame),
            ..
        } = e
            && *size > 0
        {
            files.insert(
                path.clone(),
                BaseFile {
                    size: *size,
                    sha256: *sha256,
                    frame: frame.clone(),
                },
            );
        }
    }
    Ok(BaseRelease {
        version: text.to_owned(),
        pack,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_is_not_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let e = read_capped(dir.path(), 10).unwrap_err();
        assert!(format!("{e:#}").contains("not a regular file"), "{e:#}");
        assert!(
            read_capped(&dir.path().join("absent"), 10)
                .unwrap()
                .is_none()
        );
    }
}
