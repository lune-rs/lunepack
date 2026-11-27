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
    Channel, CheckedRef, ClockReading, FeedTargetEntry, Hasher, KeysChain, Limits, MAX_ROOT_STEPS,
    ObjectStore, StoreError, StoreKey, VerifiedFeed, VerifiedKeySet, verify_manifest,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use super::fetch::{under, write_file};
use super::pending::{MAX_PENDING_BYTES, PENDING_NAME, Pending};
use super::{Stores, say};
use crate::config::{Config, PublishSettings};
use crate::release_dir::{self, verify_feed_of};
use crate::state::{DEFAULT_STATE, MAX_STATE_BYTES, State};

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

/// `<channel>`'s feed, relative to the prefix.
pub fn feed_rel(channel: &Channel) -> String {
    format!("feed-{}.json", channel.as_str())
}

/// Reads `key` and prints one `read:` line for it.
pub fn read_doc(store: &dyn ObjectStore, key: &StoreKey, cap: u64) -> Result<Option<Vec<u8>>> {
    let got = get(store, key, cap)?;
    say(&format!(
        "read: {key} {}",
        if got.is_some() { "found" } else { "absent" }
    ))?;
    Ok(got)
}

/// The store has not been published to yet: a document every publish needs is absent.
#[derive(Debug)]
pub struct NotPublished {
    /// What is absent, as a sentence part (`the private bucket has no <key>`).
    pub what: String,
}

impl std::fmt::Display for NotPublished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: run `lunepack publish init` first (nothing was written)",
            self.what
        )
    }
}

impl std::error::Error for NotPublished {}

/// What a command reads from the two buckets before it decides anything (P-D6).
pub struct StoreRead {
    /// The state file's key and bytes.
    pub state_key: StoreKey,
    pub state_read: Vec<u8>,
    /// The pending-deletes record as read, and whether the store had one.
    pub pending: Pending,
    pub pending_existed: bool,
    /// `keys.json`'s bytes, and the `root-<k>.json` files after the config's root.
    pub keys_bytes: Vec<u8>,
    pub roots: Vec<(u64, Vec<u8>)>,
    /// The bytes of each `[publish]` channel's feed (`None`: none yet).
    pub feeds_read: BTreeMap<Channel, Option<Vec<u8>>>,
    /// The keys of every feed the commands must see: the `[publish]` channels' and those of the
    /// channels the state file records that are no longer in `[publish]` (see `guard_feeds`).
    pub feed_keys: Vec<(Channel, StoreKey)>,
    /// The version of the root the walk ended at, and the key set under it.
    pub root_doc_k: u64,
    pub chain: KeysChain,
    /// The `[publish]` channels' feeds that exist, verified with the time checks skipped.
    pub feeds: BTreeMap<Channel, VerifiedFeed>,
    /// The feeds of channels outside `[publish] channels` that the state file records and the
    /// public bucket still holds, verified with the time checks skipped. They are only read: no
    /// command writes, refreshes or drops from them, but what they list is never purged.
    pub guard_feeds: BTreeMap<Channel, VerifiedFeed>,
    /// The bytes of the guard feeds.
    pub guard_read: BTreeMap<Channel, Vec<u8>>,
}

impl StoreRead {
    /// The versions any feed in the store lists, a guard feed's included.
    pub fn listed(&self) -> BTreeSet<String> {
        listed_versions(self.feeds.values().chain(self.guard_feeds.values()))
    }
}

/// The versions the `feeds` list, by their text.
pub fn listed_versions<'a>(feeds: impl IntoIterator<Item = &'a VerifiedFeed>) -> BTreeSet<String> {
    feeds
        .into_iter()
        .flat_map(|f| f.releases().iter().map(|r| r.version_text().to_owned()))
        .collect()
}

/// Reads the state file and the pending record from the private store (the state file first) and
/// `keys.json`, the roots and every `[publish]` channel's feed from the public store, and the feeds
/// of the channels the state file records that `[publish]` no longer names (they guard what they
/// list, F1); writes them
/// into `wdir` (and the state file to `state_file`) the way the feed writers open a release
/// directory; and verifies the chain. A missing state file or `keys.json` is [`NotPublished`].
pub fn read_store(
    stores: &Stores,
    config: &Config,
    publish: &PublishSettings,
    wdir: &Path,
    state_file: &Path,
    skip: &ClockReading,
) -> Result<StoreRead> {
    read_store_walk(stores, config, publish, wdir, state_file, skip, None)
}

/// [`read_store`], with the root walk ended at `root-<walk_to>.json` when `walk_to` is given: the
/// roots after it are read into [`StoreRead::roots`] but not walked, and `keys.json` and the feeds
/// are verified under the root the walk ends at. Only `publish keys` passes `Some`, to read a store
/// whose rotation it left half done (F7); every other command walks every root.
pub fn read_store_walk(
    stores: &Stores,
    config: &Config,
    publish: &PublishSettings,
    wdir: &Path,
    state_file: &Path,
    skip: &ClockReading,
    walk_to: Option<u64>,
) -> Result<StoreRead> {
    let prefix = publish.prefix.as_str();
    let state_key = key(prefix, DEFAULT_STATE)?;
    let Some(state_read) = read_doc(stores.private.as_ref(), &state_key, MAX_STATE_BYTES)? else {
        return Err(NotPublished {
            what: format!("the private bucket has no {state_key}"),
        }
        .into());
    };
    fs::write(state_file, &state_read).context("cannot write the work directory")?;
    let pending_key = key(prefix, PENDING_NAME)?;
    let (pending, pending_existed) =
        match read_doc(stores.private.as_ref(), &pending_key, MAX_PENDING_BYTES)? {
            Some(bytes) => (Pending::parse(prefix, &bytes)?, true),
            None => (Pending::default(), false),
        };

    let keys_key = key(prefix, "keys.json")?;
    let Some(keys_bytes) = read_doc(stores.public.as_ref(), &keys_key, Limits::V1.keys_doc_bytes)?
    else {
        return Err(NotPublished {
            what: format!("the public bucket has no {keys_key}"),
        }
        .into());
    };
    // Channels the state file records but `[publish]` does not name: their feeds are still read.
    let recorded: Vec<Channel> = State::load(state_file)?
        .record(&config.app_id)
        .feeds
        .keys()
        .filter_map(|c| Channel::parse(c).ok())
        .filter(|c| !publish.channels.contains(c))
        .collect();
    let mut roots = Vec::new();
    for k in config.root_version + 1..=config.root_version + MAX_ROOT_STEPS {
        let rk = key(prefix, &format!("root-{k}.json"))?;
        match read_doc(stores.public.as_ref(), &rk, Limits::V1.root_doc_bytes)? {
            Some(bytes) => roots.push((k, bytes)),
            None => break,
        }
    }
    let mut feeds_read: BTreeMap<Channel, Option<Vec<u8>>> = BTreeMap::new();
    let mut feed_keys = Vec::new();
    for channel in &publish.channels {
        let fk = key(prefix, &feed_rel(channel))?;
        let got = read_doc(stores.public.as_ref(), &fk, Limits::V1.feed_doc_bytes)?;
        feeds_read.insert(channel.clone(), got);
        feed_keys.push((channel.clone(), fk));
    }
    let mut guard_read: BTreeMap<Channel, Vec<u8>> = BTreeMap::new();
    for channel in recorded {
        let fk = key(prefix, &feed_rel(&channel))?;
        if let Some(bytes) = read_doc(stores.public.as_ref(), &fk, Limits::V1.feed_doc_bytes)? {
            guard_read.insert(channel.clone(), bytes);
        }
        feed_keys.push((channel, fk));
    }

    fs::write(release_dir::keys_path(wdir), &keys_bytes)
        .context("cannot write the work directory")?;
    for (k, bytes) in roots
        .iter()
        .filter(|(k, _)| walk_to.is_none_or(|to| *k <= to))
    {
        fs::write(release_dir::root_path(wdir, *k), bytes)
            .context("cannot write the work directory")?;
    }
    for (channel, bytes) in &feeds_read {
        if let Some(bytes) = bytes {
            fs::write(wdir.join(feed_rel(channel)), bytes)
                .context("cannot write the work directory")?;
        }
    }
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let opened = release_dir::open(wdir, config, &hasher, &verifier, skip)
        .context("the store's key set does not verify (if a `publish keys` stopped after uploading a root-<k>.json, run that `publish keys` again to finish it)")?;
    let chain = opened
        .chain
        .ok_or_else(|| anyhow!("internal error: keys.json vanished"))?;
    let mut feeds: BTreeMap<Channel, VerifiedFeed> = BTreeMap::new();
    for (channel, bytes) in &feeds_read {
        if let Some(bytes) = bytes {
            let feed = verify_feed_of(&chain, &config.app_id, channel, bytes, skip, &verifier)
                .with_context(|| format!("the store's {} does not verify", feed_rel(channel)))?;
            feeds.insert(channel.clone(), feed);
        }
    }
    let mut guard_feeds: BTreeMap<Channel, VerifiedFeed> = BTreeMap::new();
    for (channel, bytes) in &guard_read {
        let feed = verify_feed_of(&chain, &config.app_id, channel, bytes, skip, &verifier)
            .with_context(|| {
                format!(
                    "the store's {} (a channel the state file records, not in [publish] channels) does not verify; it must be read so that what it lists is never purged: delete that feed object yourself if the channel is gone",
                    feed_rel(channel)
                )
            })?;
        guard_feeds.insert(channel.clone(), feed);
    }
    Ok(StoreRead {
        state_key,
        state_read,
        pending,
        pending_existed,
        keys_bytes,
        roots,
        feeds_read,
        feed_keys,
        root_doc_k: opened.root_doc_k,
        chain,
        feeds,
        guard_feeds,
        guard_read,
    })
}

/// P-D7: downloads every release the `feeds` list, except `skip_version`, and checks it against
/// the document that lists it. Returns the objects of each version (by its text) and how many
/// manifests were fetched.
pub fn download_retained(
    store: &dyn ObjectStore,
    prefix: &str,
    wdir: &Path,
    chain: &KeysChain,
    feeds: &BTreeMap<Channel, VerifiedFeed>,
    skip_version: Option<&str>,
) -> Result<(BTreeMap<String, BTreeSet<String>>, usize)> {
    let mut objects_of: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut fetched: BTreeSet<String> = BTreeSet::new();
    for feed in feeds.values() {
        for (i, release) in feed.releases().iter().enumerate() {
            if Some(release.version_text()) == skip_version {
                continue;
            }
            for target in release.targets().keys() {
                let entry = feed
                    .target_entry(i, *target)
                    .context("internal error: a release without its target")?;
                if !fetched.insert(entry.reference().path().to_owned()) {
                    continue;
                }
                let rels = download_target(store, prefix, wdir, chain.keys(), &entry)?;
                objects_of
                    .entry(release.version_text().to_owned())
                    .or_default()
                    .extend(rels);
            }
        }
    }
    Ok((objects_of, fetched.len()))
}
