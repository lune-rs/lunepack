//! `lunepack publish fetch --release-dir <dir> --version <v>` (P-D6 first half).
//!
//! Reads the app's public feed (`[update] feed`) through the transport a client uses and fills a
//! new release directory: `keys.json`, the `root-<k>.json` files after the config's root, the
//! `feed-<channel>.json` of every `[publish]` channel that has one, and, for each channel and
//! target, the manifests and packs of the `deltas` newest earlier releases the feed lists. `pack`
//! and `feed add` then run on that directory unchanged.
//!
//! Nothing here consults the environment: the public feed is read without a credential. Every
//! request prints `GET <relative path> <status>`. The directory is built next to its place and
//! moved there once complete, so a failed fetch leaves nothing behind.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use lunepack::unstable_internals::{ABSENT_ROOT_STATUSES, FeedUrls};
use lunepack_core::fetch::check_document;
use lunepack_core::{
    AppId, BlockingTransport, CancelToken, Channel, ClockReading, FeedTargetEntry, Floors, Hasher,
    Limits, Request, ResponseInfo, RootWalk, StoreKey, Target, VerifiedFeed, Version,
    verify_manifest,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use super::{Usage, say, settings};
use crate::cmd_prebuilt::transport_for;
use crate::config::Config;
use crate::release_dir::verify_feed_of;

/// Arguments of `publish fetch`.
#[derive(Args)]
pub struct FetchArgs {
    /// The release directory to fill: absent or empty.
    #[arg(long = "release-dir")]
    release_dir: PathBuf,
    /// The version about to be published (SemVer); no feed may list it yet.
    #[arg(long)]
    version: String,
}

/// What a GET of a document came to.
enum Document {
    /// `200` and the whole body, within its cap.
    Body(Vec<u8>),
    /// Any other status.
    Status(u16),
}

/// The reads of one fetch: the transport, where it reads, and the hash and signature adapters.
struct Reader<'a> {
    transport: &'a dyn BlockingTransport,
    urls: &'a FeedUrls,
}

impl Reader<'_> {
    /// Sends the request for `rel`, prints its line and returns the response.
    fn request(&self, rel: &str) -> Result<lunepack_core::BlockingResponse> {
        let url = self.urls.join(rel).map_err(|e| anyhow!("{rel}: {e}"))?;
        let response = self
            .transport
            .get(
                &Request {
                    url,
                    range: None,
                    if_range: None,
                },
                &CancelToken::new(),
            )
            .with_context(|| format!("cannot fetch {rel}"))?;
        say(&format!("GET {rel} {}", response.head.status))?;
        Ok(response)
    }

    /// A document of at most `cap` bytes.
    fn document(&self, rel: &str, cap: u64) -> Result<Document> {
        let response = self.request(rel)?;
        if response.head.status != 200 {
            return Ok(Document::Status(response.head.status));
        }
        let info = ResponseInfo::from_head(&response.head)
            .map_err(|e| anyhow!("{rel}: the response is not usable: {e}"))?;
        check_document(&info, cap)
            .map_err(|e| anyhow!("{rel}: the response is not usable: {e}"))?;
        let mut body = Vec::new();
        response
            .body
            .take(cap.saturating_add(1))
            .read_to_end(&mut body)
            .with_context(|| format!("cannot read {rel}"))?;
        if body.len() as u64 > cap {
            bail!("{rel} is over {cap} bytes");
        }
        Ok(Document::Body(body))
    }

    /// Like [`Reader::document`], but only `200` is acceptable.
    fn required(&self, rel: &str, cap: u64) -> Result<Vec<u8>> {
        match self.document(rel, cap)? {
            Document::Body(bytes) => Ok(bytes),
            Document::Status(status) => bail!("{rel}: the server answered {status}"),
        }
    }

    /// Streams `rel` into `dest`, which must come to exactly `size` bytes of SHA-256 `sha256`.
    /// `Ok(Err(why))` when the bytes are not those (nothing is left at `dest`); an error for a
    /// status or transport failure.
    fn pack(
        &self,
        rel: &str,
        size: u64,
        sha256: lunepack_core::Sha256Digest,
        dest: &Path,
    ) -> Result<std::result::Result<(), String>> {
        let response = self.request(rel)?;
        if response.head.status != 200 {
            bail!("{rel}: the server answered {}", response.head.status);
        }
        let info = ResponseInfo::from_head(&response.head)
            .map_err(|e| anyhow!("{rel}: the response is not usable: {e}"))?;
        check_document(&info, size)
            .map_err(|e| anyhow!("{rel}: the response is not usable: {e}"))?;
        let part = dest.with_extension("part");
        let outcome = (|| -> Result<std::result::Result<(), String>> {
            let mut file =
                File::create(&part).with_context(|| format!("cannot create {}", part.display()))?;
            let mut body = response.body.take(size.saturating_add(1));
            let mut state = Sha256Hasher.sha256_start();
            let mut buf = vec![0u8; 64 * 1024];
            let mut total = 0u64;
            loop {
                let n = body
                    .read(&mut buf)
                    .with_context(|| format!("cannot read {rel}"))?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                state.update(&buf[..n]);
                file.write_all(&buf[..n])
                    .with_context(|| format!("cannot write {}", part.display()))?;
            }
            file.flush()
                .with_context(|| format!("cannot write {}", part.display()))?;
            if total != size {
                return Ok(Err(format!("{rel} is not {size} bytes")));
            }
            if state.finalize() != sha256 {
                return Ok(Err(format!("{rel} does not match its manifest")));
            }
            Ok(Ok(()))
        })();
        match outcome {
            Ok(Ok(())) => {
                fs::rename(&part, dest)
                    .with_context(|| format!("cannot place {}", dest.display()))?;
                Ok(Ok(()))
            }
            other => {
                let _ = fs::remove_file(&part);
                other
            }
        }
    }
}

/// A release directory's place must be absent or an empty directory.
fn check_release_dir(dir: &Path) -> Result<()> {
    match fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => {
            if fs::read_dir(dir)
                .with_context(|| format!("cannot list {}", dir.display()))?
                .next()
                .is_some()
            {
                bail!("{} is not empty", dir.display());
            }
            Ok(())
        }
        Ok(_) => bail!("{} is not a directory", dir.display()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", dir.display())),
    }
}

/// A path a signed document names, joined under `base`: relative, with no `.` or `..` segment.
pub(super) fn under(base: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty()
        || rel.starts_with('/')
        || rel.contains(['\\', ':'])
        || rel
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        bail!("a signed document names a path outside the release directory");
    }
    Ok(base.join(rel))
}

pub(super) fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    fs::write(path, bytes).with_context(|| format!("cannot write {}", path.display()))
}

/// The base releases of one feed: for each wanted target, the `deltas` highest versions below
/// `version` that list it.
fn bases_of(
    feed: &VerifiedFeed,
    require: &[Target],
    deltas: usize,
    version: &Version,
    into: &mut BTreeMap<(String, Target), FeedTargetEntry>,
) {
    let targets: Vec<Target> = if require.is_empty() {
        let mut all: Vec<Target> = feed
            .releases()
            .iter()
            .flat_map(|r| r.targets().keys().copied())
            .collect();
        all.sort();
        all.dedup();
        all
    } else {
        require.to_vec()
    };
    for target in targets {
        let mut listed: Vec<(&Version, usize)> = feed
            .releases()
            .iter()
            .enumerate()
            .filter(|(_, r)| r.version() < version && r.targets().contains_key(&target))
            .map(|(i, r)| (r.version(), i))
            .collect();
        listed.sort_by(|a, b| b.0.cmp(a.0));
        for (_, index) in listed.into_iter().take(deltas) {
            if let Some(entry) = feed.target_entry(index, target) {
                into.entry((entry.version_text().to_owned(), target))
                    .or_insert(entry);
            }
        }
    }
}

/// `publish fetch`.
pub fn fetch(config_path: &Path, args: &FetchArgs) -> Result<()> {
    let config = Config::load(config_path)?;
    let (update, publish) = settings(&config)?;
    let version = Version::parse(&args.version)
        .map_err(|_| Usage("--version is not a SemVer version".into()))?;
    StoreKey::version_folder(&publish.prefix, &args.version)
        .map_err(|_| Usage("--version is not usable as a folder name".into()))?;
    check_release_dir(&args.release_dir)?;

    // `[update] feed` as the update config writes it (a trailing `/`), by the client's own rules.
    let feed = if update.feed.ends_with('/') {
        update.feed.clone()
    } else {
        format!("{}/", update.feed)
    };
    let kind = lunepack::check_config_feed(&feed).map_err(|e| anyhow!("[update] feed: {e}"))?;
    let urls = FeedUrls::new(&feed).map_err(|e| anyhow!("[update] feed: {e}"))?;
    let transport = transport_for(&feed, kind)?;
    let reader = Reader {
        transport: transport.as_ref(),
        urls: &urls,
    };

    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    // A reader of the documents for a writer's use: time checks are skipped (a feed or key set
    // that has run out is the thing a publisher replaces).
    let skip = ClockReading::read(&lunepack::SystemClock, Some(u64::MAX));
    let app_id: &AppId = &config.app_id;

    let staging = tempfile::Builder::new()
        .prefix(".lunepack-fetch-")
        .tempdir_in(parent_of(&args.release_dir)?)
        .context("cannot create a working directory next to the release directory")?;
    let stage = staging.path();

    // keys.json, then the roots after the config's, then the key set under the last root.
    let keys_bytes = reader.required("keys.json", Limits::V1.keys_doc_bytes)?;
    let mut walk = RootWalk::new(config.trusted_root(&hasher, &verifier)?);
    let mut roots: Vec<(u64, Vec<u8>)> = Vec::new();
    while let Some(k) = walk.next_version() {
        let rel = format!("root-{k}.json");
        match reader.document(&rel, Limits::V1.root_doc_bytes)? {
            Document::Body(bytes) => {
                walk.advance(&bytes, &hasher, &verifier)
                    .with_context(|| format!("{rel} does not verify"))?;
                roots.push((k, bytes));
            }
            Document::Status(status) if ABSENT_ROOT_STATUSES.contains(&status) => break,
            Document::Status(status) => bail!("{rel}: the server answered {status}"),
        }
    }
    let chain = walk
        .verify_keys(
            app_id,
            &Floors::default(),
            &keys_bytes,
            &skip,
            &hasher,
            &verifier,
        )
        .context("keys.json does not verify under the roots")?;

    // The feeds of the publish channels: 404 is a channel nothing was published to.
    let mut feeds: Vec<(Channel, Vec<u8>, VerifiedFeed)> = Vec::new();
    for channel in &publish.channels {
        let rel = format!("feed-{}.json", channel.as_str());
        match reader.document(&rel, Limits::V1.feed_doc_bytes)? {
            Document::Body(bytes) => {
                let verified = verify_feed_of(&chain, app_id, channel, &bytes, &skip, &verifier)
                    .with_context(|| format!("{rel} does not verify"))?;
                feeds.push((channel.clone(), bytes, verified));
            }
            Document::Status(404) => {}
            Document::Status(status) => bail!("{rel}: the server answered {status}"),
        }
    }
    for (channel, _, feed) in &feeds {
        if feed
            .releases()
            .iter()
            .any(|r| r.version() == &version || r.version_text() == args.version)
        {
            bail!(
                "version {} is already published (feed-{}.json lists it)",
                args.version,
                channel.as_str()
            );
        }
    }

    // Only now, with the chain and the feeds verified, the bases.
    let mut wanted: BTreeMap<(String, Target), FeedTargetEntry> = BTreeMap::new();
    for (_, _, feed) in &feeds {
        bases_of(
            feed,
            &publish.require_targets,
            usize::from(publish.deltas),
            &version,
            &mut wanted,
        );
    }
    let mut placed = 0usize;
    for ((text, target), entry) in &wanted {
        let reference = entry.reference();
        let manifest_rel = reference.path().to_owned();
        let manifest_dest = under(stage, &manifest_rel)?;
        let bytes = reader.required(&manifest_rel, reference.size())?;
        let manifest = match verify_manifest(chain.keys(), entry, &bytes, &hasher, &verifier) {
            Ok(manifest) => manifest,
            Err(e) => {
                say(&format!(
                    "base: {text} {} skipped: {manifest_rel} does not verify: {e}",
                    target.as_str()
                ))?;
                continue;
            }
        };
        let pack_ref = manifest.pack();
        let pack_rel = pack_ref.path().to_owned();
        let pack_dest = under(stage, &pack_rel)?;
        if let Some(parent) = pack_dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        match reader.pack(&pack_rel, pack_ref.size(), pack_ref.sha256(), &pack_dest)? {
            Ok(()) => {}
            Err(why) => {
                // The version's directory goes too when nothing else of it was fetched.
                if let Some(parent) = pack_dest.parent() {
                    let _ = fs::remove_dir(parent);
                }
                say(&format!("base: {text} {} skipped: {why}", target.as_str()))?;
                continue;
            }
        }
        write_file(&manifest_dest, &bytes)?;
        placed += 1;
    }

    // Everything verified: write the documents and move the directory into place.
    write_file(&stage.join("keys.json"), &keys_bytes)?;
    for (k, bytes) in &roots {
        write_file(&stage.join(format!("root-{k}.json")), bytes)?;
    }
    for (channel, bytes, _) in &feeds {
        write_file(
            &stage.join(format!("feed-{}.json", channel.as_str())),
            bytes,
        )?;
    }
    let staged = staging.keep();
    #[cfg(unix)]
    fs::set_permissions(&staged, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .with_context(|| format!("cannot set the mode of {}", staged.display()))?;
    let placed_in = place(&staged, &args.release_dir);
    if placed_in.is_err() {
        let _ = fs::remove_dir_all(&staged);
    }
    placed_in?;
    say(&format!(
        "fetched: keys.json, {} root(s), {} feed(s), {placed} base(s) into {}",
        roots.len(),
        feeds.len(),
        args.release_dir.display()
    ))
}

/// The directory a new entry of `dir` is made in.
fn parent_of(dir: &Path) -> Result<PathBuf> {
    let absolute =
        std::path::absolute(dir).with_context(|| format!("cannot resolve {}", dir.display()))?;
    let parent = absolute
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", dir.display()))?
        .to_path_buf();
    fs::create_dir_all(&parent).with_context(|| format!("cannot create {}", parent.display()))?;
    Ok(parent)
}

/// Moves the finished directory to its place (the place is absent or empty).
fn place(staged: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        fs::remove_dir(dest).with_context(|| format!("cannot replace {}", dest.display()))?;
    }
    fs::rename(staged, dest).with_context(|| format!("cannot place {}", dest.display()))
}
