//! `lunepack publish push --release-dir <dir>... --version <v> --sign <signer>...` (P-D6..P-D13).
//!
//! A push builds the whole new published state in a work directory first and decides every write
//! before the first one: it reads the state file and the pending-deletes record from the private
//! store and the key set, roots and feeds from the public store (with credentials, not through
//! the CDN); holds every release directory to them (P-D6); merges the release's `<version>/`
//! files; downloads every retained release (P-D7); runs the feed writers in-process (`feed add`
//! for the new version, `feed refresh --drop` for retention); verifies the whole work directory
//! the way `verify` does; and checks every object it would upload against what the store holds.
//! Only then does it write, in the order of [`ORDER`] (P-D8):
//!
//! 1. the pending record with the version in `uploading`;
//! 2. the new version's packs and deltas, then its manifests (an equal object already there is
//!    kept, P-D9);
//! 3. the pending record with this run's deletes, before any feed;
//! 4. each changed feed, after re-reading it and refusing if it changed since this run read it;
//! 5. the deletes, each pending key whose version folder no current feed lists (a failed delete
//!    stays in the record, is named, and does not fail the run);
//! 6. the pending record as it is now; 7. the state file.
//!
//! `keys.json` and the roots are never written: P-D6 holds them equal to the store's copies, so
//! P-D8's second stage is empty for a push. A push stopped part-way is completed by running it
//! again with the same release directories (P-D13).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use lunepack_core::{
    AppId, Channel, Clock, ClockReading, KeysChain, Limits, MAX_ROOT_STEPS, StoreKey, Target,
    VerifiedFeed, Version,
};
use lunepack_crypto::Ed25519Verifier;

use super::pending::{PENDING_NAME, Pending, version_of};
use super::work::{self, LocalFile, StoreRead, Upload, feed_rel, key};
use super::{Stores, Usage, say, settings};
use crate::cmd_feed::{self, AddArgs, RefreshArgs, Writer};
use crate::cmd_verify::check_release_dir;
use crate::config::{Config, PublishSettings};
use crate::release_dir::{self, read_capped, verify_feed_of};
use crate::state::{DEFAULT_STATE, State, StateArgs};

/// The state file's name under the prefix (the existing state file format, M3-R2-D1).
pub const STATE_NAME: &str = DEFAULT_STATE;
const MANIFEST_SUFFIX: &str = ".manifest.json";

/// Arguments of `publish push`.
#[derive(Args)]
pub struct PushArgs {
    /// A release directory `publish fetch` filled and `pack` packed into; repeat for several (one
    /// per build job). Their `<version>/` files are merged.
    #[arg(long = "release-dir", required = true)]
    release_dirs: Vec<PathBuf>,
    /// The version to publish (SemVer), as its folder is named.
    #[arg(long)]
    version: String,
    /// Targets the release must have, comma-separated; added to `[publish] require_targets`.
    #[arg(long = "require-targets", value_delimiter = ',')]
    require_targets: Vec<String>,
    /// A release signer for the feeds: a name from the config, `file:<path>` or `env:<VAR>`;
    /// repeat to reach the key set's threshold.
    #[arg(long = "sign", required = true)]
    sign: Vec<String>,
    /// Do every read and check, print what would be written and deleted, and write nothing.
    #[arg(long = "dry-run")]
    dry_run: bool,
    /// Use a local directory as both buckets (`<dir>/public`, `<dir>/private`), for tests and
    /// trials; no credential is read.
    #[arg(long = "store-dir")]
    pub store_dir: Option<PathBuf>,
}

/// The clocks of a push: the one feeds are issued at (the writer clock, M3-D5) and the one the
/// finished work directory is verified at (the system clock: what a client sees).
#[derive(Clone)]
pub(crate) struct Clocks {
    pub feed: Arc<dyn Clock>,
    pub check: Arc<dyn Clock>,
}

/// A shared clock handed to a writer, which takes its clock by value.
pub(crate) struct Shared(pub(crate) Arc<dyn Clock>);

impl Clock for Shared {
    fn now_unix_secs(&self) -> u64 {
        self.0.now_unix_secs()
    }
}

/// One push, resolved from the command line.
pub(crate) struct Job<'a> {
    pub config_path: &'a Path,
    pub config: &'a Config,
    pub version: &'a str,
    pub release_dirs: &'a [PathBuf],
    pub require: Vec<Target>,
    pub sign: &'a [String],
    pub dry_run: bool,
    pub clocks: Clocks,
}

/// The stages of the commit, in the order a push runs them (P-D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// The pending record gains the version in `uploading`.
    MarkUploading,
    /// Packs, deltas and any other non-manifest object of the version.
    Objects,
    /// The version's manifests.
    Manifests,
    /// The pending record gains this run's deletes.
    RecordDeletes,
    /// Each changed feed, after its race check.
    Feeds,
    /// The pending deletes no current feed lists.
    Deletes,
    /// The pending record as it is after the deletes.
    FinalRecord,
    /// The state file.
    State,
}

/// The commit order.
pub(crate) const ORDER: [Phase; 8] = [
    Phase::MarkUploading,
    Phase::Objects,
    Phase::Manifests,
    Phase::RecordDeletes,
    Phase::Feeds,
    Phase::Deletes,
    Phase::FinalRecord,
    Phase::State,
];

/// One feed to write.
#[derive(Debug, Clone)]
pub(crate) struct FeedWrite {
    pub key: StoreKey,
    /// The bytes this run read at its start (`None`: no feed yet).
    pub read: Option<Vec<u8>>,
    /// The new feed.
    pub bytes: Vec<u8>,
}

/// Everything a push decided before its first write.
pub(crate) struct Plan {
    pub prefix: String,
    pub version: String,
    pub app_id: AppId,
    pub chain: KeysChain,
    /// The record as read, and whether the store had one.
    pub pending: Pending,
    pub pending_existed: bool,
    pub objects: Vec<Upload>,
    pub manifests: Vec<Upload>,
    /// Objects already in the store with the same bytes.
    pub kept: Vec<StoreKey>,
    /// The objects of the releases this run drops from every feed.
    pub deletes: BTreeSet<StoreKey>,
    pub feeds: Vec<FeedWrite>,
    /// Every feed key the delete filter reads: the `[publish]` channels' and the guard feeds'.
    pub feed_keys: Vec<(Channel, StoreKey)>,
    /// The version folders the new feeds list, for the dry run's view of the filter.
    pub listed_after: BTreeSet<String>,
    pub state_key: StoreKey,
    pub state_read: Vec<u8>,
    pub state: Vec<u8>,
}

impl Plan {
    /// What to do after the race check refused: a push has release directories built against the
    /// feed that moved, a refresh has nothing to rebuild.
    fn rerun_hint(&self) -> &'static str {
        if self.version.is_empty() {
            "Run `publish refresh` again"
        } else {
            "Run `publish fetch` and `pack` again, then `publish push`"
        }
    }
}

/// `publish push`.
pub fn push(config_path: &Path, args: &PushArgs, open: super::OpenStores<'_>) -> Result<()> {
    super::refuse_source_date_epoch("push")?;
    let config = Config::load(config_path)?;
    let (_, publish) = settings(&config)?;
    Version::parse(&args.version).map_err(|_| Usage("--version is not a SemVer version".into()))?;
    StoreKey::version_folder(&publish.prefix, &args.version)
        .map_err(|_| Usage("--version is not usable as a folder name".into()))?;
    let mut require = Vec::new();
    for text in &args.require_targets {
        let target = Target::parse(text).map_err(|_| {
            Usage("--require-targets names something that is not a target id".into())
        })?;
        require.push(target);
    }
    // The credentials are read here, before any request; a missing variable is named.
    let stores = open(publish, args.store_dir.as_deref())?;
    let job = Job {
        config_path,
        config: &config,
        version: &args.version,
        release_dirs: &args.release_dirs,
        require,
        sign: &args.sign,
        dry_run: args.dry_run,
        clocks: Clocks {
            feed: Arc::from(crate::config::writer_clock()?),
            check: Arc::new(lunepack::SystemClock),
        },
    };
    run(&job, &stores, &ORDER)
}

/// Plans the push, then commits it in `order` (always [`ORDER`] outside tests).
pub(crate) fn run(job: &Job<'_>, stores: &Stores, order: &[Phase]) -> Result<()> {
    let work = tempfile::Builder::new()
        .prefix("lunepack-push-")
        .tempdir()
        .context("cannot create a work directory")?;
    let plan = plan(job, stores, work.path())?;
    show(&plan, job.dry_run, order)?;
    if job.dry_run {
        return say("dry run: nothing was written");
    }
    commit(&plan, stores, order)?;
    say(&format!(
        "published: {} under {}/",
        plan.version, plan.prefix
    ))
}

/// The `root-<k>.json` files after `from` in `dir`, until the first gap.
pub(crate) fn local_roots(dir: &Path, from: u64) -> Result<Vec<(u64, Vec<u8>)>> {
    let mut out = Vec::new();
    for k in from + 1..=from + MAX_ROOT_STEPS {
        match read_capped(&release_dir::root_path(dir, k), Limits::V1.root_doc_bytes)? {
            Some(bytes) => out.push((k, bytes)),
            None => break,
        }
    }
    Ok(out)
}

fn changed(dir: &Path, what: &str) -> anyhow::Error {
    anyhow!(
        "the store changed since fetch: {what} in {} is not the store's (nothing was written); run `publish fetch` and `pack` again",
        dir.display()
    )
}

/// Reads, checks and decides everything before the first write.
fn plan(job: &Job<'_>, stores: &Stores, work_root: &Path) -> Result<Plan> {
    let config = job.config;
    let (_, publish) = settings(config)?;
    let prefix = publish.prefix.as_str();
    let v = job.version;
    let version = Version::parse(v).context("--version is not a SemVer version")?;
    let wdir = work_root.join("release");
    fs::create_dir(&wdir).context("cannot create the work directory")?;
    let state_file = work_root.join(STATE_NAME);
    let skip = ClockReading::read(job.clocks.check.as_ref(), Some(u64::MAX));

    // The two buckets' documents, verified (the state file is the first read).
    let StoreRead {
        state_key,
        state_read,
        pending,
        pending_existed,
        keys_bytes,
        roots,
        feeds_read,
        feed_keys,
        root_doc_k,
        chain,
        feeds: feeds_before,
        guard_feeds,
        guard_read: _,
    } = work::read_store(stores, config, publish, &wdir, &state_file, &skip)?;

    // The release: every release directory's `<version>/` files, merged.
    let mut new_files: BTreeMap<String, LocalFile> = BTreeMap::new();
    let mut from_dir: BTreeMap<String, &Path> = BTreeMap::new();
    for rd in job.release_dirs {
        for (rel, file) in work::version_files(rd, v)? {
            match new_files.get(&rel) {
                Some(have) if have.len != file.len || have.sha256 != file.sha256 => bail!(
                    "{rel} differs between {} and {} (nothing was written)",
                    from_dir[&rel].display(),
                    rd.display()
                ),
                Some(_) => {}
                None => {
                    from_dir.insert(rel.clone(), rd);
                    new_files.insert(rel, file);
                }
            }
        }
    }
    let mut new_manifests: BTreeMap<Target, (String, u64, [u8; 32])> = BTreeMap::new();
    for (rel, file) in &new_files {
        let Some(name) = rel.strip_prefix(&format!("{v}/")) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(MANIFEST_SUFFIX) else {
            continue;
        };
        if stem.contains('/') {
            continue;
        }
        let target = Target::parse(stem)
            .with_context(|| format!("{rel}: the name does not hold a target id"))?;
        new_manifests.insert(target, (rel.clone(), file.len, file.sha256));
    }
    if new_manifests.is_empty() {
        bail!("the release directories hold no manifest of {v}: pack it first");
    }
    let mut required: Vec<Target> = publish.require_targets.clone();
    required.extend(job.require.iter().copied());
    for target in &required {
        if !new_manifests.contains_key(target) {
            bail!(
                "the release has no {} target, which must be published (nothing was written)",
                target.as_str()
            );
        }
    }

    // P-D6: a feed that already lists the version (this version's own half-finished push) must
    // list exactly these manifests; its `feed add` is skipped.
    let mut skip_add: BTreeSet<Channel> = BTreeSet::new();
    for (channel, feed) in &feeds_before {
        let Some(release) = feed
            .releases()
            .iter()
            .find(|r| r.version_text() == v || *r.version() == version)
        else {
            continue;
        };
        let listed: BTreeMap<Target, (String, u64, [u8; 32])> = release
            .targets()
            .iter()
            .map(|(t, c)| (*t, (c.path().to_owned(), c.size(), *c.sha256().as_bytes())))
            .collect();
        if release.version_text() != v || listed != new_manifests {
            bail!(
                "the store changed since fetch: {} already lists {} with other manifests (nothing was written)",
                feed_rel(channel),
                release.version_text()
            );
        }
        skip_add.insert(channel.clone());
    }
    // P-D6: each release directory was built against exactly the store's documents.
    for rd in job.release_dirs {
        if read_capped(&release_dir::keys_path(rd), Limits::V1.keys_doc_bytes)?.as_deref()
            != Some(keys_bytes.as_slice())
        {
            return Err(changed(rd, "keys.json"));
        }
        if local_roots(rd, config.root_version)? != roots {
            return Err(changed(rd, "the root-<k>.json files"));
        }
        for (channel, bytes) in &feeds_read {
            if skip_add.contains(channel) {
                continue;
            }
            let local = read_capped(&rd.join(feed_rel(channel)), Limits::V1.feed_doc_bytes)?;
            if local != *bytes {
                return Err(changed(rd, &feed_rel(channel)));
            }
        }
    }

    // P-D7: every retained release, downloaded and checked.
    let (objects_of, fetched) = work::download_retained(
        stores.public.as_ref(),
        prefix,
        &wdir,
        &chain,
        &feeds_before,
        Some(v),
    )?;
    say(&format!(
        "retained: {fetched} manifest(s) of {} release(s) downloaded",
        objects_of.len()
    ))?;
    for (rel, file) in &new_files {
        let dest = work_root.join("release").join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).context("cannot write the work directory")?;
        }
        fs::copy(&file.path, &dest)
            .with_context(|| format!("cannot copy {}", file.path.display()))?;
    }

    // The feeds, written in the work directory by the feed writers.
    let mut wconfig = config.clone();
    wconfig.state_path = state_file.clone();
    let writer = |config: &Config| Writer {
        config_path: job.config_path,
        config: config.clone(),
        clock: Box::new(Shared(job.clocks.feed.clone())),
    };
    let prerelease = !version.as_semver().pre.is_empty();
    let targets = if prerelease {
        &publish.prerelease_channels
    } else {
        &publish.channels
    };
    for channel in targets {
        if skip_add.contains(channel) {
            say(&format!("{}: already lists {v}", feed_rel(channel)))?;
            continue;
        }
        cmd_feed::add_with(
            writer(&wconfig),
            &AddArgs {
                release_dir: wdir.clone(),
                channel: channel.as_str().to_owned(),
                version: v.to_owned(),
                rollout: None,
                rollout_seed: None,
                expires_after_days: Some(u64::from(publish.feed_days)),
                sign: job.sign.to_vec(),
                state: StateArgs::default(),
            },
        )?;
    }
    for channel in &publish.channels {
        let Some(feed) = work_feed(&wdir, config, &chain, channel, &skip)? else {
            continue;
        };
        let drop = retention(&feed, publish, v);
        if drop.is_empty() {
            continue;
        }
        say(&format!("{}: drops {}", feed_rel(channel), drop.join(", ")))?;
        cmd_feed::refresh_with(
            writer(&wconfig),
            &RefreshArgs {
                release_dir: wdir.clone(),
                channel: channel.as_str().to_owned(),
                expires_after_days: Some(u64::from(publish.feed_days)),
                drop,
                sign: job.sign.to_vec(),
                state: StateArgs::default(),
            },
        )?;
    }

    // The state: what the feeds now are, including those written by an earlier run of this push.
    let mut state = State::load(&state_file)?;
    let mut record = state.record(&config.app_id);
    let mut feeds_after: BTreeMap<Channel, VerifiedFeed> = BTreeMap::new();
    for channel in &publish.channels {
        if let Some(feed) = work_feed(&wdir, config, &chain, channel, &skip)? {
            let seq = record.feeds.entry(channel.as_str().to_owned()).or_insert(0);
            *seq = (*seq).max(feed.seq());
            feeds_after.insert(channel.clone(), feed);
        }
    }
    record.set_keys(root_doc_k, chain.keys());
    state.save(&config.app_id, record, StateArgs::default())?;
    let state_bytes = fs::read(&state_file).context("cannot read the work directory")?;

    // P-D7: the whole work directory, as a client checks it, before anything is written.
    let reading = ClockReading::read(job.clocks.check.as_ref(), None);
    let checked = check_release_dir(&wdir, config, &reading, &mut |l| {
        say(&format!("check: {l}"))
    })
    .context("the release would not verify (nothing was written)")?;
    let mut referenced = BTreeSet::new();
    for t in checked
        .feeds
        .iter()
        .flat_map(|f| &f.releases)
        .filter(|r| r.version == v)
        .flat_map(|r| &r.targets)
    {
        let deltas: Vec<_> = t.manifest.deltas().iter().map(|d| d.file()).collect();
        referenced.extend(work::objects_of(
            &t.manifest_path,
            t.manifest.pack(),
            &deltas,
        ));
    }
    let stray = work::unreferenced(new_files.keys(), &referenced);
    if !stray.is_empty() {
        bail!(
            "{} {} in {v}/ but no manifest of the release names it; only manifests, packs and deltas are published (nothing was written)",
            stray.join(", "),
            if stray.len() == 1 { "is" } else { "are" }
        );
    }

    // What is dropped from every feed, and the objects that go with it (P-D10).
    // The feeds of channels outside `[publish]` stay as they are and keep what they list.
    let listed_before = work::listed_versions(feeds_before.values().chain(guard_feeds.values()));
    let listed_after = work::listed_versions(feeds_after.values().chain(guard_feeds.values()));
    let mut deletes = BTreeSet::new();
    for dropped in listed_before.difference(&listed_after) {
        for rel in objects_of.get(dropped).into_iter().flatten() {
            let k = key(prefix, rel)?;
            if version_of(prefix, &k) != Some(dropped.as_str())
                || StoreKey::version_folder(prefix, dropped).is_err()
            {
                say(&format!(
                    "not purged: {k} lies outside the folder of {dropped}"
                ))?;
                continue;
            }
            deletes.insert(k);
        }
    }

    // The uploads: refused all together, before any write, when one differs from the store's.
    let mut objects = Vec::new();
    let mut manifests = Vec::new();
    let mut kept = Vec::new();
    let mut differ = Vec::new();
    for (rel, file) in &new_files {
        let up = Upload {
            key: key(prefix, rel)?,
            rel: rel.clone(),
            file: file.clone(),
        };
        match work::existing(stores.public.as_ref(), &up)? {
            Some(true) => kept.push(up.key),
            Some(false) => differ.push(up.key.to_string()),
            None if rel.ends_with(MANIFEST_SUFFIX) => manifests.push(up),
            None => objects.push(up),
        }
    }
    if !differ.is_empty() {
        bail!(
            "the store already holds other bytes at {} (nothing was written); a published object is never replaced",
            differ.join(", ")
        );
    }

    let mut feeds = Vec::new();
    for (channel, fk) in &feed_keys {
        let Some(bytes) = read_capped(&wdir.join(feed_rel(channel)), Limits::V1.feed_doc_bytes)?
        else {
            continue;
        };
        let read = feeds_read.get(channel).cloned().flatten();
        if read.as_deref() != Some(bytes.as_slice()) {
            feeds.push(FeedWrite {
                key: fk.clone(),
                read,
                bytes,
            });
        }
    }

    Ok(Plan {
        prefix: prefix.to_owned(),
        version: v.to_owned(),
        app_id: config.app_id.clone(),
        chain,
        pending,
        pending_existed,
        objects,
        manifests,
        kept,
        deletes,
        feeds,
        feed_keys,
        listed_after,
        state_key,
        state_read,
        state: state_bytes,
    })
}

/// The work directory's feed of `channel`, read with time checks skipped.
pub(crate) fn work_feed(
    wdir: &Path,
    config: &Config,
    chain: &KeysChain,
    channel: &Channel,
    skip: &ClockReading,
) -> Result<Option<VerifiedFeed>> {
    let Some(bytes) = read_capped(&wdir.join(feed_rel(channel)), Limits::V1.feed_doc_bytes)? else {
        return Ok(None);
    };
    Ok(Some(
        verify_feed_of(
            chain,
            &config.app_id,
            channel,
            &bytes,
            skip,
            &Ed25519Verifier,
        )
        .with_context(|| format!("the new {} does not verify", feed_rel(channel)))?,
    ))
}

/// The releases of `feed` beyond the newest `keep` by precedence (never by text or file order);
/// the version being published is never dropped.
pub(crate) fn retention(
    feed: &VerifiedFeed,
    publish: &PublishSettings,
    version: &str,
) -> Vec<String> {
    drops(
        feed.releases()
            .iter()
            .map(|r| (r.version().clone(), r.version_text().to_owned())),
        publish.keep as usize,
        version,
    )
}

/// [`retention`] over `(precedence, text)` pairs.
pub(crate) fn drops(
    releases: impl IntoIterator<Item = (Version, String)>,
    keep: usize,
    version: &str,
) -> Vec<String> {
    let mut ranked: Vec<_> = releases.into_iter().collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0));
    ranked
        .into_iter()
        .skip(keep)
        .map(|(_, text)| text)
        .filter(|text| text != version)
        .collect()
}

/// Prints the plan: in a dry run, everything a push would write and delete.
pub(crate) fn show(plan: &Plan, dry_run: bool, order: &[Phase]) -> Result<()> {
    let would = if dry_run { "would " } else { "" };
    for k in &plan.kept {
        say(&format!("kept: {k} (already in the store, the same bytes)"))?;
    }
    if !dry_run {
        return Ok(());
    }
    for up in plan.objects.iter().chain(&plan.manifests) {
        say(&format!(
            "{would}upload: {} ({} bytes)",
            up.key, up.file.len
        ))?;
    }
    if order.contains(&Phase::Feeds) {
        for f in &plan.feeds {
            say(&format!("{would}write: {}", f.key))?;
        }
    }
    // A command whose order has no delete phase (a refresh) leaves the private bucket alone.
    if !order.contains(&Phase::Deletes) {
        return Ok(());
    }
    let mut pending = plan.pending.clone();
    pending.keys.extend(plan.deletes.iter().cloned());
    let mut after = pending.clone();
    for k in &pending.keys {
        match version_of(&plan.prefix, k) {
            Some(folder) if plan.listed_after.contains(folder) => {
                say(&format!("{would}keep: {k} (a feed lists {folder})"))?;
                after.keys.remove(k);
            }
            _ => {
                say(&format!("{would}delete: {k}"))?;
                after.keys.remove(k);
            }
        }
    }
    after.uploading.retain(|u| !plan.listed_after.contains(u));
    if !plan.pending_existed || after != plan.pending {
        say(&format!(
            "{would}write: {}/{PENDING_NAME}: {}",
            plan.prefix,
            String::from_utf8_lossy(&after.to_bytes()).trim_end()
        ))?;
    }
    if plan.state != plan.state_read {
        say(&format!(
            "{would}write: {}: {}",
            plan.state_key,
            String::from_utf8_lossy(&plan.state)
                .split_whitespace()
                .collect::<String>()
        ))?;
    }
    Ok(())
}

/// Writes the plan in `order`.
pub(crate) fn commit(plan: &Plan, stores: &Stores, order: &[Phase]) -> Result<()> {
    let pending_key = key(&plan.prefix, PENDING_NAME)?;
    let mut pending = plan.pending.clone();
    let mut stored = plan.pending_existed.then(|| plan.pending.clone());
    let write_record = |p: &Pending, stored: &mut Option<Pending>| -> Result<()> {
        if stored.as_ref() == Some(p) {
            return Ok(());
        }
        work::put_bytes(
            stores.private.as_ref(),
            &pending_key,
            PENDING_NAME,
            &p.to_bytes(),
        )?;
        *stored = Some(p.clone());
        say(&format!("wrote: {pending_key}"))
    };
    for phase in order {
        match phase {
            Phase::MarkUploading => {
                if !plan.objects.is_empty() || !plan.manifests.is_empty() {
                    pending.uploading.insert(plan.version.clone());
                    write_record(&pending, &mut stored)?;
                }
            }
            Phase::Objects | Phase::Manifests => {
                let list = if *phase == Phase::Objects {
                    &plan.objects
                } else {
                    &plan.manifests
                };
                for up in list {
                    work::put_file(stores.public.as_ref(), up)?;
                    say(&format!("uploaded: {}", up.key))?;
                }
            }
            Phase::RecordDeletes => {
                pending.keys.extend(plan.deletes.iter().cloned());
                write_record(&pending, &mut stored)?;
            }
            Phase::Feeds => {
                for f in &plan.feeds {
                    let now = work::get(stores.public.as_ref(), &f.key, Limits::V1.feed_doc_bytes)?;
                    if now != f.read {
                        bail!(
                            "{} changed in the store since this run read it (another publish?); it was not written. {}",
                            f.key,
                            plan.rerun_hint()
                        );
                    }
                    work::put_bytes(stores.public.as_ref(), &f.key, f.key.as_str(), &f.bytes)?;
                    say(&format!("wrote: {}", f.key))?;
                }
            }
            Phase::Deletes => deletes(plan, stores, &mut pending)?,
            Phase::FinalRecord => write_record(&pending, &mut stored)?,
            Phase::State => {
                if plan.state != plan.state_read {
                    work::put_bytes(
                        stores.private.as_ref(),
                        &plan.state_key,
                        STATE_NAME,
                        &plan.state,
                    )?;
                    say(&format!("wrote: {}", plan.state_key))?;
                }
            }
        }
    }
    Ok(())
}

/// Runs the pending deletes (P-D8 (5)): every feed is re-read first, and a key whose version folder
/// a current feed lists is not deleted and leaves the record. A failed delete stays in the record.
pub(crate) fn deletes(plan: &Plan, stores: &Stores, pending: &mut Pending) -> Result<()> {
    let skip = ClockReading::read(&lunepack::SystemClock, Some(u64::MAX));
    let mut live = BTreeSet::new();
    for (channel, fk) in &plan.feed_keys {
        let bytes = match work::get(stores.public.as_ref(), fk, Limits::V1.feed_doc_bytes) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => continue,
            Err(e) => {
                say(&format!(
                    "not deleted: {} key(s) kept in the record, {fk} could not be read: {e:#}",
                    pending.keys.len()
                ))?;
                return Ok(());
            }
        };
        match verify_feed_of(
            &plan.chain,
            &plan.app_id,
            channel,
            &bytes,
            &skip,
            &Ed25519Verifier,
        ) {
            Ok(feed) => live.extend(feed.releases().iter().map(|r| r.version_text().to_owned())),
            Err(e) => {
                say(&format!(
                    "not deleted: {} key(s) kept in the record, {fk} does not verify: {e}",
                    pending.keys.len()
                ))?;
                return Ok(());
            }
        }
    }
    pending.uploading.retain(|u| !live.contains(u));
    for k in pending.keys.clone() {
        match version_of(&plan.prefix, &k) {
            Some(folder) if live.contains(folder) => {
                say(&format!("not deleted: {k} (a feed lists {folder} again)"))?;
                pending.keys.remove(&k);
            }
            _ => match stores.public.delete(&k) {
                Ok(()) => {
                    say(&format!("deleted: {k}"))?;
                    pending.keys.remove(&k);
                }
                Err(e) => say(&format!(
                    "not deleted: {e} (kept in the record for the next run)"
                ))?,
            },
        }
    }
    Ok(())
}
#[cfg(test)]
pub(crate) mod tests {
    //! The push logic over in-memory stores: the order of the writes, failures injected at every
    //! write and the rerun that completes the push (P-D13), the race check, retention and purge,
    //! and an invariant checker over the operation log that a reordering of the same plan fails.
    //! Fixtures are made at test time by the CLI's own code (key generation, `init`, `keys set`,
    //! `pack`) with throwaway keys.

    use std::io::Read;
    use std::sync::{Arc, Mutex, PoisonError};

    use clap::Parser;
    use lunepack_core::{
        Hasher, ObjectStore, StoreError, StoreMethod, encoding::hex_encode, verify_manifest,
    };
    use lunepack_crypto::Sha256Hasher;
    use lunepack_testkit::{MemStore, StoreFault};

    use super::*;

    const APP: &str = "org.example.hello";
    pub(crate) const P: &str = "hello";

    #[derive(Parser)]
    pub(crate) struct Wrap<A: clap::Args> {
        #[command(flatten)]
        args: A,
    }

    pub(crate) fn parse<A: clap::Args>(args: &[&str]) -> A {
        Wrap::<A>::try_parse_from(std::iter::once("lunepack").chain(args.iter().copied()))
            .expect("arguments parse")
            .args
    }

    pub(crate) fn s(p: &Path) -> &str {
        p.to_str().expect("utf-8 path")
    }

    pub(crate) fn k(rel: &str) -> StoreKey {
        StoreKey::new(P, rel).unwrap()
    }

    pub(crate) fn targets() -> [&'static str; 2] {
        if cfg!(windows) {
            ["windows-x86_64", "windows-aarch64"]
        } else {
            ["linux-x86_64", "linux-aarch64"]
        }
    }

    // --- a store that logs every operation with its body ------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub(crate) enum Bucket {
        Public,
        Private,
    }

    #[derive(Debug, Clone)]
    pub(crate) enum Op {
        Get,
        Put(StoreKey, Vec<u8>),
        Delete(StoreKey),
    }

    /// One logged operation: the bucket, the operation, and whether it took effect.
    pub(crate) type Log = Arc<Mutex<Vec<(Bucket, Op, bool)>>>;

    /// Before the `nth` (from 0) get of `key`, the store's object there becomes `bytes`.
    pub(crate) struct Hook {
        pub(crate) key: StoreKey,
        pub(crate) nth: usize,
        pub(crate) bytes: Vec<u8>,
    }

    pub(crate) struct Rec {
        bucket: Bucket,
        inner: MemStore,
        log: Log,
        hook: Arc<Mutex<Option<Hook>>>,
    }

    impl Rec {
        fn note(&self, op: Op, applied: bool) {
            self.log
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((self.bucket, op, applied));
        }
    }

    impl ObjectStore for Rec {
        fn get(&self, key: &StoreKey, max_len: u64) -> Result<Option<Vec<u8>>, StoreError> {
            {
                let mut hook = self.hook.lock().unwrap_or_else(PoisonError::into_inner);
                let fire = match hook.as_mut() {
                    Some(h) if &h.key == key && h.nth == 0 => true,
                    Some(h) if &h.key == key => {
                        h.nth -= 1;
                        false
                    }
                    _ => false,
                };
                if fire && let Some(h) = hook.take() {
                    self.inner.seed(key, &h.bytes);
                }
            }
            let got = self.inner.get(key, max_len);
            self.note(Op::Get, got.is_ok());
            got
        }

        fn put(
            &self,
            key: &StoreKey,
            body: &mut dyn Read,
            len: u64,
            sha256: [u8; 32],
            content_type: &str,
        ) -> Result<(), StoreError> {
            let mut bytes = Vec::new();
            body.read_to_end(&mut bytes).unwrap();
            let result = self.inner.put(
                key,
                &mut std::io::Cursor::new(&bytes),
                len,
                sha256,
                content_type,
            );
            let applied = self.inner.contents(key).as_deref() == Some(bytes.as_slice());
            self.note(Op::Put(key.clone(), bytes), applied);
            result
        }

        fn delete(&self, key: &StoreKey) -> Result<(), StoreError> {
            let result = self.inner.delete(key);
            self.note(Op::Delete(key.clone()), result.is_ok());
            result
        }
    }

    // --- the world: signing material, configs, the two buckets ------------------------------

    pub(crate) struct World {
        pub(crate) dir: tempfile::TempDir,
        /// The config `pack` runs under (no `[update]`), next to the publisher's state file.
        pub(crate) pack_config: PathBuf,
        /// The app's config with `[update]`, `[install]` and `[publish]`.
        pub(crate) config: PathBuf,
        pub(crate) release_signer: PathBuf,
        pub(crate) root_signer: PathBuf,
        pub(crate) release_public: String,
        pub(crate) public: MemStore,
        pub(crate) private: MemStore,
        pub(crate) log: Log,
        pub(crate) hook: Arc<Mutex<Option<Hook>>>,
    }

    pub(crate) type Snapshot = BTreeMap<StoreKey, Vec<u8>>;

    pub(crate) fn snapshot_of(store: &MemStore) -> Snapshot {
        store
            .keys()
            .into_iter()
            .map(|key| {
                let bytes = store.contents(&key).unwrap();
                (key, bytes)
            })
            .collect()
    }

    impl World {
        /// A bootstrapped app: `keys.json` in the public bucket and the state file in the private
        /// one, as `publish init` leaves them. `publish` is appended to `[publish]`.
        pub(crate) fn new(publish: &str) -> World {
            let dir = tempfile::tempdir().unwrap();
            let root = lunepack_crypto::generate_key_file(&dir.path().join("root")).unwrap();
            let release = lunepack_crypto::generate_key_file(&dir.path().join("release")).unwrap();
            let pack_config = dir.path().join("lunepack.toml");
            crate::cmd_keys::init(
                &pack_config,
                &parse(&["--app-id", APP, "--root-key", &hex_encode(&root.public_key)]),
            )
            .unwrap();
            let origin = dir.path().join("origin");
            fs::create_dir(&origin).unwrap();
            let root_sign = format!("file:{}", s(&root.path));
            crate::cmd_keys::set_keys(
                &pack_config,
                &parse(&[
                    "--release-dir",
                    s(&origin),
                    "--threshold",
                    "1",
                    "--release-key",
                    &hex_encode(&release.public_key),
                    "--sign",
                    &root_sign,
                ]),
            )
            .unwrap();
            let config = dir.path().join("app.toml");
            let mut text = fs::read_to_string(&pack_config).unwrap();
            text.push_str(&format!(
                "\n[update]\nfeed = \"https://updates.example.com/hello/\"\n\n[install]\nentry = \"bin/app\"\nname = \"Hello\"\n\n\
                 [publish]\nprefix = \"{P}\"\nstore = \"r2\"\naccount_id_env = \"HELLO_R2_ACCOUNT_ID\"\n\
                 access_key_env = \"HELLO_R2_KEY\"\nsecret_key_env = \"HELLO_R2_SECRET\"\n\
                 public_bucket = \"hello-public\"\nprivate_bucket = \"hello-private\"\n{publish}"
            ));
            fs::write(&config, text).unwrap();
            let hasher: Arc<dyn Hasher> = Arc::new(Sha256Hasher);
            let w = World {
                public: MemStore::new(hasher.clone()),
                private: MemStore::new(hasher),
                log: Log::default(),
                hook: Arc::default(),
                pack_config,
                config,
                release_signer: release.path,
                root_signer: root.path.clone(),
                release_public: hex_encode(&release.public_key),
                dir,
            };
            w.public.seed(
                &k("keys.json"),
                &fs::read(origin.join("keys.json")).unwrap(),
            );
            w.private.seed(
                &k(STATE_NAME),
                &fs::read(w.dir.path().join(STATE_NAME)).unwrap(),
            );
            w
        }

        /// A release directory as `publish fetch` fills it (here: everything the public bucket
        /// holds, so every listed release can be a base).
        pub(crate) fn fetch(&self, name: &str) -> PathBuf {
            let rd = self.dir.path().join(name);
            fs::create_dir(&rd).unwrap();
            for (key, bytes) in snapshot_of(&self.public) {
                let path = rd.join(&key.as_str()[P.len() + 1..]);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, bytes).unwrap();
            }
            rd
        }

        /// Packs `version` for `target` into `rd`.
        pub(crate) fn pack(&self, rd: &Path, version: &str, target: &str) {
            let input = self.dir.path().join(format!("input-{version}-{target}"));
            if !input.exists() {
                fs::create_dir_all(input.join("bin")).unwrap();
                fs::write(
                    input.join("bin/app"),
                    format!("app {version}\n").repeat(400),
                )
                .unwrap();
                fs::write(input.join("readme.txt"), format!("readme of {version}\n")).unwrap();
            }
            let sign = format!("file:{}", s(&self.release_signer));
            crate::cmd_pack::pack(
                &self.pack_config,
                &parse(&[
                    "--input",
                    s(&input),
                    "--version",
                    version,
                    "--target",
                    target,
                    "--release-dir",
                    s(rd),
                    "--sign",
                    &sign,
                ]),
                &crate::NoCodeSign,
            )
            .unwrap();
        }

        pub(crate) fn stores(&self) -> Stores {
            let rec = |bucket, inner: &MemStore| -> Box<dyn ObjectStore> {
                Box::new(Rec {
                    bucket,
                    inner: inner.clone(),
                    log: self.log.clone(),
                    hook: self.hook.clone(),
                })
            };
            Stores {
                public: rec(Bucket::Public, &self.public),
                private: rec(Bucket::Private, &self.private),
            }
        }

        pub(crate) fn push_in(
            &self,
            rds: &[PathBuf],
            version: &str,
            dry_run: bool,
            order: &[Phase],
        ) -> Result<()> {
            let config = Config::load(&self.config)?;
            let sign = [format!("file:{}", s(&self.release_signer))];
            let clock: Arc<dyn Clock> = Arc::new(lunepack::SystemClock);
            run(
                &Job {
                    config_path: &self.config,
                    config: &config,
                    version,
                    release_dirs: rds,
                    require: Vec::new(),
                    sign: &sign,
                    dry_run,
                    clocks: Clocks {
                        feed: clock.clone(),
                        check: clock,
                    },
                },
                &self.stores(),
                order,
            )
        }

        pub(crate) fn push(&self, rds: &[PathBuf], version: &str) -> Result<()> {
            self.push_in(rds, version, false, &ORDER)
        }

        /// fetch, pack one target, push: one ordinary publish.
        pub(crate) fn publish(&self, version: &str) {
            let rd = self.fetch(&format!("rd-{version}"));
            self.pack(&rd, version, targets()[0]);
            self.push(&[rd], version).unwrap();
        }

        pub(crate) fn log(&self) -> Vec<(Bucket, Op, bool)> {
            self.log.lock().unwrap().clone()
        }

        pub(crate) fn clear_log(&self) {
            self.log.lock().unwrap().clear();
        }

        /// The writes of the log (puts and deletes), as `(bucket, PUT|DELETE, key)`.
        pub(crate) fn writes(&self) -> Vec<(Bucket, &'static str, String)> {
            self.log()
                .into_iter()
                .filter_map(|(b, op, _)| match op {
                    Op::Put(key, _) => Some((b, "PUT", key.to_string())),
                    Op::Delete(key) => Some((b, "DELETE", key.to_string())),
                    Op::Get => None,
                })
                .collect()
        }

        pub(crate) fn chain(&self) -> KeysChain {
            let config = Config::load(&self.config).unwrap();
            let skip = ClockReading::read(&lunepack::SystemClock, Some(u64::MAX));
            // The key set under the root walk, as a client reaches it (a rotation adds roots).
            let docs = tempfile::tempdir().unwrap();
            for (key, bytes) in snapshot_of(&self.public) {
                let rel = &key.as_str()[P.len() + 1..];
                if rel == "keys.json" || (rel.starts_with("root-") && !rel.contains('/')) {
                    fs::write(docs.path().join(rel), bytes).unwrap();
                }
            }
            release_dir::open(docs.path(), &config, &Sha256Hasher, &Ed25519Verifier, &skip)
                .unwrap()
                .chain
                .unwrap()
        }

        pub(crate) fn feed(&self, channel: &str) -> Option<VerifiedFeed> {
            let bytes = self.public.contents(&k(&format!("feed-{channel}.json")))?;
            let skip = ClockReading::read(&lunepack::SystemClock, Some(u64::MAX));
            Some(
                verify_feed_of(
                    &self.chain(),
                    &AppId::parse(APP).unwrap(),
                    &Channel::parse(channel).unwrap(),
                    &bytes,
                    &skip,
                    &Ed25519Verifier,
                )
                .unwrap(),
            )
        }

        /// The versions the public bucket's feed of `channel` lists, sorted as text.
        pub(crate) fn listed(&self, channel: &str) -> Vec<String> {
            let mut out: Vec<String> = self
                .feed(channel)
                .map(|f| {
                    f.releases()
                        .iter()
                        .map(|r| r.version_text().to_owned())
                        .collect()
                })
                .unwrap_or_default();
            out.sort();
            out
        }

        pub(crate) fn pending(&self) -> Pending {
            Pending::parse(P, &self.private.contents(&k(PENDING_NAME)).unwrap()).unwrap()
        }

        pub(crate) fn state_record(&self) -> crate::state::Record {
            let p = self.dir.path().join("state-check.json");
            fs::write(&p, self.private.contents(&k(STATE_NAME)).unwrap()).unwrap();
            State::load(&p).unwrap().record(&AppId::parse(APP).unwrap())
        }

        /// The version folders that hold objects in the public bucket.
        pub(crate) fn folders(&self) -> BTreeSet<String> {
            snapshot_of(&self.public)
                .into_keys()
                .filter(|key| key.as_str()[P.len() + 1..].contains('/'))
                .filter_map(|key| version_of(P, &key).map(str::to_owned))
                .collect()
        }

        pub(crate) fn snapshot(&self) -> (Snapshot, Snapshot) {
            (snapshot_of(&self.public), snapshot_of(&self.private))
        }

        /// `keys rotate-root` in `rd`: a new root key (generated as `<name>` in the world's
        /// directory), signed by the root key file `old` and the new one. Returns the new key
        /// file.
        pub(crate) fn rotate_root(&self, rd: &Path, old: &Path, name: &str) -> PathBuf {
            let new_root = lunepack_crypto::generate_key_file(&self.dir.path().join(name)).unwrap();
            let old = format!("file:{}", s(old));
            let new = format!("file:{}", s(&new_root.path));
            crate::cmd_keys::rotate_root_cmd(
                &self.pack_config,
                &parse(&[
                    "--release-dir",
                    s(rd),
                    "--new-root-key",
                    &hex_encode(&new_root.public_key),
                    "--new-threshold",
                    "1",
                    "--sign",
                    &old,
                    "--sign-new",
                    &new,
                    "--trust-release-dir",
                ]),
            )
            .unwrap();
            new_root.path
        }

        /// Whether a client (and a push) can read the store's key set: `keys.json` verifies under
        /// the walk through every root the bucket holds.
        pub(crate) fn readable(&self) -> bool {
            let config = Config::load(&self.config).unwrap();
            let skip = ClockReading::read(&lunepack::SystemClock, Some(u64::MAX));
            let docs = tempfile::tempdir().unwrap();
            for (key, bytes) in snapshot_of(&self.public) {
                let rel = &key.as_str()[P.len() + 1..];
                if rel == "keys.json" || (rel.starts_with("root-") && !rel.contains('/')) {
                    fs::write(docs.path().join(rel), bytes).unwrap();
                }
            }
            release_dir::open(docs.path(), &config, &Sha256Hasher, &Ed25519Verifier, &skip)
                .is_ok_and(|o| o.chain.is_some())
        }

        /// Puts both buckets back to `snap`, with no fault and an empty log.
        pub(crate) fn restore(&self, snap: &(Snapshot, Snapshot)) {
            for (store, objects) in [(&self.public, &snap.0), (&self.private, &snap.1)] {
                for key in snapshot_of(store).into_keys() {
                    store.delete(&key).unwrap();
                }
                for (key, bytes) in objects {
                    store.seed(key, bytes);
                }
                store.clear_faults();
            }
            self.clear_log();
        }
    }

    pub(crate) fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    // --- the invariant checker ---------------------------------------------------------------

    /// The objects a feed's bytes list, given the objects present: every manifest, and the pack
    /// and deltas of each manifest present. `missing` gets each listed object that is absent.
    pub(crate) fn listed_objects(
        chain: &KeysChain,
        feed_key: &StoreKey,
        feed: &[u8],
        present: &Snapshot,
        missing: &mut Vec<StoreKey>,
    ) -> BTreeSet<StoreKey> {
        let name = &feed_key.as_str()[P.len() + 1..];
        let channel = name
            .strip_prefix("feed-")
            .and_then(|n| n.strip_suffix(".json"))
            .unwrap();
        let skip = ClockReading::read(&lunepack::SystemClock, Some(u64::MAX));
        let feed = verify_feed_of(
            chain,
            &AppId::parse(APP).unwrap(),
            &Channel::parse(channel).unwrap(),
            feed,
            &skip,
            &Ed25519Verifier,
        )
        .unwrap();
        let mut out = BTreeSet::new();
        for (i, release) in feed.releases().iter().enumerate() {
            for target in release.targets().keys() {
                let entry = feed.target_entry(i, *target).unwrap();
                let mk = k(entry.reference().path());
                out.insert(mk.clone());
                let Some(bytes) = present.get(&mk) else {
                    missing.push(mk);
                    continue;
                };
                let manifest =
                    verify_manifest(chain.keys(), &entry, bytes, &Sha256Hasher, &Ed25519Verifier)
                        .unwrap();
                let mut objects = vec![k(manifest.pack().path())];
                objects.extend(manifest.deltas().iter().map(|d| k(d.file().path())));
                for o in objects {
                    if !present.contains_key(&o) {
                        missing.push(o.clone());
                    }
                    out.insert(o);
                }
            }
        }
        out
    }

    pub(crate) fn is_feed(key: &StoreKey) -> bool {
        let rel = &key.as_str()[P.len() + 1..];
        rel.starts_with("feed-") && !rel.contains('/')
    }

    /// Replays the public bucket's log from `initial`: no feed is written before every object it
    /// lists is there, and no object is deleted while a feed in the bucket lists it.
    pub(crate) fn check_invariants(
        chain: &KeysChain,
        initial: &Snapshot,
        log: &[(Bucket, Op, bool)],
    ) -> std::result::Result<(), String> {
        let mut sim = initial.clone();
        for (bucket, op, applied) in log {
            if *bucket != Bucket::Public || !applied {
                continue;
            }
            match op {
                Op::Get => {}
                Op::Put(key, body) => {
                    if is_feed(key) {
                        let mut missing = Vec::new();
                        listed_objects(chain, key, body, &sim, &mut missing);
                        if let Some(m) = missing.first() {
                            return Err(format!("{key} was written before {m}"));
                        }
                    }
                    sim.insert(key.clone(), body.clone());
                }
                Op::Delete(key) => {
                    for (fk, body) in sim.iter().filter(|(fk, _)| is_feed(fk)) {
                        if listed_objects(chain, fk, body, &sim, &mut Vec::new()).contains(key) {
                            return Err(format!("{key} was deleted while {fk} lists it"));
                        }
                    }
                    sim.remove(key);
                }
            }
        }
        Ok(())
    }

    /// Every listed object of every feed in the bucket is there.
    pub(crate) fn assert_consistent(w: &World) {
        let chain = w.chain();
        let present = snapshot_of(&w.public);
        for fk in present.keys().filter(|key| is_feed(key)) {
            let mut missing = Vec::new();
            listed_objects(&chain, fk, &present[fk], &present, &mut missing);
            assert!(missing.is_empty(), "{fk} lists missing {missing:?}");
        }
    }

    // --- tests -----------------------------------------------------------------------------------

    #[test]
    fn a_first_publish_writes_in_the_commit_order() {
        let w = World::new("");
        let rd = w.fetch("rd");
        w.pack(&rd, "1.0.0", targets()[0]);
        let initial = snapshot_of(&w.public);
        w.push(&[rd], "1.0.0").unwrap();
        let t = targets()[0];
        let writes = w.writes();
        let pos = |what: &str| {
            writes
                .iter()
                .position(|(_, _, key)| key == what)
                .unwrap_or_else(|| panic!("{what} not written: {writes:?}"))
        };
        let pending = format!("{P}/{PENDING_NAME}");
        let pack = pos(&format!("{P}/1.0.0/{t}.pack"));
        let manifest = pos(&format!("{P}/1.0.0/{t}.manifest.json"));
        let feed = pos(&format!("{P}/feed-stable.json"));
        let state = pos(&format!("{P}/{STATE_NAME}"));
        assert_eq!(writes[0], (Bucket::Private, "PUT", pending.clone()));
        assert!(
            0 < pack && pack < manifest && manifest < feed && feed < state,
            "{writes:?}"
        );
        assert_eq!(
            state,
            writes.len() - 1,
            "the state file is last: {writes:?}"
        );
        // The record's last write comes after the feed and leaves nothing behind.
        let last_record = writes
            .iter()
            .rposition(|(_, _, key)| *key == pending)
            .unwrap();
        assert!(feed < last_record && last_record < state, "{writes:?}");
        assert_eq!(w.pending(), Pending::default());
        assert_eq!(w.listed("stable"), ["1.0.0"]);
        assert_eq!(
            w.public
                .content_type(&k(&format!("1.0.0/{t}.pack")))
                .as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(
            w.public.content_type(&k("feed-stable.json")).as_deref(),
            Some("application/json")
        );
        check_invariants(&w.chain(), &initial, &w.log()).unwrap();
        assert_consistent(&w);
        assert_eq!(
            w.state_record().feeds.get("stable"),
            Some(&w.feed("stable").unwrap().seq())
        );
    }

    #[test]
    fn retention_keeps_the_newest_by_precedence_and_purges_the_rest() {
        let w = World::new("keep = 2\n");
        w.publish("1.9.0");
        w.publish("1.10.0");
        assert_eq!(w.folders(), set(&["1.9.0", "1.10.0"]));
        let before = snapshot_of(&w.public);
        w.clear_log();
        w.publish("1.11.0");
        // By text order 1.10.0 would go; by precedence 1.9.0 does.
        assert_eq!(w.listed("stable"), ["1.10.0", "1.11.0"]);
        assert_eq!(w.folders(), set(&["1.10.0", "1.11.0"]));
        assert_eq!(w.pending(), Pending::default());
        check_invariants(&w.chain(), &before, &w.log()).unwrap();
        assert_consistent(&w);
        // The record held the deletes before the feed was written, and the deletes came after.
        let writes = w.writes();
        let feed = writes
            .iter()
            .position(|(_, _, key)| key.ends_with("feed-stable.json"))
            .unwrap();
        let recorded_before_feed = w
            .log()
            .into_iter()
            .take_while(|(_, op, _)| !matches!(op, Op::Put(key, _) if is_feed(key)))
            .any(|(_, op, _)| match op {
                Op::Put(key, body) if key.as_str().ends_with(PENDING_NAME) => {
                    Pending::parse(P, &body)
                        .unwrap()
                        .keys
                        .iter()
                        .any(|key| key.as_str().contains("/1.9.0/"))
                }
                _ => false,
            });
        assert!(recorded_before_feed, "{writes:?}");
        let first_delete = writes.iter().position(|(_, m, _)| *m == "DELETE").unwrap();
        assert!(feed < first_delete, "{writes:?}");
    }

    #[test]
    fn retention_ranks_by_precedence_and_never_drops_the_new_version() {
        let w = World::new("keep = 2\n");
        w.publish("1.10.0");
        w.publish("2.0.0-rc.1");
        // 1.9.0 is below both, but the version being published stays.
        w.publish("1.9.0");
        assert_eq!(w.listed("stable"), ["1.10.0", "1.9.0", "2.0.0-rc.1"]);
        // 2.0.0-rc.1 < 2.0.0, and 1.9.0 < 1.10.0.
        w.publish("2.0.0");
        assert_eq!(w.listed("stable"), ["2.0.0", "2.0.0-rc.1"]);
        assert_eq!(w.folders(), set(&["2.0.0", "2.0.0-rc.1"]));
        assert_consistent(&w);
    }

    #[test]
    fn a_version_another_channel_lists_is_not_purged() {
        let w = World::new(
            "channels = [\"stable\", \"beta\"]\nprerelease_channels = [\"beta\"]\nkeep = 1\n",
        );
        w.publish("1.0.0");
        assert_eq!(w.listed("stable"), ["1.0.0"]);
        assert_eq!(w.listed("beta"), ["1.0.0"]);
        // A pre-release goes to beta only; beta drops 1.0.0, which stable still lists.
        w.publish("2.0.0-rc.1");
        assert_eq!(w.listed("stable"), ["1.0.0"]);
        assert_eq!(w.listed("beta"), ["2.0.0-rc.1"]);
        assert_eq!(w.folders(), set(&["1.0.0", "2.0.0-rc.1"]));
        // 2.0.0 goes to both: stable drops 1.0.0 too, and it is purged.
        w.publish("2.0.0");
        assert_eq!(w.listed("stable"), ["2.0.0"]);
        assert_eq!(w.listed("beta"), ["2.0.0"]);
        assert_eq!(w.folders(), set(&["2.0.0"]));
        assert_consistent(&w);
    }

    #[test]
    fn a_feed_of_a_channel_taken_out_of_the_config_still_protects_what_it_lists() {
        let w = World::new(
            "channels = [\"stable\", \"beta\"]\nprerelease_channels = [\"beta\"]\nkeep = 1\n",
        );
        w.publish("1.0.0");
        // beta is taken out of `[publish]`; its feed stays in the bucket and the state records it.
        let text = fs::read_to_string(&w.config).unwrap();
        fs::write(
            &w.config,
            text.replace(
                "channels = [\"stable\", \"beta\"]\nprerelease_channels = [\"beta\"]\n",
                "channels = [\"stable\"]\n",
            ),
        )
        .unwrap();
        assert!(
            fs::read_to_string(&w.config)
                .unwrap()
                .contains("channels = [\"stable\"]")
        );
        w.publish("1.1.0");
        assert_eq!(w.listed("stable"), ["1.1.0"]);
        assert_eq!(w.listed("beta"), ["1.0.0"], "the beta feed is not written");
        assert_eq!(w.folders(), set(&["1.0.0", "1.1.0"]));
        assert_eq!(w.pending(), Pending::default());
        // The guard feed is read with the others, so the delete filter sees it too.
        w.publish("1.2.0");
        assert_eq!(w.folders(), set(&["1.0.0", "1.2.0"]));
        assert_consistent(&w);
    }

    #[test]
    fn release_dirs_merge_and_a_conflict_or_a_missing_target_refuses() {
        let [a, b] = targets();
        let w = World::new(&format!("require_targets = [\"{a}\"]\n"));
        let rd1 = w.fetch("rd1");
        let rd2 = w.fetch("rd2");
        w.pack(&rd1, "1.0.0", a);
        w.pack(&rd2, "1.0.0", b);
        // A required target that is not there.
        let e = format!(
            "{:#}",
            w.push(std::slice::from_ref(&rd2), "1.0.0").unwrap_err()
        );
        assert!(e.contains(&format!("no {a} target")), "{e}");
        // The same path with other bytes.
        let rd3 = w.fetch("rd3");
        fs::create_dir_all(rd3.join("1.0.0")).unwrap();
        let name = format!("1.0.0/{a}.pack");
        let mut other = fs::read(rd1.join(&name)).unwrap();
        other[0] ^= 1;
        fs::write(rd3.join(&name), other).unwrap();
        let e = format!("{:#}", w.push(&[rd1.clone(), rd3], "1.0.0").unwrap_err());
        assert!(e.contains(&format!("{name} differs between")), "{e}");
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        // Both targets merged into one release.
        w.push(&[rd1, rd2], "1.0.0").unwrap();
        let feed = w.feed("stable").unwrap();
        let targets: Vec<&str> = feed.releases()[0]
            .targets()
            .keys()
            .map(|t| t.as_str())
            .collect();
        assert_eq!(targets.len(), 2, "{targets:?}");
        assert_consistent(&w);
    }

    #[test]
    fn a_stray_file_in_the_version_folder_refuses() {
        let w = World::new("");
        let rd = w.fetch("rd");
        w.pack(&rd, "1.0.0", targets()[0]);
        fs::write(rd.join("1.0.0/notes.txt"), "x").unwrap();
        let e = format!("{:#}", w.push(&[rd], "1.0.0").unwrap_err());
        assert!(
            e.contains("1.0.0/notes.txt is in 1.0.0/ but no manifest"),
            "{e}"
        );
        assert!(w.writes().is_empty());
    }

    #[test]
    fn the_store_changed_since_fetch_refuses_before_any_write() {
        let w = World::new("");
        w.publish("1.0.0");
        // Another release published after this release dir was fetched.
        let rd = w.fetch("rd");
        w.pack(&rd, "1.1.0", targets()[0]);
        w.publish("1.0.5");
        w.clear_log();
        let e = format!("{:#}", w.push(&[rd], "1.1.0").unwrap_err());
        assert!(
            e.contains("the store changed since fetch: feed-stable.json"),
            "{e}"
        );
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        // A keys.json in the release dir that is not the store's.
        let rd2 = w.fetch("rd2");
        w.pack(&rd2, "1.1.0", targets()[0]);
        let mut keys = fs::read(rd2.join("keys.json")).unwrap();
        keys.push(b'\n');
        fs::write(rd2.join("keys.json"), keys).unwrap();
        let e = format!("{:#}", w.push(&[rd2], "1.1.0").unwrap_err());
        assert!(
            e.contains("the store changed since fetch: keys.json"),
            "{e}"
        );
        assert!(w.writes().is_empty());
    }

    #[test]
    fn an_object_that_differs_refuses_before_any_upload_and_an_equal_one_is_kept() {
        let w = World::new("");
        let rd = w.fetch("rd");
        let t = targets()[0];
        w.pack(&rd, "1.0.0", t);
        let pack = k(&format!("1.0.0/{t}.pack"));
        w.public.seed(&pack, b"something else");
        let e = format!(
            "{:#}",
            w.push(std::slice::from_ref(&rd), "1.0.0").unwrap_err()
        );
        assert!(e.contains(&format!("other bytes at {pack}")), "{e}");
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        w.public.seed(
            &pack,
            &fs::read(rd.join(format!("1.0.0/{t}.pack"))).unwrap(),
        );
        w.push(&[rd], "1.0.0").unwrap();
        assert!(
            !w.writes()
                .iter()
                .any(|(_, _, key)| *key == pack.to_string())
        );
        assert_eq!(w.listed("stable"), ["1.0.0"]);
    }

    #[test]
    fn a_dry_run_reads_and_checks_and_writes_nothing() {
        let w = World::new("keep = 1\n");
        w.publish("1.0.0");
        let snap = w.snapshot();
        let rd = w.fetch("rd");
        w.pack(&rd, "1.1.0", targets()[0]);
        w.clear_log();
        w.push_in(std::slice::from_ref(&rd), "1.1.0", true, &ORDER)
            .unwrap();
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        assert!(w.snapshot() == snap, "a dry run changed a bucket");
        // A dry run still refuses what a push refuses.
        fs::write(rd.join("1.1.0/stray"), "x").unwrap();
        assert!(w.push_in(&[rd], "1.1.0", true, &ORDER).is_err());
    }

    #[test]
    fn no_state_file_or_no_key_set_refuses() {
        let w = World::new("");
        let rd = w.fetch("rd");
        w.pack(&rd, "1.0.0", targets()[0]);
        let state = w.private.contents(&k(STATE_NAME)).unwrap();
        w.private.delete(&k(STATE_NAME)).unwrap();
        let e = format!(
            "{:#}",
            w.push(std::slice::from_ref(&rd), "1.0.0").unwrap_err()
        );
        assert!(e.contains("publish init"), "{e}");
        w.private.seed(&k(STATE_NAME), &state);
        w.public.delete(&k("keys.json")).unwrap();
        let e = format!("{:#}", w.push(&[rd], "1.0.0").unwrap_err());
        assert!(e.contains("has no hello/keys.json"), "{e}");
        assert!(w.writes().is_empty());
    }

    #[test]
    fn the_race_check_refuses_a_feed_that_changed_since_it_was_read() {
        let w = World::new("");
        w.publish("1.0.0");
        let rd = w.fetch("rd");
        w.pack(&rd, "1.1.0", targets()[0]);
        let feed = w.public.contents(&k("feed-stable.json")).unwrap();
        // The second get of the feed is the race check's; before it, another feed lands.
        let mut theirs = feed.clone();
        theirs.push(b' ');
        *w.hook.lock().unwrap() = Some(Hook {
            key: k("feed-stable.json"),
            nth: 1,
            bytes: theirs.clone(),
        });
        w.clear_log();
        let e = format!("{:#}", w.push(&[rd], "1.1.0").unwrap_err());
        assert!(
            e.contains("feed-stable.json changed in the store since this run read it"),
            "{e}"
        );
        assert_eq!(w.public.contents(&k("feed-stable.json")).unwrap(), theirs);
        let writes = w.writes();
        assert!(
            !writes
                .iter()
                .any(|(_, _, key)| key.ends_with("feed-stable.json"))
        );
        assert!(!writes.iter().any(|(_, _, key)| key.ends_with(STATE_NAME)));
        assert!(writes.iter().any(|(_, _, key)| key.contains("/1.1.0/")));
        assert!(w.pending().uploading.contains("1.1.0"));
    }

    #[test]
    fn a_failed_delete_stays_in_the_record_and_the_next_run_retries_it() {
        let w = World::new("keep = 1\n");
        w.publish("1.0.0");
        let t = targets()[0];
        let pack = k(&format!("1.0.0/{t}.pack"));
        w.public
            .inject(StoreMethod::Delete, Some(&pack), StoreFault::Status(503));
        w.publish("1.1.0");
        assert_eq!(w.listed("stable"), ["1.1.0"]);
        assert!(w.public.contents(&pack).is_some());
        assert_eq!(w.pending().keys, BTreeSet::from([pack.clone()]));
        w.public.clear_faults();
        w.publish("1.2.0");
        assert!(w.public.contents(&pack).is_none());
        assert_eq!(w.pending(), Pending::default());
        assert_eq!(w.folders(), set(&["1.2.0"]));
    }

    /// The scenario of the failure tests: 1.0.0 and 1.1.0 on two channels with `keep = 2`, then
    /// 1.2.0, which drops 1.0.0 from both.
    fn failure_world() -> (World, PathBuf) {
        let w = World::new("channels = [\"stable\", \"beta\"]\nkeep = 2\n");
        w.publish("1.0.0");
        w.publish("1.1.0");
        let rd = w.fetch("rd-1.2.0-shared");
        w.pack(&rd, "1.2.0", targets()[0]);
        w.clear_log();
        (w, rd)
    }

    fn assert_complete(w: &World) {
        assert_eq!(w.listed("stable"), ["1.1.0", "1.2.0"]);
        assert_eq!(w.listed("beta"), ["1.1.0", "1.2.0"]);
        assert_eq!(w.folders(), set(&["1.1.0", "1.2.0"]));
        assert_eq!(w.pending(), Pending::default());
        assert_consistent(w);
        let record = w.state_record();
        for channel in ["stable", "beta"] {
            assert_eq!(
                record.feeds.get(channel),
                Some(&w.feed(channel).unwrap().seq()),
                "{channel}"
            );
        }
    }

    #[test]
    fn a_rerun_completes_a_push_stopped_at_any_write() {
        let (w, rd) = failure_world();
        let snap = w.snapshot();
        w.push(std::slice::from_ref(&rd), "1.2.0").unwrap();
        assert_complete(&w);
        // Every write of the clean run, with the count of earlier writes to the same key.
        let mut seen: BTreeMap<(Bucket, &'static str, String), usize> = BTreeMap::new();
        let points: Vec<_> = w
            .writes()
            .into_iter()
            .map(|op| {
                let n = seen.entry(op.clone()).or_default();
                *n += 1;
                (op, *n - 1)
            })
            .collect();
        let deletes = points
            .iter()
            .filter(|((_, m, _), _)| *m == "DELETE")
            .count();
        assert!(deletes >= 2 && points.len() >= deletes + 8, "{points:?}");
        for fault in [StoreFault::Status(500), StoreFault::LostAnswer] {
            for ((bucket, method, key), after) in &points {
                w.restore(&snap);
                let store = match bucket {
                    Bucket::Public => &w.public,
                    Bucket::Private => &w.private,
                };
                let method = if *method == "PUT" {
                    StoreMethod::Put
                } else {
                    StoreMethod::Delete
                };
                let key = StoreKey::parse(P, key).unwrap();
                store.inject_after(method, Some(&key), *after, fault);
                let first = w.push(std::slice::from_ref(&rd), "1.2.0");
                if method == StoreMethod::Delete {
                    first.unwrap_or_else(|e| panic!("a failed delete is not fatal: {e:#}"));
                } else {
                    assert!(
                        first.is_err(),
                        "{fault:?} at {key}: a failed write fails the push"
                    );
                }
                check_invariants(&w.chain(), &snap.0, &w.log())
                    .unwrap_or_else(|e| panic!("{fault:?} at {key}: {e}"));
                assert_consistent(&w);
                // The rerun, with the same release dir and nothing failing (P-D13).
                w.public.clear_faults();
                w.private.clear_faults();
                w.push(std::slice::from_ref(&rd), "1.2.0")
                    .unwrap_or_else(|e| panic!("{fault:?} at {key}: the rerun failed: {e:#}"));
                assert_complete(&w);
            }
        }
    }

    /// The same plan with phase `moved` run just before `before`: a test-only order, never in the
    /// binary.
    fn reordered(moved: Phase, before: Phase) -> Vec<Phase> {
        let mut order: Vec<Phase> = ORDER.iter().copied().filter(|p| *p != moved).collect();
        let at = order.iter().position(|p| *p == before).unwrap();
        order.insert(at, moved);
        order
    }

    #[test]
    fn the_checker_passes_the_real_order_and_fails_a_reordered_plan() {
        // The feeds moved before the objects they list.
        let (w, rd) = failure_world();
        let snap = w.snapshot();
        w.push(std::slice::from_ref(&rd), "1.2.0").unwrap();
        check_invariants(&w.chain(), &snap.0, &w.log()).unwrap();
        w.restore(&snap);
        w.push_in(
            std::slice::from_ref(&rd),
            "1.2.0",
            false,
            &reordered(Phase::Feeds, Phase::Objects),
        )
        .unwrap();
        let e = check_invariants(&w.chain(), &snap.0, &w.log()).unwrap_err();
        assert!(
            e.contains("feed-") && e.contains("was written before"),
            "{e}"
        );

        // The purge moved before the feeds, with a version published again while its old
        // objects are still in the pending record (an earlier run deleted them, then stopped
        // before it rewrote the record).
        let w = World::new("keep = 1\n");
        w.publish("1.0.0");
        w.publish("1.1.0");
        let t = targets()[0];
        let stale: BTreeSet<StoreKey> = [
            k(&format!("1.0.0/{t}.pack")),
            k(&format!("1.0.0/{t}.manifest.json")),
        ]
        .into();
        let mut record = w.pending();
        record.keys.extend(stale.iter().cloned());
        w.private.seed(&k(PENDING_NAME), &record.to_bytes());
        let rd = w.fetch("rd-again");
        w.pack(&rd, "1.0.0", t);
        let snap = w.snapshot();
        w.clear_log();
        w.push(std::slice::from_ref(&rd), "1.0.0").unwrap();
        check_invariants(&w.chain(), &snap.0, &w.log()).unwrap();
        assert!(w.public.contents(&k(&format!("1.0.0/{t}.pack"))).is_some());
        assert!(w.pending().keys.is_disjoint(&stale));
        assert_consistent(&w);
        w.restore(&snap);
        w.push_in(
            &[rd],
            "1.0.0",
            false,
            &reordered(Phase::Deletes, Phase::Feeds),
        )
        .unwrap();
        let e = check_invariants(&w.chain(), &snap.0, &w.log()).unwrap_err();
        assert!(e.contains("was written before"), "{e}");
    }
}
