//! `lunepack publish drop --version <v> --sign <signer>... [--dry-run]` (S6, user Q12).
//!
//! Takes one release out of every `[publish]` channel's feed that lists it and deletes its objects:
//! the push job's command, run with the push token (it writes both buckets). It reads the stores
//! the way a push does (the state file first, the pending record, the key set, every feed, the
//! guard feeds included), refuses a store older than the state file records, downloads and checks
//! every listed release (P-D7), re-signs each feed that lists the version through the in-process
//! `feed refresh --drop`, and verifies the work directory before the first write. It writes, in
//! the order of [`ORDER`]:
//!
//! 1. the pending record with the release's objects (from its verified manifests), before any feed;
//! 2. each changed feed, after its race check;
//! 3. the state file with the new feeds' `seq`, so a pre-drop feed put back is older than the record
//!    and refused by every later refresh, push and drop (S6);
//! 4. the deletes (P-D8 (5): a key whose version a current feed lists is not deleted);
//! 5. the pending record as it is now.
//!
//! A drop stopped part-way is completed by running it again: while a feed lists the version the
//! rerun drops it, and once none does the pending record still names its objects (it holds them
//! from the first write to the last), so the rerun runs the deletes and the writes after them. A
//! version no feed lists and the record does not name is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Args;
use lunepack_core::{Channel, Clock, ClockReading, Limits, StoreKey, VerifiedFeed, Version};

use super::pending::version_of;
use super::push::{FeedWrite, Phase, Plan, Shared, commit, show, work_feed};
use super::refresh::refuse_rolled_back;
use super::work::{self, StoreRead, feed_rel, key};
use super::{Stores, Usage, say, settings};
use crate::cmd_feed::{self, RefreshArgs as FeedRefreshArgs, Writer};
use crate::cmd_verify::check_release_dir;
use crate::config::Config;
use crate::release_dir::read_capped;
use crate::state::{DEFAULT_STATE, State, StateArgs};

/// Arguments of `publish drop`.
#[derive(Args)]
pub struct DropArgs {
    /// The release to take out of every `[publish]` channel's feed that lists it, by its version
    /// text as the feeds list it; its objects are deleted.
    #[arg(long)]
    version: String,
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

/// One drop, resolved from the command line.
pub(crate) struct Job<'a> {
    pub config_path: &'a Path,
    pub config: &'a Config,
    pub version: &'a str,
    pub sign: &'a [String],
    pub dry_run: bool,
    /// The time feeds are issued and checked at.
    pub clock: Arc<dyn Clock>,
}

/// The commit order of a drop. The state file comes right after the feeds, before the deletes: the
/// record holds the release's objects until the last write, so a rerun after any write finds what
/// is left to do, and the state file records the new feeds as early as it can (S6).
pub(crate) const ORDER: [Phase; 5] = [
    Phase::RecordDeletes,
    Phase::Feeds,
    Phase::State,
    Phase::Deletes,
    Phase::FinalRecord,
];

/// `publish drop`.
pub fn drop_release(
    config_path: &Path,
    args: &DropArgs,
    open: super::OpenStores<'_>,
) -> Result<()> {
    super::refuse_source_date_epoch("drop")?;
    let config = Config::load(config_path)?;
    let (_, publish) = settings(&config)?;
    Version::parse(&args.version).map_err(|_| Usage("--version is not a SemVer version".into()))?;
    StoreKey::version_folder(&publish.prefix, &args.version)
        .map_err(|_| Usage("--version is not usable as a folder name".into()))?;
    // The credentials are read here, before any request; a missing variable is named.
    let stores = open(publish, args.store_dir.as_deref())?;
    let job = Job {
        config_path,
        config: &config,
        version: &args.version,
        sign: &args.sign,
        dry_run: args.dry_run,
        clock: Arc::new(lunepack::SystemClock),
    };
    run(&job, &stores, &ORDER)
}

/// Plans the drop, then commits it in `order` (always [`ORDER`] outside tests).
pub(crate) fn run(job: &Job<'_>, stores: &Stores, order: &[Phase]) -> Result<()> {
    let work = tempfile::Builder::new()
        .prefix("lunepack-drop-")
        .tempdir()
        .context("cannot create a work directory")?;
    let plan = plan(job, stores, work.path())?;
    show(&plan, job.dry_run, order)?;
    if job.dry_run {
        return say("dry run: nothing was written");
    }
    commit(&plan, stores, order)?;
    say(&format!(
        "dropped: {} from {} feed(s) under {}/",
        plan.version,
        plan.feeds.len(),
        plan.prefix
    ))
}

fn lists(feed: &VerifiedFeed, version: &str) -> bool {
    feed.releases().iter().any(|r| r.version_text() == version)
}

/// Reads, checks and decides everything before the first write.
fn plan(job: &Job<'_>, stores: &Stores, work_root: &Path) -> Result<Plan> {
    let config = job.config;
    let (_, publish) = settings(config)?;
    let prefix = publish.prefix.as_str();
    let v = job.version;
    let wdir = work_root.join("release");
    fs::create_dir(&wdir).context("cannot create the work directory")?;
    let state_file = work_root.join(DEFAULT_STATE);
    let skip = ClockReading::read(job.clock.as_ref(), Some(u64::MAX));

    let read = work::read_store(stores, config, publish, &wdir, &state_file, &skip)?;
    refuse_rolled_back(&read, config, &state_file)?;

    // A guard feed is never written, so it would go on listing the release and its objects could
    // not be deleted.
    if let Some((channel, _)) = read.guard_feeds.iter().find(|(_, f)| lists(f, v)) {
        bail!(
            "{} lists {v}, and its channel is not in [publish] channels, which no command writes; add the channel back to channels to drop {v} from its feed (nothing was written)",
            feed_rel(channel)
        );
    }
    let channels: Vec<Channel> = read
        .feeds
        .iter()
        .filter(|(_, f)| lists(f, v))
        .map(|(c, _)| c.clone())
        .collect();
    let left = read
        .pending
        .keys
        .iter()
        .filter(|k| version_of(prefix, k) == Some(v))
        .count();
    if channels.is_empty() {
        if left == 0 {
            bail!(
                "no feed of a [publish] channel lists {v}, and the pending record names none of its objects: nothing to drop (nothing was written)"
            );
        }
        say(&format!(
            "no feed lists {v}: finishing an earlier drop of it ({left} object(s) in the pending record)"
        ))?;
    }

    // P-D7: every release a feed lists, downloaded and checked; the objects of `v` come from its
    // verified manifests.
    let (objects_of, fetched) = work::download_retained(
        stores.public.as_ref(),
        prefix,
        &wdir,
        &read.chain,
        &read.feeds,
        None,
    )?;
    say(&format!(
        "retained: {fetched} manifest(s) of {} release(s) downloaded",
        objects_of.len()
    ))?;
    let mut wconfig = config.clone();
    wconfig.state_path = state_file.clone();
    for channel in &channels {
        say(&format!("{}: drops {v}", feed_rel(channel)))?;
        cmd_feed::refresh_with(
            Writer {
                config_path: job.config_path,
                config: wconfig.clone(),
                clock: Box::new(Shared(job.clock.clone())),
            },
            &FeedRefreshArgs {
                release_dir: wdir.clone(),
                channel: channel.as_str().to_owned(),
                expires_after_days: Some(u64::from(publish.feed_days)),
                drop: vec![v.to_owned()],
                sign: job.sign.to_vec(),
                state: StateArgs::default(),
            },
        )?;
    }

    // The state: the feeds as they are after the drop (a refresh since the last push included),
    // so the record holds every feed this run leaves in the store (S6).
    let mut state = State::load(&state_file)?;
    let mut record = state.record(&config.app_id);
    let mut feeds_after: BTreeMap<Channel, VerifiedFeed> = BTreeMap::new();
    for channel in &publish.channels {
        if let Some(feed) = work_feed(&wdir, config, &read.chain, channel, &skip)? {
            let seq = record.feeds.entry(channel.as_str().to_owned()).or_insert(0);
            *seq = (*seq).max(feed.seq());
            feeds_after.insert(channel.clone(), feed);
        }
    }
    record.set_keys(read.root_doc_k, read.chain.keys());
    state.save(&config.app_id, record, StateArgs::default())?;
    let state_bytes = fs::read(&state_file).context("cannot read the work directory")?;

    // P-D7: the whole work directory, as a client checks it, before anything is written.
    let reading = ClockReading::read(job.clock.as_ref(), None);
    check_release_dir(&wdir, config, &reading, &mut |l| {
        say(&format!("check: {l}"))
    })
    .with_context(|| format!("the feeds without {v} would not verify (nothing was written)"))?;

    let listed_after = work::listed_versions(feeds_after.values().chain(read.guard_feeds.values()));
    if listed_after.contains(v) {
        bail!("internal error: a feed still lists {v} after the drop (nothing was written)");
    }
    // What goes with the release (P-D10): the objects its verified manifests name.
    let mut deletes = BTreeSet::new();
    for rel in objects_of.get(v).into_iter().flatten() {
        let k = key(prefix, rel)?;
        if version_of(prefix, &k) != Some(v) {
            say(&format!("not purged: {k} lies outside the folder of {v}"))?;
            continue;
        }
        deletes.insert(k);
    }

    let mut feeds = Vec::new();
    for (channel, fk) in &read.feed_keys {
        let Some(bytes) = read_capped(&wdir.join(feed_rel(channel)), Limits::V1.feed_doc_bytes)?
        else {
            continue;
        };
        let was = read.feeds_read.get(channel).cloned().flatten();
        if was.as_deref() != Some(bytes.as_slice()) {
            feeds.push(FeedWrite {
                key: fk.clone(),
                read: was,
                bytes,
            });
        }
    }
    let StoreRead {
        state_key,
        state_read,
        pending,
        pending_existed,
        feed_keys,
        chain,
        ..
    } = read;
    Ok(Plan {
        prefix: prefix.to_owned(),
        version: v.to_owned(),
        app_id: config.app_id.clone(),
        chain,
        pending,
        pending_existed,
        objects: Vec::new(),
        manifests: Vec::new(),
        kept: Vec::new(),
        deletes,
        feeds,
        feed_keys,
        listed_after,
        state_key,
        state_read,
        state: state_bytes,
        rerun_hint: "Run `publish drop` again",
    })
}

#[cfg(test)]
pub(crate) mod tests {
    //! The drop over in-memory stores: what it writes and in which order, the refusals, the S6
    //! anchor (a pre-drop feed put back is refused by refresh and push), a rerun after a fault at
    //! every write, the race check, and the invariant checker over a reordered drop.

    use lunepack_core::{StoreKey, StoreMethod};
    use lunepack_testkit::StoreFault;

    use super::*;
    use crate::cmd_publish::pending::{PENDING_NAME, Pending};
    use crate::cmd_publish::push::STATE_NAME;
    use crate::cmd_publish::push::tests::{
        Bucket, Hook, World, assert_consistent, check_invariants, k, s, set, snapshot_of, targets,
    };
    use crate::cmd_publish::{exit_status, refresh};

    pub(crate) fn drop_in(
        w: &World,
        signer: &Path,
        version: &str,
        dry_run: bool,
        order: &[Phase],
    ) -> Result<()> {
        let config = Config::load(&w.config)?;
        let sign = [format!("file:{}", s(signer))];
        run(
            &Job {
                config_path: &w.config,
                config: &config,
                version,
                sign: &sign,
                dry_run,
                clock: Arc::new(lunepack::SystemClock),
            },
            &w.stores(),
            order,
        )
    }

    fn drop_v(w: &World, version: &str) -> Result<()> {
        drop_in(w, &w.release_signer, version, false, &ORDER)
    }

    fn refresh_all(w: &World) -> Result<()> {
        let config = Config::load(&w.config)?;
        let sign = [format!("file:{}", s(&w.release_signer))];
        refresh::run(
            &refresh::Job {
                config_path: &w.config,
                config: &config,
                sign: &sign,
                within_days: None,
                skip_if_unpublished: false,
                dry_run: false,
                clock: Arc::new(lunepack::SystemClock),
            },
            &w.stores(),
            &refresh::ORDER,
        )
    }

    fn pack_key(version: &str) -> StoreKey {
        k(&format!("{version}/{}.pack", targets()[0]))
    }

    /// The record of every feed the bucket holds equals its `seq`.
    fn assert_recorded(w: &World, channels: &[&str]) {
        let record = w.state_record();
        for channel in channels {
            assert_eq!(
                record.feeds.get(*channel),
                Some(&w.feed(channel).unwrap().seq()),
                "{channel}"
            );
        }
    }

    /// Two channels, a pre-release on beta only: a drop writes only the feeds that list the
    /// version, records them before its deletes, deletes the release's objects after its feeds,
    /// and leaves every other release where it was.
    #[test]
    fn a_drop_unlists_the_release_records_the_new_feeds_and_deletes_its_objects() {
        let w = World::new(
            "channels = [\"stable\", \"beta\"]\nprerelease_channels = [\"beta\"]\nkeep = 5\n",
        );
        w.publish("1.0.0");
        w.publish("1.1.0");
        w.publish("2.0.0-rc.1");
        // A refresh since the last push: the record is behind the store's feeds.
        refresh_all(&w).unwrap();
        let initial = snapshot_of(&w.public);
        w.clear_log();
        drop_v(&w, "2.0.0-rc.1").unwrap();
        assert_eq!(w.listed("stable"), ["1.0.0", "1.1.0"]);
        assert_eq!(w.listed("beta"), ["1.0.0", "1.1.0"]);
        assert_eq!(w.folders(), set(&["1.0.0", "1.1.0"]));
        assert_eq!(w.pending(), Pending::default());
        // The state file records both feeds as they are now, the refreshed stable one included.
        assert_recorded(&w, &["stable", "beta"]);
        check_invariants(&w.chain(), &initial, &w.log()).unwrap();
        assert_consistent(&w);

        let writes = w.writes();
        let pos = |what: &str| {
            writes
                .iter()
                .position(|(_, m, key)| *m == "PUT" && key == what)
                .unwrap_or_else(|| panic!("{what} not written: {writes:?}"))
        };
        let pending = format!("{P}/{PENDING_NAME}", P = crate::cmd_publish::push::tests::P);
        let record = pos(&pending);
        let feed = pos(&k("feed-beta.json").to_string());
        let state = pos(&k(STATE_NAME).to_string());
        let first_delete = writes.iter().position(|(_, m, _)| *m == "DELETE").unwrap();
        let last_record = writes
            .iter()
            .rposition(|(_, _, key)| *key == pending)
            .unwrap();
        assert!(
            record < feed && feed < state && state < first_delete && first_delete < last_record,
            "{writes:?}"
        );
        assert_eq!(last_record, writes.len() - 1, "{writes:?}");
        // The record written before the feed holds the release's objects.
        let held = w.log().into_iter().find_map(|(_, op, _)| match op {
            crate::cmd_publish::push::tests::Op::Put(key, body) if key.as_str() == pending => {
                Some(Pending::parse(crate::cmd_publish::push::tests::P, &body).unwrap())
            }
            _ => None,
        });
        assert!(held.unwrap().keys.contains(&pack_key("2.0.0-rc.1")));
        // stable does not list it and is not written.
        assert!(
            !writes
                .iter()
                .any(|(_, _, key)| key.ends_with("feed-stable.json")),
            "{writes:?}"
        );

        // A push after it publishes over the shorter feeds.
        w.publish("1.2.0");
        assert_eq!(w.listed("stable"), ["1.0.0", "1.1.0", "1.2.0"]);
        assert_consistent(&w);
    }

    #[test]
    fn a_version_no_feed_lists_or_a_guard_feed_lists_is_refused_and_nothing_is_written() {
        let w = World::new("channels = [\"stable\", \"beta\"]\nkeep = 5\n");
        w.publish("1.0.0");
        w.publish("1.1.0");
        w.clear_log();
        for version in ["0.9.0", "1.1.0+build"] {
            let e = drop_v(&w, version).unwrap_err();
            assert_eq!(exit_status(&e), 1, "{e:#}");
            assert!(format!("{e:#}").contains("nothing to drop"), "{e:#}");
        }
        assert!(w.writes().is_empty(), "{:?}", w.writes());

        // beta out of [publish] channels: its feed guards 1.0.0 and is never written.
        let config = fs::read_to_string(&w.config).unwrap().replace(
            "channels = [\"stable\", \"beta\"]",
            "channels = [\"stable\"]",
        );
        fs::write(&w.config, config).unwrap();
        w.clear_log();
        let e = drop_v(&w, "1.0.0").unwrap_err();
        assert_eq!(exit_status(&e), 1, "{e:#}");
        assert!(
            format!("{e:#}").contains("feed-beta.json lists 1.0.0, and its channel is not in"),
            "{e:#}"
        );
        assert!(w.writes().is_empty(), "{:?}", w.writes());
    }

    /// S6: an attacker with the refresh token keeps a copy of the public bucket from before the
    /// drop (the feed with the release and its objects) and puts it back. The state file records
    /// the drop's feed, so the next refresh and the next push refuse the older feed and sign
    /// nothing; the same drop without its state write (a test-only order) lets the refresh list
    /// the dropped release again, which is the finding.
    #[test]
    fn after_a_drop_a_pre_drop_feed_put_back_is_refused_by_refresh_and_push() {
        let w = World::new("keep = 5\n");
        w.publish("1.0.0");
        w.publish("1.1.0");
        // The pre-drop feed has the highest seq a feed had before the drop: a refreshed one.
        refresh_all(&w).unwrap();
        let before_drop = snapshot_of(&w.public);
        let snap = w.snapshot();

        let replay = |w: &World| {
            for (key, bytes) in &before_drop {
                w.public.seed(key, bytes);
            }
            w.clear_log();
        };
        drop_v(&w, "1.0.0").unwrap();
        assert_eq!(w.listed("stable"), ["1.1.0"]);
        replay(&w);
        assert_eq!(w.listed("stable"), ["1.0.0", "1.1.0"]);
        let e = format!("{:#}", refresh_all(&w).unwrap_err());
        assert!(
            e.contains("older than the state file records") && e.contains("feed-stable.json"),
            "{e}"
        );
        let rd = w.fetch("rd-after-replay");
        w.pack(&rd, "1.2.0", targets()[0]);
        assert!(w.push(&[rd], "1.2.0").is_err());
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        // A drop again refuses it too, and so does the rerun of the same drop.
        assert!(drop_v(&w, "1.0.0").is_err());
        assert!(w.writes().is_empty(), "{:?}", w.writes());

        // The control: without the state write the replayed feed is re-signed and listed again.
        w.restore(&snap);
        let unanchored: Vec<Phase> = ORDER
            .iter()
            .copied()
            .filter(|p| *p != Phase::State)
            .collect();
        drop_in(&w, &w.release_signer, "1.0.0", false, &unanchored).unwrap();
        replay(&w);
        refresh_all(&w).unwrap();
        assert_eq!(w.listed("stable"), ["1.0.0", "1.1.0"]);
    }

    /// The store after a complete drop of 1.0.0 from both channels.
    fn assert_complete(w: &World) {
        assert_eq!(w.listed("stable"), ["1.1.0"]);
        assert_eq!(w.listed("beta"), ["1.1.0"]);
        assert_eq!(w.folders(), set(&["1.1.0"]));
        assert_eq!(w.pending(), Pending::default());
        assert_consistent(w);
        assert_recorded(w, &["stable", "beta"]);
    }

    #[test]
    fn a_rerun_completes_a_drop_stopped_at_any_write() {
        let w = World::new("channels = [\"stable\", \"beta\"]\nkeep = 5\n");
        w.publish("1.0.0");
        w.publish("1.1.0");
        refresh_all(&w).unwrap();
        w.clear_log();
        let snap = w.snapshot();
        drop_v(&w, "1.0.0").unwrap();
        assert_complete(&w);
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
        // record, two feeds, state, the deletes (manifest and pack), record.
        assert!(points.len() >= 7, "{points:?}");
        let mut done_before_rerun = 0;
        for fault in [StoreFault::Status(500), StoreFault::LostAnswer] {
            for ((bucket, method, at), after) in &points {
                let what = format!("{fault:?} at {method} {at}");
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
                let at = StoreKey::parse(crate::cmd_publish::push::tests::P, at).unwrap();
                store.inject_after(method, Some(&at), *after, fault);
                let first = drop_v(&w, "1.0.0");
                if method == StoreMethod::Delete {
                    first.unwrap_or_else(|e| panic!("{what}: a failed delete is not fatal: {e:#}"));
                } else {
                    assert!(first.is_err(), "{what}: a failed write fails the drop");
                }
                check_invariants(&w.chain(), &snap.0, &w.log())
                    .unwrap_or_else(|e| panic!("{what}: {e}"));
                assert_consistent(&w);
                w.public.clear_faults();
                w.private.clear_faults();
                // Only a lost answer to the last write leaves a store already complete, which
                // a rerun cannot tell from a version never listed: it refuses and writes nothing.
                let complete = w.listed("stable") == ["1.1.0"]
                    && w.listed("beta") == ["1.1.0"]
                    && w.folders() == set(&["1.1.0"])
                    && w.pending() == Pending::default();
                w.clear_log();
                let rerun = drop_v(&w, "1.0.0");
                if complete {
                    done_before_rerun += 1;
                    let e = format!("{:#}", rerun.unwrap_err());
                    assert!(e.contains("nothing to drop"), "{what}: {e}");
                    assert!(w.writes().is_empty(), "{what}: {:?}", w.writes());
                } else {
                    rerun.unwrap_or_else(|e| panic!("{what}: the rerun failed: {e:#}"));
                }
                assert_complete(&w);
            }
        }
        assert_eq!(done_before_rerun, 1, "only LostAnswer at the last record");
    }

    /// The order's two load-bearing points, each shown by a test-only reordering: deletes run
    /// before the feeds delete nothing (the live filter, P-D8 (5), sees the release still listed
    /// and keeps its objects), and a record written after the feeds leaves, when it fails, a store
    /// whose dropped objects no rerun finds.
    #[test]
    fn a_reordered_drop_keeps_listed_objects_or_loses_its_deletes() {
        let w = World::new("keep = 5\n");
        w.publish("1.0.0");
        w.publish("1.1.0");
        let snap = w.snapshot();
        w.clear_log();
        drop_v(&w, "1.0.0").unwrap();
        check_invariants(&w.chain(), &snap.0, &w.log()).unwrap();

        w.restore(&snap);
        let mut early: Vec<Phase> = ORDER
            .iter()
            .copied()
            .filter(|p| *p != Phase::Deletes)
            .collect();
        early.insert(1, Phase::Deletes);
        drop_in(&w, &w.release_signer, "1.0.0", false, &early).unwrap();
        check_invariants(&w.chain(), &snap.0, &w.log()).unwrap();
        assert!(
            w.writes().iter().all(|(_, m, _)| *m == "PUT"),
            "{:?}",
            w.writes()
        );
        assert!(w.public.contents(&pack_key("1.0.0")).is_some());

        // The record after the feeds, and its write fails: the feeds no longer list 1.0.0 and
        // the record does not name its objects, so the rerun refuses and they stay.
        w.restore(&snap);
        let late = [
            Phase::Feeds,
            Phase::RecordDeletes,
            Phase::State,
            Phase::Deletes,
            Phase::FinalRecord,
        ];
        w.private.inject(
            StoreMethod::Put,
            Some(&k(PENDING_NAME)),
            StoreFault::Status(500),
        );
        assert!(drop_in(&w, &w.release_signer, "1.0.0", false, &late).is_err());
        w.private.clear_faults();
        let e = format!("{:#}", drop_v(&w, "1.0.0").unwrap_err());
        assert!(e.contains("nothing to drop"), "{e}");
        assert!(w.public.contents(&pack_key("1.0.0")).is_some());
        // The real order with the same fault: the rerun deletes them.
        w.restore(&snap);
        w.private.inject(
            StoreMethod::Put,
            Some(&k(PENDING_NAME)),
            StoreFault::Status(500),
        );
        assert!(drop_v(&w, "1.0.0").is_err());
        w.private.clear_faults();
        drop_v(&w, "1.0.0").unwrap();
        assert!(w.public.contents(&pack_key("1.0.0")).is_none());
    }

    #[test]
    fn a_dry_run_reads_and_checks_and_writes_nothing() {
        let w = World::new("keep = 5\n");
        w.publish("1.0.0");
        w.publish("1.1.0");
        let snap = w.snapshot();
        w.clear_log();
        drop_in(&w, &w.release_signer, "1.0.0", true, &ORDER).unwrap();
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        assert!(w.snapshot() == snap, "a dry run changed a bucket");
        assert!(drop_in(&w, &w.release_signer, "0.9.0", true, &ORDER).is_err());
    }

    #[test]
    fn the_race_check_refuses_a_feed_that_changed_since_it_was_read() {
        let w = World::new("keep = 5\n");
        w.publish("1.0.0");
        w.publish("1.1.0");
        let mut theirs = w.public.contents(&k("feed-stable.json")).unwrap();
        theirs.push(b' ');
        // The second get of the feed is the race check's.
        *w.hook.lock().unwrap() = Some(Hook {
            key: k("feed-stable.json"),
            nth: 1,
            bytes: theirs.clone(),
        });
        w.clear_log();
        let e = format!("{:#}", drop_v(&w, "1.0.0").unwrap_err());
        assert!(
            e.contains("changed in the store since this run read it")
                && e.contains("Run `publish drop` again"),
            "{e}"
        );
        assert_eq!(w.public.contents(&k("feed-stable.json")).unwrap(), theirs);
        let writes = w.writes();
        assert!(
            writes
                .iter()
                .all(|(b, _, key)| *b == Bucket::Private && key.ends_with(PENDING_NAME)),
            "only the record before the feeds: {writes:?}"
        );
        assert!(w.public.contents(&pack_key("1.0.0")).is_some());
    }
}
