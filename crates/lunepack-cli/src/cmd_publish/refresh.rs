//! `lunepack publish refresh [--if-expiring-within-days N] [--skip-if-unpublished] [--dry-run]`.
//!
//! Re-signs each channel's feed (or each that expires within N days) with a new `seq` and
//! expiry, the releases unchanged. The work is a push without a new version: the stores' documents
//! are read and verified into a work directory, every listed release is downloaded and checked
//! (P-D7), and the in-process `feed refresh` re-signs the due feeds. The one thing it writes is
//! each changed feed, after its race check (P-D8): it never writes the private bucket (no state
//! file, no pending record) and runs no pending delete; a push does those (S1), so a refresh job's
//! token needs write access to the public bucket and read access to the private one only. Before
//! it signs anything it refuses a store whose feed, key set or root is older than the state file
//! records: a rolled-back document is caught, never re-signed. With nothing due it writes nothing.
//!
//! A refresh never takes a release out of a feed: that is `publish drop` (S6), which records the
//! feeds it writes in the state file, so a pre-drop feed put back is refused here.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Args;
use lunepack_core::{Channel, Clock, ClockReading, Limits};

use super::push::{FeedWrite, Phase, Plan, Shared, commit, show, work_feed};
use super::work::{self, NotPublished, StoreRead, feed_rel};
use super::{Stores, say, settings};
use crate::cmd_feed::{self, RefreshArgs as FeedRefreshArgs, SECS_PER_DAY, Writer};
use crate::cmd_verify::check_release_dir;
use crate::config::Config;
use crate::release_dir::read_capped;
use crate::state::{DEFAULT_STATE, State, StateArgs};

/// Arguments of `publish refresh`.
#[derive(Args)]
pub struct RefreshArgs {
    /// Only re-sign a feed that expires within this many days (or has expired); without it every
    /// feed is re-signed.
    #[arg(
        long = "if-expiring-within-days",
        value_parser = clap::value_parser!(u64).range(0..=36_500)
    )]
    within_days: Option<u64>,
    /// When the store has no `keys.json` or no feed yet, print a notice and exit 0 (a scheduled
    /// refresh of an app that has not published); without it that is an error.
    #[arg(long = "skip-if-unpublished")]
    skip_if_unpublished: bool,
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

/// One refresh, resolved from the command line.
pub(crate) struct Job<'a> {
    pub config_path: &'a Path,
    pub config: &'a Config,
    pub sign: &'a [String],
    pub within_days: Option<u64>,
    pub skip_if_unpublished: bool,
    pub dry_run: bool,
    /// The time feeds are issued, checked and compared with their expiry at.
    pub clock: Arc<dyn Clock>,
}

/// The commit order of a refresh: the feeds only (S1).
pub(crate) const ORDER: [Phase; 1] = [Phase::Feeds];

/// `publish refresh`.
pub fn refresh(config_path: &Path, args: &RefreshArgs, open: super::OpenStores<'_>) -> Result<()> {
    super::refuse_source_date_epoch("refresh")?;
    let config = Config::load(config_path)?;
    let (_, publish) = settings(&config)?;
    // The credentials are read here, before any request; a missing variable is named.
    let stores = open(publish, args.store_dir.as_deref())?;
    let job = Job {
        config_path,
        config: &config,
        sign: &args.sign,
        within_days: args.within_days,
        skip_if_unpublished: args.skip_if_unpublished,
        dry_run: args.dry_run,
        clock: Arc::new(lunepack::SystemClock),
    };
    run(&job, &stores, &ORDER)
}

/// Plans the refresh, then commits it in `order` (always [`ORDER`] outside tests).
pub(crate) fn run(job: &Job<'_>, stores: &Stores, order: &[Phase]) -> Result<()> {
    let work = tempfile::Builder::new()
        .prefix("lunepack-refresh-")
        .tempdir()
        .context("cannot create a work directory")?;
    let Some(plan) = plan(job, stores, work.path())? else {
        return Ok(());
    };
    show(&plan, job.dry_run, order)?;
    if job.dry_run {
        return say("dry run: nothing was written");
    }
    commit(&plan, stores, order)?;
    say(&format!(
        "refreshed: {} feed(s) written under {}/",
        plan.feeds.len(),
        plan.prefix
    ))
}

/// S1: refuses (before anything is signed or written) a store whose root walk, `keys.json` or feed
/// is older than what the private state file records, which a rolled-back bucket would show. A
/// document the state file has no record of, or a recorded feed that is absent, is not compared.
/// `publish drop` runs it too.
pub(crate) fn refuse_rolled_back(
    read: &StoreRead,
    config: &Config,
    state_file: &Path,
) -> Result<()> {
    let record = State::load(state_file)?.record(&config.app_id);
    let mut older = Vec::new();
    let mut compare = |what: String, field: &str, recorded: Option<u64>, found: u64| {
        if let Some(recorded) = recorded
            && found < recorded
        {
            older.push(format!(
                "{what}: {field} {found} in the store is older than the {recorded} the state file records"
            ));
        }
    };
    compare(
        "the root walk".to_owned(),
        "version",
        record.root_version,
        read.root_doc_k,
    );
    compare(
        "keys.json".to_owned(),
        "version",
        record.keys_version,
        read.chain.keys().version(),
    );
    for (channel, feed) in read.feeds.iter().chain(&read.guard_feeds) {
        compare(
            feed_rel(channel),
            "seq",
            record.feeds.get(channel.as_str()).copied(),
            feed.seq(),
        );
    }
    if older.is_empty() {
        return Ok(());
    }
    bail!(
        "the public bucket holds documents older than the state file records (a rolled-back bucket?); nothing was signed or written:\n  {}",
        older.join("\n  ")
    )
}

/// Reads, checks and decides everything before the first write; `None` when there is nothing to
/// do (a line saying so was printed).
fn plan(job: &Job<'_>, stores: &Stores, work_root: &Path) -> Result<Option<Plan>> {
    let config = job.config;
    let (_, publish) = settings(config)?;
    let prefix = publish.prefix.as_str();
    let wdir = work_root.join("release");
    fs::create_dir(&wdir).context("cannot create the work directory")?;
    let state_file = work_root.join(DEFAULT_STATE);
    let skip = ClockReading::read(job.clock.as_ref(), Some(u64::MAX));

    let read = match work::read_store(stores, config, publish, &wdir, &state_file, &skip) {
        Ok(read) => read,
        Err(e) => match e.downcast_ref::<NotPublished>() {
            Some(missing) if job.skip_if_unpublished => {
                say(&format!("notice: nothing to refresh: {}", missing.what))?;
                return Ok(None);
            }
            _ => return Err(e),
        },
    };
    if read.feeds.is_empty() {
        if job.skip_if_unpublished {
            say("notice: nothing to refresh: the public bucket has no feed yet")?;
            return Ok(None);
        }
        bail!("the public bucket has no feed to refresh: publish a release first");
    }

    refuse_rolled_back(&read, config, &state_file)?;

    let now = job.clock.now_unix_secs();
    let due: Vec<Channel> = read
        .feeds
        .iter()
        .filter(|(_, feed)| match job.within_days {
            None => true,
            Some(days) => feed
                .expires()
                .is_some_and(|e| e <= now.saturating_add(days.saturating_mul(SECS_PER_DAY))),
        })
        .map(|(channel, _)| channel.clone())
        .collect();
    if !read.pending.keys.is_empty() {
        say(&format!(
            "notice: {} pending delete(s) are left to the next `publish push`; a refresh never writes the private bucket",
            read.pending.keys.len()
        ))?;
    }
    if due.is_empty() {
        say(&match job.within_days {
            Some(days) => format!("nothing to refresh: no feed expires within {days} day(s)"),
            None => "nothing to refresh".to_owned(),
        })?;
        return Ok(None);
    }

    let mut feeds_after = read.feeds.clone();
    {
        // P-D7: every release a feed lists, downloaded and checked, before any feed is re-signed.
        let (objects, fetched) = work::download_retained(
            stores.public.as_ref(),
            prefix,
            &wdir,
            &read.chain,
            &read.feeds,
            None,
        )?;
        say(&format!(
            "retained: {fetched} manifest(s) of {} release(s) downloaded",
            objects.len()
        ))?;
        let mut wconfig = config.clone();
        wconfig.state_path = state_file.clone();
        for channel in &due {
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
                    drop: Vec::new(),
                    sign: job.sign.to_vec(),
                    state: StateArgs::default(),
                },
            )?;
        }
        for channel in &publish.channels {
            if let Some(feed) = work_feed(&wdir, config, &read.chain, channel, &skip)? {
                feeds_after.insert(channel.clone(), feed);
            }
        }
        // P-D7: the whole work directory, as a client checks it, before anything is written.
        let reading = ClockReading::read(job.clock.as_ref(), None);
        check_release_dir(&wdir, config, &reading, &mut |l| {
            say(&format!("check: {l}"))
        })
        .context("the refreshed feeds would not verify (nothing was written)")?;
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
        guard_feeds,
        ..
    } = read;
    Ok(Some(Plan {
        prefix: prefix.to_owned(),
        version: String::new(),
        app_id: config.app_id.clone(),
        chain,
        pending,
        pending_existed,
        objects: Vec::new(),
        manifests: Vec::new(),
        kept: Vec::new(),
        deletes: BTreeSet::new(),
        feeds,
        feed_keys,
        listed_after: work::listed_versions(feeds_after.values().chain(guard_feeds.values())),
        state_key,
        state: state_read.clone(),
        state_read,
        rerun_hint: "Run `publish refresh` again",
    }))
}

#[cfg(test)]
mod tests {
    //! The refresh logic over in-memory stores: nothing due writes nothing, the commit order, the
    //! race check, and the stale pending record (P-D8 (5)).

    use lunepack_core::{ObjectStore, StoreKey};

    use super::*;
    use crate::cmd_publish::pending::{PENDING_NAME, Pending};
    use crate::cmd_publish::push::tests::{
        Bucket, Hook, Op, World, assert_consistent, check_invariants, k, s, snapshot_of, targets,
    };

    fn refresh_in(
        w: &World,
        within_days: Option<u64>,
        skip_if_unpublished: bool,
        dry_run: bool,
    ) -> Result<()> {
        let config = Config::load(&w.config)?;
        let sign = [format!("file:{}", s(&w.release_signer))];
        run(
            &Job {
                config_path: &w.config,
                config: &config,
                sign: &sign,
                within_days,
                skip_if_unpublished,
                dry_run,
                clock: Arc::new(lunepack::SystemClock),
            },
            &w.stores(),
            &ORDER,
        )
    }

    fn pack_key(version: &str) -> StoreKey {
        k(&format!("{version}/{}.pack", targets()[0]))
    }

    #[test]
    fn nothing_due_and_nothing_pending_writes_nothing() {
        let w = World::new("");
        w.publish("1.0.0");
        let before = w.snapshot();
        w.clear_log();
        refresh_in(&w, Some(7), false, false).unwrap();
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        assert!(w.snapshot() == before);
    }

    #[test]
    fn a_refresh_keeps_the_releases_raises_the_seq_and_writes_only_the_public_feed() {
        let w = World::new("keep = 5\n");
        w.publish("1.0.0");
        w.publish("1.1.0");
        let seq = w.feed("stable").unwrap().seq();
        let initial = snapshot_of(&w.public);
        let private_before = snapshot_of(&w.private);
        w.clear_log();
        refresh_in(&w, None, false, false).unwrap();
        assert_eq!(w.listed("stable"), ["1.0.0", "1.1.0"]);
        let feed = w.feed("stable").unwrap();
        assert!(feed.seq() > seq);
        // S1: the state file is the private bucket's, and a refresh leaves it where it was.
        assert_eq!(w.state_record().feeds.get("stable"), Some(&seq));
        assert!(snapshot_of(&w.private) == private_before);
        assert_eq!(
            w.writes(),
            [(Bucket::Public, "PUT", k("feed-stable.json").to_string())]
        );
        check_invariants(&w.chain(), &initial, &w.log()).unwrap();
        assert_consistent(&w);
    }

    #[test]
    fn a_push_after_several_refreshes_succeeds_and_records_the_newest_seq() {
        let w = World::new("keep = 5\n");
        w.publish("1.0.0");
        for _ in 0..3 {
            refresh_in(&w, None, false, false).unwrap();
        }
        let seq = w.feed("stable").unwrap().seq();
        assert!(w.state_record().feeds.get("stable").unwrap() < &seq);
        w.publish("1.1.0");
        assert_eq!(w.listed("stable"), ["1.0.0", "1.1.0"]);
        assert!(w.state_record().feeds.get("stable").unwrap() > &seq);
        // And a refresh after the push still works against the updated record.
        refresh_in(&w, None, false, false).unwrap();
        assert_consistent(&w);
    }

    #[test]
    fn a_store_whose_feed_was_replaced_by_an_older_genuine_one_is_refused_and_nothing_is_written() {
        let w = World::new("keep = 5\n");
        w.publish("1.0.0");
        let older = w.public.contents(&k("feed-stable.json")).unwrap();
        w.publish("1.1.0");
        w.public.seed(&k("feed-stable.json"), &older);
        w.clear_log();
        for within in [None, Some(7)] {
            let e = format!("{:#}", refresh_in(&w, within, false, false).unwrap_err());
            assert!(
                e.contains("older than the state file records") && e.contains("feed-stable.json"),
                "{e}"
            );
        }
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        assert_eq!(w.public.contents(&k("feed-stable.json")).unwrap(), older);
        // A push refuses it too (the writer's own check against the state file).
        let rd = w.fetch("rd-rolled-back");
        w.pack(&rd, "1.2.0", targets()[0]);
        assert!(w.push(&[rd], "1.2.0").is_err());
    }

    #[test]
    fn a_dry_run_writes_nothing() {
        let w = World::new("");
        w.publish("1.0.0");
        let before = w.snapshot();
        w.clear_log();
        refresh_in(&w, None, false, true).unwrap();
        assert!(w.writes().is_empty());
        assert!(w.snapshot() == before);
    }

    #[test]
    fn a_refresh_leaves_the_pending_record_and_its_deletes_to_the_next_push() {
        let w = World::new("");
        w.publish("1.0.0");
        // The record names the listed 1.0.0's pack and an object of an unlisted 0.9.0.
        let gone = pack_key("0.9.0");
        w.public.seed(&gone, b"old");
        let mut record = Pending::default();
        record.keys.insert(gone.clone());
        record.keys.insert(pack_key("1.0.0"));
        w.private.seed(&k(PENDING_NAME), &record.to_bytes());
        w.clear_log();
        // Neither a refresh with nothing due nor one that re-signs deletes or rewrites anything
        // of the record.
        refresh_in(&w, Some(7), false, false).unwrap();
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        refresh_in(&w, None, false, false).unwrap();
        assert!(w.public.contents(&gone).is_some());
        assert!(w.public.contents(&pack_key("1.0.0")).is_some());
        assert_eq!(w.pending(), record);
        assert!(
            w.writes()
                .iter()
                .all(|(b, op, _)| *b == Bucket::Public && *op == "PUT"),
            "{:?}",
            w.writes()
        );
        // The next push runs them (P-D8 (5)): the unlisted object goes, the listed one stays and
        // leaves the record.
        w.publish("1.1.0");
        assert!(w.public.contents(&gone).is_none());
        assert!(w.public.contents(&pack_key("1.0.0")).is_some());
        assert_eq!(w.pending(), Pending::default());
    }

    #[test]
    fn the_race_check_refuses_a_feed_that_changed_since_it_was_read() {
        let w = World::new("");
        w.publish("1.0.0");
        let mut theirs = w.public.contents(&k("feed-stable.json")).unwrap();
        theirs.push(b' ');
        // The second get of the feed is the race check's.
        *w.hook.lock().unwrap() = Some(Hook {
            key: k("feed-stable.json"),
            nth: 1,
            bytes: theirs.clone(),
        });
        w.clear_log();
        let e = format!("{:#}", refresh_in(&w, None, false, false).unwrap_err());
        assert!(
            e.contains("changed in the store since this run read it"),
            "{e}"
        );
        assert_eq!(w.public.contents(&k("feed-stable.json")).unwrap(), theirs);
        assert!(w.writes().is_empty(), "{:?}", w.writes());
    }

    #[test]
    fn an_unpublished_store_is_skipped_or_refused() {
        // No keys.json.
        let w = World::new("");
        w.public.delete(&k("keys.json")).unwrap();
        w.clear_log();
        refresh_in(&w, None, true, false).unwrap();
        let e = format!("{:#}", refresh_in(&w, None, false, false).unwrap_err());
        assert!(e.contains("publish init"), "{e}");
        assert!(w.writes().is_empty());
        // Keys but no feed.
        let w = World::new("");
        refresh_in(&w, None, true, false).unwrap();
        let e = format!("{:#}", refresh_in(&w, None, false, false).unwrap_err());
        assert!(e.contains("no feed to refresh"), "{e}");
        assert!(w.writes().is_empty());
    }

    #[test]
    fn a_failed_delete_stays_in_the_record_until_a_push_retries_it() {
        use lunepack_core::StoreMethod;
        use lunepack_testkit::StoreFault;
        let w = World::new("keep = 1\n");
        w.publish("1.0.0");
        let pack = pack_key("1.0.0");
        w.public
            .inject(StoreMethod::Delete, Some(&pack), StoreFault::Status(503));
        w.publish("1.1.0");
        let record = std::collections::BTreeSet::from([pack.clone()]);
        assert_eq!(w.pending().keys, record);
        w.public.clear_faults();
        // A refresh is no retry: it neither deletes nor touches the record.
        refresh_in(&w, None, false, false).unwrap();
        assert!(w.public.contents(&pack).is_some());
        assert_eq!(w.pending().keys, record);
        w.publish("1.2.0");
        assert!(w.public.contents(&pack).is_none());
        assert_eq!(w.pending(), Pending::default());
        assert_eq!(w.listed("stable"), ["1.2.0"]);
        let _ = Op::Get;
    }
}
