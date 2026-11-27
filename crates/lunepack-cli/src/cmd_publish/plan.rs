//! `lunepack publish plan [--version <v>]`: what the stores hold and what a push would do. It
//! reads (with the store credentials) and writes nothing.
//!
//! It prints each `[publish]` channel's feed (its `seq`, expiry and releases), with `--version`
//! what a push of that version would add and drop, the pending deletes, and every version in the
//! record's `uploading` list that no feed lists: an abandoned push, whose folder needs a rerun of
//! `publish push` with its release directories or a clean-up by hand. Its objects are named from
//! the store's manifests of it, verified under the key set, when any are there.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use lunepack_core::{
    Channel, Clock, ClockReading, Limits, StoreKey, Target, VerifiedFeed, Version,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use super::push::drops;
use super::work::{self, StoreRead, feed_rel, key};
use super::{Stores, Usage, say, settings};
use crate::cmd_feed::SECS_PER_DAY;
use crate::config::Config;
use crate::state::DEFAULT_STATE;

/// Arguments of `publish plan`.
#[derive(Args)]
pub struct PlanArgs {
    /// The version about to be published (SemVer): show what a push of it would add and drop.
    #[arg(long)]
    version: Option<String>,
    /// Use a local directory as both buckets (`<dir>/public`, `<dir>/private`), for tests and
    /// trials; no credential is read.
    #[arg(long = "store-dir")]
    pub store_dir: Option<PathBuf>,
}

/// When `feed` expires, as a phrase.
fn expiry(feed: &VerifiedFeed, now: u64) -> String {
    match feed.expires() {
        None => "never expires".to_owned(),
        Some(e) if e > now => format!("expires in {} day(s)", (e - now) / SECS_PER_DAY),
        Some(e) => format!("expired {} day(s) ago", (now - e) / SECS_PER_DAY),
    }
}

/// `publish plan`.
pub fn plan(config_path: &Path, args: &PlanArgs, open: super::OpenStores<'_>) -> Result<()> {
    let config = Config::load(config_path)?;
    let (_, publish) = settings(&config)?;
    let prefix = publish.prefix.as_str();
    let version = match &args.version {
        None => None,
        Some(text) => {
            let parsed = Version::parse(text)
                .map_err(|_| Usage("--version is not a SemVer version".into()))?;
            StoreKey::version_folder(prefix, text)
                .map_err(|_| Usage("--version is not usable as a folder name".into()))?;
            Some((text.as_str(), parsed))
        }
    };
    let stores = open(publish, args.store_dir.as_deref())?;
    let work = tempfile::Builder::new()
        .prefix("lunepack-plan-")
        .tempdir()
        .context("cannot create a work directory")?;
    let wdir = work.path().join("release");
    std::fs::create_dir(&wdir).context("cannot create the work directory")?;
    let clock = lunepack::SystemClock;
    let skip = ClockReading::read(&clock, Some(u64::MAX));
    let now = clock.now_unix_secs();
    let read = work::read_store(
        &stores,
        &config,
        publish,
        &wdir,
        &work.path().join(DEFAULT_STATE),
        &skip,
    )?;

    // The feeds as they are.
    let describe = |channel: &Channel, feed: &VerifiedFeed| {
        let mut releases: Vec<_> = feed.releases().iter().collect();
        releases.sort_by(|a, b| b.version().cmp(a.version()));
        let names: Vec<&str> = releases.iter().map(|r| r.version_text()).collect();
        format!(
            "{}: seq {}, {}, {} release(s): {}",
            feed_rel(channel),
            feed.seq(),
            expiry(feed, now),
            names.len(),
            names.join(", ")
        )
    };
    for channel in &publish.channels {
        match read.feeds.get(channel) {
            None => say(&format!("{}: absent", feed_rel(channel)))?,
            Some(feed) => say(&describe(channel, feed))?,
        }
    }
    for (channel, feed) in &read.guard_feeds {
        say(&format!(
            "{} (not in [publish] channels; never written, and what it lists is never purged)",
            describe(channel, feed)
        ))?;
    }

    // What a push of the version would do to each feed.
    if let Some((text, parsed)) = &version {
        let targets: &[Channel] = if parsed.as_semver().pre.is_empty() {
            &publish.channels
        } else {
            &publish.prerelease_channels
        };
        for channel in &publish.channels {
            let feed = read.feeds.get(channel);
            if feed.is_none() && !targets.contains(channel) {
                continue;
            }
            let mut after: Vec<(Version, String)> = feed
                .map(|f| {
                    f.releases()
                        .iter()
                        .map(|r| (r.version().clone(), r.version_text().to_owned()))
                        .collect()
                })
                .unwrap_or_default();
            let listed = after.iter().any(|(_, t)| t == text);
            let adds = targets.contains(channel) && !listed;
            if adds {
                after.push((parsed.clone(), (*text).to_owned()));
            }
            let dropped = drops(after, publish.keep as usize, text);
            let mut parts = Vec::new();
            if adds {
                parts.push(format!("add {text}"));
            } else if listed {
                parts.push(format!("already lists {text}"));
            }
            if !dropped.is_empty() {
                parts.push(format!("drop {}", dropped.join(", ")));
            }
            if parts.is_empty() {
                parts.push("no change".to_owned());
            }
            say(&format!(
                "push {text}: {}: {}",
                feed_rel(channel),
                parts.join("; ")
            ))?;
        }
    }

    report_pending(&read, prefix, &stores, now)?;
    say("plan: nothing was written")
}

/// The pending deletes and the abandoned pushes.
fn report_pending(read: &StoreRead, prefix: &str, stores: &Stores, now: u64) -> Result<()> {
    if read.pending.keys.is_empty() {
        say("pending deletes: none")?;
    } else {
        say(&format!(
            "pending deletes: {} key(s), retried by the next push or refresh",
            read.pending.keys.len()
        ))?;
        for k in &read.pending.keys {
            say(&format!("  {k}"))?;
        }
    }
    let listed = read.listed();
    for v in &read.pending.uploading {
        if listed.contains(v) {
            say(&format!(
                "uploading: {v} (a feed lists it; the next push or refresh clears the mark)"
            ))?;
            continue;
        }
        say(&format!(
            "abandoned: {v} is marked uploading and no feed lists it; rerun `publish push` for it with its release directories, or remove its objects by hand"
        ))?;
        let Ok(parsed) = Version::parse(v) else {
            continue;
        };
        let mut found = false;
        for target in Target::ALL {
            let rel = format!("{v}/{}.manifest.json", target.as_str());
            let at = key(prefix, &rel)?;
            let Some(bytes) =
                work::get(stores.public.as_ref(), &at, Limits::V1.manifest_doc_bytes)?
            else {
                continue;
            };
            found = true;
            match lunepack_core::verify_payload_manifest(
                read.chain.keys(),
                (&parsed, target),
                &bytes,
                now,
                &Sha256Hasher,
                &Ed25519Verifier,
            ) {
                Ok(manifest) => {
                    say(&format!("  {at}"))?;
                    let mut paths = vec![manifest.pack().path().to_owned()];
                    paths.extend(manifest.deltas().iter().map(|d| d.file().path().to_owned()));
                    for path in paths {
                        match key(prefix, &path) {
                            Ok(object) => say(&format!("  {object}"))?,
                            Err(_) => say("  (an object the manifest names is not a usable key)")?,
                        }
                    }
                }
                Err(e) => say(&format!("  {at} (present, but does not verify: {e})"))?,
            }
        }
        if !found {
            say(&format!(
                "  no manifest of {v} in the store; objects under {prefix}/{v}/ may remain"
            ))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! `plan` over in-memory stores: it performs no put and no delete.

    use super::*;
    use crate::cmd_publish::pending::{PENDING_NAME, Pending};
    use crate::cmd_publish::push::tests::{Op, World, k, targets};

    #[test]
    fn plan_performs_gets_only() {
        let w = World::new("keep = 1\n");
        w.publish("1.0.0");
        // An abandoned push: 1.1.0 marked uploading, its manifest in the store, no feed lists it.
        let rd = w.fetch("rd-1.1.0");
        w.pack(&rd, "1.1.0", targets()[0]);
        for entry in std::fs::read_dir(rd.join("1.1.0")).unwrap() {
            let path = entry.unwrap().path();
            let rel = format!("1.1.0/{}", path.file_name().unwrap().to_str().unwrap());
            w.public.seed(&k(&rel), &std::fs::read(&path).unwrap());
        }
        let mut record = Pending::default();
        record.uploading.insert("1.1.0".to_owned());
        record
            .keys
            .insert(k(&format!("1.0.0/{}.pack", targets()[0])));
        w.private.seed(&k(PENDING_NAME), &record.to_bytes());
        let before = w.snapshot();
        w.clear_log();
        let open = |_: &crate::config::PublishSettings, _: Option<&Path>| Ok(w.stores());
        plan(
            &w.config,
            &PlanArgs {
                version: Some("1.2.0".to_owned()),
                store_dir: None,
            },
            &open,
        )
        .unwrap();
        let log = w.log();
        assert!(!log.is_empty());
        assert!(
            log.iter().all(|(_, op, _)| matches!(op, Op::Get)),
            "plan wrote: {:?}",
            w.writes()
        );
        assert!(w.snapshot() == before);
    }
}
