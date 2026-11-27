//! `lunepack publish keys --release-dir <dir> [--dry-run]`: the user's own upload of a key-set
//! change (a revocation, a threshold or window change, a root rotation), like `init`; never an
//! agent's and never CI's.
//!
//! `push` and `refresh` never write `keys.json` or a root (P-D6 holds the release directories
//! equal to the store's), so a change made by `lunepack keys set` or `keys rotate-root` in a
//! fetched release directory needs this command to reach the store. It
//!
//! 1. reads the stores and verifies what is there, like `push`;
//! 2. checks the directory's root walk and `keys.json` under the config's root, that the store's
//!    roots are a prefix of the directory's, that the key set is newer than the store's, and that
//!    the state file's record is not lowered;
//! 3. checks, in-process, that every feed in the store (the `[publish]` channels' and the guard
//!    feeds') and every manifest they list still verifies under the new key set, so the upload
//!    cannot leave clients with a feed they reject;
//! 4. uploads the new `root-<k>.json` files, then `keys.json`, then the state file (its record of
//!    the root and key set), after re-reading `keys.json` to catch another writer.
//!
//! A rerun after any failure completes the rest: a `keys.json` already equal to the store's is
//! kept, and only a state record that is behind is written.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use lunepack_core::{ClockReading, KeysChain, Limits, StoreKey, verify_manifest};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use super::push::local_roots;
use super::work::{self, StoreRead, feed_rel, key};
use super::{Stores, Usage, say, settings};
use crate::config::Config;
use crate::release_dir::{self, read_capped, verify_feed_of};
use crate::state::{DEFAULT_STATE, State, StateArgs};

/// Arguments of `publish keys`.
#[derive(Args)]
pub struct KeysArgs {
    /// The release directory `lunepack keys set` or `keys rotate-root` changed, filled by
    /// `publish fetch` before.
    #[arg(long = "release-dir")]
    release_dir: PathBuf,
    /// Do every read and check, print what would be uploaded, and write nothing.
    #[arg(long = "dry-run")]
    dry_run: bool,
    /// Use a local directory as both buckets (`<dir>/public`, `<dir>/private`), for tests and
    /// trials; no credential is read.
    #[arg(long = "store-dir")]
    pub store_dir: Option<PathBuf>,
}

/// `publish keys`.
pub fn keys(config_path: &Path, args: &KeysArgs, open: super::OpenStores<'_>) -> Result<()> {
    super::refuse_source_date_epoch("keys")?;
    let config = Config::load(config_path)?;
    let (_, publish) = settings(&config)?;
    let dir = args.release_dir.as_path();

    // The directory's documents, checked under the config's root before any request.
    let reading = ClockReading::read(&lunepack::SystemClock, None);
    let opened = release_dir::open(dir, &config, &Sha256Hasher, &Ed25519Verifier, &reading)
        .with_context(|| format!("{} does not verify", dir.display()))?;
    let Some(new_chain) = opened.chain else {
        return Err(Usage(format!(
            "{} has no keys.json: run `lunepack keys set` first",
            dir.display()
        ))
        .into());
    };
    let new_keys_bytes = read_capped(&release_dir::keys_path(dir), Limits::V1.keys_doc_bytes)?
        .context("keys.json vanished")?;
    let new_roots = local_roots(dir, config.root_version)?;
    let new_root_k = opened.root_doc_k;

    let stores = open(publish, args.store_dir.as_deref())?;
    let work = tempfile::Builder::new()
        .prefix("lunepack-keys-")
        .tempdir()
        .context("cannot create a work directory")?;
    let wdir = work.path().join("release");
    fs::create_dir(&wdir).context("cannot create the work directory")?;
    let state_file = work.path().join(DEFAULT_STATE);
    let skip = ClockReading::read(&lunepack::SystemClock, Some(u64::MAX));
    let read = work::read_store(&stores, &config, publish, &wdir, &state_file, &skip)?;

    // The store's roots must be the start of the directory's: the directory was made from them.
    if new_roots.len() < read.roots.len() || new_roots[..read.roots.len()] != read.roots[..] {
        bail!(
            "the root-<k>.json files in {} do not continue the store's (nothing was written): run `publish fetch` into a new directory and make the change there",
            dir.display()
        );
    }
    let roots_new: Vec<&(u64, Vec<u8>)> = new_roots[read.roots.len()..].iter().collect();
    let same_keys = new_keys_bytes == read.keys_bytes;
    if !same_keys && new_chain.keys().version() <= read.chain.keys().version() {
        bail!(
            "keys.json in {} is version {}, not newer than the store's {} (nothing was written): run `lunepack keys set` or `keys rotate-root` on a fetched directory",
            dir.display(),
            new_chain.keys().version(),
            read.chain.keys().version()
        );
    }
    if same_keys && !roots_new.is_empty() {
        bail!(
            "{} has root-<k>.json files the store lacks but the store's keys.json (nothing was written): a root rotation changes keys.json too",
            dir.display()
        );
    }

    // The state file's record: this change must not lower it.
    let mut state = State::load(&state_file)?;
    let record = state.record(&config.app_id);
    let mut next = record.clone();
    next.set_keys(new_root_k, new_chain.keys());
    let lowered = record.lowered_by(&next);
    if !lowered.is_empty() {
        bail!(
            "the private state file records newer documents than the directory's ({}); nothing was written",
            lowered.join("; ")
        );
    }

    // Every live feed and manifest must still verify under the new key set.
    if !same_keys {
        let broken = unverifiable(&stores, publish.prefix.as_str(), &config, &read, &new_chain)?;
        if !broken.is_empty() {
            bail!(
                "the new key set would stop these from verifying (nothing was written):\n  {}\nrefresh the feeds with a key you keep (`publish refresh --sign <that key>`) before removing the old key, and drop releases whose manifests only a removed key signed",
                broken.join("\n  ")
            );
        }
    }

    // What is written: roots, then keys.json, then the state file.
    let prefix = publish.prefix.as_str();
    let mut uploads: Vec<(StoreKey, String, &[u8])> = Vec::new();
    for (k, bytes) in &roots_new {
        uploads.push((
            key(prefix, &format!("root-{k}.json"))?,
            format!("root-{k}.json"),
            bytes.as_slice(),
        ));
    }
    if !same_keys {
        uploads.push((
            key(prefix, "keys.json")?,
            "keys.json".to_owned(),
            new_keys_bytes.as_slice(),
        ));
    }
    let state_bytes = if next == record {
        read.state_read.clone()
    } else {
        state.save(&config.app_id, next, StateArgs::default())?;
        fs::read(&state_file).context("cannot read the work directory")?
    };
    let state_changed = state_bytes != read.state_read;
    if uploads.is_empty() && !state_changed {
        return say("nothing to publish: keys.json and the roots equal the store's");
    }
    if args.dry_run {
        for (at, _, bytes) in &uploads {
            say(&format!("would upload: {at} ({} bytes)", bytes.len()))?;
        }
        if state_changed {
            say(&format!("would write: {}", read.state_key))?;
        }
        return say("dry run: nothing was written");
    }

    // Another writer between the read and the first write: refuse.
    if !uploads.is_empty() {
        let keys_key = key(prefix, "keys.json")?;
        let now = work::get(stores.public.as_ref(), &keys_key, Limits::V1.keys_doc_bytes)?;
        if now.as_deref() != Some(read.keys_bytes.as_slice()) {
            bail!(
                "{keys_key} changed in the store since this run read it (another publish?); nothing was written. Run `publish keys` again"
            );
        }
    }
    for (at, rel, bytes) in &uploads {
        work::put_bytes(stores.public.as_ref(), at, rel, bytes)?;
        say(&format!("uploaded: {at}"))?;
    }
    if state_changed {
        work::put_bytes(
            stores.private.as_ref(),
            &read.state_key,
            DEFAULT_STATE,
            &state_bytes,
        )?;
        say(&format!("wrote: {}", read.state_key))?;
    }
    say(&format!(
        "published: key set version {} under {prefix}/",
        new_chain.keys().version()
    ))
}

/// The feeds in the store and the manifests they list that do not verify under `chain`'s key set,
/// one description each. A feed that does not verify is named without its manifests (they cannot
/// be read from it).
fn unverifiable(
    stores: &Stores,
    prefix: &str,
    config: &Config,
    read: &StoreRead,
    chain: &KeysChain,
) -> Result<Vec<String>> {
    let verifier = Ed25519Verifier;
    let skip = ClockReading::read(&lunepack::SystemClock, Some(u64::MAX));
    let mut broken = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let documents = read
        .feeds_read
        .iter()
        .filter_map(|(c, b)| b.as_ref().map(|b| (c, b)))
        .chain(read.guard_read.iter());
    for (channel, bytes) in documents {
        let feed = match verify_feed_of(chain, &config.app_id, channel, bytes, &skip, &verifier) {
            Ok(feed) => feed,
            Err(e) => {
                broken.push(format!("{}: {e}", feed_rel(channel)));
                continue;
            }
        };
        for (i, release) in feed.releases().iter().enumerate() {
            for target in release.targets().keys() {
                let entry = feed
                    .target_entry(i, *target)
                    .context("internal error: a release without its target")?;
                let rel = entry.reference().path().to_owned();
                if !seen.insert(rel.clone()) {
                    continue;
                }
                let at = key(prefix, &rel)?;
                let outcome =
                    match work::get(stores.public.as_ref(), &at, entry.reference().size())? {
                        None => Err(anyhow!(
                            "listed by {}, but the store has none",
                            feed_rel(channel)
                        )),
                        Some(bytes) => {
                            verify_manifest(chain.keys(), &entry, &bytes, &Sha256Hasher, &verifier)
                                .map(|_| ())
                                .map_err(Into::into)
                        }
                    };
                if let Err(e) = outcome {
                    broken.push(format!("{rel}: {e}"));
                }
            }
        }
    }
    Ok(broken)
}

#[cfg(test)]
mod tests {
    //! `publish keys` over in-memory stores: the upload order, the refusal that keeps clients
    //! from a feed they reject, a dry run, the rerun after a failure, and a root rotation.

    use lunepack_core::{StoreMethod, encoding::hex_encode};
    use lunepack_testkit::StoreFault;

    use super::*;
    use crate::cmd_publish::push::tests::{Bucket, World, parse, s};
    use crate::state::DEFAULT_STATE;

    fn keys_in(w: &World, rd: &Path, dry_run: bool) -> Result<()> {
        let open = |_: &crate::config::PublishSettings, _: Option<&Path>| Ok(w.stores());
        let mut args = vec!["--release-dir", s(rd)];
        if dry_run {
            args.push("--dry-run");
        }
        keys(&w.config, &parse::<KeysArgs>(&args), &open)
    }

    /// `keys set` in `rd` for the given release keys (hex), signed by the root.
    fn set_release_keys(w: &World, rd: &Path, release_keys: &[&str]) -> Result<()> {
        let root = format!("file:{}", s(&w.root_signer));
        let mut args = vec![
            "--release-dir",
            s(rd),
            "--threshold",
            "1",
            "--sign",
            &root,
            "--trust-release-dir",
        ];
        for k in release_keys {
            args.push("--release-key");
            args.push(k);
        }
        crate::cmd_keys::set_keys(&w.pack_config, &parse(&args))
    }

    fn release_public(w: &World) -> String {
        w.release_public.clone()
    }

    fn record_keys_version(w: &World) -> Option<u64> {
        w.state_record().keys_version
    }

    #[test]
    fn a_second_release_key_is_published_in_order_and_the_state_follows() {
        let w = World::new("");
        w.publish("1.0.0");
        let rd = w.fetch("rd-keys");
        let extra = lunepack_crypto::generate_key_file(&w.dir.path().join("extra")).unwrap();
        set_release_keys(
            &w,
            &rd,
            &[&release_public(&w), &hex_encode(&extra.public_key)],
        )
        .unwrap();
        w.clear_log();
        keys_in(&w, &rd, true).unwrap();
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        keys_in(&w, &rd, false).unwrap();
        assert_eq!(
            w.writes()
                .into_iter()
                .map(|(b, op, k)| (b, op, k.rsplit('/').next().unwrap().to_owned()))
                .collect::<Vec<_>>(),
            [
                (Bucket::Public, "PUT", "keys.json".to_owned()),
                (Bucket::Private, "PUT", DEFAULT_STATE.to_owned()),
            ]
        );
        assert_eq!(
            w.public
                .contents(&crate::cmd_publish::push::tests::k("keys.json")),
            fs::read(rd.join("keys.json")).ok()
        );
        assert_eq!(record_keys_version(&w), Some(2));
        // The store still serves a feed that verifies, and a second run has nothing to do.
        assert_eq!(w.listed("stable"), ["1.0.0"]);
        w.clear_log();
        keys_in(&w, &rd, false).unwrap();
        assert!(w.writes().is_empty());
        // A push by the old key still works under the new key set.
        w.publish("1.1.0");
    }

    #[test]
    fn removing_the_key_that_signed_the_live_feed_is_refused_and_nothing_is_written() {
        let w = World::new("");
        w.publish("1.0.0");
        let rd = w.fetch("rd-revoke");
        let extra = lunepack_crypto::generate_key_file(&w.dir.path().join("extra")).unwrap();
        // `keys set` itself refuses (its own feed check) unless told otherwise; the store check
        // is the one this command adds for feeds the directory does not hold.
        let e = set_release_keys(&w, &rd, &[&hex_encode(&extra.public_key)]).unwrap_err();
        assert!(format!("{e:#}").contains("feed-stable.json"), "{e:#}");
        std::fs::remove_file(rd.join("feed-stable.json")).unwrap();
        set_release_keys(&w, &rd, &[&hex_encode(&extra.public_key)]).unwrap();
        w.clear_log();
        let e = format!("{:#}", keys_in(&w, &rd, false).unwrap_err());
        assert!(
            e.contains("would stop these from verifying") && e.contains("feed-stable.json"),
            "{e}"
        );
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        assert_eq!(record_keys_version(&w), Some(1));
    }

    #[test]
    fn a_failed_upload_is_completed_by_a_rerun() {
        let w = World::new("");
        w.publish("1.0.0");
        let rd = w.fetch("rd-rerun");
        let extra = lunepack_crypto::generate_key_file(&w.dir.path().join("extra")).unwrap();
        set_release_keys(
            &w,
            &rd,
            &[&release_public(&w), &hex_encode(&extra.public_key)],
        )
        .unwrap();
        let keys_key = crate::cmd_publish::push::tests::k("keys.json");
        let state_key = crate::cmd_publish::push::tests::k(DEFAULT_STATE);
        // keys.json fails: nothing changed, the rerun does everything.
        w.public
            .inject(StoreMethod::Put, Some(&keys_key), StoreFault::Status(503));
        assert!(keys_in(&w, &rd, false).is_err());
        assert_eq!(record_keys_version(&w), Some(1));
        w.public.clear_faults();
        // The state file fails after keys.json: the rerun writes only the state file.
        w.private
            .inject(StoreMethod::Put, Some(&state_key), StoreFault::Status(503));
        assert!(keys_in(&w, &rd, false).is_err());
        assert_eq!(record_keys_version(&w), Some(1));
        w.private.clear_faults();
        w.clear_log();
        keys_in(&w, &rd, false).unwrap();
        assert_eq!(
            w.writes(),
            [(Bucket::Private, "PUT", state_key.to_string())]
        );
        assert_eq!(record_keys_version(&w), Some(2));
    }

    #[test]
    fn a_root_rotation_uploads_the_root_before_keys_json_and_a_push_follows() {
        let w = World::new("");
        w.publish("1.0.0");
        let rd = w.fetch("rd-root");
        let new_root = lunepack_crypto::generate_key_file(&w.dir.path().join("newroot")).unwrap();
        let old = format!("file:{}", s(&w.root_signer));
        let new = format!("file:{}", s(&new_root.path));
        crate::cmd_keys::rotate_root_cmd(
            &w.pack_config,
            &parse(&[
                "--release-dir",
                s(&rd),
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
        w.clear_log();
        keys_in(&w, &rd, false).unwrap();
        let names: Vec<String> = w
            .writes()
            .into_iter()
            .map(|(_, _, k)| k.rsplit('/').next().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["root-2.json", "keys.json", DEFAULT_STATE]);
        assert_eq!(w.state_record().root_version, Some(2));
        // The next push reads the walk through the new root.
        w.publish("1.1.0");
        assert_eq!(w.listed("stable"), ["1.0.0", "1.1.0"]);
    }

    #[test]
    fn an_older_or_unrelated_directory_is_refused() {
        let w = World::new("");
        w.publish("1.0.0");
        let rd = w.fetch("rd-same");
        // The directory equals the store: nothing to publish, nothing written.
        w.clear_log();
        keys_in(&w, &rd, false).unwrap();
        assert!(w.writes().is_empty());
        // A directory with no keys.json is a usage error.
        let empty = w.dir.path().join("rd-empty");
        fs::create_dir(&empty).unwrap();
        let e = keys_in(&w, &empty, false).unwrap_err();
        assert_eq!(super::super::exit_status(&e), 2);
    }
}
