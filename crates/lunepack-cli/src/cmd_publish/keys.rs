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
//! A rerun after any failure completes the rest (F7): a `keys.json` already equal to the store's
//! is kept, and only a state record that is behind is written. A rotation that stopped after a
//! `root-<k>.json` upload leaves a store whose last root did not sign its `keys.json`, which no
//! other command reads; this command alone reads such a store with the walk ended at the root the
//! state file records, when every root after it is byte-equal to the directory's, and uploads the
//! rest. When an upload of this run fails, the roots this run uploaded are removed again (last
//! first, and only while the store's `keys.json` is still the old one), so clients keep a store
//! they can read; a root that cannot be removed is named and left to the rerun.

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
    let read = match work::read_store(&stores, &config, publish, &wdir, &state_file, &skip) {
        Ok(read) => read,
        Err(e) => match half_done(&stores, &config, publish, work.path(), &new_roots, &skip)? {
            Some(read) => read,
            None => return Err(e),
        },
    };

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
                "the new key set would stop these from verifying (nothing was written):\n  {}\nrefresh the feeds with a key you keep (`publish refresh --sign <that key>`) before removing the old key, and drop the releases whose manifests only a removed key signed (`publish refresh --sign <that key> --drop <version>`); then run this again with the same directory",
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
    let mut sent_roots: Vec<&StoreKey> = Vec::new();
    for (at, rel, bytes) in &uploads {
        if rel.starts_with("root-") {
            // Noted before the request: a lost answer may have stored it.
            sent_roots.push(at);
        }
        if let Err(e) = work::put_bytes(stores.public.as_ref(), at, rel, bytes) {
            take_back(&stores, prefix, &sent_roots, &read.keys_bytes)?;
            return Err(e);
        }
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

/// F7: the store as a rotation that stopped part-way left it, or `None`. It is read with the root
/// walk ended at the root the state file records (the config's root when it records none), and is
/// taken only when that read verifies and every store root after that one is byte-equal to the
/// directory's root of the same number: this run then uploads the rest.
fn half_done(
    stores: &Stores,
    config: &Config,
    publish: &crate::config::PublishSettings,
    work_root: &Path,
    dir_roots: &[(u64, Vec<u8>)],
    skip: &ClockReading,
) -> Result<Option<StoreRead>> {
    let state_file = work_root.join("half-done-state.json");
    let state_key = key(publish.prefix.as_str(), DEFAULT_STATE)?;
    // Any failure here reports the first read's error instead.
    let Ok(Some(state_bytes)) = work::get(
        stores.private.as_ref(),
        &state_key,
        crate::state::MAX_STATE_BYTES,
    ) else {
        return Ok(None);
    };
    fs::write(&state_file, &state_bytes).context("cannot write the work directory")?;
    let Ok(state) = State::load(&state_file) else {
        return Ok(None);
    };
    let walk_to = state
        .record(&config.app_id)
        .root_version
        .unwrap_or(config.root_version);
    let wdir = work_root.join("half-done");
    fs::create_dir(&wdir).context("cannot create the work directory")?;
    let Ok(read) = work::read_store_walk(
        stores,
        config,
        publish,
        &wdir,
        &state_file,
        skip,
        Some(walk_to),
    ) else {
        return Ok(None);
    };
    let after: Vec<&(u64, Vec<u8>)> = read.roots.iter().filter(|(k, _)| *k > walk_to).collect();
    if after.is_empty() || after.iter().any(|root| !dir_roots.contains(root)) {
        return Ok(None);
    }
    // The state file the rest of the run reads is this one.
    fs::copy(&state_file, work_root.join(DEFAULT_STATE))
        .context("cannot write the work directory")?;
    say(&format!(
        "notice: the store holds {} of this directory but the keys.json root-{walk_to} signed: a `publish keys` stopped part-way; this run uploads the rest",
        after
            .iter()
            .map(|(k, _)| format!("root-{k}.json"))
            .collect::<Vec<_>>()
            .join(", ")
    ))?;
    Ok(Some(read))
}

/// F7: after a failed upload, removes the roots this run sent (`sent`, last first), while the
/// store's `keys.json` is still `old_keys`; a root walk past the root that signed `keys.json` would
/// stop every client. Each outcome is printed; nothing here fails the run (the upload's error is
/// the one reported, and a rerun finishes what is left).
fn take_back(stores: &Stores, prefix: &str, sent: &[&StoreKey], old_keys: &[u8]) -> Result<()> {
    if sent.is_empty() {
        return Ok(());
    }
    let keys_key = key(prefix, "keys.json")?;
    match work::get(stores.public.as_ref(), &keys_key, Limits::V1.keys_doc_bytes) {
        Ok(Some(now)) if now == old_keys => {}
        _ => {
            // keys.json may be the new one (an answer lost after the write): the roots stay.
            return say(&format!(
                "not removed: {} ({keys_key} could not be read back as the old one); run `publish keys` again to finish",
                sent.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    for at in sent.iter().rev() {
        match stores.public.delete(at) {
            Ok(()) => say(&format!(
                "removed: {at} (uploaded by this run; the store's keys.json is still the old one)"
            ))?,
            Err(e) => {
                say(&format!(
                    "not removed: {at}: {e}; run `publish keys` again to finish"
                ))?;
                // An earlier root stays too: the walk must not skip a number.
                return Ok(());
            }
        }
    }
    Ok(())
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
    use crate::cmd_publish::push::tests::{Bucket, World, parse, s, snapshot_of};
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

    /// A fetched directory with a root rotation of `steps` steps, ready for `publish keys`.
    fn rotated(w: &World, name: &str, steps: usize) -> PathBuf {
        let rd = w.fetch(name);
        let mut signer = w.root_signer.clone();
        for i in 0..steps {
            signer = w.rotate_root(&rd, &signer, &format!("{name}-root{}", i + 2));
        }
        rd
    }

    /// What push, refresh and plan read first: `read_store`, which walks every root.
    fn others_read(w: &World) -> Result<()> {
        let config = Config::load(&w.config)?;
        let (_, publish) = settings(&config)?;
        let work = tempfile::tempdir()?;
        let wdir = work.path().join("release");
        fs::create_dir(&wdir)?;
        let skip = ClockReading::read(&lunepack::SystemClock, Some(u64::MAX));
        work::read_store(
            &w.stores(),
            &config,
            publish,
            &wdir,
            &work.path().join(DEFAULT_STATE),
            &skip,
        )
        .map(|_| ())
    }

    /// F7: a rotation (one step, then two) stopped at each of its writes, by a refused request or
    /// by an answer lost after the write, with the take-back of the roots working or failing: the
    /// rerun with the same directory completes it, the store is then the clean run's, and a push
    /// follows. While the take-back works, the store stays one a client reads; a store left half
    /// done is refused by the reader every other command uses.
    #[test]
    fn a_rotation_stopped_at_any_write_is_completed_by_a_rerun() {
        for steps in [1, 2] {
            let w = World::new("");
            w.publish("1.0.0");
            let rd = rotated(&w, &format!("rd-rotate-{steps}"), steps);
            let snap = w.snapshot();
            w.clear_log();
            keys_in(&w, &rd, false).unwrap();
            let done = snapshot_of(&w.public);
            let record = w.state_record();
            let points = w.writes();
            assert_eq!(points.len(), steps + 2, "{points:?}");
            let mut half_done = 0;
            for take_back_fails in [false, true] {
                for fault in [StoreFault::Status(500), StoreFault::LostAnswer] {
                    for (bucket, _, at) in &points {
                        let what = format!(
                            "{steps} step(s), {fault:?} at {at}, take-back fails: {take_back_fails}"
                        );
                        w.restore(&snap);
                        let store = match bucket {
                            Bucket::Public => &w.public,
                            Bucket::Private => &w.private,
                        };
                        let at = StoreKey::parse(crate::cmd_publish::push::tests::P, at).unwrap();
                        store.inject(StoreMethod::Put, Some(&at), fault);
                        if take_back_fails {
                            w.public
                                .inject(StoreMethod::Delete, None, StoreFault::Status(503));
                        }
                        assert!(keys_in(&w, &rd, false).is_err(), "{what}");
                        w.public.clear_faults();
                        w.private.clear_faults();
                        if w.readable() {
                            others_read(&w).unwrap_or_else(|e| panic!("{what}: {e:#}"));
                        } else {
                            assert!(take_back_fails, "{what}: the take-back left it unreadable");
                            half_done += 1;
                            let e = format!("{:#}", others_read(&w).unwrap_err());
                            assert!(
                                e.contains("does not verify") && e.contains("publish keys"),
                                "{what}: {e}"
                            );
                        }
                        keys_in(&w, &rd, false)
                            .unwrap_or_else(|e| panic!("{what}: the rerun failed: {e:#}"));
                        assert!(snapshot_of(&w.public) == done, "{what}");
                        assert_eq!(w.state_record(), record, "{what}");
                    }
                }
            }
            // With a failed take-back, a root stored before the fault (or by it) is left: half done.
            assert_eq!(half_done, 2 * steps, "{steps} step(s)");
            w.publish("1.1.0");
            assert_eq!(w.listed("stable"), ["1.0.0", "1.1.0"]);
        }
    }

    fn refresh_with_key(w: &World, signer: &Path, drop: &[&str]) -> Result<()> {
        use crate::cmd_publish::refresh;
        let config = Config::load(&w.config)?;
        let sign = [format!("file:{}", s(signer))];
        let drop: Vec<String> = drop.iter().map(|v| (*v).to_owned()).collect();
        refresh::run(
            &refresh::Job {
                config_path: &w.config,
                config: &config,
                sign: &sign,
                within_days: None,
                skip_if_unpublished: false,
                drop: &drop,
                dry_run: false,
                clock: std::sync::Arc::new(lunepack::SystemClock),
            },
            &w.stores(),
            &refresh::ORDER,
        )
    }

    /// F8: the whole revocation of the one release key, as PUBLISHING.md gives it, through
    /// `publish` alone: move 1 (both keys), the new key in the CI secrets, a release signed by the
    /// new key, `publish refresh --sign <new> --drop` of every release only the old key signed,
    /// then move 2 (the new key alone). The old key then signs nothing the store accepts.
    #[test]
    fn a_leaked_release_key_is_revoked_end_to_end() {
        let mut w = World::new("keep = 5\n");
        w.publish("1.0.0");
        w.publish("1.1.0");
        let old_signer = w.release_signer.clone();
        let new = lunepack_crypto::generate_key_file(&w.dir.path().join("new-release")).unwrap();
        let new_public = hex_encode(&new.public_key);

        // Move 1: the old and the new key.
        let rd = w.fetch("rd-move-1");
        set_release_keys(&w, &rd, &[&release_public(&w), &new_public]).unwrap();
        keys_in(&w, &rd, false).unwrap();
        // The CI environments now hold the new key: the next release is signed by it.
        w.release_signer = new.path.clone();
        w.publish("1.2.0");
        assert_eq!(w.listed("stable"), ["1.0.0", "1.1.0", "1.2.0"]);

        // Move 2 too early: the manifests of 1.0.0 and 1.1.0 need the old key. (The owner keeps
        // this directory: `keys set` recorded its key set in the owner's state file.)
        let early = w.fetch("rd-move-2-early");
        // (`keys set` refuses on its own over the directory's copy of the feed; the store's check
        // is the one under test.)
        fs::remove_file(early.join("feed-stable.json")).unwrap();
        set_release_keys(&w, &early, &[&new_public]).unwrap();
        w.clear_log();
        let e = format!("{:#}", keys_in(&w, &early, false).unwrap_err());
        assert!(
            e.contains("would stop these from verifying")
                && e.contains("1.0.0/")
                && e.contains("1.1.0/"),
            "{e}"
        );
        assert!(w.writes().is_empty(), "{:?}", w.writes());

        // Drop what only the old key signed, re-signing the feed with the new key.
        refresh_with_key(&w, &new.path, &["1.0.0", "1.1.0"]).unwrap();
        assert_eq!(w.listed("stable"), ["1.2.0"]);

        // Move 2, the refused directory published again as it is: the new key alone.
        keys_in(&w, &early, false).unwrap();
        assert_eq!(w.chain().keys().version(), 3);
        assert_eq!(record_keys_version(&w), Some(3));

        // The old key signs nothing the store takes; the new one refreshes and publishes.
        assert!(refresh_with_key(&w, &old_signer, &[]).is_err());
        refresh_with_key(&w, &new.path, &[]).unwrap();
        w.publish("1.3.0");
        assert_eq!(w.listed("stable"), ["1.2.0", "1.3.0"]);
        // The dropped releases' objects are left in the bucket, listed by no feed.
        assert!(w.folders().contains("1.0.0"));
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
