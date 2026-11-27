//! `lunepack publish init --release-dir <dir> [--dry-run]` (P-D11): the user's own first upload of
//! a new app, from a release directory `lunepack init` and `lunepack keys set` made.
//!
//! It checks the directory's root walk and `keys.json` under the config's root, takes the state
//! file's record of this app (and no other app's), refuses when the store already holds other
//! bytes at any document it would write (naming the first), and then uploads the roots,
//! `keys.json` and the state file, in that order. A document already there with exactly these
//! bytes is kept, so a rerun after a failed upload completes the rest (F7). An existing prefix
//! needs no init: its documents are already there.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use lunepack_core::{ClockReading, Limits, ObjectStore, StoreError, StoreKey};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use super::push::local_roots;
use super::work::{self, key};
use super::{Stores, Usage, say, settings};
use crate::config::Config;
use crate::release_dir::{self, read_capped};
use crate::state::{DEFAULT_STATE, MAX_STATE_BYTES, State, StateArgs};

/// Arguments of `publish init`.
#[derive(Args)]
pub struct InitArgs {
    /// The release directory with `keys.json` and any `root-<k>.json` files.
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

/// One document to upload.
struct Item {
    at: StoreKey,
    /// The name under the prefix, for the content type.
    rel: String,
    bytes: Vec<u8>,
    /// The cap a reader of it applies; the existence check reads at most this much.
    cap: u64,
    private: bool,
}

/// What the store has at an item's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Found {
    Absent,
    /// Exactly the item's bytes (an earlier run's upload).
    Same,
    /// Other bytes, or an object over the item's cap.
    Other,
}

/// What the store has at `item.at`.
fn found(store: &dyn ObjectStore, item: &Item) -> Result<Found> {
    let found = match store.get(&item.at, item.cap) {
        Ok(None) => Found::Absent,
        Ok(Some(bytes)) if bytes == item.bytes => Found::Same,
        Ok(Some(_)) | Err(StoreError::TooLarge { .. }) => Found::Other,
        Err(e) => return Err(e.into()),
    };
    say(&format!(
        "read: {} {}",
        item.at,
        match found {
            Found::Absent => "absent",
            Found::Same => "found, the same bytes",
            Found::Other => "found",
        }
    ))?;
    Ok(found)
}

/// `publish init`.
pub fn init(config_path: &Path, args: &InitArgs, open: super::OpenStores<'_>) -> Result<()> {
    super::refuse_source_date_epoch("init")?;
    let config = Config::load(config_path)?;
    let (_, publish) = settings(&config)?;
    let prefix = publish.prefix.as_str();
    let dir = args.release_dir.as_path();

    // The local documents, checked before any request.
    let reading = ClockReading::read(&lunepack::SystemClock, None);
    let opened = release_dir::open(dir, &config, &Sha256Hasher, &Ed25519Verifier, &reading)
        .with_context(|| format!("{} does not verify", dir.display()))?;
    let Some(chain) = opened.chain else {
        return Err(Usage(format!(
            "{} has no keys.json: run `lunepack keys set` first",
            dir.display()
        ))
        .into());
    };
    let keys_bytes = read_capped(&release_dir::keys_path(dir), Limits::V1.keys_doc_bytes)?
        .context("keys.json vanished")?;
    let roots = local_roots(dir, config.root_version)?;
    let record = State::load(&config.state_path)?.record(&config.app_id);
    if record.keys_version != Some(chain.keys().version()) {
        bail!(
            "the state file records no keys.json version {} for this app: run `lunepack keys set` for the keys.json in {}",
            chain.keys().version(),
            dir.display()
        );
    }
    // The store's state file holds this app's record only, not any other app's.
    let scratch = tempfile::tempdir().context("cannot create a work directory")?;
    let scratch_state = scratch.path().join(DEFAULT_STATE);
    State::load(&scratch_state)?.save(&config.app_id, record, StateArgs::default())?;
    let state_bytes = fs::read(&scratch_state).context("cannot read the work directory")?;

    let mut items = Vec::new();
    for (k, bytes) in roots {
        items.push(Item {
            at: key(prefix, &format!("root-{k}.json"))?,
            rel: format!("root-{k}.json"),
            bytes,
            cap: Limits::V1.root_doc_bytes,
            private: false,
        });
    }
    items.push(Item {
        at: key(prefix, "keys.json")?,
        rel: "keys.json".to_owned(),
        bytes: keys_bytes,
        cap: Limits::V1.keys_doc_bytes,
        private: false,
    });
    items.push(Item {
        at: key(prefix, DEFAULT_STATE)?,
        rel: DEFAULT_STATE.to_owned(),
        bytes: state_bytes,
        cap: MAX_STATE_BYTES,
        private: true,
    });

    // The credentials are read here; every check precedes the first write.
    let stores: Stores = open(publish, args.store_dir.as_deref())?;
    let store_of = |item: &Item| -> &dyn ObjectStore {
        if item.private {
            stores.private.as_ref()
        } else {
            stores.public.as_ref()
        }
    };
    let mut todo = Vec::new();
    for item in &items {
        match found(store_of(item), item)? {
            Found::Absent => todo.push(item),
            Found::Same => {}
            Found::Other => bail!(
                "the store already holds {} (nothing was written): `publish init` writes only into an empty prefix",
                item.at
            ),
        }
    }
    if todo.is_empty() {
        return say(&format!(
            "nothing to upload: {prefix}/ already holds these documents"
        ));
    }
    if args.dry_run {
        for item in &todo {
            say(&format!(
                "would upload: {} ({} bytes)",
                item.at,
                item.bytes.len()
            ))?;
        }
        return say("dry run: nothing was written");
    }
    for item in &todo {
        work::put_bytes(store_of(item), &item.at, &item.rel, &item.bytes)?;
        say(&format!("uploaded: {}", item.at))?;
    }
    say(&format!("initialized: {prefix}/"))
}

#[cfg(test)]
mod tests {
    //! `publish init` over in-memory stores: a run stopped at any write is completed by a rerun.

    use lunepack_core::StoreMethod;
    use lunepack_testkit::StoreFault;

    use super::*;
    use crate::cmd_publish::push::tests::{Bucket, P, Snapshot, World, parse, s};

    fn init_in(w: &World, rd: &Path) -> Result<()> {
        let open = |_: &crate::config::PublishSettings, _: Option<&Path>| Ok(w.stores());
        init(
            &w.config,
            &parse::<InitArgs>(&["--release-dir", s(rd)]),
            &open,
        )
    }

    /// F7: an init (with a root rotation, so it writes a root, `keys.json` and the state file)
    /// stopped at each write, by a refused request or an answer lost after the write: the rerun
    /// completes it to the clean run's store, and a push follows.
    #[test]
    fn a_rerun_completes_an_init_stopped_at_any_write() {
        let w = World::new("");
        let origin = w.dir.path().join("origin");
        w.rotate_root(&origin, &w.root_signer, "init-root2");
        let empty = (Snapshot::new(), Snapshot::new());
        w.restore(&empty);
        init_in(&w, &origin).unwrap();
        let done = w.snapshot();
        let points = w.writes();
        assert_eq!(
            points
                .iter()
                .map(|(_, _, k)| k.rsplit('/').next().unwrap())
                .collect::<Vec<_>>(),
            ["root-2.json", "keys.json", DEFAULT_STATE]
        );
        for fault in [StoreFault::Status(500), StoreFault::LostAnswer] {
            for (bucket, _, at) in &points {
                w.restore(&empty);
                let store = match bucket {
                    Bucket::Public => &w.public,
                    Bucket::Private => &w.private,
                };
                let at = StoreKey::parse(P, at).unwrap();
                store.inject(StoreMethod::Put, Some(&at), fault);
                assert!(init_in(&w, &origin).is_err(), "{fault:?} at {at}");
                w.public.clear_faults();
                w.private.clear_faults();
                init_in(&w, &origin)
                    .unwrap_or_else(|e| panic!("{fault:?} at {at}: the rerun failed: {e:#}"));
                assert!(w.snapshot() == done, "{fault:?} at {at}");
            }
        }
        // A finished init has nothing to upload, and a push reads what it wrote.
        w.clear_log();
        init_in(&w, &origin).unwrap();
        assert!(w.writes().is_empty(), "{:?}", w.writes());
        w.publish("1.0.0");
    }
}
