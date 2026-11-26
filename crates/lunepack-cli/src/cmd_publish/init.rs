//! `lunepack publish init --release-dir <dir> [--dry-run]` (P-D11): the user's own first upload of
//! a new app, from a release directory `lunepack init` and `lunepack keys set` made.
//!
//! It checks the directory's root walk and `keys.json` under the config's root, takes the state
//! file's record of this app (and no other app's), refuses when the store already holds any
//! document it would write (naming the first), and then uploads the roots, `keys.json` and the
//! state file, in that order. An existing prefix needs no init: its documents are already there.

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

/// Whether the store has an object at `at`: an object over `cap` exists too.
fn exists(store: &dyn ObjectStore, at: &StoreKey, cap: u64) -> Result<bool> {
    let found = match store.get(at, cap) {
        Ok(got) => got.is_some(),
        Err(StoreError::TooLarge { .. }) => true,
        Err(e) => return Err(e.into()),
    };
    say(&format!(
        "read: {at} {}",
        if found { "found" } else { "absent" }
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
    for item in &items {
        if exists(store_of(item), &item.at, item.cap)? {
            bail!(
                "the store already holds {} (nothing was written): `publish init` writes only into an empty prefix",
                item.at
            );
        }
    }
    if args.dry_run {
        for item in &items {
            say(&format!(
                "would upload: {} ({} bytes)",
                item.at,
                item.bytes.len()
            ))?;
        }
        return say("dry run: nothing was written");
    }
    for item in &items {
        work::put_bytes(store_of(item), &item.at, &item.rel, &item.bytes)?;
        say(&format!("uploaded: {}", item.at))?;
    }
    say(&format!("initialized: {prefix}/"))
}
