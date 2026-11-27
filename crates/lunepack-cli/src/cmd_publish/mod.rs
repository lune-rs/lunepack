//! `lunepack publish`: the standard publish flow of an app (P-D1..P-D13).
//!
//! `fetch` reads the app's public feed over the transport clients use and fills a release
//! directory from it; it reads no credential. `push` publishes a packed release to the app's
//! stores, which the composition root (`main.rs`) builds and hands in as [`Stores`]; `refresh`
//! re-signs the feeds (it writes the public bucket only), `plan` shows what the stores hold and what
//! a push would do (it writes nothing), and `init` uploads a fresh app's first documents and `keys` a key-set change.

pub mod fetch;
pub mod init;
pub mod keys;
pub mod pending;
pub mod plan;
pub mod push;
pub mod refresh;
pub mod work;

use std::fmt;
use std::io::Write;
use std::path::Path;

use anyhow::{Result, anyhow, bail};
use clap::Subcommand;
use lunepack_core::ObjectStore;

use crate::config::{Config, PublishSettings, UpdateSettings};

/// An error that ends the process with status 2, like a usage error of the argument parser.
#[derive(Debug)]
pub struct Usage(pub String);

impl fmt::Display for Usage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Usage {}

/// The exit status of a failed command: 2 for a [`Usage`] error, 1 otherwise.
pub fn exit_status(error: &anyhow::Error) -> u8 {
    if error.downcast_ref::<Usage>().is_some() {
        2
    } else {
        1
    }
}

/// `lunepack publish <command>`.
#[derive(Subcommand)]
pub enum PublishCommand {
    /// Fill a release directory from the public feed: the key set, the roots, the feeds of the
    /// `[publish]` channels and the newest earlier releases, so `pack` can build deltas against
    /// them. Reads no credential.
    Fetch(fetch::FetchArgs),
    /// Publish a packed release: check the release directories against the store, verify every
    /// retained release, write the feeds in-process, then upload in the commit order, purge what
    /// retention dropped and write the state file last.
    Push(push::PushArgs),
    /// Re-sign each channel's feed (all, or those expiring soon) with a new `seq`. Writes the
    /// public bucket only: the state file and the pending deletes are a push's, and a feed older
    /// than the state file records is refused.
    Refresh(refresh::RefreshArgs),
    /// Show the feeds, what a push of a version would add and drop, the pending deletes and any
    /// abandoned push. Reads the stores; writes nothing.
    Plan(plan::PlanArgs),
    /// Upload a new app's `keys.json`, roots and state file from a local release directory.
    Init(init::InitArgs),
    /// Upload a key-set change (`keys set`, `keys rotate-root`) made in a fetched release
    /// directory: new roots, then `keys.json`, then the state file's record, after checking every
    /// feed and manifest in the store still verifies under the new key set. The owner's command;
    /// never an agent's or CI's.
    Keys(keys::KeysArgs),
}

/// The two buckets of an app (P-D4): the public one clients read, the private one with the state
/// file and the pending-deletes record.
pub struct Stores {
    /// Feeds, key set, roots, manifests, packs, deltas.
    pub public: Box<dyn ObjectStore>,
    /// The state file and the pending-deletes record.
    pub private: Box<dyn ObjectStore>,
}

/// Builds the stores of `[publish]`, or the two directories under `--store-dir` when given; it
/// reads the credentials (only from the variables `[publish]` names).
pub type OpenStores<'a> = &'a dyn Fn(&PublishSettings, Option<&Path>) -> Result<Stores>;

/// Runs a `publish` command with the config at `config`.
pub fn run(config: &Path, command: &PublishCommand, open: OpenStores<'_>) -> Result<()> {
    match command {
        PublishCommand::Fetch(args) => fetch::fetch(config, args),
        PublishCommand::Push(args) => push::push(config, args, open),
        PublishCommand::Refresh(args) => refresh::refresh(config, args, open),
        PublishCommand::Plan(args) => plan::plan(config, args, open),
        PublishCommand::Init(args) => init::init(config, args, open),
        PublishCommand::Keys(args) => keys::keys(config, args, open),
    }
}

/// `[update]` and `[publish]` of a config that has both; the publish commands need them.
pub(crate) fn settings(config: &Config) -> Result<(&UpdateSettings, &PublishSettings)> {
    match (&config.update, &config.publish) {
        (Some(update), Some(publish)) => Ok((update, publish)),
        _ => Err(anyhow!(
            "`publish` needs [update], [install] and [publish] in the config"
        )),
    }
}

/// Writes one line to stdout; a closed pipe is an error, not a panic.
pub(crate) fn say(line: &str) -> Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}")?;
    Ok(())
}

/// Q6: the commands that issue a feed (`push`, `refresh`) or are part of the publishing job
/// (`init`) refuse a set `SOURCE_DATE_EPOCH`, before any network access: the writers would issue
/// the feed at that fixed time. It belongs only in the `pack` and `setup` job.
pub(crate) fn refuse_source_date_epoch(command: &str) -> Result<()> {
    if std::env::var_os("SOURCE_DATE_EPOCH").is_some() {
        bail!(
            "SOURCE_DATE_EPOCH is set, and `publish {command}` would issue its documents at that fixed time; unset it for this command (set it only in the job that runs `pack` and `setup`)"
        );
    }
    Ok(())
}
