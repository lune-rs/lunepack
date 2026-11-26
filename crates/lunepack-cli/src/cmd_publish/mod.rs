//! `lunepack publish`: the standard publish flow of an app (P-D1..P-D13).
//!
//! `fetch` reads the app's public feed over the transport clients use and fills a release
//! directory from it; it reads no credential. `push` publishes a packed release to the app's
//! stores, which the composition root (`main.rs`) builds and hands in as [`Stores`].

pub mod fetch;
pub mod pending;
pub mod push;
pub mod work;

use std::fmt;
use std::io::Write;
use std::path::Path;

use anyhow::{Result, anyhow};
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
