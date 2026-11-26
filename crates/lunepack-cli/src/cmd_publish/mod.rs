//! `lunepack publish`: the standard publish flow of an app (P-D1..P-D13).
//!
//! `fetch` reads the app's public feed over the transport clients use and fills a release
//! directory from it; it reads no credential. The commands that write to a store come in the next
//! steps of the publish work.

pub mod fetch;

use std::fmt;
use std::io::Write;
use std::path::Path;

use anyhow::{Result, anyhow};
use clap::Subcommand;

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
}

/// Runs a `publish` command with the config at `config`.
pub fn run(config: &Path, command: &PublishCommand) -> Result<()> {
    match command {
        PublishCommand::Fetch(args) => fetch::fetch(config, args),
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
