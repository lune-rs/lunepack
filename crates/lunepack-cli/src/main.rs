//! Command-line packager and release tool; the composition root that wires traits to adapters.
//!
//! Exit status: 0 on success, 1 on any failure (`error: <message and causes>` on stderr), 2 on a
//! usage error (clap, or an argument `publish` refuses). No command prints private-key material, an environment variable's value or
//! a config value.

mod cmd_feed;
mod cmd_keys;
mod cmd_pack;
mod cmd_prebuilt;
mod cmd_publish;
mod cmd_setup;
mod cmd_verify;
mod codesign;
mod config;
mod dmg;
mod pipeline;
mod pkg;
mod place;
mod plist;
mod prebuilt;
mod project_key;
mod release_dir;
mod stamp;
mod state;
mod tool;
mod zip;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use lunepack_core::{CodeSign, Error, SignItem};
use lunepack_http::{Credentials, DirStore, S3Store};

use crate::config::{PublishSettings, StoreKind};

#[derive(Parser)]
#[command(
    name = "lunepack",
    version,
    about = "Package, sign and publish app releases"
)]
struct Cli {
    /// The config file.
    #[arg(long, global = true, default_value = config::DEFAULT_CONFIG)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a config naming the app and its compiled-in root keys.
    Init(cmd_keys::InitArgs),
    /// Manage signing keys, `keys.json` and root rotation.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Package a build-output directory into a signed release: `<version>/<target>.pack` and
    /// `<version>/<target>.manifest.json` in the release directory.
    Pack(cmd_pack::PackArgs),
    /// Manage the signed feed of a channel.
    Feed {
        #[command(subcommand)]
        command: FeedCommand,
    },
    /// Check a release directory the way a client does: keys, feeds, manifests, packs and frames.
    Verify(cmd_verify::VerifyArgs),
    /// Verify a release directory, then show what it holds.
    Inspect(cmd_verify::InspectArgs),
    /// Build a Linux setup file: the release's runtime with one version's key set, manifest and
    /// pack, installable offline (`<app_id>-<version>-<target>-setup`).
    Setup(cmd_setup::SetupArgs),
    /// The standard publish flow: fetch the published state, then push a release; refresh the
    /// feeds, plan and init.
    Publish {
        #[command(subcommand)]
        command: cmd_publish::PublishCommand,
    },
    /// lunepack's own prebuilt binaries: what this CLI pins, and the project's signed list of them.
    Prebuilt {
        #[command(subcommand)]
        command: PrebuiltCommand,
    },
}

#[derive(Subcommand)]
enum PrebuiltCommand {
    /// Show the project's key sets compiled into this CLI and the binaries it pins.
    List(cmd_prebuilt::ListArgs),
    /// Parse a list with this CLI's own parser and print what it read (no key, no network).
    Check(cmd_prebuilt::CheckArgs),
    /// Sign a list: write its envelope after checking it under the project's key set.
    Sign(cmd_prebuilt::SignArgs),
    /// Check a list's envelope under a key set, and optionally the downloaded files.
    Verify(cmd_prebuilt::VerifyArgs),
    /// Download this CLI's pinned binaries of one target and check them against the pins.
    Fetch(cmd_prebuilt::FetchArgs),
}

#[derive(Subcommand)]
enum FeedCommand {
    /// Add a release (or more targets of it) to a channel's feed.
    Add(cmd_feed::AddArgs),
    /// Re-sign a channel's feed with a new `seq` and expiry; the releases stay.
    Refresh(cmd_feed::RefreshArgs),
}

#[derive(Subcommand)]
enum KeysCommand {
    /// Generate a signing key file; prints its public key and id.
    Gen(cmd_keys::GenArgs),
    /// Print a signer's public key and id.
    Show(cmd_keys::ShowArgs),
    /// Write `keys.json` with the release keys, signed by the root.
    Set(cmd_keys::SetArgs),
    /// Rotate the root: write the next `root-<k>.json` and re-sign `keys.json`.
    RotateRoot(cmd_keys::RotateArgs),
}

/// The code-signing hook of C2 stage 2 in M3: the identity, which changes nothing.
struct NoCodeSign;

impl CodeSign for NoCodeSign {
    fn sign_tree(&self, _root: &std::path::Path, _plan: &[SignItem]) -> Result<(), Error> {
        Ok(())
    }
}

/// The value of the variable `name`, which `[publish] <field>` names. The error names the variable,
/// never a value.
fn publish_env(name: &str, field: &str) -> anyhow::Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) | Err(std::env::VarError::NotPresent) => {
            bail!("the environment variable {name} ([publish] {field}) is not set")
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("the environment variable {name} ([publish] {field}) is not valid text")
        }
    }
}

/// The store credentials, from the variables `[publish]` names; read once per store, so no copy
/// outlives the `Credentials` that zeroize it.
fn store_credentials(publish: &PublishSettings) -> anyhow::Result<Credentials> {
    Ok(Credentials::new(
        publish_env(&publish.access_key_env, "access_key_env")?,
        publish_env(&publish.secret_key_env, "secret_key_env")?,
    ))
}

/// The stores of `publish` (the composition root wires the adapters): `S3Store` for `r2` and `s3`,
/// signing at the system clock (never `SOURCE_DATE_EPOCH`'s), or two `DirStore`s under
/// `--store-dir`, which reads no variable.
fn open_stores(
    publish: &PublishSettings,
    store_dir: Option<&Path>,
) -> anyhow::Result<cmd_publish::Stores> {
    if let Some(dir) = store_dir {
        return Ok(cmd_publish::Stores {
            public: Box::new(DirStore::new(dir.join("public"))),
            private: Box::new(DirStore::new(dir.join("private"))),
        });
    }
    let clock: Arc<dyn lunepack_core::Clock> = Arc::new(lunepack::SystemClock);
    let open = |bucket: &str| -> anyhow::Result<Box<dyn lunepack_core::ObjectStore>> {
        let credentials = store_credentials(publish)?;
        let store = match &publish.store {
            StoreKind::R2 { account_id_env } => S3Store::r2(
                &publish_env(account_id_env, "account_id_env")?,
                bucket,
                credentials,
                clock.clone(),
            ),
            StoreKind::S3 {
                endpoint_env,
                region,
            } => S3Store::new(
                &publish_env(endpoint_env, "endpoint_env")?,
                bucket,
                region,
                credentials,
                clock.clone(),
            ),
        };
        Ok(Box::new(
            store.context("[publish] does not describe a usable store")?,
        ))
    };
    Ok(cmd_publish::Stores {
        public: open(&publish.public_bucket)?,
        private: open(&publish.private_bucket)?,
    })
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Init(args) => cmd_keys::init(&cli.config, &args),
        Command::Keys { command } => match command {
            KeysCommand::Gen(args) => cmd_keys::gen_key(&args),
            KeysCommand::Show(args) => cmd_keys::show_key(&cli.config, &args),
            KeysCommand::Set(args) => cmd_keys::set_keys(&cli.config, &args),
            KeysCommand::RotateRoot(args) => cmd_keys::rotate_root_cmd(&cli.config, &args),
        },
        Command::Pack(args) => cmd_pack::pack(&cli.config, &args, &NoCodeSign),
        Command::Feed { command } => match command {
            FeedCommand::Add(args) => cmd_feed::add(&cli.config, &args),
            FeedCommand::Refresh(args) => cmd_feed::refresh(&cli.config, &args),
        },
        Command::Verify(args) => cmd_verify::verify(&cli.config, &args),
        Command::Inspect(args) => cmd_verify::inspect(&cli.config, &args),
        Command::Setup(args) => cmd_setup::setup(&cli.config, &args),
        Command::Publish { command } => cmd_publish::run(&cli.config, &command, &open_stores),
        Command::Prebuilt { command } => match command {
            PrebuiltCommand::List(args) => cmd_prebuilt::list(&args),
            PrebuiltCommand::Check(args) => cmd_prebuilt::check(&args),
            PrebuiltCommand::Sign(args) => cmd_prebuilt::sign(&cli.config, &args),
            PrebuiltCommand::Verify(args) => cmd_prebuilt::verify(&args),
            PrebuiltCommand::Fetch(args) => cmd_prebuilt::fetch(&args),
        },
    }
}

fn main() -> ExitCode {
    // Usage errors and --help are handled (and exit) here; 2 is clap's status for a usage error.
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(cmd_publish::exit_status(&e))
        }
    }
}
