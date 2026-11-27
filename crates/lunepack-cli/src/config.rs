//! `lunepack.toml` (M3 step 7), signer specs and the writer clock.
//!
//! The file is local configuration, not a document anyone signs: it names the app, the compiled-in
//! root (public keys only) and how to reach each signer. It holds no secret, but it may name
//! variables and commands, so a parse error reports the file and the line and never the text of
//! the line.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use lunepack_core::encoding::hex_decode_array;
use lunepack_core::limits::MAX_JSON_INT;
use lunepack_core::update_config::{DEFAULT_HEALTH_TIMEOUT_SECS, HEALTH_TIMEOUT_SECS};
use lunepack_core::{
    AppId, ArgvTemplate, Channel, Clock, FileType, Hasher, InstallMeta, PublisherPolicy, RelPath,
    Signer, StoreKey, Target, TemplateRole, TrustedRoot, Verifier,
};
use lunepack_crypto::{CommandSigner, Ed25519Signer};
use serde::Deserialize;

/// The default config path.
pub const DEFAULT_CONFIG: &str = "lunepack.toml";
/// Largest config file read.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    app_id: String,
    root: RawRoot,
    #[serde(default)]
    signers: BTreeMap<String, RawSigner>,
    /// The publisher state file (M3-R2-D1), relative to the config's directory.
    state: Option<String>,
    /// How a packed tree updates itself (M5-D7); absent for an app that does not.
    update: Option<RawUpdate>,
    /// How the packed tree is installed (M5-D4); required with `update`.
    install: Option<RawInstall>,
    /// Windows-only packager inputs (M7-D14).
    windows: Option<RawWindows>,
    /// macOS-only packager inputs (M8, step 7).
    macos: Option<RawMacos>,
    /// OS code signing, per operating system (M9-D2).
    codesign: Option<RawCodeSign>,
    /// Where and how a release is published (P-D4); absent for an app that does not use
    /// `lunepack publish`.
    publish: Option<RawPublish>,
}

/// `[publish]`: names of environment variables, never their values (P-D4).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPublish {
    prefix: String,
    store: String,
    account_id_env: Option<String>,
    endpoint_env: Option<String>,
    region: Option<String>,
    access_key_env: String,
    secret_key_env: String,
    private_access_key_env: Option<String>,
    private_secret_key_env: Option<String>,
    public_bucket: String,
    private_bucket: String,
    keep: Option<u64>,
    deltas: Option<u64>,
    feed_days: Option<u64>,
    channels: Option<Vec<String>>,
    prerelease_channels: Option<Vec<String>>,
    #[serde(default)]
    require_targets: Vec<String>,
}

/// `[codesign]`: one section per operating system that is signed (M9-D2); there is none for Linux.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCodeSign {
    windows: Option<RawCodeSignSection>,
    macos: Option<RawCodeSignSection>,
}

/// `[codesign.windows]` or `[codesign.macos]`: argv templates (M9-D1) for the developer's signing
/// tools. The macOS-only keys are refused in the Windows section, naming the key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCodeSignSection {
    sign: Vec<String>,
    sign_bundle: Option<Vec<String>>,
    sign_outer: Option<Vec<String>>,
    sign_installer: Option<Vec<String>>,
    verify: Option<Vec<String>>,
    notarize: Option<Vec<String>>,
    staple: Option<Vec<String>>,
    timeout_secs: Option<u64>,
    notarize_timeout_secs: Option<u64>,
}

/// `[macos]`: inputs for the update window's helper app; not part of any signed document.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMacos {
    /// An `.icns` file, relative to the config's directory.
    icon: Option<String>,
}

/// `[windows]`: inputs for stamping a Windows stub and setup file; not part of any signed document.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWindows {
    /// An `.ico` file, relative to the config's directory.
    icon: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUpdate {
    feed: String,
    channel: Option<String>,
    health_timeout_secs: Option<u64>,
    /// `off`, `warn` or `enforce` (M9-D6); absent takes the default for the target.
    publisher_check: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInstall {
    entry: String,
    name: String,
    comment: Option<String>,
    publisher: Option<String>,
    icon: Option<String>,
    #[serde(default)]
    categories: Vec<String>,
    bin: Option<String>,
    #[serde(default)]
    terminal: bool,
    /// `[[install.file_types]]` (M7-D3).
    #[serde(default)]
    file_types: Vec<RawFileType>,
    /// Handled URL schemes (M7-D3).
    #[serde(default)]
    url_schemes: Vec<String>,
    /// Start at sign-in (M7-D3).
    #[serde(default)]
    autostart: bool,
    /// `[install.linux]`, `[install.windows]`, `[install.macos]` (P-D5).
    linux: Option<RawInstallOs>,
    windows: Option<RawInstallOs>,
    macos: Option<RawInstallOs>,
}

/// `[install.<os>]` (P-D5): the two install values that differ per operating system, and nothing
/// else.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInstallOs {
    entry: Option<String>,
    icon: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFileType {
    ext: String,
    mime: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoot {
    #[serde(default = "first_root_version")]
    version: u64,
    threshold: u64,
    keys: Vec<String>,
}

fn first_root_version() -> u64 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSigner {
    file: Option<String>,
    env: Option<String>,
    command: Option<Vec<String>>,
    public: Option<String>,
}

/// How to reach one signer, from `[signers.<name>]`.
#[derive(Debug, Clone)]
pub enum SignerSpec {
    /// A PKCS#8 PEM key file, already resolved against the config's directory.
    File(PathBuf),
    /// A PKCS#8 PEM key in an environment variable.
    Env(String),
    /// An external command and the public key it signs for.
    Command {
        /// Program and arguments.
        argv: Vec<String>,
        /// The public key the command must sign for.
        public: [u8; 32],
    },
}

/// The channel a packed tree follows when `[update]` names none.
pub const DEFAULT_UPDATE_CHANNEL: &str = "stable";

/// `[update]` and `[install]`, parsed: what the packager writes into the tree's update config
/// (FORMAT.md 13). The fields are checked again by the config writer in the core.
#[derive(Debug, Clone)]
pub struct UpdateSettings {
    /// The feed directory URL, as written.
    pub feed: String,
    /// The channel the tree follows.
    pub channel: Channel,
    /// How long a supervised start may take to confirm its health.
    pub health_timeout_secs: u64,
    /// The install metadata of `[install]`; a target's own values come from
    /// [`UpdateSettings::install_for`].
    pub install: InstallMeta,
    /// `[install.<os>]` overrides (P-D5).
    overrides: InstallOverrides,
    /// `[update] publisher_check` as written (M9-D6); `None` takes the default for the target,
    /// see [`Config::publisher_policy`].
    pub publisher_check: Option<PublisherPolicy>,
}

/// What `[install.<os>]` overrides, per operating system.
#[derive(Debug, Clone, Default)]
struct InstallOverrides {
    linux: OsInstall,
    windows: OsInstall,
    macos: OsInstall,
}

#[derive(Debug, Clone, Default)]
struct OsInstall {
    entry: Option<RelPath>,
    icon: Option<RelPath>,
}

impl UpdateSettings {
    /// The install metadata for `target`: `[install]` with the `entry` and `icon` of the target's
    /// `[install.<os>]` table laid over it (P-D5).
    pub fn install_for(&self, target: Target) -> InstallMeta {
        let os = if target.is_windows() {
            &self.overrides.windows
        } else if target.is_macos() {
            &self.overrides.macos
        } else {
            &self.overrides.linux
        };
        let mut install = self.install.clone();
        if let Some(entry) = &os.entry {
            install.entry = entry.clone();
        }
        if let Some(icon) = &os.icon {
            install.icon = Some(icon.clone());
        }
        install
    }
}

/// Where `[publish]` says the store is (P-D4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreKind {
    /// Cloudflare R2: the account id is in this environment variable.
    R2 {
        /// Name of the variable that holds the account id.
        account_id_env: String,
    },
    /// Any other S3-compatible store.
    S3 {
        /// Name of the variable that holds the endpoint URL.
        endpoint_env: String,
        /// The region to sign for.
        region: String,
    },
}

/// `[publish]`, parsed and checked (P-D4). It holds the names of the variables that carry the
/// credentials, never a value.
#[derive(Debug, Clone)]
pub struct PublishSettings {
    /// The app's prefix in both buckets: one key segment.
    pub prefix: String,
    /// The kind of store.
    pub store: StoreKind,
    /// Name of the variable holding the access key id.
    pub access_key_env: String,
    /// Name of the variable holding the secret key.
    pub secret_key_env: String,
    /// Names of the variables holding the access key id and the secret key of the private bucket
    /// (S4): both or neither; without them the private bucket uses the pair above too.
    pub private_keys_env: Option<(String, String)>,
    /// The bucket the clients read (feeds, manifests, packs).
    pub public_bucket: String,
    /// The bucket that holds the state file and the pending-deletes record.
    pub private_bucket: String,
    /// How many versions stay published.
    pub keep: u32,
    /// How many earlier versions each release gets a delta from.
    pub deltas: u8,
    /// How many days a feed's signature stays valid.
    pub feed_days: u32,
    /// The channels a release may go to.
    pub channels: Vec<Channel>,
    /// The channels a pre-release goes to.
    pub prerelease_channels: Vec<Channel>,
    /// Targets every release must have.
    pub require_targets: Vec<Target>,
}

/// Default of `[publish] keep`.
pub const DEFAULT_PUBLISH_KEEP: u32 = 10;
/// Default of `[publish] deltas` (the same as `pack --deltas`).
pub const DEFAULT_PUBLISH_DELTAS: u8 = 3;
/// Default of `[publish] feed_days`.
pub const DEFAULT_PUBLISH_FEED_DAYS: u32 = 90;

/// How long one sign or verify call may run when the section names no `timeout_secs` (M9-D2).
pub const DEFAULT_CODESIGN_TIMEOUT_SECS: u64 = 300;
/// How long one notarize call may run when the section names no `notarize_timeout_secs` (M9-D2).
pub const DEFAULT_NOTARIZE_TIMEOUT_SECS: u64 = 3600;
/// The longest timeout a section may name: a day (a larger value is a typo).
pub const MAX_CODESIGN_TIMEOUT_SECS: u64 = 24 * 60 * 60;

/// One resolved `[codesign.<os>]` section (M9-D2): every template parsed, every default applied.
#[derive(Debug, Clone)]
pub struct CodeSignSection {
    /// `sign`: each unsigned PE (Windows) or loose Mach-O file (macOS).
    pub sign: ArgvTemplate,
    /// `sign_bundle`: nested bundles (macOS); defaults to `sign`.
    pub sign_bundle: ArgvTemplate,
    /// `sign_outer`: the app bundle (macOS); defaults to `sign_bundle`.
    pub sign_outer: ArgvTemplate,
    /// `sign_installer`: `Setup.exe`, the installer app's items, the `.dmg` and the all-users `.pkg`
    /// (M11-D8); defaults to `sign`.
    pub sign_installer: ArgvTemplate,
    /// `verify`: run on the signed outer object.
    pub verify: Option<ArgvTemplate>,
    /// `notarize` (macOS); present exactly when `staple` is.
    pub notarize: Option<ArgvTemplate>,
    /// `staple` (macOS); present exactly when `notarize` is.
    pub staple: Option<ArgvTemplate>,
    /// How long one sign or verify call may run.
    pub timeout: Duration,
    /// How long one notarize call may run.
    pub notarize_timeout: Duration,
}

/// A parsed, validated `lunepack.toml`.
#[derive(Debug, Clone)]
pub struct Config {
    /// The app id.
    pub app_id: AppId,
    /// The compiled-in root's version.
    pub root_version: u64,
    /// The compiled-in root's threshold.
    pub root_threshold: u64,
    /// The compiled-in root's public keys.
    pub root_keys: Vec<[u8; 32]>,
    /// The publisher state file (M3-R2-D1): `state` resolved against the config's directory, or
    /// `lunepack-state.json` next to the config.
    pub state_path: PathBuf,
    /// `[update]` with `[install]`, when the config has them.
    pub update: Option<UpdateSettings>,
    /// `[windows] icon`, resolved against the config's directory (M7-D14); checked as an ICO when
    /// the packager stamps a Windows stub or setup file.
    pub windows_icon: Option<PathBuf>,
    /// `[macos] icon`, resolved against the config's directory (M8-D6); checked as an `.icns` file
    /// when the packager builds the helper app of a `macos-*` pack with `--ui`.
    pub macos_icon: Option<PathBuf>,
    /// `[codesign.windows]`, when the config has it (M9-D2).
    pub codesign_windows: Option<CodeSignSection>,
    /// `[codesign.macos]`, when the config has it (M9-D2).
    pub codesign_macos: Option<CodeSignSection>,
    /// `[publish]`, when the config has it (P-D4).
    pub publish: Option<PublishSettings>,
    signers: BTreeMap<String, SignerSpec>,
}

fn update_settings(file: &str, u: RawUpdate, i: RawInstall) -> Result<UpdateSettings> {
    let channel = Channel::parse(u.channel.as_deref().unwrap_or(DEFAULT_UPDATE_CHANNEL))
        .map_err(|_| anyhow!("{file}: update.channel is not a channel id"))?;
    let health_timeout_secs = u.health_timeout_secs.unwrap_or(DEFAULT_HEALTH_TIMEOUT_SECS);
    if !HEALTH_TIMEOUT_SECS.contains(&health_timeout_secs) {
        bail!("{file}: update.health_timeout_secs is outside 5..=3600");
    }
    let rel = |value: &str, field: &str| {
        RelPath::parse(value).map_err(|_| anyhow!("{file}: install.{field} is not a tree path"))
    };
    let os_install = |os: &str, raw: Option<RawInstallOs>| -> Result<OsInstall> {
        let Some(raw) = raw else {
            return Ok(OsInstall::default());
        };
        Ok(OsInstall {
            entry: raw
                .entry
                .as_deref()
                .map(|v| rel(v, &format!("{os}.entry")))
                .transpose()?,
            icon: raw
                .icon
                .as_deref()
                .map(|v| rel(v, &format!("{os}.icon")))
                .transpose()?,
        })
    };
    let overrides = InstallOverrides {
        linux: os_install("linux", i.linux)?,
        windows: os_install("windows", i.windows)?,
        macos: os_install("macos", i.macos)?,
    };
    let publisher_check = u
        .publisher_check
        .as_deref()
        .map(|text| {
            PublisherPolicy::parse(text).ok_or_else(|| {
                anyhow!("{file}: update.publisher_check is not \"off\", \"warn\" or \"enforce\"")
            })
        })
        .transpose()?;
    let install = InstallMeta {
        entry: rel(&i.entry, "entry")?,
        name: i.name,
        comment: i.comment,
        icon: i.icon.as_deref().map(|v| rel(v, "icon")).transpose()?,
        categories: i.categories,
        bin: i.bin,
        terminal: i.terminal,
        publisher: i.publisher,
        file_types: i
            .file_types
            .into_iter()
            .map(|t| FileType {
                ext: t.ext,
                mime: t.mime,
                name: t.name,
            })
            .collect(),
        url_schemes: i.url_schemes,
        autostart: i.autostart,
    };
    Ok(UpdateSettings {
        feed: u.feed,
        channel,
        health_timeout_secs,
        install,
        overrides,
        publisher_check,
    })
}

/// An environment variable name, `[A-Z_][A-Z0-9_]*`; the error names the key, never the text.
fn env_name(file: &str, key: &str, value: &str) -> Result<String> {
    let mut bytes = value.bytes();
    let ok = value.len() <= 128
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_uppercase() || b == b'_')
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !ok {
        bail!("{file}: publish.{key} is not an environment variable name ([A-Z_][A-Z0-9_]*)");
    }
    Ok(value.to_owned())
}

/// A bucket name: 3-63 of lowercase letters, digits, `.` and `-`, alphanumeric at both ends.
fn bucket_name(file: &str, key: &str, value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let ok = (3..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric();
    if !ok {
        bail!("{file}: publish.{key} is not a bucket name (3-63 of a-z, 0-9, . and -)");
    }
    Ok(value.to_owned())
}

fn in_range<T: TryFrom<u64>>(
    file: &str,
    key: &str,
    value: Option<u64>,
    default: T,
    range: std::ops::RangeInclusive<u64>,
) -> Result<T> {
    let Some(value) = value else {
        return Ok(default);
    };
    match T::try_from(value) {
        Ok(v) if range.contains(&value) => Ok(v),
        _ => bail!(
            "{file}: publish.{key} is outside {}..={}",
            range.start(),
            range.end()
        ),
    }
}

fn channel_list(file: &str, key: &str, values: &[String]) -> Result<Vec<Channel>> {
    if values.is_empty() {
        bail!("{file}: publish.{key} is empty");
    }
    let mut out: Vec<Channel> = Vec::new();
    for (index, value) in values.iter().enumerate() {
        let channel = Channel::parse(value)
            .map_err(|_| anyhow!("{file}: publish.{key}[{index}] is not a channel id"))?;
        if out.contains(&channel) {
            bail!("{file}: publish.{key}[{index}] repeats a channel");
        }
        out.push(channel);
    }
    Ok(out)
}

fn publish_settings(
    file: &str,
    raw: RawPublish,
    update_channel: &Channel,
) -> Result<PublishSettings> {
    if raw.prefix.contains('/') {
        bail!("{file}: publish.prefix must be one path segment (no /)");
    }
    StoreKey::new(&raw.prefix, "x").map_err(|e| anyhow!("{file}: publish.prefix: {e}"))?;
    let store = match raw.store.as_str() {
        "r2" => {
            for (key, present) in [
                ("endpoint_env", raw.endpoint_env.is_some()),
                ("region", raw.region.is_some()),
            ] {
                if present {
                    bail!("{file}: publish.{key} applies to store = \"s3\" only");
                }
            }
            let var = raw.account_id_env.as_deref().ok_or_else(|| {
                anyhow!("{file}: publish.account_id_env is required for store = \"r2\"")
            })?;
            StoreKind::R2 {
                account_id_env: env_name(file, "account_id_env", var)?,
            }
        }
        "s3" => {
            if raw.account_id_env.is_some() {
                bail!("{file}: publish.account_id_env applies to store = \"r2\" only");
            }
            let var = raw.endpoint_env.as_deref().ok_or_else(|| {
                anyhow!("{file}: publish.endpoint_env is required for store = \"s3\"")
            })?;
            let region = raw
                .region
                .ok_or_else(|| anyhow!("{file}: publish.region is required for store = \"s3\""))?;
            if region.is_empty()
                || region.len() > 32
                || !region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                bail!("{file}: publish.region is not a region name (1-32 of a-z, 0-9 and -)");
            }
            StoreKind::S3 {
                endpoint_env: env_name(file, "endpoint_env", var)?,
                region,
            }
        }
        _ => bail!("{file}: publish.store is not \"r2\" or \"s3\""),
    };
    let public_bucket = bucket_name(file, "public_bucket", &raw.public_bucket)?;
    let private_bucket = bucket_name(file, "private_bucket", &raw.private_bucket)?;
    if public_bucket == private_bucket {
        bail!("{file}: publish.public_bucket and publish.private_bucket must differ");
    }
    let channels = match &raw.channels {
        Some(list) => channel_list(file, "channels", list)?,
        None => vec![update_channel.clone()],
    };
    let prerelease_channels = match &raw.prerelease_channels {
        Some(list) => channel_list(file, "prerelease_channels", list)?,
        None => channels.clone(),
    };
    if prerelease_channels.iter().any(|c| !channels.contains(c)) {
        bail!(
            "{file}: publish.prerelease_channels names a channel that is not in publish.channels"
        );
    }
    let mut require_targets: Vec<Target> = Vec::new();
    for (index, text) in raw.require_targets.iter().enumerate() {
        let target = Target::parse(text)
            .map_err(|_| anyhow!("{file}: publish.require_targets[{index}] is not a target id"))?;
        if require_targets.contains(&target) {
            bail!("{file}: publish.require_targets[{index}] repeats a target");
        }
        require_targets.push(target);
    }
    let private_keys_env = match (&raw.private_access_key_env, &raw.private_secret_key_env) {
        (None, None) => None,
        (Some(access), Some(secret)) => Some((
            env_name(file, "private_access_key_env", access)?,
            env_name(file, "private_secret_key_env", secret)?,
        )),
        (Some(_), None) => bail!(
            "{file}: publish.private_secret_key_env is required with publish.private_access_key_env (both or neither)"
        ),
        (None, Some(_)) => bail!(
            "{file}: publish.private_access_key_env is required with publish.private_secret_key_env (both or neither)"
        ),
    };
    Ok(PublishSettings {
        prefix: raw.prefix,
        store,
        access_key_env: env_name(file, "access_key_env", &raw.access_key_env)?,
        secret_key_env: env_name(file, "secret_key_env", &raw.secret_key_env)?,
        private_keys_env,
        public_bucket,
        private_bucket,
        keep: in_range(file, "keep", raw.keep, DEFAULT_PUBLISH_KEEP, 1..=100)?,
        deltas: in_range(file, "deltas", raw.deltas, DEFAULT_PUBLISH_DELTAS, 0..=16)?,
        feed_days: in_range(
            file,
            "feed_days",
            raw.feed_days,
            DEFAULT_PUBLISH_FEED_DAYS,
            1..=3650,
        )?,
        channels,
        prerelease_channels,
        require_targets,
    })
}

/// Parses one template of `[codesign.<os>]`; the error names the section, the key and (from the
/// core) the element index, never an element's text.
fn template(
    file: &str,
    os: &str,
    key: &str,
    role: TemplateRole,
    elements: &[String],
) -> Result<ArgvTemplate> {
    ArgvTemplate::parse(role, elements).map_err(|e| anyhow!("{file}: codesign.{os}.{key}: {e}"))
}

/// A timeout key: 1 second to a day.
fn timeout(file: &str, os: &str, key: &str, value: Option<u64>, default: u64) -> Result<Duration> {
    let secs = value.unwrap_or(default);
    if secs == 0 || secs > MAX_CODESIGN_TIMEOUT_SECS {
        bail!("{file}: codesign.{os}.{key} is outside 1..={MAX_CODESIGN_TIMEOUT_SECS}");
    }
    Ok(Duration::from_secs(secs))
}

fn codesign_section(file: &str, os: &str, raw: RawCodeSignSection) -> Result<CodeSignSection> {
    let macos = os == "macos";
    if !macos {
        // The keys that belong to the macOS bundle flow are refused here, naming the key.
        for (key, present) in [
            ("sign_bundle", raw.sign_bundle.is_some()),
            ("sign_outer", raw.sign_outer.is_some()),
            ("notarize", raw.notarize.is_some()),
            ("staple", raw.staple.is_some()),
            ("notarize_timeout_secs", raw.notarize_timeout_secs.is_some()),
        ] {
            if present {
                bail!("{file}: codesign.{os}.{key} applies to macOS only");
            }
        }
    }
    let sign = template(file, os, "sign", TemplateRole::Sign, &raw.sign)?;
    let optional = |key: &str, role: TemplateRole, value: &Option<Vec<String>>| {
        value
            .as_deref()
            .map(|elements| template(file, os, key, role, elements))
            .transpose()
    };
    let sign_bundle = optional("sign_bundle", TemplateRole::Sign, &raw.sign_bundle)?;
    let sign_outer = optional("sign_outer", TemplateRole::Sign, &raw.sign_outer)?;
    let sign_installer = optional("sign_installer", TemplateRole::Sign, &raw.sign_installer)?;
    let verify = optional("verify", TemplateRole::Verify, &raw.verify)?;
    let notarize = optional("notarize", TemplateRole::Notarize, &raw.notarize)?;
    let staple = optional("staple", TemplateRole::Staple, &raw.staple)?;
    match (&notarize, &staple) {
        (Some(_), None) => bail!("{file}: codesign.{os}.notarize needs staple"),
        (None, Some(_)) => bail!("{file}: codesign.{os}.staple needs notarize"),
        _ => {}
    }
    let sign_bundle = sign_bundle.unwrap_or_else(|| sign.clone());
    let sign_outer = sign_outer.unwrap_or_else(|| sign_bundle.clone());
    let sign_installer = sign_installer.unwrap_or_else(|| sign.clone());
    Ok(CodeSignSection {
        sign,
        sign_bundle,
        sign_outer,
        sign_installer,
        verify,
        notarize,
        staple,
        timeout: timeout(
            file,
            os,
            "timeout_secs",
            raw.timeout_secs,
            DEFAULT_CODESIGN_TIMEOUT_SECS,
        )?,
        notarize_timeout: timeout(
            file,
            os,
            "notarize_timeout_secs",
            raw.notarize_timeout_secs,
            DEFAULT_NOTARIZE_TIMEOUT_SECS,
        )?,
    })
}

/// A 64-character lowercase hex value; the error names `what`, never the text.
pub fn hex32(text: &str, what: &str) -> Result<[u8; 32]> {
    hex_decode_array::<32>(text).map_err(|_| anyhow!("{what} is not 64 lowercase hex characters"))
}

fn line_of(text: &str, offset: usize) -> usize {
    let end = offset.min(text.len());
    text.as_bytes()[..end]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

impl Config {
    /// Reads and validates the config at `path`.
    pub fn load(path: &Path) -> Result<Config> {
        let mut text = String::new();
        // Classified before opening: Windows cannot open a directory, and a FIFO blocks on open.
        if let Ok(meta) = fs::metadata(path)
            && !meta.is_file()
        {
            bail!("{} is not a regular file", path.display());
        }
        let file = File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .with_context(|| format!("cannot read {}", path.display()))?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            bail!("{} is over {MAX_CONFIG_BYTES} bytes", path.display());
        }
        Config::parse(path, &text)
    }

    /// Parses `text`, read from `path` (which only labels errors).
    pub fn parse(path: &Path, text: &str) -> Result<Config> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| {
            let message = e.message();
            // Only the messages that name a key, never ones that echo a value.
            let shown = if ["unknown field", "missing field", "duplicate key"]
                .iter()
                .any(|p| message.starts_with(p))
            {
                message
            } else {
                "invalid syntax or value"
            };
            match e.span() {
                Some(span) => anyhow!(
                    "{}: line {}: {shown}",
                    path.display(),
                    line_of(text, span.start)
                ),
                None => anyhow!("{}: {shown}", path.display()),
            }
        })?;
        let ctx = || format!("{}", path.display());

        let app_id = AppId::parse(&raw.app_id).with_context(|| format!("{}: app_id", ctx()))?;
        let root_keys = raw
            .root
            .keys
            .iter()
            .enumerate()
            .map(|(i, k)| hex32(k, &format!("{}: root.keys[{i}]", ctx())))
            .collect::<Result<Vec<_>>>()?;
        if raw.root.version == 0 || raw.root.version > MAX_JSON_INT {
            bail!("{}: root.version is out of range", ctx());
        }

        let dir = path.parent().unwrap_or(Path::new(""));
        let mut signers = BTreeMap::new();
        for (name, s) in raw.signers {
            let at = format!("{}: signers.{name}", ctx());
            let spec = match (s.file, s.env, s.command, s.public) {
                (Some(file), None, None, None) => SignerSpec::File(dir.join(file)),
                (None, Some(var), None, None) => SignerSpec::Env(var),
                (None, None, Some(argv), Some(public)) => {
                    if argv.first().is_none_or(String::is_empty) {
                        bail!("{at}: command is empty");
                    }
                    SignerSpec::Command {
                        argv,
                        public: hex32(&public, &format!("{at}.public"))?,
                    }
                }
                (None, None, Some(_), None) => bail!("{at}: a command signer needs `public`"),
                _ => bail!(
                    "{at}: give exactly one of `file`, `env` or `command` (with `public`), and `public` only with `command`"
                ),
            };
            signers.insert(name, spec);
        }
        let state_path = match raw.state {
            Some(s) if s.is_empty() => bail!("{}: state is empty", ctx()),
            Some(s) => dir.join(s),
            None => dir.join(crate::state::DEFAULT_STATE),
        };
        let windows_icon = match raw.windows.and_then(|w| w.icon) {
            Some(i) if i.is_empty() => bail!("{}: windows.icon is empty", ctx()),
            Some(i) => Some(dir.join(i)),
            None => None,
        };
        let macos_icon = match raw.macos.and_then(|m| m.icon) {
            Some(i) if i.is_empty() => bail!("{}: macos.icon is empty", ctx()),
            Some(i) => Some(dir.join(i)),
            None => None,
        };
        let codesign = raw.codesign.unwrap_or(RawCodeSign {
            windows: None,
            macos: None,
        });
        let codesign_windows = codesign
            .windows
            .map(|section| codesign_section(&ctx(), "windows", section))
            .transpose()?;
        let codesign_macos = codesign
            .macos
            .map(|section| codesign_section(&ctx(), "macos", section))
            .transpose()?;
        let update = match (raw.update, raw.install) {
            (None, None) => None,
            (None, Some(_)) => bail!("{}: [install] needs [update]", ctx()),
            (Some(_), None) => bail!("{}: [update] needs [install]", ctx()),
            (Some(u), Some(i)) => Some(update_settings(&ctx(), u, i)?),
        };
        let publish = raw
            .publish
            .map(|p| {
                let default_channel = match &update {
                    Some(u) => u.channel.clone(),
                    None => Channel::parse(DEFAULT_UPDATE_CHANNEL)
                        .map_err(|_| anyhow!("the default channel is not a channel id"))?,
                };
                publish_settings(&ctx(), p, &default_channel)
            })
            .transpose()?;
        Ok(Config {
            app_id,
            root_version: raw.root.version,
            root_threshold: raw.root.threshold,
            root_keys,
            state_path,
            update,
            windows_icon,
            macos_icon,
            codesign_windows,
            codesign_macos,
            publish,
            signers,
        })
    }

    /// The `[codesign.<os>]` section that applies to `target`: `windows` for a `windows-*` target,
    /// `macos` for a `macos-*` one, none for Linux (M9-D2). A section for another OS is ignored.
    pub fn codesign_for(&self, target: Target) -> Option<&CodeSignSection> {
        if target.is_windows() {
            self.codesign_windows.as_ref()
        } else if target.is_macos() {
            self.codesign_macos.as_ref()
        } else {
            None
        }
    }

    /// The channel `pack --channel <requested>` writes into the update config: `requested` must be
    /// a channel id listed in `[publish] channels` (P-D5). The error names the allowed set.
    pub fn pack_channel(&self, requested: &str) -> Result<Channel> {
        let channel =
            Channel::parse(requested).map_err(|_| anyhow!("--channel is not a channel id"))?;
        if self.update.is_none() {
            bail!("--channel needs [update] and [install] in the config");
        }
        let Some(publish) = &self.publish else {
            bail!("--channel needs [publish] in the config: its channels are the allowed set");
        };
        if !publish.channels.contains(&channel) {
            let allowed: Vec<&str> = publish.channels.iter().map(Channel::as_str).collect();
            bail!(
                "--channel {requested} is not one of the [publish] channels: {}",
                allowed.join(", ")
            );
        }
        Ok(channel)
    }

    /// The publisher-continuity policy to write into the config of a tree for `target` (M9-D6): an
    /// explicit `[update] publisher_check` wins; otherwise `enforce` when the target's OS has a
    /// `[codesign.<os>]` section, else `off`.
    pub fn publisher_policy(&self, target: Target) -> PublisherPolicy {
        if let Some(explicit) = self.update.as_ref().and_then(|u| u.publisher_check) {
            return explicit;
        }
        if self.codesign_for(target).is_some() {
            PublisherPolicy::Enforce
        } else {
            PublisherPolicy::Off
        }
    }

    /// The compiled-in root; checks the version, threshold and keys like a root document's.
    pub fn trusted_root(
        &self,
        hasher: &dyn Hasher,
        verifier: &dyn Verifier,
    ) -> Result<TrustedRoot> {
        TrustedRoot::from_parts(
            self.app_id.clone(),
            self.root_version,
            self.root_threshold,
            &self.root_keys,
            hasher,
            verifier,
        )
        .context("the root in the config is not valid")
    }

    fn signer(&self, name: &str) -> Result<Box<dyn Signer>> {
        match self.signers.get(name) {
            None => bail!("no signer named {name:?} in the config"),
            Some(SignerSpec::File(path)) => Ok(Box::new(Ed25519Signer::from_key_file(path)?)),
            Some(SignerSpec::Env(var)) => Ok(Box::new(Ed25519Signer::from_env(var)?)),
            Some(SignerSpec::Command { argv, public }) => {
                Ok(Box::new(CommandSigner::new(argv.clone(), *public)?))
            }
        }
    }
}

/// Resolves a `--sign` spec: `file:<path>`, `env:<VAR>` or a signer name from the config at
/// `config_path` (read only when a name is given).
pub fn resolve_signer(config_path: &Path, spec: &str) -> Result<Box<dyn Signer>> {
    if let Some(path) = spec.strip_prefix("file:") {
        return Ok(Box::new(Ed25519Signer::from_key_file(Path::new(path))?));
    }
    if let Some(var) = spec.strip_prefix("env:") {
        return Ok(Box::new(Ed25519Signer::from_env(var)?));
    }
    Config::load(config_path)?.signer(spec)
}

/// A clock fixed at one instant (`SOURCE_DATE_EPOCH`).
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_unix_secs(&self) -> u64 {
        self.0
    }
}

/// The clock writers use (M3-D5): `SOURCE_DATE_EPOCH` when set (ASCII decimal digits only, at most
/// 2^53 - 1), the system clock otherwise. A malformed value is an error that names the variable
/// and does not echo it.
pub fn writer_clock() -> Result<Box<dyn Clock>> {
    let Some(value) = std::env::var_os("SOURCE_DATE_EPOCH") else {
        return Ok(Box::new(lunepack::SystemClock));
    };
    let secs = value
        .to_str()
        .filter(|t| !t.is_empty() && t.len() <= 16 && t.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|t| t.parse::<u64>().ok())
        .filter(|n| *n <= MAX_JSON_INT);
    match secs {
        Some(n) => Ok(Box::new(FixedClock(n))),
        None => bail!("SOURCE_DATE_EPOCH is not a decimal number of seconds in 0..=2^53-1"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "app_id = \"org.example.app\"\n[root]\nthreshold = 1\nkeys = [\"0000000000000000000000000000000000000000000000000000000000000001\"]\n";

    fn parse(extra: &str) -> Result<Config> {
        Config::parse(Path::new("/cfg/lunepack.toml"), &format!("{BASE}{extra}"))
    }

    #[test]
    fn windows_icon_is_resolved_against_the_configs_directory() {
        assert!(parse("").unwrap().windows_icon.is_none());
        let c = parse("[windows]\nicon = \"art/app.ico\"\n").unwrap();
        assert_eq!(c.windows_icon, Some(PathBuf::from("/cfg/art/app.ico")));
        assert!(parse("[windows]\nicon = \"\"\n").is_err());
        let e = parse("[windows]\nmanifest = \"x\"\n").unwrap_err();
        assert!(format!("{e:#}").contains("unknown field"), "{e:#}");
    }

    #[test]
    fn macos_icon_is_resolved_against_the_configs_directory() {
        assert!(parse("").unwrap().macos_icon.is_none());
        let c = parse("[macos]\nicon = \"art/app.icns\"\n").unwrap();
        assert_eq!(c.macos_icon, Some(PathBuf::from("/cfg/art/app.icns")));
        assert!(parse("[macos]\nicon = \"\"\n").is_err());
        let e = parse("[macos]\nbundle = \"x\"\n").unwrap_err();
        assert!(format!("{e:#}").contains("unknown field"), "{e:#}");
    }

    #[test]
    fn install_declarations_are_parsed() {
        let update = "[update]\nfeed = \"https://updates.example.com/app\"\n";
        let install = "[install]\nentry = \"bin/app\"\nname = \"App\"\nurl_schemes = [\"app\"]\nautostart = true\n\
            [[install.file_types]]\next = \"app\"\nmime = \"application/x-app\"\nname = \"App file\"\n";
        let c = parse(&format!("{update}{install}")).unwrap();
        let i = c.update.unwrap().install;
        assert_eq!(i.url_schemes, ["app"]);
        assert!(i.autostart);
        assert_eq!(i.file_types.len(), 1);
        assert_eq!(i.file_types[0].ext, "app");
        let bare = "[install]\nentry = \"bin/app\"\nname = \"App\"\n";
        let i = parse(&format!("{update}{bare}"))
            .unwrap()
            .update
            .unwrap()
            .install;
        assert!(i.file_types.is_empty() && i.url_schemes.is_empty() && !i.autostart);
        let unknown = format!("{update}{install}icon = \"x\"\n");
        // A key in a file type table that does not exist is refused, naming the key.
        let bad = unknown.replace("name = \"App file\"", "name = \"App file\"\nglob = \"*\"");
        let e = parse(&bad).unwrap_err();
        assert!(format!("{e:#}").contains("unknown field"), "{e:#}");
    }

    const INSTALL: &str = "[install]\nentry = \"bin/app\"\nname = \"App\"\n";

    fn err(extra: &str) -> String {
        format!("{:#}", parse(extra).unwrap_err())
    }

    #[test]
    fn a_codesign_section_resolves_its_defaults() {
        let c = parse(
            "[codesign.macos]\nsign = [\"codesign\", \"--sign\", \"{env:ID}\", \"{path}\"]\n\
             sign_outer = [\"codesign\", \"--options\", \"runtime\", \"{path}\"]\n\
             verify = [\"codesign\", \"--verify\", \"{path}\"]\n\
             notarize = [\"notarytool\", \"{zip}\"]\nstaple = [\"stapler\", \"{path}\"]\n\
             timeout_secs = 60\n",
        )
        .unwrap();
        let m = c.codesign_macos.as_ref().unwrap();
        assert!(c.codesign_windows.is_none());
        // `sign_bundle` defaults to `sign`, `sign_installer` to `sign`, `sign_outer` is its own.
        assert_eq!(m.sign_bundle, m.sign);
        assert_eq!(m.sign_installer, m.sign);
        assert_ne!(m.sign_outer, m.sign);
        assert!(m.verify.is_some() && m.notarize.is_some() && m.staple.is_some());
        assert_eq!(m.timeout, Duration::from_secs(60));
        assert_eq!(m.notarize_timeout, Duration::from_secs(3600));
        // `sign_outer` defaults to `sign_bundle` when only that is given.
        let c = parse(
            "[codesign.macos]\nsign = [\"a\", \"{path}\"]\nsign_bundle = [\"b\", \"{path}\"]\n",
        )
        .unwrap();
        let m = c.codesign_macos.unwrap();
        assert_eq!(m.sign_outer, m.sign_bundle);
        assert_ne!(m.sign_outer, m.sign);
        assert_eq!(m.timeout, Duration::from_secs(300));
        // The Windows section, and the section chosen by target.
        let c = parse("[codesign.windows]\nsign = [\"signtool\", \"sign\", \"{path}\"]\n").unwrap();
        assert!(c.codesign_for(Target::WindowsX86_64).is_some());
        assert!(c.codesign_for(Target::WindowsAarch64).is_some());
        assert!(c.codesign_for(Target::MacosUniversal).is_none());
        assert!(c.codesign_for(Target::LinuxX86_64).is_none());
    }

    #[test]
    fn a_codesign_section_refuses_what_it_does_not_define() {
        // An unknown key and an unknown section, each named.
        let e = err("[codesign.macos]\nsign = [\"a\"]\nsigned = true\n");
        assert!(e.contains("unknown field") && e.contains("signed"), "{e}");
        let e = err("[codesign.linux]\nsign = [\"a\"]\n");
        assert!(e.contains("unknown field") && e.contains("linux"), "{e}");
        let e = err("[codesign.macos]\nverify = [\"a\"]\n");
        assert!(e.contains("missing field") && e.contains("sign"), "{e}");
        // macOS-only keys in the Windows section.
        for key in [
            "sign_bundle",
            "sign_outer",
            "notarize",
            "staple",
            "notarize_timeout_secs",
        ] {
            let value = if key.ends_with("secs") {
                "5"
            } else {
                "[\"a\"]"
            };
            let e = err(&format!(
                "[codesign.windows]\nsign = [\"a\"]\n{key} = {value}\n"
            ));
            assert!(e.contains(key) && e.contains("macOS only"), "{e}");
        }
    }

    #[test]
    fn a_template_error_names_the_section_the_key_and_the_element() {
        let e = err("[codesign.macos]\nsign = [\"codesign\", \"ok\", \"--f={path}\"]\n");
        assert!(
            e.contains("codesign.macos.sign") && e.contains("element 2"),
            "{e}"
        );
        assert!(!e.contains("--f="), "{e}");
        let e = err("[codesign.windows]\nsign = [\"x\"]\nverify = [\"{path}\"]\n");
        assert!(
            e.contains("codesign.windows.verify") && e.contains("element 0"),
            "{e}"
        );
        // `{zip}` belongs to notarize only.
        let e = err("[codesign.macos]\nsign = [\"a\", \"{zip}\"]\n");
        assert!(
            e.contains("codesign.macos.sign") && e.contains("{zip}"),
            "{e}"
        );
        let e = err("[codesign.macos]\nsign = []\n");
        assert!(
            e.contains("codesign.macos.sign") && e.contains("empty"),
            "{e}"
        );
        let e = err("[codesign.macos]\nsign = [\"a\", \"{env:lower}\"]\n");
        assert!(e.contains("element 1") && !e.contains("lower"), "{e}");
    }

    #[test]
    fn notarize_and_staple_come_together() {
        let base = "[codesign.macos]\nsign = [\"a\", \"{path}\"]\n";
        let e = err(&format!("{base}notarize = [\"n\", \"{{zip}}\"]\n"));
        assert!(e.contains("notarize needs staple"), "{e}");
        let e = err(&format!("{base}staple = [\"s\", \"{{path}}\"]\n"));
        assert!(e.contains("staple needs notarize"), "{e}");
        // `{bundle}` is fine in a notarize template, `{zip}` in a staple one is not.
        parse(&format!(
            "{base}notarize = [\"n\", \"{{bundle}}\"]\nstaple = [\"s\", \"{{path}}\"]\n"
        ))
        .unwrap();
        let e = err(&format!(
            "{base}notarize = [\"n\", \"{{zip}}\"]\nstaple = [\"s\", \"{{zip}}\"]\n"
        ));
        assert!(e.contains("codesign.macos.staple"), "{e}");
    }

    #[test]
    fn codesign_timeouts_are_bounded() {
        let base = "[codesign.macos]\nsign = [\"a\", \"{path}\"]\n";
        for key in ["timeout_secs", "notarize_timeout_secs"] {
            let e = err(&format!("{base}{key} = 0\n"));
            assert!(e.contains(key) && e.contains("outside"), "{e}");
            let e = err(&format!("{base}{key} = 99999999999\n"));
            assert!(e.contains(key), "{e}");
            let c = parse(&format!("{base}{key} = 5\n")).unwrap();
            assert!(c.codesign_macos.is_some());
        }
    }

    #[test]
    fn publisher_check_parses_and_defaults_by_target() {
        let with = |member: &str| {
            format!("[update]\nfeed = \"https://updates.example.com/app\"\n{member}{INSTALL}")
        };
        let win = "[codesign.windows]\nsign = [\"s\", \"{path}\"]\n";
        let u = |c: &Config| c.update.as_ref().unwrap().publisher_check;
        let c = parse(&with("")).unwrap();
        assert_eq!(u(&c), None);
        for (text, policy) in [
            ("off", PublisherPolicy::Off),
            ("warn", PublisherPolicy::Warn),
            ("enforce", PublisherPolicy::Enforce),
        ] {
            let c = parse(&with(&format!("publisher_check = \"{text}\"\n"))).unwrap();
            assert_eq!(u(&c), Some(policy));
            // An explicit value wins whatever sections exist.
            let c = parse(&format!(
                "{win}{}",
                with(&format!("publisher_check = \"{text}\"\n"))
            ))
            .unwrap();
            assert_eq!(c.publisher_policy(Target::WindowsX86_64), policy);
        }
        for bad in ["\"Enforce\"", "\"on\"", "\"\"", "1", "true"] {
            let e = err(&with(&format!("publisher_check = {bad}\n")));
            assert!(
                e.contains("publisher_check") || e.contains("invalid"),
                "{e}"
            );
        }
        // The default: enforce where the target's OS has a section, off elsewhere.
        let c = parse(&format!("{win}{}", with(""))).unwrap();
        assert_eq!(
            c.publisher_policy(Target::WindowsX86_64),
            PublisherPolicy::Enforce
        );
        assert_eq!(
            c.publisher_policy(Target::MacosUniversal),
            PublisherPolicy::Off
        );
        assert_eq!(
            c.publisher_policy(Target::LinuxAarch64),
            PublisherPolicy::Off
        );
        let c = parse(&with("")).unwrap();
        assert_eq!(
            c.publisher_policy(Target::WindowsX86_64),
            PublisherPolicy::Off
        );
        // Without [update] there is nothing to write.
        assert_eq!(
            parse("").unwrap().publisher_policy(Target::WindowsX86_64),
            PublisherPolicy::Off
        );
    }

    const UPDATE: &str = "[update]\nfeed = \"https://updates.example.com/app\"\n";
    const PUBLISH: &str = "[publish]\nprefix = \"app\"\nstore = \"r2\"\n\
        account_id_env = \"APP_R2_ACCOUNT_ID\"\naccess_key_env = \"APP_R2_KEY\"\n\
        secret_key_env = \"APP_R2_SECRET\"\npublic_bucket = \"app-public\"\n\
        private_bucket = \"app-private\"\n";

    fn publish_with(extra: &str) -> String {
        format!("{PUBLISH}{extra}")
    }

    fn publish_err(text: &str) -> String {
        err(&format!("{UPDATE}{INSTALL}{text}"))
    }

    #[test]
    fn a_config_without_publish_or_os_installs_is_as_before() {
        let c = parse(&format!("{UPDATE}{INSTALL}")).unwrap();
        assert!(c.publish.is_none());
        let u = c.update.as_ref().unwrap();
        for target in [
            Target::LinuxX86_64,
            Target::WindowsX86_64,
            Target::MacosUniversal,
        ] {
            let install = u.install_for(target);
            assert_eq!(install.entry, u.install.entry, "{target:?}");
            assert_eq!(install.icon, u.install.icon);
        }
        assert!(parse("").unwrap().publish.is_none());
    }

    #[test]
    fn publish_parses_with_its_defaults() {
        let c = parse(&format!("{UPDATE}{INSTALL}{PUBLISH}")).unwrap();
        let p = c.publish.unwrap();
        assert_eq!(p.prefix, "app");
        assert_eq!(
            p.store,
            StoreKind::R2 {
                account_id_env: "APP_R2_ACCOUNT_ID".to_owned()
            }
        );
        assert_eq!(
            (p.access_key_env.as_str(), p.secret_key_env.as_str()),
            ("APP_R2_KEY", "APP_R2_SECRET")
        );
        assert_eq!(p.private_keys_env, None);
        assert_eq!(
            (p.public_bucket.as_str(), p.private_bucket.as_str()),
            ("app-public", "app-private")
        );
        assert_eq!(
            (p.keep, p.deltas, p.feed_days),
            (
                DEFAULT_PUBLISH_KEEP,
                DEFAULT_PUBLISH_DELTAS,
                DEFAULT_PUBLISH_FEED_DAYS
            )
        );
        assert_eq!(
            (p.keep, p.deltas, p.feed_days),
            (10, 3, 90),
            "the documented defaults"
        );
        // `channels` defaults to `[update] channel` alone, and pre-releases to all channels.
        let names = |list: &[Channel]| {
            list.iter()
                .map(|c| c.as_str().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&p.channels), ["stable"]);
        assert_eq!(names(&p.prerelease_channels), ["stable"]);
        assert!(p.require_targets.is_empty());
        let c = parse(&format!(
            "[update]\nfeed = \"https://updates.example.com/app\"\nchannel = \"nightly\"\n{INSTALL}{PUBLISH}"
        ))
        .unwrap();
        assert_eq!(names(&c.publish.unwrap().channels), ["nightly"]);
    }

    #[test]
    fn publish_parses_every_key() {
        let text = format!(
            "{UPDATE}{INSTALL}[publish]\nprefix = \"my-app_1\"\nstore = \"s3\"\n\
             endpoint_env = \"S3_ENDPOINT\"\nregion = \"eu-west-1\"\naccess_key_env = \"_K\"\n\
             secret_key_env = \"S\"\npublic_bucket = \"my.pub-1\"\nprivate_bucket = \"my-priv\"\n\
             keep = 100\ndeltas = 0\nfeed_days = 3650\nchannels = [\"stable\", \"beta\"]\n\
             prerelease_channels = [\"beta\"]\nrequire_targets = [\"linux-x86_64\", \"macos-universal\"]\n"
        );
        let p = parse(&text).unwrap().publish.unwrap();
        assert_eq!(
            p.store,
            StoreKind::S3 {
                endpoint_env: "S3_ENDPOINT".to_owned(),
                region: "eu-west-1".to_owned()
            }
        );
        assert_eq!((p.keep, p.deltas, p.feed_days), (100, 0, 3650));
        assert_eq!(p.channels.len(), 2);
        assert_eq!(p.prerelease_channels.len(), 1);
        assert_eq!(
            p.require_targets,
            [Target::LinuxX86_64, Target::MacosUniversal]
        );
        // The lowest values of each range.
        let low = parse(&format!(
            "{UPDATE}{INSTALL}{}",
            publish_with("keep = 1\nfeed_days = 1\ndeltas = 16\n")
        ))
        .unwrap()
        .publish
        .unwrap();
        assert_eq!((low.keep, low.deltas, low.feed_days), (1, 16, 1));
    }

    #[test]
    fn publish_refuses_each_bad_value_naming_the_key() {
        let cases: &[(&str, &str, &str)] = &[
            // (what to append or replace, expected key in the message, expected phrase)
            ("keep = 0\n", "publish.keep", "outside 1..=100"),
            ("keep = 101\n", "publish.keep", "outside 1..=100"),
            ("deltas = 17\n", "publish.deltas", "outside 0..=16"),
            ("feed_days = 0\n", "publish.feed_days", "outside 1..=3650"),
            (
                "feed_days = 3651\n",
                "publish.feed_days",
                "outside 1..=3650",
            ),
            ("channels = []\n", "publish.channels", "empty"),
            (
                "channels = [\"Bad Channel\"]\n",
                "publish.channels[0]",
                "not a channel id",
            ),
            (
                "channels = [\"a\", \"a\"]\n",
                "publish.channels[1]",
                "repeats",
            ),
            (
                "channels = [\"a\"]\nprerelease_channels = [\"b\"]\n",
                "publish.prerelease_channels",
                "not in publish.channels",
            ),
            (
                "require_targets = [\"amiga-m68k\"]\n",
                "publish.require_targets[0]",
                "not a target id",
            ),
            (
                "require_targets = [\"linux-x86_64\", \"linux-x86_64\"]\n",
                "publish.require_targets[1]",
                "repeats",
            ),
            (
                "endpoint_env = \"X\"\n",
                "publish.endpoint_env",
                "applies to store = \"s3\"",
            ),
            (
                "region = \"auto\"\n",
                "publish.region",
                "applies to store = \"s3\"",
            ),
            ("surprise = 1\n", "surprise", "unknown field"),
        ];
        for (extra, key, phrase) in cases {
            let e = publish_err(&publish_with(extra));
            assert!(e.contains(key) && e.contains(phrase), "{extra:?}: {e}");
        }
        // Replaced values.
        let replaced: &[(&str, &str, &str, &str)] = &[
            (
                "prefix = \"app\"",
                "prefix = \"a/b\"",
                "publish.prefix",
                "one path segment",
            ),
            (
                "prefix = \"app\"",
                "prefix = \"\"",
                "publish.prefix",
                "empty",
            ),
            (
                "prefix = \"app\"",
                "prefix = \"..\"",
                "publish.prefix",
                ". or .. segment",
            ),
            (
                "prefix = \"app\"",
                "prefix = \"a b\"",
                "publish.prefix",
                "whitespace",
            ),
            (
                "prefix = \"app\"",
                "prefix = \"a\\\\b\"",
                "publish.prefix",
                "backslash",
            ),
            (
                "prefix = \"app\"",
                "prefix = \"\\u00e9\"",
                "publish.prefix",
                "non-ASCII",
            ),
            (
                "store = \"r2\"",
                "store = \"gcs\"",
                "publish.store",
                "not \"r2\" or \"s3\"",
            ),
            (
                "APP_R2_ACCOUNT_ID",
                "lower_case",
                "publish.account_id_env",
                "environment variable name",
            ),
            (
                "APP_R2_KEY",
                "1STARTS_WITH_DIGIT",
                "publish.access_key_env",
                "environment variable name",
            ),
            (
                "APP_R2_SECRET",
                "HAS-DASH",
                "publish.secret_key_env",
                "environment variable name",
            ),
            (
                "APP_R2_SECRET",
                "",
                "publish.secret_key_env",
                "environment variable name",
            ),
            (
                "app-public",
                "Upper",
                "publish.public_bucket",
                "not a bucket name",
            ),
            (
                "app-private",
                "ab",
                "publish.private_bucket",
                "not a bucket name",
            ),
            (
                "app-private",
                "app-public",
                "publish.public_bucket",
                "must differ",
            ),
        ];
        for (from, to, key, phrase) in replaced {
            let e = publish_err(&PUBLISH.replace(from, to));
            assert!(e.contains(key) && e.contains(phrase), "{from} -> {to}: {e}");
        }
        // Missing keys.
        for missing in [
            "prefix",
            "store",
            "access_key_env",
            "secret_key_env",
            "public_bucket",
            "private_bucket",
        ] {
            let text: String = PUBLISH
                .lines()
                .filter(|l| !l.starts_with(missing))
                .collect::<Vec<_>>()
                .join("\n");
            let e = publish_err(&format!("{text}\n"));
            assert!(
                e.contains("missing field") && e.contains(missing),
                "{missing}: {e}"
            );
        }
        let e = publish_err(&PUBLISH.replace("account_id_env = \"APP_R2_ACCOUNT_ID\"\n", ""));
        assert!(e.contains("publish.account_id_env is required"), "{e}");
        // S4: the private bucket's own pair, both or neither, each a variable name.
        let both = "private_access_key_env = \"APP_R2_STATE_KEY\"\nprivate_secret_key_env = \"APP_R2_STATE_SECRET\"\n";
        let c = parse(&format!("{UPDATE}{INSTALL}{}", publish_with(both))).unwrap();
        assert_eq!(
            c.publish.unwrap().private_keys_env,
            Some((
                "APP_R2_STATE_KEY".to_owned(),
                "APP_R2_STATE_SECRET".to_owned()
            ))
        );
        for (half, named) in [
            (
                "private_access_key_env = \"APP_R2_STATE_KEY\"\n",
                "publish.private_secret_key_env is required",
            ),
            (
                "private_secret_key_env = \"APP_R2_STATE_SECRET\"\n",
                "publish.private_access_key_env is required",
            ),
        ] {
            let e = publish_err(&publish_with(half));
            assert!(e.contains(named) && e.contains("both or neither"), "{e}");
        }
        let e = publish_err(&publish_with(
            &both.replace("APP_R2_STATE_SECRET", "bad-name"),
        ));
        assert!(
            e.contains("publish.private_secret_key_env is not an environment variable name"),
            "{e}"
        );
        // s3 needs its own keys and refuses r2's.
        let s3 = PUBLISH.replace("store = \"r2\"", "store = \"s3\"");
        let e = publish_err(&s3);
        assert!(
            e.contains("publish.account_id_env applies to store = \"r2\""),
            "{e}"
        );
        let s3 = s3.replace("account_id_env = \"APP_R2_ACCOUNT_ID\"\n", "");
        let e = publish_err(&s3);
        assert!(e.contains("publish.endpoint_env is required"), "{e}");
        let e = publish_err(&format!("{s3}endpoint_env = \"EP\"\n"));
        assert!(e.contains("publish.region is required"), "{e}");
        for region in ["", "US-EAST", "a b", &"a".repeat(33)] {
            let e = publish_err(&format!(
                "{s3}endpoint_env = \"EP\"\nregion = \"{region}\"\n"
            ));
            assert!(
                e.contains("publish.region is not a region name"),
                "{region:?}: {e}"
            );
        }
    }

    #[test]
    fn publish_errors_never_echo_a_value() {
        let secretish = "hunter2-VALUE";
        for (from, to) in [
            ("APP_R2_KEY", secretish),
            ("app-public", secretish),
            ("store = \"r2\"", "store = \"hunter2-VALUE\""),
            ("prefix = \"app\"", "prefix = \"hunter2 VALUE\""),
        ] {
            let e = publish_err(&PUBLISH.replace(from, to));
            assert!(
                !e.contains(secretish) && !e.contains("hunter2"),
                "{from}: {e}"
            );
        }
        let e = publish_err(&publish_with("channels = [\"hunter2 VALUE\"]\n"));
        assert!(!e.contains("hunter2"), "{e}");
    }

    #[test]
    fn publish_works_without_update_and_defaults_its_channel() {
        let c = parse(PUBLISH).unwrap();
        let p = c.publish.unwrap();
        assert_eq!(p.channels.len(), 1);
        assert_eq!(p.channels[0].as_str(), DEFAULT_UPDATE_CHANNEL);
    }

    #[test]
    fn os_install_overrides_pick_the_targets_entry_and_icon() {
        let text = format!(
            "{UPDATE}[install]\nentry = \"bin/app\"\nname = \"App\"\nicon = \"assets/icon.svg\"\n\
             [install.windows]\nentry = \"bin/app.exe\"\nicon = \"assets/icon.png\"\n\
             [install.macos]\nentry = \"Contents/MacOS/App\"\n"
        );
        let c = parse(&text).unwrap();
        let u = c.update.unwrap();
        let entry = |t: Target| u.install_for(t).entry.as_str().to_owned();
        let icon = |t: Target| u.install_for(t).icon.map(|i| i.as_str().to_owned());
        for t in [Target::LinuxX86_64, Target::LinuxAarch64] {
            assert_eq!(entry(t), "bin/app");
            assert_eq!(icon(t).as_deref(), Some("assets/icon.svg"));
        }
        for t in [Target::WindowsX86_64, Target::WindowsAarch64] {
            assert_eq!(entry(t), "bin/app.exe");
            assert_eq!(icon(t).as_deref(), Some("assets/icon.png"));
        }
        for t in [
            Target::MacosUniversal,
            Target::MacosAarch64,
            Target::MacosX86_64,
        ] {
            assert_eq!(entry(t), "Contents/MacOS/App");
            assert_eq!(
                icon(t).as_deref(),
                Some("assets/icon.svg"),
                "icon not overridden"
            );
        }
        // Everything else in `[install]` is shared, and `[install]` itself is not changed.
        assert_eq!(u.install.entry.as_str(), "bin/app");
        assert_eq!(u.install_for(Target::WindowsX86_64).name, "App");
        // The `[windows] icon` and `[macos] icon` stamping inputs stay beside them.
        let c = parse(&format!(
            "{text}[windows]\nicon = \"art/app.ico\"\n[macos]\nicon = \"art/app.icns\"\n"
        ))
        .unwrap();
        assert_eq!(c.windows_icon, Some(PathBuf::from("/cfg/art/app.ico")));
        assert_eq!(c.macos_icon, Some(PathBuf::from("/cfg/art/app.icns")));
    }

    #[test]
    fn os_install_refuses_other_keys_and_bad_paths() {
        let with = |table: &str| format!("{UPDATE}{INSTALL}{table}");
        for key in [
            "channel",
            "name",
            "terminal",
            "autostart",
            "feed",
            "app_id",
            "bin",
        ] {
            for os in ["linux", "windows", "macos"] {
                let e = err(&with(&format!("[install.{os}]\n{key} = \"x\"\n")));
                assert!(
                    e.contains("unknown field") && e.contains(key),
                    "{os} {key}: {e}"
                );
            }
        }
        let e = err(&with("[install.freebsd]\nentry = \"x\"\n"));
        assert!(e.contains("unknown field") && e.contains("freebsd"), "{e}");
        for (os, key, value) in [
            ("linux", "entry", "/abs"),
            ("windows", "entry", "../up"),
            ("macos", "icon", ""),
            ("windows", "icon", "a//b"),
        ] {
            let e = err(&with(&format!("[install.{os}]\n{key} = \"{value}\"\n")));
            assert!(
                e.contains(&format!("install.{os}.{key} is not a tree path")),
                "{os} {key}: {e}"
            );
        }
        // An override table needs `[install]`, which needs `[update]`.
        let e = err("[install.macos]\nentry = \"x\"\n");
        assert!(
            e.contains("missing field") || e.contains("[install]"),
            "{e}"
        );
    }

    #[test]
    fn pack_channel_is_limited_to_the_publish_channels() {
        let base = format!("{UPDATE}{INSTALL}");
        let c = parse(&format!(
            "{base}{}",
            publish_with("channels = [\"stable\", \"beta\"]\n")
        ))
        .unwrap();
        assert_eq!(c.pack_channel("beta").unwrap().as_str(), "beta");
        assert_eq!(c.pack_channel("stable").unwrap().as_str(), "stable");
        let e = c.pack_channel("nightly").unwrap_err().to_string();
        assert!(
            e.contains("--channel nightly") && e.contains("stable, beta"),
            "{e}"
        );
        let e = c.pack_channel("Not A Channel").unwrap_err().to_string();
        assert!(
            e.contains("not a channel id") && !e.contains("Not A"),
            "{e}"
        );
        // No [publish], or no [update].
        let none = parse(&base).unwrap();
        let e = none.pack_channel("beta").unwrap_err().to_string();
        assert!(e.contains("--channel needs [publish]"), "{e}");
        let e = parse(PUBLISH)
            .unwrap()
            .pack_channel("stable")
            .unwrap_err()
            .to_string();
        assert!(e.contains("--channel needs [update]"), "{e}");
    }

    #[test]
    fn a_directory_is_not_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let e = Config::load(dir.path()).unwrap_err();
        assert!(format!("{e:#}").contains("not a regular file"), "{e:#}");
    }
}
