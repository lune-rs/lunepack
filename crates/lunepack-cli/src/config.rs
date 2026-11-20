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
    Signer, Target, TemplateRole, TrustedRoot, Verifier,
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
    /// The install metadata.
    pub install: InstallMeta,
    /// `[update] publisher_check` as written (M9-D6); `None` takes the default for the target,
    /// see [`Config::publisher_policy`].
    pub publisher_check: Option<PublisherPolicy>,
}

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
    /// `sign_installer`: `Setup.exe`, the installer app's items and the `.dmg`; defaults to `sign`.
    #[allow(dead_code)] // read by `lunepack setup` (M9 step 4)
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
        publisher_check,
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

    #[test]
    fn a_directory_is_not_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let e = Config::load(dir.path()).unwrap_err();
        assert!(format!("{e:#}").contains("not a regular file"), "{e:#}");
    }
}
