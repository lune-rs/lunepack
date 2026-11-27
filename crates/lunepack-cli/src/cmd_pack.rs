//! `pack` (M3 step 8): C2 stages 1 to 5 over any build-output directory (M3-D13), then the
//! self-verification of M3-D9 and placement: the pack first, the manifest last, neither ever
//! overwritten.
//!
//! The packaged app is opaque: its id comes from the config, its version and target from the
//! flags; nothing here reads a build system's files or runs a toolchain.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::digest::U53;
use lunepack_core::error::UpdateConfigError;
use lunepack_core::update_config::MACOS_ENTRY_DIR;
use lunepack_core::{
    AppId, ArtifactRef, BinaryKind, Channel, ClockReading, CodeSign, DeltaFile, Hasher,
    InstallMeta, KeysChain, Limits, MAX_PATCH_WINDOW, NameRule, PayloadKind, RelPath, ReleaseDoc,
    ReleaseLayout, Signer, Target, UpdateConfig, VerifiedEntry, VerifiedKeySet, Version,
    check_pe_stub, check_runtime_image, check_service_image, check_ui_image, decode_verified,
    macos_name_ok, next_feed, sign_envelope, verify_manifest, windows_name_ok,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use crate::cmd_setup::bundle_stem;
use crate::codesign::OsCodeSign;
use crate::config::{Config, resolve_signer, writer_clock};
use crate::pipeline::{self, Settings, UpdatePlan};
use crate::place;
use crate::plist;
use crate::prebuilt::{self, PinState};
use crate::release_dir;
use crate::stamp;

/// Prefix of the work dir under the system temp dir.
pub const WORK_PREFIX: &str = "lunepack-pack-";
/// Largest `--runtime` file read, in bytes.
pub(crate) const MAX_RUNTIME_BYTES: u64 = 256 * 1024 * 1024;
/// Largest `--ui` file read, in bytes.
pub(crate) const MAX_UI_BYTES: u64 = 64 * 1024 * 1024;
/// Largest `--stub` file read, in bytes.
pub(crate) const MAX_STUB_BYTES: u64 = 32 * 1024 * 1024;
/// Largest `--service` file read, in bytes.
pub(crate) const MAX_SERVICE_BYTES: u64 = 32 * 1024 * 1024;
/// Default memory budget of the pack stage, in MiB.
const DEFAULT_BUDGET_MIB: u64 = 2048;
/// Default of `--deltas` (M12-D3).
const DEFAULT_DELTAS: u8 = 3;
/// The channel of the throwaway feed the self-check signs; never written anywhere.
const SELF_CHECK_CHANNEL: &str = "pack-self-check";

/// Arguments of `pack`.
#[derive(Args)]
pub struct PackArgs {
    /// The build output to package: any directory (the app's files as they should be installed).
    #[arg(long)]
    input: PathBuf,
    /// The release version (SemVer 2.0.0), used verbatim.
    #[arg(long)]
    version: String,
    /// The target id, such as `windows-x86_64` or `linux-aarch64`.
    #[arg(long)]
    target: String,
    /// The release directory (with `keys.json`); required unless `--assemble` is given.
    #[arg(
        long = "release-dir",
        required_unless_present = "assemble",
        conflicts_with = "assemble"
    )]
    release_dir: Option<PathBuf>,
    /// A release signer: a name from the config, `file:<path>` or `env:<VAR>`; repeat to reach
    /// the key set's threshold. Required unless `--assemble` is given.
    #[arg(
        long = "sign",
        required_unless_present = "assemble",
        conflicts_with = "assemble"
    )]
    sign: Vec<String>,
    /// The app id; when given, it must equal the config's.
    #[arg(long = "app-id")]
    app_id: Option<String>,
    /// Encoder threads (default: the available parallelism). The output does not depend on it.
    #[arg(long)]
    jobs: Option<NonZeroUsize>,
    /// Memory budget of the encoders, in MiB; a file over the whole budget is encoded alone.
    #[arg(long = "memory-budget-mib", default_value_t = DEFAULT_BUDGET_MIB,
          value_parser = clap::value_parser!(u64).range(1..=(1 << 40)))]
    memory_budget_mib: u64,
    /// The static runtime to place beside the entry; required when the config has `[update]`, and
    /// refused without it.
    #[arg(long)]
    runtime: Option<PathBuf>,
    /// The UI binary to place beside the runtime; needs `--runtime` and `[update]`, and is refused
    /// without them. Optional: without it the UI is absent and the app runs headless.
    #[arg(long)]
    ui: Option<PathBuf>,
    /// The Windows launcher stub (M7-D7) to stamp and place beside the entry as
    /// `lunepack-stub.exe`: required for a `windows-*` target when the config has `[update]`, and
    /// refused for any other target. The console stub for a terminal app, the GUI stub otherwise.
    #[arg(long)]
    stub: Option<PathBuf>,
    /// Delta patches (M12-D3): from each feed of the release directory, the N highest earlier
    /// versions it lists for this target (with no usable feed, the N highest earlier versions in
    /// the directory), at most 16 in all; `0` writes no delta.
    #[arg(long, default_value_t = DEFAULT_DELTAS,
          value_parser = clap::value_parser!(u8).range(0..=16))]
    deltas: u8,
    /// The update service, placed beside the entry as `lunepack-service.exe` (Windows) or
    /// `lunepack-service` (Linux and macOS; in `Contents/MacOS` for macOS). Optional: it enables
    /// per-machine installs. Needs `--runtime` and `[update]`.
    #[arg(long)]
    service: Option<PathBuf>,
    /// For a `macos-*` target with `[update]` (M8-D8): write the tree `pack` would hash to this
    /// new directory and stop, so it can be code-signed and then packed. Takes no release
    /// directory and no signer, and writes nothing to a release.
    #[arg(long)]
    assemble: Option<PathBuf>,
    /// The channel the packed tree follows (P-D5): one of the config's `[publish] channels`;
    /// without it the tree follows `[update] channel`.
    #[arg(long)]
    channel: Option<String>,
    /// Refuse a `--runtime`, `--ui`, `--stub` or `--service` that is not a binary this CLI pins
    /// (the project's signed list for this CLI's version; `lunepack prebuilt list`).
    #[arg(long = "require-pinned")]
    require_pinned: bool,
}

fn say(line: &str) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{line}").context("cannot write to stdout")
}

fn key_id_hex(public: &[u8; 32]) -> String {
    Sha256Hasher.sha256(public).to_hex()
}

/// The `--sign` signers must be distinct release keys, each inside its window at `now`, and reach
/// the key set's threshold.
pub(crate) fn check_signers(
    signers: &[Box<dyn Signer>],
    keys: &VerifiedKeySet,
    now: u64,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for s in signers {
        let public = s.public_key();
        let at = keys
            .keys()
            .keys()
            .iter()
            .position(|k| k.public().as_bytes() == &public);
        let Some(at) = at else {
            bail!(
                "the signer with key id {} is not in keys.json",
                key_id_hex(&public)
            );
        };
        let window = keys
            .windows()
            .get(at)
            .context("internal error: a key without a window")?;
        if !window.contains(now) {
            bail!(
                "the release key with id {} is not valid at {now} (window {}..{})",
                key_id_hex(&public),
                window.not_before,
                window.not_after
            );
        }
        if !seen.insert(public) {
            bail!(
                "the release key with id {} is given twice",
                key_id_hex(&public)
            );
        }
    }
    if seen.len() < keys.threshold() {
        bail!(
            "a manifest needs {} release signer(s), {} given",
            keys.threshold(),
            seen.len()
        );
    }
    Ok(())
}

/// D25: a version directory of equal precedence and other text would be a second name for the
/// same release.
fn check_precedence(dir: &Path, version: &Version, text: &str) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("cannot list {}", dir.display()))? {
        let entry = entry.with_context(|| format!("cannot list {}", dir.display()))?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name == text || !entry.path().is_dir() {
            continue;
        }
        if Version::parse(&name).is_ok_and(|v| v == *version) {
            bail!(
                "{} already holds version {name:?}, of equal precedence to {text:?}",
                dir.display()
            );
        }
    }
    Ok(())
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// M3-D9: the manifest and pack are checked the way a client checks them, through a throwaway feed
/// signed by the same signers.
#[allow(clippy::too_many_arguments)]
fn self_verify(
    chain: &KeysChain,
    signers: &[&dyn Signer],
    app_id: &AppId,
    version: &str,
    target: Target,
    now: u64,
    manifest: &[u8],
    pack: &[u8],
    deltas: &[DeltaFile],
) -> Result<(usize, usize)> {
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let reference = ArtifactRef {
        path: format!("{version}/{}.manifest.json", target.as_str()),
        size: U53::new(manifest.len() as u64)?,
        sha256: hasher.sha256(manifest),
    };
    let release = ReleaseDoc {
        version: version.to_owned(),
        targets: BTreeMap::from([(target.as_str().to_owned(), reference)]),
        rollout: None,
    };
    let channel = Channel::parse(SELF_CHECK_CHANNEL)?;
    let feed = next_feed(None, app_id, &channel, now, vec![release], None)?;
    let feed_bytes = sign_envelope(
        PayloadKind::Feed,
        &feed.to_payload(),
        signers,
        &hasher,
        &verifier,
    )?;
    let reading = ClockReading::read(&crate::config::FixedClock(now), None);
    let feed =
        release_dir::verify_feed_of(chain, app_id, &channel, &feed_bytes, &reading, &verifier)?;
    let keys = chain.keys();
    let entry = feed
        .target_entry(0, target)
        .context("the feed lists no manifest for the target")?;
    let manifest = verify_manifest(keys, &entry, manifest, &hasher, &verifier)?;
    manifest.pack().check_bytes(pack, &hasher)?;
    let mut frames = 0;
    for e in manifest.entries() {
        if let VerifiedEntry::File {
            path,
            frame: Some(frame),
            ..
        } = e
        {
            // check_bytes and verify_manifest bound every frame inside the pack.
            let start = usize::try_from(frame.offset())?;
            let end = start + usize::try_from(frame.length())?;
            decode_verified(
                frame,
                &pack[start..end],
                &hasher,
                &LzmaCodec,
                &mut io::sink(),
            )
            .with_context(|| format!("{path} does not decode"))?;
            frames += 1;
        }
    }
    // Every delta file the manifest lists is the one about to be placed, and every patch's bytes
    // are the ones it signs; each patch was round-tripped against its base when it was encoded.
    if manifest.deltas().len() != deltas.len() {
        bail!("the manifest lists another number of delta files than were made");
    }
    let mut patches = 0;
    for (delta, file) in manifest.deltas().iter().zip(deltas) {
        if delta.file().path() != file.path {
            bail!(
                "the manifest lists {} where {} was made",
                delta.file().path(),
                file.path
            );
        }
        delta.file().check_bytes(&file.bytes, &hasher)?;
        for patch in delta.patches() {
            let start = usize::try_from(patch.offset())?;
            let end = start + usize::try_from(patch.length())?;
            let bytes = file
                .bytes
                .get(start..end)
                .context("a patch lies outside its delta file")?;
            if hasher.sha256(bytes) != patch.sha256() {
                bail!(
                    "{}: the patch of {} does not match",
                    file.path,
                    patch.path()
                );
            }
            patches += 1;
        }
    }
    Ok((frames, patches))
}

/// What `[update]` adds to a pack, built before anything is read from the input tree.
struct Prepared {
    install: InstallMeta,
    runtime: Vec<u8>,
    ui: Option<Vec<u8>>,
    /// The stamped Windows stub (M7-D14); `Some` exactly for a `windows-*` target.
    stub: Option<Vec<u8>>,
    /// The update service's bytes (M10-D7, M11); `Some` exactly with `--service`, for any target.
    service: Option<Vec<u8>>,
    /// The helper app's `Info.plist` (M8-D6); `Some` for a `macos-*` target with `--ui`.
    helper_plist: Option<Vec<u8>>,
    /// The helper app's checked `.icns` bytes, when `[macos] icon` is set and a helper is built.
    helper_icon: Option<Vec<u8>>,
    config: Vec<u8>,
}

/// Names the config field a core refusal is about, never the value.
fn config_error(e: UpdateConfigError) -> anyhow::Error {
    match &e {
        UpdateConfigError::Feed(rule) => anyhow!("[update] feed: {rule}"),
        UpdateConfigError::Invalid { field, rule } => match field.strip_prefix("install.") {
            Some(name) => anyhow!("[install] {name}: {rule}"),
            None if ["feed", "channel", "health_timeout_secs"].contains(field) => {
                anyhow!("[update] {field}: {rule}")
            }
            None => anyhow!("the update config is not valid: {e}"),
        },
        _ => anyhow!("the update config is not valid: {e}"),
    }
}

/// Reads the file named by `flag` (`--runtime` or `--ui`), refusing a non-regular file and one
/// over `cap` bytes.
fn read_capped(path: &Path, flag: &str, cap: u64) -> Result<Vec<u8>> {
    // Classified before opening: a FIFO blocks on open.
    let meta = fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    if !meta.is_file() {
        bail!("{flag} {} is not a regular file", path.display());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|f| f.take(cap + 1).read_to_end(&mut bytes))
        .with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() as u64 > cap {
        bail!("{flag} {} is over {cap} bytes", path.display());
    }
    Ok(bytes)
}

/// The inputs of [`prepare_update`] that are not the config.
struct UpdateInputs<'a> {
    runtime: Option<&'a Path>,
    ui: Option<&'a Path>,
    stub: Option<&'a Path>,
    service: Option<&'a Path>,
    /// `--channel`, already checked against `[publish] channels`.
    channel: Option<&'a Channel>,
    /// The `--input` directory, where a PNG `install.icon` is read from.
    input: &'a Path,
    /// The `--version` text, written into a stamped stub's version info.
    version_text: &'a str,
    /// What this CLI pins: each given binary is classified against it as read.
    pins: &'a PinState,
    /// `--require-pinned`: a local build is an error.
    require_pinned: bool,
}

/// M7-D15, M7-D14 for a `windows-*` target: the install `name` is the install folder's name, the
/// entry is an `.exe`, and the numeric version fits the stub's 16-bit fields. Errors name the
/// field and the rule, never the value.
fn check_windows_install(install: &InstallMeta, version: &Version) -> Result<()> {
    if let Err(rule) = windows_name_ok(&install.name) {
        bail!("[install] name: not a valid Windows folder and shortcut name: {rule}");
    }
    let file = install.entry.components().last().unwrap_or_default();
    if !file.to_ascii_lowercase().ends_with(".exe") {
        bail!("[install] entry: a Windows target's entry must be an .exe file");
    }
    stamp::version_numbers(version)?;
    Ok(())
}

/// M8-D6 for a `macos-*` target: the entry is `Contents/MacOS/<file>`, so the runtime lands in
/// `Contents/MacOS` and the bundle's `Info.plist` is where `Contents/Info.plist` expects it. When
/// `install.name` is not a usable bundle name, the installed bundle is named after the app id
/// (M8-D1) and `pack` says so on stderr, naming the rule and never the name.
fn check_macos_install(install: &InstallMeta) -> Result<()> {
    let parts: Vec<&str> = install.entry.components().collect();
    if parts.len() != 3 || parts[..2].join("/") != MACOS_ENTRY_DIR {
        bail!("[install] entry: a macos-* target's entry must be {MACOS_ENTRY_DIR}/<file>");
    }
    if let Err(rule) = macos_name_ok(&install.name) {
        let why = match rule {
            NameRule::Empty => "empty",
            NameRule::TooLong => "longer than 200 bytes",
            NameRule::ForbiddenChar => "holds `/`, `:` or a control character",
            NameRule::Edge => "starts with a dot",
            _ => "not accepted",
        };
        eprintln!(
            "warning: [install] name is not usable as a macOS bundle name ({why}); \
             the installed bundle will be named after the app id"
        );
    }
    Ok(())
}

/// The helper app's `.icns` from `[macos] icon`, read and checked (M8-D6). Errors name the option,
/// never the file's content.
fn macos_icon_file(path: &Path) -> Result<Vec<u8>> {
    let bytes = release_dir::read_capped(path, plist::MAX_ICNS_BYTES)
        .map_err(|_| anyhow!("[macos] icon: cannot be read as a file of at most 4 MiB"))?
        .ok_or_else(|| anyhow!("[macos] icon: the file does not exist"))?;
    plist::check_icns(&bytes).map_err(|e| anyhow!("[macos] icon: {e}"))?;
    Ok(bytes)
}

/// The icon bytes a Windows stub or setup file is stamped with (M7-D14): `[windows] icon` when
/// given, else a PNG `install.icon` read through `read_icon`, else none (an SVG or no icon).
pub(crate) fn pick_icon(
    config: &Config,
    install: &InstallMeta,
    read_icon: impl FnOnce(&RelPath) -> Result<Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    if let Some(path) = &config.windows_icon {
        return stamp::windows_icon_file(path).map(Some);
    }
    match &install.icon {
        Some(icon) => stamp::install_icon(icon, || read_icon(icon)),
        None => Ok(None),
    }
}

/// Reads a PNG `install.icon` from the input tree, through real directories only.
fn read_input_icon(input: &Path, icon: &RelPath) -> Result<Vec<u8>> {
    pipeline::regular_file_in(input, icon, "install.icon")?;
    read_capped(
        &input.join(icon.as_str()),
        "install.icon",
        stamp::MAX_ICON_BYTES,
    )
}

/// Checks the `--stub` bytes as read, stamps them (M7-D14), checks the stamped bytes again and
/// returns them.
fn prepare_stub(
    config: &Config,
    install: &InstallMeta,
    bytes: &[u8],
    inputs: &UpdateInputs<'_>,
    version: &Version,
    target: Target,
) -> Result<Vec<u8>> {
    let console = install.terminal;
    let kind = if console { "console" } else { "GUI" };
    check_pe_stub(bytes, target, console)
        .map_err(|e| anyhow!("--stub is not a {kind} stub for {}: {e}", target.as_str()))?;
    // The input tree is read only when it is one: a bad `--input` fails in `assemble`.
    let icon = pick_icon(config, install, |icon| read_input_icon(inputs.input, icon))?;
    let file = install.entry.components().last().unwrap_or_default();
    let fields = stamp::Fields {
        description: &install.name,
        product: &install.name,
        company: install.publisher.as_deref(),
        version_text: inputs.version_text,
        numbers: stamp::version_numbers(version)?,
        original_filename: file,
        icon: icon.as_deref(),
    };
    let stamped = stamp::stamp(bytes, &fields).context("--stub cannot be stamped")?;
    check_pe_stub(&stamped, target, console).map_err(|e| {
        anyhow!(
            "the stamped --stub is not a {kind} stub for {}: {e}",
            target.as_str()
        )
    })?;
    Ok(stamped)
}

/// One lunepack binary given to `pack`, as read.
struct Given<'a> {
    flag: &'static str,
    path: &'a Path,
    kind: BinaryKind,
    bytes: &'a [u8],
}

/// One line per given binary: a pinned release binary (kind, version, target) or a local build.
/// A binary counts as pinned only by a row of its kind for exactly `target` with its size and
/// SHA-256, and only in the state `pinned`. With `require`, the first local build is an error.
fn pin_report(
    pins: &PinState,
    target: Target,
    given: &[Given<'_>],
    require: bool,
) -> Result<Vec<String>> {
    let mut lines = Vec::with_capacity(given.len());
    for g in given {
        match pins.pinned_row(g.kind, target, g.bytes, &Sha256Hasher) {
            Some(row) => {
                let version = pins.list().map_or("", |l| l.version_text());
                lines.push(format!(
                    "binary: {} is a pinned release binary ({} {version} {})",
                    g.flag,
                    row.kind(),
                    row.target().as_str()
                ));
            }
            None if require => bail!(
                "{} {} is a local build, not a binary this CLI pins as {} for {} (--require-pinned); \
                 get the pinned binaries with `lunepack prebuilt fetch --target {} --out <dir>` \
                 (`lunepack prebuilt list` shows what this CLI pins)",
                g.flag,
                g.path.display(),
                g.kind,
                target.as_str(),
                target.as_str()
            ),
            None => lines.push(format!("binary: {} is a local build", g.flag)),
        }
    }
    Ok(lines)
}

/// M5-D7: with `[update]` the runtime is required and the update config is written for this
/// version and target; without it `--runtime` is refused. `--ui` (M6) needs both and is refused
/// without them. `--stub` (M7) is required for a `windows-*` target and refused for any other.
/// Every check that needs no tree runs here.
fn prepare_update(
    config: &Config,
    inputs: &UpdateInputs<'_>,
    version: &Version,
    target: Target,
) -> Result<Option<Prepared>> {
    let Some(settings) = &config.update else {
        if inputs.runtime.is_some() {
            bail!("--runtime needs [update] and [install] in the config");
        }
        if inputs.ui.is_some() {
            bail!("--ui needs [update] and [install] in the config");
        }
        if inputs.stub.is_some() {
            bail!("--stub needs [update] and [install] in the config");
        }
        if inputs.service.is_some() {
            bail!("--service needs [update] and [install] in the config");
        }
        return Ok(None);
    };
    let Some(runtime) = inputs.runtime else {
        if inputs.ui.is_some() {
            bail!("--ui needs --runtime");
        }
        if inputs.stub.is_some() {
            bail!("--stub needs --runtime");
        }
        if inputs.service.is_some() {
            bail!("--service needs --runtime");
        }
        bail!("--runtime is required when the config has [update]");
    };
    if inputs.stub.is_some() && !target.is_windows() {
        bail!("--stub is only for windows-* targets");
    }
    // `[install]` with the target's `[install.<os>]` laid over it (P-D5).
    let install = settings.install_for(target);
    if target.is_windows() {
        if inputs.stub.is_none() {
            bail!("--stub is required for a windows-* target when the config has [update]");
        }
        check_windows_install(&install, version)?;
    }
    if target.is_macos() {
        check_macos_install(&install)?;
    }
    let root = config.trusted_root(&Sha256Hasher, &Ed25519Verifier)?;
    let mut document = UpdateConfig::new(
        &root,
        version.clone(),
        target,
        &settings.feed,
        inputs
            .channel
            .cloned()
            .unwrap_or_else(|| settings.channel.clone()),
        settings.health_timeout_secs,
        install,
    )
    .map_err(config_error)?;
    // M9-D6: what the installed tree enforces about the next update's publisher; `Off` is not
    // written (M9-R1-D1), so a config without OS signing keeps its bytes.
    document.publisher_check = config.publisher_policy(target);
    // The authoritative check, the one the facade runs before any request: the URL parser agrees.
    lunepack::check_config_feed(&document.feed).map_err(config_error)?;
    let bytes = read_capped(runtime, "--runtime", MAX_RUNTIME_BYTES)?;
    check_runtime_image(&bytes, target)
        .map_err(|e| anyhow!("--runtime is not a runtime for {}: {e}", target.as_str()))?;
    let ui = inputs
        .ui
        .map(|path| {
            let bytes = read_capped(path, "--ui", MAX_UI_BYTES)?;
            check_ui_image(&bytes, target)
                .map_err(|e| anyhow!("--ui is not a UI for {}: {e}", target.as_str()))?;
            Ok::<_, anyhow::Error>(bytes)
        })
        .transpose()?;
    // Classified as read, before stamping (M13 step 12).
    let stub_read = inputs
        .stub
        .map(|path| read_capped(path, "--stub", MAX_STUB_BYTES))
        .transpose()?;
    let stub = stub_read
        .as_deref()
        .map(|bytes| prepare_stub(config, &document.install, bytes, inputs, version, target))
        .transpose()?;
    let service = inputs
        .service
        .map(|path| {
            let bytes = read_capped(path, "--service", MAX_SERVICE_BYTES)?;
            // A Windows service is a hardened console PE (M10-D7); a Linux or macOS one is checked
            // as a runtime is (static, the target's format and architecture).
            let checked = if target.is_windows() {
                check_service_image(&bytes, target)
            } else {
                check_runtime_image(&bytes, target)
            };
            checked.map_err(|e| {
                anyhow!(
                    "--service is not a service image for {}: {e}",
                    target.as_str()
                )
            })?;
            Ok::<_, anyhow::Error>(bytes)
        })
        .transpose()?;
    let stub_kind = if document.install.terminal {
        BinaryKind::StubConsole
    } else {
        BinaryKind::Stub
    };
    let mut given = vec![Given {
        flag: "--runtime",
        path: runtime,
        kind: BinaryKind::Runtime,
        bytes: &bytes,
    }];
    if let (Some(path), Some(bytes)) = (inputs.ui, ui.as_deref()) {
        given.push(Given {
            flag: "--ui",
            path,
            kind: BinaryKind::Ui,
            bytes,
        });
    }
    if let (Some(path), Some(bytes)) = (inputs.stub, stub_read.as_deref()) {
        given.push(Given {
            flag: "--stub",
            path,
            kind: stub_kind,
            bytes,
        });
    }
    if let (Some(path), Some(bytes)) = (inputs.service, service.as_deref()) {
        given.push(Given {
            flag: "--service",
            path,
            kind: BinaryKind::Service,
            bytes,
        });
    }
    for line in pin_report(inputs.pins, target, &given, inputs.require_pinned)? {
        say(&line)?;
    }
    // The helper app's files exist only with a UI, and `[macos] icon` is read only then.
    let (helper_plist, helper_icon) = if target.is_macos() && ui.is_some() {
        let icon = config
            .macos_icon
            .as_deref()
            .map(macos_icon_file)
            .transpose()?;
        let plist =
            plist::helper_info_plist(&config.app_id, &document.install.name, icon.is_some())
                .context("the helper app's Info.plist cannot be written")?;
        (Some(plist), icon)
    } else {
        (None, None)
    };
    Ok(Some(Prepared {
        install: document.install.clone(),
        config: document.to_bytes().map_err(config_error)?,
        runtime: bytes,
        ui,
        stub,
        service,
        helper_plist,
        helper_icon,
    }))
}

/// `pack`: see the module documentation.
pub fn pack(config_path: &Path, args: &PackArgs, code_sign: &dyn CodeSign) -> Result<()> {
    let config = Config::load(config_path)?;
    if let Some(id) = &args.app_id
        && id != config.app_id.as_str()
    {
        bail!(
            "--app-id {id:?} is not the config's app id {:?}",
            config.app_id.as_str()
        );
    }
    let version = Version::parse(&args.version).context("--version is not a SemVer version")?;
    let target = Target::parse(&args.target)?;
    let channel = args
        .channel
        .as_deref()
        .map(|requested| config.pack_channel(requested))
        .transpose()?;
    // M3-D10: a Windows host cannot know the exec bits of a Unix target.
    if cfg!(windows) && !target.is_windows() {
        bail!(
            "{} cannot be packed on a Windows host: exec bits are unknowable here",
            target.as_str()
        );
    }

    if args.assemble.is_some() {
        if !target.is_macos() {
            bail!("--assemble is only for macos-* targets");
        }
        if config.update.is_none() {
            bail!("--assemble needs [update] and [install] in the config");
        }
    }
    let pins = prebuilt::compiled_in();
    if let PinState::Inconsistent(reason) = &pins {
        eprintln!(
            "warning: this CLI's pinned binary list is inconsistent ({reason}); every binary counts as a local build"
        );
    }
    let prepared = prepare_update(
        &config,
        &UpdateInputs {
            runtime: args.runtime.as_deref(),
            ui: args.ui.as_deref(),
            stub: args.stub.as_deref(),
            service: args.service.as_deref(),
            channel: channel.as_ref(),
            input: &args.input,
            version_text: &args.version,
            pins: &pins,
            require_pinned: args.require_pinned,
        },
        &version,
        target,
    )?;
    let update_plan = prepared.as_ref().map(|p| UpdatePlan {
        target,
        install: &p.install,
        runtime: &p.runtime,
        ui: p.ui.as_deref(),
        stub: p.stub.as_deref(),
        service: p.service.as_deref(),
        config: &p.config,
        helper_plist: p.helper_plist.as_deref(),
        helper_icon: p.helper_icon.as_deref(),
    });
    // The OS signing hook (M9): the config's `[codesign.<os>]` for this target, else the caller's.
    let os_sign = config.codesign_for(target).map(|section| {
        let stem = match (&config.update, target.is_macos()) {
            (Some(u), true) => bundle_stem(&u.install.name, &config.app_id).to_owned(),
            _ => config.app_id.as_str().to_owned(),
        };
        OsCodeSign::new(section.clone(), format!("{stem}.app"))
    });
    if os_sign.is_some() && target.is_macos() && update_plan.is_none() {
        bail!(
            "[codesign.macos] needs [update] and [install] in the config: the bundle's main \
             executable is install.entry"
        );
    }
    let code_sign: &dyn CodeSign = match &os_sign {
        Some(os) => os,
        None => code_sign,
    };
    if let Some(dest) = &args.assemble {
        // M8-D8: write the tree to sign, and stop. Nothing is signed, read from or written to a
        // release. `[update]` was checked above, so there is a plan.
        let Some(plan) = &update_plan else {
            bail!("internal error: --assemble without an update plan");
        };
        pipeline::assemble_bundle(&args.input, dest, plan)?;
        say("assemble: wrote the bundle; code-sign it, then pack it with the same options")?;
        say(&format!("assembled: {}", dest.display()))?;
        return Ok(());
    }
    let (Some(release_dir_arg), true) = (&args.release_dir, !args.sign.is_empty()) else {
        bail!("internal error: pack needs a release directory and a signer");
    };

    let clock = writer_clock()?;
    let now = clock.now_unix_secs();
    // Time checks are skipped on the documents read (M3-D9); the signers' windows are checked
    // at `now` below.
    let skip = ClockReading::read(clock.as_ref(), Some(u64::MAX));
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let opened = release_dir::open(release_dir_arg, &config, &hasher, &verifier, &skip)?;
    let Some(chain) = opened.chain else {
        bail!(
            "{} has no keys.json; run `lunepack keys set` first",
            release_dir_arg.display()
        );
    };
    let keys = chain.keys();
    let signers = args
        .sign
        .iter()
        .map(|s| resolve_signer(config_path, s))
        .collect::<Result<Vec<_>>>()?;
    check_signers(&signers, keys, now)?;

    let version_dir = release_dir_arg.join(&args.version);
    let pack_path = version_dir.join(format!("{}.pack", target.as_str()));
    let manifest_path = version_dir.join(format!("{}.manifest.json", target.as_str()));
    for path in [&manifest_path, &pack_path] {
        if exists(path) {
            bail!("{} already exists", path.display());
        }
    }
    check_precedence(release_dir_arg, &version, &args.version)?;
    let layout = ReleaseLayout::new(config.app_id.clone(), &args.version, target)?;

    let mut delta_lines = Vec::new();
    let bases = release_dir::select_bases(
        &release_dir::BaseQuery {
            dir: release_dir_arg,
            chain: &chain,
            app_id: &config.app_id,
            version: &version,
            target,
            per_feed: usize::from(args.deltas),
            now,
            skip: &skip,
        },
        &hasher,
        &verifier,
        &mut delta_lines,
    )?;
    for base in &bases {
        let path = release_dir_arg.join(delta_rel(&args.version, target, &base.version));
        if exists(&path) {
            bail!("{} already exists", path.display());
        }
    }
    if args.deltas > 0 {
        let list: Vec<&str> = bases.iter().map(|b| b.version.as_str()).collect();
        say(&format!(
            "delta: base(s) {}",
            if list.is_empty() {
                "none".to_owned()
            } else {
                list.join(", ")
            }
        ))?;
    }

    let workers = match args.jobs {
        Some(n) => n.get(),
        None => std::thread::available_parallelism().map_or(1, NonZeroUsize::get),
    };
    let set = Settings {
        workers,
        budget: args.memory_budget_mib.saturating_mul(1024 * 1024),
        code_sign,
        os_signing: os_sign.is_some(),
        encoder: &LzmaCodec,
        codec: &LzmaCodec,
        hasher: &hasher,
        update: update_plan,
        bases: &bases,
        patch_window_cap: MAX_PATCH_WINDOW,
    };
    // Removed on drop: on success and on every error path.
    let work = tempfile::Builder::new()
        .prefix(WORK_PREFIX)
        .tempdir()
        .context("cannot create a work dir under the system temp dir")?;
    let built = pipeline::build(
        &args.input,
        work.path(),
        layout,
        target,
        now,
        &set,
        &mut |line| say(line),
    )?;
    drop(work);

    let refs: Vec<&dyn Signer> = signers.iter().map(|s| s.as_ref()).collect();
    let manifest = sign_envelope(
        PayloadKind::Manifest,
        &built.manifest.to_payload(),
        &refs,
        &hasher,
        &verifier,
    )?;
    say(&format!("sign: manifest signed by {} key(s)", refs.len()))?;
    check_manifest_size(manifest.len() as u64)?;
    let (frames, patches) = self_verify(
        &chain,
        &refs,
        &config.app_id,
        &args.version,
        target,
        now,
        &manifest,
        &built.pack,
        &built.deltas,
    )
    .context("the new release does not verify (nothing was written)")?;
    say(&format!("verify: manifest, pack and {frames} frame(s) ok"))?;
    if !built.deltas.is_empty() {
        say(&format!(
            "verify: {} delta file(s) and {patches} patch(es) ok",
            built.deltas.len()
        ))?;
    }

    // The pack and the delta files first, the manifest that names them last.
    fs::create_dir_all(&version_dir)
        .with_context(|| format!("cannot create {}", version_dir.display()))?;
    place::write_new(&pack_path, &built.pack)?;
    let mut placed = vec![pack_path.clone()];
    for delta in &built.deltas {
        let path = release_dir_arg.join(&delta.path);
        place::write_new(&path, &delta.bytes)?;
        placed.push(path);
    }
    place::write_new(&manifest_path, &manifest)?;
    placed.push(manifest_path.clone());
    for path in &placed {
        say(&format!("placed: {}", path.display()))?;
    }

    let r = &built.report;
    say(&format!(
        "totals: {} file(s), {} input bytes, {} pack bytes",
        r.files,
        r.input_bytes,
        built.pack.len()
    ))?;
    for (codec, count) in &r.per_codec {
        say(&format!("codec {codec}: {count}"))?;
    }
    for (path, codec, reason) in &r.dropped {
        say(&format!("dropped: {path} {}: {reason}", codec.id()))?;
    }
    for line in &delta_lines {
        say(line)?;
    }
    for line in &r.deltas {
        say(line)?;
    }
    Ok(())
}

/// FORMAT.md 4: a signed manifest is at most 64 MiB; deltas are what can push one over, so the
/// error names `--deltas`.
fn check_manifest_size(len: u64) -> Result<()> {
    let cap = Limits::V1.manifest_doc_bytes;
    if len > cap {
        bail!(
            "the signed manifest is {len} bytes, over the format's {cap}-byte cap; pack with a lower --deltas (nothing was written)"
        );
    }
    Ok(())
}

/// The delta file of `version` from `from`, relative to the release directory (FORMAT.md 9.3).
fn delta_rel(version: &str, target: Target, from: &str) -> String {
    format!("{version}/{}.from-{from}.delta", target.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_over_the_cap_names_deltas() {
        let cap = Limits::V1.manifest_doc_bytes;
        assert!(check_manifest_size(cap).is_ok());
        let e = check_manifest_size(cap + 1).unwrap_err();
        assert!(format!("{e:#}").contains("--deltas"), "{e:#}");
    }

    /// A `pinned` state whose list pins `runtime` and `stub` for `windows-x86_64`, signed now by a
    /// throwaway key with the real writer.
    fn pinned(runtime: &[u8], stub: &[u8]) -> PinState {
        use lunepack_core::encoding::hex_encode;
        use lunepack_crypto::{Ed25519Signer, generate_key_file};

        let dir = tempfile::tempdir().unwrap();
        let key = generate_key_file(&dir.path().join("k")).unwrap();
        let signer = Ed25519Signer::from_key_file(&key.path).unwrap();
        let public = hex_encode(&key.public_key);
        let row = |kind: &str, bytes: &[u8]| {
            format!(
                r#"{{"kind":"{kind}","target":"windows-x86_64","size":{},"sha256":"{}"}}"#,
                bytes.len(),
                Sha256Hasher.sha256(bytes).to_hex()
            )
        };
        let table = format!(
            r#"{{"format":1,"kind":"prebuilt","critical":[],"version":"0.1.0","source_commit":"{}","rehearsal":false,"binaries":[{},{}]}}"#,
            "a".repeat(40),
            row("runtime", runtime),
            row("stub", stub)
        );
        let envelope = sign_envelope(
            PayloadKind::Prebuilt,
            table.as_bytes(),
            &[&signer as &dyn Signer],
            &Sha256Hasher,
            &Ed25519Verifier,
        )
        .unwrap();
        let keys = [public.as_str()];
        let roots = [crate::project_key::ProjectKeySet {
            version: 1,
            threshold: 1,
            keys: &keys,
        }];
        let state = prebuilt::pin_state(&roots, table.as_bytes(), &envelope, "0.1.0");
        assert_eq!(state.name(), "pinned");
        state
    }

    fn given<'a>(flag: &'static str, kind: BinaryKind, bytes: &'a [u8]) -> Given<'a> {
        Given {
            flag,
            path: Path::new("in/file"),
            kind,
            bytes,
        }
    }

    #[test]
    fn pin_report_classifies_the_stub_as_read_and_not_as_stamped() {
        let (runtime, stub) = (b"runtime bytes".as_slice(), b"MZ stub as read".as_slice());
        let state = pinned(runtime, stub);
        let win = Target::parse("windows-x86_64").unwrap();
        let lines = pin_report(
            &state,
            win,
            &[
                given("--runtime", BinaryKind::Runtime, runtime),
                given("--stub", BinaryKind::Stub, stub),
            ],
            true,
        )
        .unwrap();
        assert_eq!(
            lines,
            [
                "binary: --runtime is a pinned release binary (runtime 0.1.0 windows-x86_64)",
                "binary: --stub is a pinned release binary (stub 0.1.0 windows-x86_64)",
            ]
        );
        // The stamped bytes differ from the ones the list names: a local build.
        let mut stamped = stub.to_vec();
        stamped.extend_from_slice(b" + version info");
        let lines = pin_report(
            &state,
            win,
            &[given("--stub", BinaryKind::Stub, &stamped)],
            false,
        )
        .unwrap();
        assert_eq!(lines, ["binary: --stub is a local build"]);
        // A console stub is classified as `stub-console`, which this list does not pin.
        let lines = pin_report(
            &state,
            win,
            &[given("--stub", BinaryKind::StubConsole, stub)],
            false,
        )
        .unwrap();
        assert_eq!(lines, ["binary: --stub is a local build"]);
    }

    #[test]
    fn require_pinned_refuses_a_local_build_and_names_the_fetch_command() {
        let (runtime, stub) = (b"runtime bytes".as_slice(), b"MZ stub".as_slice());
        let state = pinned(runtime, stub);
        let win = Target::parse("windows-x86_64").unwrap();
        let mut other = runtime.to_vec();
        other[0] ^= 1;
        for (pins, bytes) in [(&state, other.as_slice()), (&PinState::NoKey, runtime)] {
            let e = pin_report(
                pins,
                win,
                &[given("--runtime", BinaryKind::Runtime, bytes)],
                true,
            )
            .unwrap_err();
            let text = format!("{e:#}");
            assert!(
                text.contains("--runtime in/file is a local build"),
                "{text}"
            );
            assert!(
                text.contains("lunepack prebuilt fetch --target windows-x86_64"),
                "{text}"
            );
        }
        // Pinned for another target: not pinned for this one.
        let linux = Target::parse("linux-x86_64").unwrap();
        assert!(
            pin_report(
                &state,
                linux,
                &[given("--runtime", BinaryKind::Runtime, runtime)],
                true
            )
            .is_err()
        );
        // Without the flag the same binaries pass, as local builds.
        let lines = pin_report(
            &PinState::NoKey,
            win,
            &[given("--runtime", BinaryKind::Runtime, runtime)],
            false,
        )
        .unwrap();
        assert_eq!(lines, ["binary: --runtime is a local build"]);
    }
}
