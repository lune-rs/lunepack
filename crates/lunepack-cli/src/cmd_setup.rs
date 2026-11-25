//! `setup` (M6 step 7, M7 step 12, M8 step 9): builds a Linux or Windows setup file, a macOS
//! installer `.dmg` or a macOS `.zip` from a release directory (FORMAT.md 14).
//!
//! The file is the release's own runtime, then the payload (the key set, the manifest and the pack
//! of one version and target, each starting 8-byte aligned), then the trailer. Run, the runtime
//! finds the trailer at its own end and installs exactly that version with no network (M6-D4).
//!
//! Everything is verified the way the runtime will before a byte is written: the key set under the
//! release directory's trust chain, the manifest with no feed (release keys valid at the reader's
//! clock), the pack against the manifest; the runtime and the update config come from the pack
//! through their signed frames (FORMAT.md 13.6), and the trailer carries the root the config names.
//! The written file is then parsed back and verified as the runtime parses it. The output is a
//! function of the release directory only (no time, no name; a Windows setup file also depends on its
//! output file name, which the stamped runtime carries as `OriginalFilename`), so two runs with the
//! same inputs give the same bytes.
//!
//! A Windows setup file (M7-D1, M7-D11) is built the same way, with the runtime copy prepared first:
//! its Authenticode certificate table (when the pack's runtime carries one) is stripped, it is
//! stamped with the app's icon and version info (M7-D14), the stamped bytes are checked again as a
//! Windows runtime, and nothing follows the trailer. The self-check reads the file back through the
//! trailer locator the runtime uses. The stamp also writes an anchor placeholder resource (M10-D4);
//! once the payload and trailer are placed, the placeholder is overwritten in place with the
//! digests of the trailer block, the key set and the manifest (no length or offset changes), and
//! the read-back verifies the signed file against the anchor read from its own image.
//!
//! A macOS target has no setup file (M8-D7). `setup` builds `Install <name>.app` from the release's
//! own frames: its UI and its runtime (each read through its signed frame), a generated
//! `Info.plist`, the optional icon, and `lunepack-setup.payload` (the payload and trailer of a
//! setup file without the runtime part); `hdiutil` then writes it into an LZMA `.dmg` (macOS host
//! only). A release that holds the update service also gets the all-users `.pkg` (M11-D8,
//! [`crate::pkg`]): built, signed, notarized and stapled first, embedded in the app before the
//! app is signed, and written beside the image. `--zip` instead writes the bundle exactly as released into a `.zip` (any host, M8-D9):
//! every file is read through its signed frame, so nothing comes from an unverified byte.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::layout::{MachineOs, service_path_in_tree_for};
use lunepack_core::pe;
use lunepack_core::setup::{
    ANCHOR_RESOURCE_ID, ANCHOR_SIZE, Located, MAX_SETUP_RUNTIME_BYTES, PART_ALIGN, SetupAnchor,
    SetupPart, SetupTrailer, TRAILER_SIZE, locate_file, verify_setup, verify_setup_anchored,
};
use lunepack_core::update_config::{MACOS_HELPER_ICON, MACOS_HELPER_UI};
use lunepack_core::{
    AppId, Clock, ClockReading, FsError, FsErrorKind, Limits, ReadAt, RelPath, Target, TrustedRoot,
    VerifiedEntry, VerifiedManifest, Version, check_runtime_image, macos_name_ok, read_entry,
    verify_payload_manifest, windows_name_ok,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use crate::codesign::{InstallerFile, OsCodeSign, installer_app_plan};
use crate::config::{CodeSignSection, Config, FixedClock};
use crate::dmg::{self, Hdiutil, InstallerApp};
use crate::pkg::{PkgSpec, PkgTools};
use crate::place;
use crate::plist;
use crate::release_dir::{self, read_capped};
use crate::stamp;
use crate::zip;

/// Largest UI binary read out of a pack (as `pack --ui`).
const MAX_UI_BYTES: u64 = 64 * 1024 * 1024;

/// Arguments of `setup`.
#[derive(Args)]
pub struct SetupArgs {
    /// The release directory.
    dir: PathBuf,
    /// The version to install (the text as written in the release).
    #[arg(long)]
    version: String,
    /// The target (`linux-*`, `windows-*` or `macos-*`).
    #[arg(long)]
    target: String,
    /// Where to write the output (default: `<app_id>-<version>-<target>-setup`, with `.exe` for a
    /// Windows target, or `<app_id>-<version>-<target>.dmg` or `.zip` for a macOS target, in the
    /// current directory). An existing file is not replaced. A macOS `.dmg` of a release with the
    /// update service is accompanied by its all-users `.pkg`, written beside it with the same name
    /// and the extension `.pkg`.
    #[arg(long)]
    out: Option<PathBuf>,
    /// For a `macos-*` target: write the bundle as a `.zip` (any host) instead of the installer
    /// `.dmg` (a macOS host).
    #[arg(long)]
    zip: bool,
    /// Verify at this Unix time instead of the system clock.
    #[arg(long)]
    at: Option<u64>,
}

/// Bytes in memory, read as a file.
struct Bytes<'a>(&'a [u8]);

impl ReadAt for Bytes<'_> {
    fn size(&self) -> Result<u64, FsError> {
        Ok(self.0.len() as u64)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        match start
            .checked_add(buf.len())
            .and_then(|end| self.0.get(start..end))
        {
            Some(src) => {
                buf.copy_from_slice(src);
                Ok(())
            }
            None => Err(FsError::new(
                FsErrorKind::Other,
                Path::new("setup"),
                Some(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            )),
        }
    }
}

/// Appends zero bytes until `out`'s length is a multiple of [`PART_ALIGN`].
fn align(out: &mut Vec<u8>) {
    while !(out.len() as u64).is_multiple_of(PART_ALIGN) {
        out.push(0);
    }
}

/// Appends `bytes` at the next aligned offset and returns where they went.
fn place(out: &mut Vec<u8>, bytes: &[u8]) -> SetupPart {
    align(out);
    let part = SetupPart {
        offset: out.len() as u64,
        length: bytes.len() as u64,
    };
    out.extend_from_slice(bytes);
    part
}

/// The file name `setup` writes by default: a setup file for Linux and Windows, the installer
/// `.dmg` (or, with `zip`, the `.zip`) for macOS.
fn default_name(app_id: &str, version: &str, target: &str, zip: bool) -> String {
    let parsed = Target::parse(target).ok();
    if parsed.is_some_and(Target::is_macos) {
        let ext = if zip { "zip" } else { "dmg" };
        return format!("{app_id}-{version}-{target}.{ext}");
    }
    let exe = if parsed.is_some_and(Target::is_windows) {
        ".exe"
    } else {
        ""
    };
    format!("{app_id}-{version}-{target}-setup{exe}")
}

/// The Windows runtime copy of a setup file (M7-D1, M7-D14): the certificate table stripped,
/// stamped as the setup variant (`<name> Setup`, the file's own name as `OriginalFilename`) with
/// [`SetupAnchor::PLACEHOLDER`] as its anchor resource (M10-D4) in the same rewrite, and checked
/// again as a Windows runtime so the stamped bytes are what the packager would accept. After this
/// the image's length and layout are final: the anchor is later patched in place, never restamped.
fn windows_runtime(
    runtime: &[u8],
    update: &lunepack_core::UpdateConfig,
    file_name: &str,
    icon: Option<&[u8]>,
    target: Target,
) -> Result<Vec<u8>> {
    let install = &update.install;
    if let Err(rule) = windows_name_ok(&install.name) {
        bail!("[install] name: not a valid Windows folder and shortcut name: {rule}");
    }
    let unsigned = stamp::strip_certificate_table(runtime)?;
    let description = format!("{} Setup", install.name);
    let version_text = update.version.to_string();
    let fields = stamp::Fields {
        description: &description,
        product: &install.name,
        company: install.publisher.as_deref(),
        version_text: &version_text,
        numbers: stamp::version_numbers(&update.version)?,
        original_filename: file_name,
        icon,
    };
    let stamped = stamp::stamp_with_rcdata(
        &unsigned,
        &fields,
        ANCHOR_RESOURCE_ID,
        &SetupAnchor::PLACEHOLDER,
    )
    .context("the setup runtime cannot be stamped")?;
    check_runtime_image(&stamped, target).map_err(|e| {
        anyhow::anyhow!(
            "the stamped setup runtime is not a runtime for {}: {e}",
            target.as_str()
        )
    })?;
    Ok(stamped)
}

/// A release read and verified up to its pack: what every output of `setup` is built from.
struct Loaded {
    target: Target,
    version: Version,
    reading: ClockReading,
    keys_bytes: Vec<u8>,
    manifest_bytes: Vec<u8>,
    manifest: VerifiedManifest,
    pack: Vec<u8>,
    update: lunepack_core::UpdateConfig,
    root: TrustedRoot,
}

impl Loaded {
    /// One file entry of the release, out of its signed frame (FORMAT.md 13.6).
    fn read(&self, path: &RelPath, max: u64) -> Result<Vec<u8>> {
        Ok(read_entry(
            &self.manifest,
            path,
            &Bytes(&self.pack),
            &LzmaCodec,
            &Sha256Hasher,
            max,
        )?)
    }

    /// The runtime this release ships, beside its entry.
    fn runtime(&self) -> Result<Vec<u8>> {
        let partial = lunepack_core::setup::VerifiedSetup {
            manifest: self.manifest.clone(),
            config: self.update.clone(),
        };
        self.read(&partial.runtime_path()?, MAX_SETUP_RUNTIME_BYTES)
            .context("the release has no runtime beside its entry (pack it with --runtime)")
    }

    /// Appends the payload parts (each 8-aligned) and the zero bytes up to the trailer to `out`,
    /// and returns the trailer that names them (not yet appended).
    fn place_payload(&self, out: &mut Vec<u8>) -> SetupTrailer {
        let keys = place(out, &self.keys_bytes);
        let manifest = place(out, &self.manifest_bytes);
        let pack = place(out, &self.pack);
        // The trailer starts 8-aligned, so the file's length is a multiple of 8 (the trailer's size
        // is): signtool zero-pads to 8 before the certificate table, and that padding must be none
        // or the trailer is no longer the last bytes the table follows (FORMAT.md 14).
        align(out);
        SetupTrailer {
            root: self.root.clone(),
            version: self.version.clone(),
            target: self.target,
            keys,
            manifest,
            pack,
        }
    }
}

/// Reads the release `version` for `target_text` in `dir` and verifies it as the runtime will,
/// before a byte is written: the root walk and key set, the manifest with no feed, the pack against
/// the manifest, then the update config out of its signed frame.
fn load(
    dir: &Path,
    config: &Config,
    version: &str,
    target_text: &str,
    clock: &dyn Clock,
) -> Result<Loaded> {
    let (hasher, verifier, codec) = (Sha256Hasher, Ed25519Verifier, LzmaCodec);
    let target = Target::parse(target_text)
        .with_context(|| format!("--target {target_text:?} is not a target id"))?;
    let version_text = version;
    let version = Version::parse(version_text)
        .with_context(|| format!("--version {version_text:?} is not a version"))?;
    if version.to_string() != version_text {
        bail!("--version {version_text:?} is not written in its canonical form");
    }
    let reading = ClockReading::read(clock, None);

    let opened = release_dir::open(dir, config, &hasher, &verifier, &reading)?;
    let keys = opened
        .keys()
        .cloned()
        .context("the release directory has no keys.json")?;
    let keys_path = release_dir::keys_path(dir);
    let keys_bytes =
        read_capped(&keys_path, Limits::V1.keys_doc_bytes)?.context("keys.json does not exist")?;
    let manifest_rel = format!("{version_text}/{}.manifest.json", target.as_str());
    let manifest_bytes = read_capped(&dir.join(&manifest_rel), Limits::V1.manifest_doc_bytes)?
        .with_context(|| format!("{manifest_rel} does not exist"))?;
    let manifest = verify_payload_manifest(
        &keys,
        (&version, target),
        &manifest_bytes,
        reading.now(),
        &hasher,
        &verifier,
    )
    .with_context(|| format!("{manifest_rel} does not verify"))?;
    let pack_ref = manifest.pack();
    let pack = read_capped(&dir.join(pack_ref.path()), pack_ref.size())?
        .with_context(|| format!("{} does not exist", pack_ref.path()))?;
    pack_ref
        .check_bytes(&pack, &hasher)
        .with_context(|| format!("{} does not match the manifest", pack_ref.path()))?;

    // The config, out of its signed frame.
    let config_at =
        lunepack_core::RelPath::parse(lunepack_core::update_config::config_path(target))?;
    let config_bytes = read_entry(
        &manifest,
        &config_at,
        &Bytes(&pack),
        &codec,
        &hasher,
        lunepack_core::update_config::MAX_UPDATE_CONFIG_BYTES,
    )
    .context("the release has no update config (pack it with [update])")?;
    let update = lunepack_core::UpdateConfig::parse(&config_bytes)
        .context("the release's update config does not parse")?;
    if update.app_id != config.app_id {
        bail!("the release's update config names another app id than the config");
    }
    let root = update
        .root
        .to_trusted(update.app_id.clone(), &hasher, &verifier)
        .context("the release's update config names an invalid root")?;
    Ok(Loaded {
        target,
        version,
        reading,
        keys_bytes,
        manifest_bytes,
        manifest,
        pack,
        update,
        root,
    })
}

/// The bytes of the setup file of `version` for `target` in the release directory `dir`, verified.
/// `file_name` is the name the file will have (a Windows setup file carries it as its
/// `OriginalFilename`).
pub fn build(
    dir: &Path,
    config: &Config,
    version: &str,
    target: &str,
    clock: &dyn Clock,
    file_name: &str,
) -> Result<Vec<u8>> {
    let (hasher, verifier, codec) = (Sha256Hasher, Ed25519Verifier, LzmaCodec);
    let loaded = load(dir, config, version, target, clock)?;
    // OS signing of the finished file (M9-D2, M9-D5), for a Windows target with `[codesign.windows]`.
    let section = config.codesign_for(loaded.target);
    let target = loaded.target;
    if !matches!(
        target,
        Target::LinuxX86_64 | Target::LinuxAarch64 | Target::WindowsX86_64 | Target::WindowsAarch64
    ) {
        bail!("setup files are built for Linux and Windows targets only in this release");
    }
    // The runtime this release ships, beside its entry.
    let runtime = loaded.runtime()?;
    let runtime = if target.is_windows() {
        let icon = crate::cmd_pack::pick_icon(config, &loaded.update.install, |icon| {
            read_entry(
                &loaded.manifest,
                icon,
                &Bytes(&loaded.pack),
                &codec,
                &hasher,
                stamp::MAX_ICON_BYTES,
            )
            .context("the release has no readable install.icon")
        })?;
        windows_runtime(&runtime, &loaded.update, file_name, icon.as_deref(), target)?
    } else {
        runtime
    };

    let runtime_len = runtime.len();
    let mut out = runtime;
    let trailer = loaded.place_payload(&mut out);
    let trailer_block = trailer.encode()?;
    out.extend_from_slice(&trailer_block);

    // A Windows setup's anchor (M10-D4): the digests of the trailer block as written and of the
    // key-set and manifest parts, patched over the placeholder the stamp wrote. The patch changes
    // no length and no byte outside the anchor's span, so every offset in the trailer stays right.
    let anchor = if target.is_windows() {
        let anchor = SetupAnchor::of(
            &trailer_block,
            &loaded.keys_bytes,
            &loaded.manifest_bytes,
            &hasher,
        );
        patch_anchor(&mut out, runtime_len, &anchor)?;
        let tail = &out[out.len() - TRAILER_SIZE as usize..];
        let reread = SetupTrailer::parse(tail, out.len() as u64, &hasher, &verifier)
            .context("internal error: the trailer does not parse after the anchor patch")?;
        if reread != trailer {
            bail!("internal error: the trailer reads back differently after the anchor patch");
        }
        Some(anchor)
    } else {
        None
    };

    // Signed after the file is complete, and read back below as signed: the setup data ends where
    // the unsigned file ended, and the certificate table follows (M7-D11).
    let unsigned_len = out.len() as u64;
    if let Some(section) = section {
        out = sign_setup_file(section, &out, file_name)?;
    }

    // Read back as the runtime reads it: the locator finds the end of the setup data (a setup file,
    // never an ordinary file or a malformed one), the trailer is the bytes before it, then the
    // payload under it.
    let end = match locate_file(&Bytes(&out)).context("internal error: the locator cannot read")? {
        Located::Setup { end } if end == unsigned_len => end,
        _ => bail!(
            "the finished setup file is not read back as a setup file{}",
            if section.is_some() {
                " (did the signing tool change the file beyond adding its signature?)"
            } else {
                ""
            }
        ),
    };
    let tail = &out[(end - TRAILER_SIZE) as usize..end as usize];
    let parsed = SetupTrailer::parse(tail, end, &hasher, &verifier)
        .context("internal error: the written trailer does not parse")?;
    if parsed != trailer {
        bail!("internal error: the written trailer reads back differently");
    }
    verify_setup(
        &parsed,
        &Bytes(&out),
        &loaded.reading,
        &codec,
        &hasher,
        &verifier,
    )
    .context(
        "the setup does not verify as the runtime checks it (is keys.json signed under the root \
         the release's update config names?)",
    )?;
    if let Some(expected) = anchor {
        // The anchor as a started Setup.exe reads it: from its image's resource, of the signed file.
        let read = read_anchor(&out)?;
        if read != expected {
            bail!("internal error: the setup file's anchor reads back differently");
        }
        verify_setup_anchored(
            &read,
            tail,
            &Bytes(&out),
            end,
            &loaded.reading,
            &codec,
            &hasher,
            &verifier,
        )
        .context("the finished setup file does not verify against its own anchor")?;
    }
    Ok(out)
}

/// Overwrites the anchor placeholder in the runtime image (the first `runtime_len` bytes of
/// `out`) with `anchor`. The resource must be exactly [`ANCHOR_SIZE`] bytes holding the
/// placeholder, and afterwards `out` has the same length and differs only inside that span; any
/// other outcome fails the build.
fn patch_anchor(out: &mut [u8], runtime_len: usize, anchor: &SetupAnchor) -> Result<()> {
    let image = out
        .get(..runtime_len)
        .context("internal error: the runtime image is longer than the file")?;
    let span = pe::rcdata(image, ANCHOR_RESOURCE_ID)
        .map_err(|e| anyhow::anyhow!("internal error: the setup runtime's resources: {e}"))?
        .context("internal error: the setup runtime has no anchor resource")?;
    let start = usize::try_from(span.file_offset).unwrap_or(usize::MAX);
    if span.len as usize != ANCHOR_SIZE
        || start
            .checked_add(ANCHOR_SIZE)
            .is_none_or(|e| e > runtime_len)
        || out[start..start + ANCHOR_SIZE] != SetupAnchor::PLACEHOLDER
    {
        bail!("internal error: the setup runtime's anchor resource is not the placeholder");
    }
    let before = out.to_vec();
    out[start..start + ANCHOR_SIZE].copy_from_slice(&anchor.encode());
    if out.len() != before.len()
        || out[..start] != before[..start]
        || out[start + ANCHOR_SIZE..] != before[start + ANCHOR_SIZE..]
    {
        bail!("internal error: the anchor patch changed bytes outside the anchor");
    }
    Ok(())
}

/// The anchor of a Windows setup file `bytes`, read through its image's `RT_RCDATA` resource.
fn read_anchor(bytes: &[u8]) -> Result<SetupAnchor> {
    let span = pe::rcdata(bytes, ANCHOR_RESOURCE_ID)
        .map_err(|e| anyhow::anyhow!("the finished setup file's resources: {e}"))?
        .context("the finished setup file has no anchor resource")?;
    let start = usize::try_from(span.file_offset).unwrap_or(usize::MAX);
    let raw = start
        .checked_add(span.len as usize)
        .and_then(|e| bytes.get(start..e))
        .context("the finished setup file's anchor lies outside it")?;
    SetupAnchor::parse(raw).context("the finished setup file's anchor")
}

/// Signs the finished Windows setup file `bytes` with `sign_installer` (M9-D5) in a scratch
/// directory under the system temp dir, and returns the signed bytes. The file keeps its final
/// name (a signing tool may show it). The scratch directory is removed on every path.
fn sign_setup_file(section: &CodeSignSection, bytes: &[u8], file_name: &str) -> Result<Vec<u8>> {
    let scratch = tempfile::Builder::new()
        .prefix(place::TMP_PREFIX)
        .tempdir()
        .context("cannot create a scratch directory for the signing tool")?;
    let name = if file_name.is_empty() {
        "setup.exe"
    } else {
        file_name
    };
    let at = scratch.path().join(name);
    fs::write(&at, bytes).with_context(|| format!("cannot write {}", at.display()))?;
    let signer =
        OsCodeSign::for_installer(section.clone(), name.to_owned(), scratch.path().to_owned());
    signer.sign_installer_file(&at, InstallerFile::SetupExe, name)?;
    fs::read(&at).with_context(|| format!("cannot read {}", at.display()))
}

/// The stem of the bundle's file name (M8-D1's rule, as the runtime applies it at the first
/// install): `install.name` when it can be a bundle name, else the app id.
pub(crate) fn bundle_stem<'a>(name: &'a str, app_id: &'a AppId) -> &'a str {
    if macos_name_ok(name).is_ok() {
        name
    } else {
        app_id.as_str()
    }
}

/// The macOS installer's payload file (M8-D7): the payload parts from offset 0 and the trailer,
/// read back as the installer's runtime reads it.
fn macos_payload(loaded: &Loaded) -> Result<Vec<u8>> {
    let (hasher, verifier) = (Sha256Hasher, Ed25519Verifier);
    let mut out = Vec::new();
    let trailer = loaded.place_payload(&mut out);
    out.extend_from_slice(&trailer.encode()?);
    let parsed = lunepack_core::setup::parse_payload_file(&Bytes(&out), &hasher, &verifier)
        .context("internal error: the written payload file does not parse")?;
    if parsed != trailer {
        bail!("internal error: the written trailer reads back differently");
    }
    verify_setup(
        &parsed,
        &Bytes(&out),
        &loaded.reading,
        &LzmaCodec,
        &hasher,
        &verifier,
    )
    .context(
        "the payload does not verify as the installer checks it (is keys.json signed under the \
         root the release's update config names?)",
    )?;
    Ok(out)
}

/// What the installer app is made of besides the payload, read through the release's signed
/// frames.
struct InstallerParts {
    dir_name: String,
    ui: Vec<u8>,
    runtime: Vec<u8>,
    plist: Vec<u8>,
    icon: Option<Vec<u8>>,
}

fn installer_parts(loaded: &Loaded) -> Result<InstallerParts> {
    let install = &loaded.update.install;
    let has_file = |at: &RelPath| {
        loaded
            .manifest
            .entries()
            .iter()
            .any(|e| matches!(e, VerifiedEntry::File { path, .. } if path == at))
    };
    let ui_at = RelPath::parse(MACOS_HELPER_UI)?;
    if !has_file(&ui_at) {
        bail!(
            "the release has no UI (pack it with --ui, or use --zip): the installer app's \
             executable is the release's UI"
        );
    }
    let ui = loaded.read(&ui_at, MAX_UI_BYTES)?;
    let runtime = loaded.runtime()?;
    let icon_at = RelPath::parse(MACOS_HELPER_ICON)?;
    let icon = if has_file(&icon_at) {
        let bytes = loaded.read(&icon_at, plist::MAX_ICNS_BYTES)?;
        plist::check_icns(&bytes).map_err(|e| {
            anyhow::anyhow!("the release's installer icon is not an .icns file: {e}")
        })?;
        Some(bytes)
    } else {
        None
    };
    let plist = plist::installer_info_plist(
        &loaded.update.app_id,
        &install.name,
        icon.as_ref().map(|_| dmg::ICON_NAME),
    )?;
    let stem = bundle_stem(&install.name, &loaded.update.app_id);
    Ok(InstallerParts {
        dir_name: format!("Install {stem}.app"),
        ui,
        runtime,
        plist,
        icon,
    })
}

/// Whether the release holds the update service (M11-D6): a non-empty file of the target's service
/// name beside the entry, as the engine looks for it at an all-users install.
fn has_service(loaded: &Loaded) -> bool {
    let Some(at) = service_path_in_tree_for(
        &loaded.update.install.entry,
        MachineOs::of_target(loaded.target),
    ) else {
        return false;
    };
    loaded
        .manifest
        .entries()
        .iter()
        .any(|e| matches!(e, VerifiedEntry::File { path, size, .. } if *path == at && *size > 0))
}

/// What `setup` wrote for a macOS installer: the image, and the all-users package beside it.
struct Written {
    image_size: u64,
    pkg: Option<(PathBuf, u64)>,
}

/// Builds the all-users `.pkg` (M11-D8) in `scratch` and returns its bytes. In the order M11
/// step 7 fixes: built, then signed, notarized and stapled (when configured), all before the
/// caller embeds it. `shown` names the finished file in signing lines and errors.
fn build_pkg(
    loaded: &Loaded,
    parts: &InstallerParts,
    payload: &[u8],
    scratch: &Path,
    signer: Option<&OsCodeSign>,
    shown: &str,
) -> Result<(PathBuf, Vec<u8>)> {
    let version = loaded.version.to_string();
    let spec = PkgSpec {
        app_id: &loaded.update.app_id,
        version: &version,
        title: &loaded.update.install.name,
        min_os: plist::MIN_SYSTEM_VERSION,
        runtime: &parts.runtime,
        payload,
    };
    let work = scratch.join("pkg-work");
    fs::create_dir(&work).with_context(|| format!("cannot create {}", work.display()))?;
    let at = scratch.join("installer.pkg");
    PkgTools::system().build(&spec, &work, &at)?;
    if let Some(signer) = signer {
        signer.sign_installer_file(&at, InstallerFile::Pkg, shown)?;
    }
    let bytes = fs::read(&at).with_context(|| format!("cannot read {}", at.display()))?;
    Ok((at, bytes))
}

/// Writes the installer `.dmg` of the release to `out` (M8-D7, M8-D9): the installer app built in a
/// scratch directory next to `out`, `hdiutil create` and `hdiutil verify`, then the image moved to
/// `out` without replacing anything. A release that holds the update service also gets its
/// all-users `.pkg` (M11-D8), embedded in the app and written beside `out`. Returns what was
/// written.
fn write_dmg(loaded: &Loaded, out: &Path, section: Option<&CodeSignSection>) -> Result<Written> {
    if fs::symlink_metadata(out).is_ok() {
        bail!("{} already exists", out.display());
    }
    let pkg_out = has_service(loaded).then(|| out.with_extension("pkg"));
    if let Some(at) = &pkg_out
        && fs::symlink_metadata(at).is_ok()
    {
        bail!("{} already exists", at.display());
    }
    let payload = macos_payload(loaded)?;
    let parts = installer_parts(loaded)?;
    let parent = match out.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    // Everything the run creates is under this one directory, removed on every path.
    let scratch = tempfile::Builder::new()
        .prefix(place::TMP_PREFIX)
        .tempdir_in(parent)
        .with_context(|| format!("cannot create a scratch directory in {}", parent.display()))?;
    let src = scratch.path().join("src");
    fs::create_dir(&src).with_context(|| format!("cannot create {}", src.display()))?;
    let signer = section.map(|section| {
        OsCodeSign::for_installer(
            section.clone(),
            parts.dir_name.clone(),
            scratch.path().to_owned(),
        )
    });
    // M11 step 7, in this order: the package built, signed, notarized and stapled; embedded in the
    // app; then M9-D5's order: the app's items, the app, then (when configured) its notarization
    // and staple; only then is the image built, signed, notarized and stapled.
    let pkg = match &pkg_out {
        Some(at) => {
            let shown = at.file_name().map_or_else(
                || "installer.pkg".to_owned(),
                |n| n.to_string_lossy().into_owned(),
            );
            Some(build_pkg(
                loaded,
                &parts,
                &payload,
                scratch.path(),
                signer.as_ref(),
                &shown,
            )?)
        }
        None => None,
    };
    dmg::write_app(
        &src,
        &InstallerApp {
            dir_name: &parts.dir_name,
            ui: &parts.ui,
            runtime: &parts.runtime,
            plist: &parts.plist,
            payload: &payload,
            icon: parts.icon.as_deref(),
            all_users_pkg: pkg.as_ref().map(|(_, bytes)| bytes.as_slice()),
        },
    )?;
    if let Some(signer) = &signer {
        signer.run(&src.join(&parts.dir_name), &installer_app_plan())?;
    }
    let image = scratch.path().join("installer.dmg");
    let hdiutil = Hdiutil::system();
    let volume = dmg::volume_name(&loaded.update.install.name);
    hdiutil.create(&volume, &src, &image, scratch.path())?;
    hdiutil.verify(&image, scratch.path())?;
    if let Some(signer) = &signer {
        let shown = out.file_name().map_or_else(
            || "installer.dmg".to_owned(),
            |n| n.to_string_lossy().into_owned(),
        );
        signer.sign_installer_file(&image, InstallerFile::Dmg, &shown)?;
    }
    let image_size = fs::metadata(&image)
        .with_context(|| format!("cannot read {}", image.display()))?
        .len();
    place::move_new(&image, out)?;
    // The standalone package is the file that was embedded. If it cannot be placed, the image just
    // placed (this run's own file) is removed so that a failed run leaves nothing.
    let pkg = match (pkg, pkg_out) {
        (Some((built, bytes)), Some(at)) => {
            if let Err(e) = place::move_new(&built, &at) {
                let _ = fs::remove_file(out);
                return Err(e);
            }
            Some((at, bytes.len() as u64))
        }
        _ => None,
    };
    Ok(Written { image_size, pkg })
}

/// Writes the bundle of the release to `out` as a `.zip` (M8-D9) and returns its size. Every
/// file is read through its signed frame; the entries are sorted by path; nothing but the
/// manifest decides a mode (executable or not) or a link's text.
fn write_zip(loaded: &Loaded, out: &Path) -> Result<u64> {
    if fs::symlink_metadata(out).is_ok() {
        bail!("{} already exists", out.display());
    }
    let install = &loaded.update.install;
    let bundle = format!("{}.app", bundle_stem(&install.name, &loaded.update.app_id));

    // Every entry by path, and every parent directory the manifest leaves implicit.
    let mut dirs = std::collections::BTreeSet::new();
    let mut items: BTreeMap<&str, &VerifiedEntry> = BTreeMap::new();
    for entry in loaded.manifest.entries() {
        let path = entry.path().as_str();
        if matches!(entry, VerifiedEntry::Dir { .. }) {
            dirs.insert(path.to_owned());
        } else {
            items.insert(path, entry);
        }
        let mut at = path;
        while let Some((parent, _)) = at.rsplit_once('/') {
            dirs.insert(parent.to_owned());
            at = parent;
        }
    }
    if let Some(clash) = items.keys().find(|p| dirs.contains(**p)) {
        bail!("{clash}: the release lists it as a file and as a directory");
    }

    let parent = match out.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let temp = tempfile::Builder::new()
        .prefix(place::TMP_PREFIX)
        .tempfile_in(parent)
        .with_context(|| format!("cannot create a file in {}", parent.display()))?;
    let mut writer = zip::Writer::new(BufWriter::new(temp));
    writer.add(&bundle, zip::Kind::Dir)?;
    // One ordered walk over directories and the other entries: byte order of the paths.
    let mut all: BTreeMap<&str, Option<&VerifiedEntry>> = BTreeMap::new();
    for d in &dirs {
        all.insert(d.as_str(), None);
    }
    for (path, entry) in &items {
        all.insert(path, Some(entry));
    }
    for (path, entry) in all {
        let name = format!("{bundle}/{path}");
        match entry {
            None | Some(VerifiedEntry::Dir { .. }) => writer.add(&name, zip::Kind::Dir)?,
            Some(VerifiedEntry::Symlink { target, .. }) => {
                writer.add(&name, zip::Kind::Symlink { target })?;
            }
            Some(VerifiedEntry::File {
                path: rel,
                size,
                exec,
                ..
            }) => {
                let data = loaded.read(rel, *size)?;
                writer.add(
                    &name,
                    zip::Kind::File {
                        data: &data,
                        exec: *exec,
                    },
                )?;
            }
        }
    }
    let mut buffered = writer.finish()?;
    buffered.flush().context("cannot write the zip")?;
    let temp = buffered
        .into_inner()
        .map_err(|e| anyhow::anyhow!("cannot write the zip: {e}"))?;
    temp.as_file().sync_all().context("cannot write the zip")?;
    let size = temp.as_file().metadata()?.len();
    temp.persist_noclobber(out).map_err(|e| {
        if e.error.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!("{} already exists", out.display())
        } else {
            anyhow::anyhow!("cannot place {}: {}", out.display(), e.error)
        }
    })?;
    Ok(size)
}

/// `lunepack setup`.
pub fn setup(config_path: &Path, args: &SetupArgs) -> Result<()> {
    let config = Config::load(config_path)?;
    let clock: Box<dyn Clock> = match args.at {
        Some(t) => Box::new(FixedClock(t)),
        None => Box::new(lunepack::SystemClock),
    };
    let out = match &args.out {
        Some(p) => p.clone(),
        None => PathBuf::from(default_name(
            config.app_id.as_str(),
            &args.version,
            &args.target,
            args.zip,
        )),
    };
    let file_name = out
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let is_macos = Target::parse(&args.target).is_ok_and(Target::is_macos);
    if args.zip && !is_macos {
        bail!("--zip is only for macos-* targets");
    }
    if is_macos {
        if !args.zip {
            if !cfg!(target_os = "macos") {
                bail!("a .dmg is built on a macOS host only (use --zip on this host)");
            }
            if out.extension().and_then(|e| e.to_str()) != Some("dmg") {
                bail!("--out: the installer image's file name must end in .dmg");
            }
        }
        let loaded = load(&args.dir, &config, &args.version, &args.target, &*clock)?;
        if args.zip {
            let size = write_zip(&loaded, &out)?;
            println!("setup: {file_name} ({size} bytes)");
        } else {
            let written = write_dmg(&loaded, &out, config.codesign_for(loaded.target))?;
            println!("setup: {file_name} ({} bytes)", written.image_size);
            if let Some((at, size)) = written.pkg {
                let name = at
                    .file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
                println!("setup: {name} ({size} bytes)");
            }
        }
        return Ok(());
    }
    let bytes = build(
        &args.dir,
        &config,
        &args.version,
        &args.target,
        &*clock,
        &file_name,
    )?;
    crate::place::write_new(&out, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("cannot make {} executable", out.display()))?;
    }
    println!(
        "setup: {} ({} bytes)",
        out.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        bytes.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::default_name;

    #[test]
    fn the_default_name_carries_exe_for_windows_targets_only() {
        assert_eq!(
            default_name("org.example.app", "1.2.3", "windows-x86_64", false),
            "org.example.app-1.2.3-windows-x86_64-setup.exe"
        );
        assert_eq!(
            default_name("org.example.app", "1.2.3", "windows-aarch64", false),
            "org.example.app-1.2.3-windows-aarch64-setup.exe"
        );
        assert_eq!(
            default_name("org.example.app", "1.2.3", "linux-x86_64", false),
            "org.example.app-1.2.3-linux-x86_64-setup"
        );
        assert_eq!(
            default_name("org.example.app", "1.2.3", "macos-aarch64", false),
            "org.example.app-1.2.3-macos-aarch64.dmg"
        );
        assert_eq!(
            default_name("org.example.app", "1.2.3", "macos-universal", true),
            "org.example.app-1.2.3-macos-universal.zip"
        );
    }
}
