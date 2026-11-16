//! `setup` (M6 step 7): builds a Linux setup file from a release directory (FORMAT.md 14).
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
//! function of the release directory only (no time, no name), so two runs give the same bytes.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::setup::{
    MAX_SETUP_RUNTIME_BYTES, PART_ALIGN, SetupPart, SetupTrailer, TRAILER_SIZE, verify_setup,
};
use lunepack_core::{
    Clock, ClockReading, FsError, FsErrorKind, Limits, ReadAt, Target, Version, read_entry,
    verify_payload_manifest,
};
use lunepack_crypto::{Ed25519Verifier, Sha256Hasher};

use crate::config::{Config, FixedClock};
use crate::release_dir::{self, read_capped};

/// Arguments of `setup`.
#[derive(Args)]
pub struct SetupArgs {
    /// The release directory.
    dir: PathBuf,
    /// The version to install (the text as written in the release).
    #[arg(long)]
    version: String,
    /// The target (Linux only in this release).
    #[arg(long)]
    target: String,
    /// Where to write the setup file (default: `<app_id>-<version>-<target>-setup` in the current
    /// directory). An existing file is not replaced.
    #[arg(long)]
    out: Option<PathBuf>,
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

/// The bytes of the setup file of `version` for `target` in the release directory `dir`, verified.
pub fn build(
    dir: &Path,
    config: &Config,
    version: &str,
    target: &str,
    clock: &dyn Clock,
) -> Result<Vec<u8>> {
    let (hasher, verifier, codec) = (Sha256Hasher, Ed25519Verifier, LzmaCodec);
    let target =
        Target::parse(target).with_context(|| format!("--target {target:?} is not a target id"))?;
    if !matches!(target, Target::LinuxX86_64 | Target::LinuxAarch64) {
        bail!("setup files are built for Linux targets only in this release");
    }
    let version_text = version;
    let version = Version::parse(version_text)
        .with_context(|| format!("--version {version_text:?} is not a version"))?;
    if version.to_string() != version_text {
        bail!("--version {version_text:?} is not written in its canonical form");
    }
    let reading = ClockReading::read(clock, None);

    let opened = release_dir::open(dir, config, &hasher, &verifier, &reading)?;
    let keys = opened
        .keys
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

    // The config and the runtime, out of their signed frames.
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

    let trailer = SetupTrailer {
        root,
        version: version.clone(),
        target,
        keys: SetupPart {
            offset: 0,
            length: 0,
        },
        manifest: SetupPart {
            offset: 0,
            length: 0,
        },
        pack: SetupPart {
            offset: 0,
            length: 0,
        },
    };
    // The runtime this release ships, beside its entry.
    let partial = lunepack_core::setup::VerifiedSetup {
        manifest: manifest.clone(),
        config: update,
    };
    let runtime_at = partial.runtime_path()?;
    let runtime = read_entry(
        &manifest,
        &runtime_at,
        &Bytes(&pack),
        &codec,
        &hasher,
        MAX_SETUP_RUNTIME_BYTES,
    )
    .context("the release has no runtime beside its entry (pack it with --runtime)")?;

    let mut out = runtime;
    let keys_part = place(&mut out, &keys_bytes);
    let manifest_part = place(&mut out, &manifest_bytes);
    let pack_part = place(&mut out, &pack);
    let trailer = SetupTrailer {
        keys: keys_part,
        manifest: manifest_part,
        pack: pack_part,
        ..trailer
    };
    out.extend_from_slice(&trailer.encode()?);

    // Read back as the runtime reads it: the trailer at the end, then the payload under it.
    let tail = &out[out.len() - TRAILER_SIZE as usize..];
    let parsed = SetupTrailer::parse(tail, out.len() as u64, &hasher, &verifier)
        .context("internal error: the written trailer does not parse")?;
    if parsed != trailer {
        bail!("internal error: the written trailer reads back differently");
    }
    verify_setup(&parsed, &Bytes(&out), &reading, &codec, &hasher, &verifier).context(
        "the setup does not verify as the runtime checks it (is keys.json signed under the root \
         the release's update config names?)",
    )?;
    Ok(out)
}

/// `lunepack setup`.
pub fn setup(config_path: &Path, args: &SetupArgs) -> Result<()> {
    let config = Config::load(config_path)?;
    let clock: Box<dyn Clock> = match args.at {
        Some(t) => Box::new(FixedClock(t)),
        None => Box::new(lunepack::SystemClock),
    };
    let bytes = build(&args.dir, &config, &args.version, &args.target, &*clock)?;
    let out = match &args.out {
        Some(p) => p.clone(),
        None => PathBuf::from(format!(
            "{}-{}-{}-setup",
            config.app_id.as_str(),
            args.version,
            args.target
        )),
    };
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
