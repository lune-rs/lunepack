//! The setup file's trailer (FORMAT.md 14): a Linux setup file is the release's runtime, then the
//! payload (the key set, the manifest and the pack, each starting 8-byte aligned), then this
//! trailer, [`TRAILER_SIZE`] bytes at the very end of the file.
//!
//! The trailer is a body area followed by a fixed footer:
//!
//! - the body: canonical compact JSON `{"app_id","root":{"keys","threshold","version"},"target",
//!   "version"}` (members in byte order, the root as the update config writes it, FORMAT.md 13.2),
//!   then zero bytes up to the footer;
//! - the footer ([`FOOTER_SIZE`] bytes, little-endian): `format` (u32, 1), the body's length (u32),
//!   8 reserved zero bytes, then offset and length (u64 each) of the key set, the manifest and the
//!   pack, then the 16-byte [`TRAILER_MAGIC`] as the file's last bytes.
//!
//! A reader that finds the magic parses the rest fail-closed ([`SetupTrailer::parse`]); nothing in
//! the trailer is trusted beyond its shape: the root is the trust anchor the setup was built with,
//! and every part is verified against it before use (M6-D4).

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::fs::{FsError, FsErrorKind, ReadAt};
use crate::ident::AppId;
use crate::keyset::verify_key_set;
use crate::limits::Limits;
use crate::manifest::{VerifiedManifest, read_entry, verify_payload_manifest};
use crate::path::RelPath;
use crate::root::TrustedRoot;
use crate::state::RootParts;
use crate::target::Target;
use crate::traits::{Codec, Hasher, Verifier};
use crate::trust::{ClockReading, RollbackFloor};
use crate::update_config::{
    MAX_UPDATE_CONFIG_BYTES, UpdateConfig, config_path, runtime_file, ui_file,
};
use crate::version::Version;

/// The trailer's size: the last bytes of every setup file.
pub const TRAILER_SIZE: u64 = 4096;
/// The footer's size, at the end of the trailer.
pub const FOOTER_SIZE: usize = 80;
/// The last 16 bytes of a setup file.
pub const TRAILER_MAGIC: [u8; 16] = *b"\x89LUNEPACKSETUP\r\n";
/// The trailer format this build writes and reads.
pub const TRAILER_FORMAT: u32 = 1;
/// The alignment of every payload part's offset.
pub const PART_ALIGN: u64 = 8;

/// The largest runtime a setup file takes from its pack (the packager's `--runtime` cap).
pub const MAX_SETUP_RUNTIME_BYTES: u64 = 256 * 1024 * 1024;
/// The largest UI a setup takes from its pack (the packager's `--ui` cap).
pub const MAX_SETUP_UI_BYTES: u64 = 64 * 1024 * 1024;

/// The read size when the pack is hashed.
const PACK_READ: u64 = 256 * 1024;

const BODY_CAP: usize = TRAILER_SIZE as usize - FOOTER_SIZE;

/// One part of the payload: `length` bytes at `offset` of the setup file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupPart {
    /// Where the part starts in the file.
    pub offset: u64,
    /// Its length in bytes.
    pub length: u64,
}

impl SetupPart {
    fn end(self) -> Option<u64> {
        self.offset.checked_add(self.length)
    }
}

/// A setup file's trailer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupTrailer {
    /// The root the payload is verified under; its app id is the app's.
    pub root: TrustedRoot,
    /// The version the payload installs.
    pub version: Version,
    /// The target the payload is for.
    pub target: Target,
    /// The key set (`keys.json`).
    pub keys: SetupPart,
    /// The manifest.
    pub manifest: SetupPart,
    /// The pack.
    pub pack: SetupPart,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyIn {
    app_id: String,
    root: RootParts,
    target: String,
    version: String,
}

fn malformed(what: &'static str) -> Error {
    Error::Field(what)
}

/// Whether `tail` (the last bytes of a file, at least the magic's length) ends with the magic.
pub fn has_magic(tail: &[u8]) -> bool {
    tail.len() >= TRAILER_MAGIC.len() && tail[tail.len() - TRAILER_MAGIC.len()..] == TRAILER_MAGIC
}

fn body_bytes(root: &TrustedRoot, version: &Version, target: Target) -> Vec<u8> {
    let parts = RootParts::from_trusted(root);
    // Members inserted in byte order, so the text is the same with or without an
    // order-preserving map.
    let mut root_obj = Map::new();
    root_obj.insert(
        "keys".to_owned(),
        Value::Array(
            parts
                .keys
                .iter()
                .map(|k| Value::String(k.to_hex()))
                .collect(),
        ),
    );
    root_obj.insert("threshold".to_owned(), Value::from(parts.threshold));
    root_obj.insert("version".to_owned(), Value::from(parts.version));
    let mut top = Map::new();
    top.insert(
        "app_id".to_owned(),
        Value::String(root.app_id().as_str().to_owned()),
    );
    top.insert("root".to_owned(), Value::Object(root_obj));
    top.insert(
        "target".to_owned(),
        Value::String(target.as_str().to_owned()),
    );
    top.insert("version".to_owned(), Value::String(version.to_string()));
    // Strings, integers and arrays of strings cannot fail to serialise.
    serde_json::to_vec(&Value::Object(top)).unwrap_or_default()
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(b)
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(b)
}

impl SetupTrailer {
    /// The trailer's bytes, exactly [`TRAILER_SIZE`] of them. Fails when the body does not fit.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let body = body_bytes(&self.root, &self.version, self.target);
        if body.len() > BODY_CAP {
            return Err(Error::TooLarge {
                what: "setup trailer body",
                size: body.len() as u64,
                cap: BODY_CAP as u64,
            });
        }
        let mut out = body.clone();
        out.resize(BODY_CAP, 0);
        out.extend_from_slice(&TRAILER_FORMAT.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0u8; 8]);
        for part in [self.keys, self.manifest, self.pack] {
            out.extend_from_slice(&part.offset.to_le_bytes());
            out.extend_from_slice(&part.length.to_le_bytes());
        }
        out.extend_from_slice(&TRAILER_MAGIC);
        debug_assert_eq!(out.len() as u64, TRAILER_SIZE);
        Ok(out)
    }

    /// Parses the last [`TRAILER_SIZE`] bytes of a file of `file_size` bytes whose tail carries
    /// the magic ([`has_magic`]), fail-closed and in this order:
    ///
    /// 1. exactly [`TRAILER_SIZE`] bytes and the magic; `format` 1 (another is
    ///    [`Error::FormatVersion`]); the reserved bytes zero;
    /// 2. the body's length within the body area, every byte after it zero; the body strict JSON
    ///    with exactly its four members, canonical (re-encoding gives the same bytes), the root a
    ///    valid trusted root of the app id, the version and target valid;
    /// 3. every part non-empty, aligned to [`PART_ALIGN`], inside the file and ending before the
    ///    trailer, the key set and the manifest within their document caps (FORMAT.md 4), and no
    ///    two parts overlapping.
    pub fn parse(
        tail: &[u8],
        file_size: u64,
        hasher: &dyn Hasher,
        verifier: &dyn Verifier,
    ) -> Result<SetupTrailer> {
        if tail.len() as u64 != TRAILER_SIZE || !has_magic(tail) || file_size < TRAILER_SIZE {
            return Err(malformed("setup trailer: not a trailer"));
        }
        let footer = &tail[BODY_CAP..];
        let format = u32_at(footer, 0);
        if format != TRAILER_FORMAT {
            return Err(Error::FormatVersion {
                found: u64::from(format),
            });
        }
        let body_len = u32_at(footer, 4) as usize;
        if footer[8..16].iter().any(|&b| b != 0) {
            return Err(malformed("setup trailer: reserved bytes are not zero"));
        }
        if body_len == 0 || body_len > BODY_CAP {
            return Err(malformed("setup trailer: body length out of range"));
        }
        if tail[body_len..BODY_CAP].iter().any(|&b| b != 0) {
            return Err(malformed("setup trailer: padding is not zero"));
        }
        let body = &tail[..body_len];
        let doc: BodyIn = crate::json::parse_strict(body)?;
        let app_id = AppId::parse(&doc.app_id)
            .map_err(|_| malformed("setup trailer: app_id is not an app id"))?;
        let root = doc.root.to_trusted(app_id, hasher, verifier)?;
        let version = Version::parse(&doc.version)?;
        let target = Target::parse(&doc.target)?;
        if body_bytes(&root, &version, target) != body {
            return Err(malformed("setup trailer: body is not canonical"));
        }

        let part = |i: usize| SetupPart {
            offset: u64_at(footer, 16 + 16 * i),
            length: u64_at(footer, 24 + 16 * i),
        };
        let (keys, manifest, pack) = (part(0), part(1), part(2));
        let limit = file_size - TRAILER_SIZE;
        for (p, cap) in [
            (keys, Limits::V1.keys_doc_bytes),
            (manifest, Limits::V1.manifest_doc_bytes),
            (pack, limit),
        ] {
            if p.length == 0 || p.length > cap {
                return Err(malformed("setup trailer: part length out of range"));
            }
            if !p.offset.is_multiple_of(PART_ALIGN) {
                return Err(malformed("setup trailer: part offset not aligned"));
            }
            if p.end().is_none_or(|end| end > limit) {
                return Err(malformed("setup trailer: part outside the payload"));
            }
        }
        let mut sorted = [keys, manifest, pack];
        sorted.sort_by_key(|p| p.offset);
        if sorted
            .windows(2)
            .any(|w| w[0].end().is_none_or(|end| end > w[1].offset))
        {
            return Err(malformed("setup trailer: parts overlap"));
        }
        Ok(SetupTrailer {
            root,
            version,
            target,
            keys,
            manifest,
            pack,
        })
    }
}

/// `length` bytes at `offset` of `file`, read as a file of their own (a payload part).
pub struct ReadAtWindow<'a> {
    file: &'a dyn ReadAt,
    offset: u64,
    length: u64,
}

impl<'a> ReadAtWindow<'a> {
    /// The window `part` of `file`; fails when it does not lie inside `file` as it is now.
    pub fn new(file: &'a dyn ReadAt, part: SetupPart) -> Result<ReadAtWindow<'a>> {
        if part.end().is_none_or(|end| end > file.size().unwrap_or(0)) {
            return Err(malformed("setup trailer: part outside the payload"));
        }
        Ok(ReadAtWindow {
            file,
            offset: part.offset,
            length: part.length,
        })
    }
}

impl ReadAt for ReadAtWindow<'_> {
    fn size(&self) -> std::result::Result<u64, FsError> {
        Ok(self.length)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::result::Result<(), FsError> {
        let inside = offset
            .checked_add(buf.len() as u64)
            .is_some_and(|end| end <= self.length);
        if !inside {
            return Err(FsError::new(
                FsErrorKind::Other,
                std::path::Path::new("payload"),
                Some(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            ));
        }
        self.file.read_exact_at(self.offset + offset, buf)
    }
}

/// The bytes of `part` of `file`, refused above `cap` before anything is read.
fn read_part(file: &dyn ReadAt, part: SetupPart, what: &'static str, cap: u64) -> Result<Vec<u8>> {
    if part.length > cap {
        return Err(Error::TooLarge {
            what,
            size: part.length,
            cap,
        });
    }
    let window = ReadAtWindow::new(file, part)?;
    let mut bytes = vec![0u8; usize::try_from(part.length).unwrap_or(0)];
    window.read_exact_at(0, &mut bytes)?;
    Ok(bytes)
}

/// A setup file's payload, verified.
#[derive(Debug, Clone)]
pub struct VerifiedSetup {
    /// The manifest of the trailer's version and target.
    pub manifest: VerifiedManifest,
    /// The release's update config, read from the pack (FORMAT.md 13.6).
    pub config: UpdateConfig,
}

impl VerifiedSetup {
    /// The path in the release tree of a file placed beside the entry (the runtime, the UI).
    pub fn beside_entry(&self, file: &str) -> Result<RelPath> {
        let entry = self.config.install.entry.as_str();
        let path = match entry.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/{file}"),
            None => file.to_owned(),
        };
        Ok(RelPath::parse(&path)?)
    }

    /// The runtime's path in the release tree.
    pub fn runtime_path(&self) -> Result<RelPath> {
        self.beside_entry(runtime_file(self.config.target))
    }

    /// The UI's path in the release tree.
    pub fn ui_path(&self) -> Result<RelPath> {
        self.beside_entry(ui_file(self.config.target))
    }

    /// The sum of the release's file sizes.
    pub fn installed_bytes(&self) -> u64 {
        self.manifest.entries().iter().fold(0u64, |sum, e| match e {
            crate::manifest::VerifiedEntry::File { size, .. } => sum.saturating_add(*size),
            _ => sum,
        })
    }
}

/// Verifies the payload of a setup file `file` under its parsed `trailer` (M6-D4), the way the
/// runtime's setup mode and the packager's check after writing do, in FORMAT.md 11.1 order and
/// with first-install floors: the key set under the trailer's root (its expiry at `clock`), the
/// manifest under the key set (release keys valid at `clock.now()`, the trailer's version and
/// target), the whole pack against the manifest's reference, then the update config read from the pack before staging (FORMAT.md 13.6), which must
/// name the app, the version, the target and exactly the trailer's root (else
/// [`Error::Field`]). Every part is read within its cap; the pack part must be the signed size
/// and hash to the signed SHA-256.
pub fn verify_setup(
    trailer: &SetupTrailer,
    file: &dyn ReadAt,
    clock: &ClockReading,
    codec: &dyn Codec,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<VerifiedSetup> {
    let keys_bytes = read_part(file, trailer.keys, "keys", Limits::V1.keys_doc_bytes)?;
    let keys = verify_key_set(
        &trailer.root,
        &keys_bytes,
        &RollbackFloor::default(),
        clock,
        hasher,
        verifier,
    )?;
    let manifest_bytes = read_part(
        file,
        trailer.manifest,
        "manifest",
        Limits::V1.manifest_doc_bytes,
    )?;
    let manifest = verify_payload_manifest(
        &keys,
        (&trailer.version, trailer.target),
        &manifest_bytes,
        clock.now(),
        hasher,
        verifier,
    )?;
    if trailer.pack.length != manifest.pack().size() {
        return Err(Error::ArtifactSize {
            expected: manifest.pack().size(),
            actual: trailer.pack.length,
        });
    }
    let pack = ReadAtWindow::new(file, trailer.pack)?;
    // The whole pack against its signed hash, so a damaged file is refused before anything is
    // shown or written (every frame is checked again when it is used).
    let mut state = hasher.sha256_start();
    let mut buf = vec![0u8; usize::try_from(trailer.pack.length.min(PACK_READ)).unwrap_or(0)];
    let mut at = 0u64;
    while at < trailer.pack.length {
        let n = usize::try_from((trailer.pack.length - at).min(PACK_READ)).unwrap_or(0);
        pack.read_exact_at(at, &mut buf[..n])?;
        state.update(&buf[..n]);
        at += n as u64;
    }
    if state.finalize() != manifest.pack().sha256() {
        return Err(Error::ArtifactHash);
    }
    let config_at = RelPath::parse(config_path(trailer.target))?;
    let config_bytes = read_entry(
        &manifest,
        &config_at,
        &pack,
        codec,
        hasher,
        MAX_UPDATE_CONFIG_BYTES,
    )?;
    let config = UpdateConfig::parse(&config_bytes)
        .map_err(|_| malformed("setup payload: the update config does not parse"))?;
    if config.app_id != *trailer.root.app_id() {
        return Err(Error::AppIdMismatch);
    }
    if config.check_root(&trailer.root).is_err() {
        return Err(malformed(
            "setup payload: the update config names another root than the trailer",
        ));
    }
    if config.version.to_string() != trailer.version.to_string() || config.target != trailer.target
    {
        return Err(Error::VersionMismatch);
    }
    Ok(VerifiedSetup { manifest, config })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_footer_and_the_magic_have_their_sizes() {
        assert_eq!(FOOTER_SIZE, 4 + 4 + 8 + 3 * 16 + TRAILER_MAGIC.len());
        assert!(!has_magic(&[0u8; 8]));
    }
}
