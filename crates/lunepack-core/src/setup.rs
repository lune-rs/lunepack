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
//!
//! A Windows setup file also carries a [`SetupAnchor`] in an `RT_RCDATA` resource of its runtime
//! image (M10-D4): the SHA-256 digests of its trailer block, key set and manifest. Read from the
//! process's own mapped image, it binds the payload to the image that was started (and, after a
//! UAC prompt, to the image the administrator consented to); [`verify_setup_anchored`] checks it.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::digest::Sha256Digest;
use crate::error::{Error, Result};
use crate::fs::{FsError, FsErrorKind, ReadAt};
use crate::ident::AppId;
use crate::keyset::{VerifiedKeySet, verify_key_set};
use crate::limits::Limits;
use crate::manifest::{VerifiedManifest, read_entry, verify_payload_manifest};
use crate::path::RelPath;
use crate::pe::PeHeaders;
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

/// How many bytes from the start of a file the locator reads for the PE headers.
pub const HEAD_SIZE: u64 = 4096;

/// Where a file's setup data ends, if it is a setup file (M7-D11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Located {
    /// No trailer magic at either candidate end: an ordinary file (an ordinary runtime).
    None,
    /// A setup file whose trailer is the [`TRAILER_SIZE`] bytes before `end`; `end` is the file's
    /// length, or the start of a signed PE's certificate table. [`SetupTrailer::parse`] takes
    /// those bytes with `end` as the file size.
    Setup {
        /// The end of the setup data.
        end: u64,
    },
    /// The magic, and a layout no setup writer makes (exit 7 `verify`, never an ordinary run).
    Malformed,
}

/// The certificate table's start, when `head` (the first [`HEAD_SIZE`] bytes of a file of
/// `file_len` bytes, or all of a shorter one) is a PE whose security directory is non-zero with
/// an offset in `[TRAILER_SIZE, file_len)`: the second candidate end (M7-D11 (1)). The caller
/// reads the [`TRAILER_SIZE`] bytes before it for [`locate`].
pub fn table_candidate(head: &[u8], file_len: u64) -> Option<u64> {
    let headers = PeHeaders::parse(head, file_len).ok()?;
    let table = headers.security();
    let offset = u64::from(table.address);
    (!table.is_zero() && offset >= TRAILER_SIZE && offset < file_len).then_some(offset)
}

/// Finds a setup file's trailer (M7-D11). `head` is the
/// file's first [`HEAD_SIZE`] bytes (all of a shorter file), `tail_at_end` its last
/// [`TRAILER_SIZE`] bytes, `tail_at_table` the [`TRAILER_SIZE`] bytes before
/// [`table_candidate`]'s offset (`None` without one).
///
/// 1. No magic at either candidate end: [`Located::None`], whatever the headers or the
///    certificate table look like.
/// 2. The magic before the certificate table: the table must start 8-aligned, be at least 8 bytes
///    long and end exactly at the end of the file, and the trailer must lie after the PE's headers
///    and section data; anything else is [`Located::Malformed`].
/// 3. The magic at the end of a file whose PE security directory is non-zero (bytes appended after
///    a signature), or of an `MZ` file whose PE headers do not read: [`Located::Malformed`].
/// 4. The magic at the end of any other file (an unsigned PE, an ELF): a setup ending there.
pub fn locate(
    head: &[u8],
    tail_at_end: &[u8],
    tail_at_table: Option<&[u8]>,
    file_len: u64,
) -> Located {
    let full = |tail: &[u8]| tail.len() as u64 == TRAILER_SIZE && has_magic(tail);
    let at_end = full(tail_at_end);
    let at_table = tail_at_table.is_some_and(full);
    if !at_end && !at_table {
        return Located::None;
    }
    let headers = if head.starts_with(b"MZ") {
        match PeHeaders::parse(head, file_len) {
            Ok(h) => Some(h),
            Err(_) => return Located::Malformed,
        }
    } else {
        None
    };
    let security = headers
        .as_ref()
        .map(PeHeaders::security)
        .unwrap_or_default();
    if at_table {
        // `tail_at_table` exists only beside a candidate, which only a PE has.
        let Some(headers) = &headers else {
            return Located::Malformed;
        };
        let offset = u64::from(security.address);
        let size = u64::from(security.size);
        let valid = offset == table_candidate(head, file_len).unwrap_or(u64::MAX)
            && offset.is_multiple_of(PART_ALIGN)
            && size >= 8
            && offset.checked_add(size) == Some(file_len)
            && offset - TRAILER_SIZE >= headers.image_end();
        return if valid {
            Located::Setup { end: offset }
        } else {
            Located::Malformed
        };
    }
    if !security.is_zero() {
        return Located::Malformed;
    }
    Located::Setup { end: file_len }
}

/// [`locate`] over an open file: reads the head, the tail at the end and, for a PE with a
/// certificate table, the tail before the table. A file shorter than a trailer is
/// [`Located::None`].
pub fn locate_file(file: &dyn ReadAt) -> std::result::Result<Located, FsError> {
    let len = file.size()?;
    if len < TRAILER_SIZE {
        return Ok(Located::None);
    }
    let mut head = vec![0u8; usize::try_from(len.min(HEAD_SIZE)).unwrap_or(0)];
    file.read_exact_at(0, &mut head)?;
    let mut at_end = vec![0u8; TRAILER_SIZE as usize];
    file.read_exact_at(len - TRAILER_SIZE, &mut at_end)?;
    let at_table = match table_candidate(&head, len) {
        Some(offset) => {
            let mut tail = vec![0u8; TRAILER_SIZE as usize];
            file.read_exact_at(offset - TRAILER_SIZE, &mut tail)?;
            Some(tail)
        }
        None => None,
    };
    Ok(locate(&head, &at_end, at_table.as_deref(), len))
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

/// Parses the macOS installer's payload file (M8-D7, FORMAT.md 14): a setup file's payload and
/// trailer without the runtime part. Fail-closed, in this order: the file is at least
/// [`TRAILER_SIZE`] bytes long and a multiple of [`PART_ALIGN`]; its last [`TRAILER_SIZE`] bytes
/// are a trailer ([`has_magic`], then [`SetupTrailer::parse`] with the file's length); and the
/// payload starts at offset 0 (the lowest part's offset). A file at the payload's place is meant
/// to be one, so anything else is an error, never "no payload". The parts are then verified under
/// the trailer's root by [`verify_setup`], as a setup file's are.
pub fn parse_payload_file(
    file: &dyn ReadAt,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<SetupTrailer> {
    let len = file.size()?;
    if len < TRAILER_SIZE {
        return Err(malformed("setup payload: shorter than a trailer"));
    }
    if !len.is_multiple_of(PART_ALIGN) {
        return Err(malformed("setup payload: length not a multiple of 8"));
    }
    let mut tail = vec![0u8; TRAILER_SIZE as usize];
    file.read_exact_at(len - TRAILER_SIZE, &mut tail)?;
    if !has_magic(&tail) {
        return Err(malformed("setup payload: no trailer at its end"));
    }
    let trailer = SetupTrailer::parse(&tail, len, hasher, verifier)?;
    let first = [trailer.keys, trailer.manifest, trailer.pack]
        .iter()
        .map(|p| p.offset)
        .min()
        .unwrap_or(u64::MAX);
    if first != 0 {
        return Err(malformed("setup payload: does not start with a part"));
    }
    Ok(trailer)
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
    let manifest_bytes = read_part(
        file,
        trailer.manifest,
        "manifest",
        Limits::V1.manifest_doc_bytes,
    )?;
    let (setup, _) = verify_parts(
        trailer,
        &keys_bytes,
        &manifest_bytes,
        file,
        clock,
        codec,
        hasher,
        verifier,
    )?;
    Ok(setup)
}

/// [`verify_setup`]'s checks over the key set and manifest bytes already read from `file`, so a
/// caller that hashed those bytes verifies exactly them. Also returns the verified key set.
#[allow(clippy::too_many_arguments)]
fn verify_parts(
    trailer: &SetupTrailer,
    keys_bytes: &[u8],
    manifest_bytes: &[u8],
    file: &dyn ReadAt,
    clock: &ClockReading,
    codec: &dyn Codec,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<(VerifiedSetup, VerifiedKeySet)> {
    let keys = verify_key_set(
        &trailer.root,
        keys_bytes,
        &RollbackFloor::default(),
        clock,
        hasher,
        verifier,
    )?;
    let manifest = verify_payload_manifest(
        &keys,
        (&trailer.version, trailer.target),
        manifest_bytes,
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
    Ok((VerifiedSetup { manifest, config }, keys))
}

/// The id of the `RT_RCDATA` resource of a Windows setup file's runtime image that holds its
/// [`SetupAnchor`] (M10-D4).
pub const ANCHOR_RESOURCE_ID: u16 = 1;
/// The first bytes of an encoded [`SetupAnchor`].
pub const ANCHOR_MAGIC: [u8; 8] = *b"\x89LPANC\r\n";
/// The size of an encoded [`SetupAnchor`]: the magic and three SHA-256 digests.
pub const ANCHOR_SIZE: usize = 8 + 3 * 32;

/// The SHA-256 digests a Windows setup file carries of its own payload in an `RT_RCDATA` resource
/// of its runtime image (M10-D4): of the [`TRAILER_SIZE`]-byte trailer block as written, of the
/// key-set part and of the manifest part (the manifest binds the pack). A process reading the
/// anchor from its own mapped image verifies against what was started, whatever happens to the
/// file afterwards ([`verify_setup_anchored`]).
///
/// Encoding ([`ANCHOR_SIZE`] bytes): [`ANCHOR_MAGIC`], then the trailer, key-set and manifest
/// digests. Setup.exe is read only by the runtime inside it, so this is not a cross-version format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupAnchor {
    /// SHA-256 of the trailer block.
    pub trailer: Sha256Digest,
    /// SHA-256 of the key-set part.
    pub keys: Sha256Digest,
    /// SHA-256 of the manifest part.
    pub manifest: Sha256Digest,
}

impl SetupAnchor {
    /// What the packager stamps before the payload exists: the magic and 96 zero bytes. It is
    /// patched in place with the real anchor once the trailer is written; never accepted.
    pub const PLACEHOLDER: [u8; ANCHOR_SIZE] = {
        let mut b = [0u8; ANCHOR_SIZE];
        let mut i = 0;
        while i < ANCHOR_MAGIC.len() {
            b[i] = ANCHOR_MAGIC[i];
            i += 1;
        }
        b
    };

    /// The anchor of a trailer block and the key-set and manifest parts' bytes.
    pub fn of(
        trailer_block: &[u8],
        keys: &[u8],
        manifest: &[u8],
        hasher: &dyn Hasher,
    ) -> SetupAnchor {
        SetupAnchor {
            trailer: hasher.sha256(trailer_block),
            keys: hasher.sha256(keys),
            manifest: hasher.sha256(manifest),
        }
    }

    /// The [`ANCHOR_SIZE`]-byte encoding.
    pub fn encode(&self) -> [u8; ANCHOR_SIZE] {
        let mut out = [0u8; ANCHOR_SIZE];
        out[..8].copy_from_slice(&ANCHOR_MAGIC);
        out[8..40].copy_from_slice(self.trailer.as_bytes());
        out[40..72].copy_from_slice(self.keys.as_bytes());
        out[72..].copy_from_slice(self.manifest.as_bytes());
        out
    }

    /// Parses an encoding: exactly [`ANCHOR_SIZE`] bytes starting with [`ANCHOR_MAGIC`], else
    /// [`Error::SetupAnchor`]. The placeholder parses (to all-zero digests); it is refused by
    /// [`verify_setup_anchored`].
    pub fn parse(bytes: &[u8]) -> Result<SetupAnchor> {
        if bytes.len() != ANCHOR_SIZE || bytes[..8] != ANCHOR_MAGIC {
            return Err(Error::SetupAnchor("malformed"));
        }
        let digest = |at: usize| {
            let mut d = [0u8; 32];
            d.copy_from_slice(&bytes[at..at + 32]);
            Sha256Digest::from_bytes(d)
        };
        Ok(SetupAnchor {
            trailer: digest(8),
            keys: digest(40),
            manifest: digest(72),
        })
    }

    /// Whether this is the placeholder (every digest zero).
    pub fn is_placeholder(&self) -> bool {
        self.encode() == Self::PLACEHOLDER
    }
}

/// A setup file's payload verified against its anchor.
#[derive(Debug, Clone)]
pub struct AnchoredSetup {
    /// The parsed trailer (where the parts lie in the file).
    pub trailer: SetupTrailer,
    /// The verified payload.
    pub setup: VerifiedSetup,
    /// The version of the key set the verification accepted (a floor of a first record).
    pub keyset_version: u64,
}

/// Verifies a setup file against `anchor` (M10-D4), the one check a Windows setup makes before it
/// trusts its payload. `trailer_block` is the [`TRAILER_SIZE`] bytes before `end` (the end of the
/// setup data, [`locate_file`]); `file` the setup file. Fail-closed, in this order:
///
/// 1. the anchor is not the placeholder (before any hashing);
/// 2. the trailer block's SHA-256 is the anchor's, before the trailer is parsed;
/// 3. the trailer parses ([`SetupTrailer::parse`] with `end` as the file size);
/// 4. the key-set part and then the manifest part, each read once within its cap, hash to the
///    anchor's digests;
/// 5. [`verify_setup`]'s checks over exactly those bytes (the pack is bound by the manifest).
///
/// Steps 1, 2 and 4 fail with [`Error::SetupAnchor`]; the rest with what [`verify_setup`] returns.
/// The trailer's root is never trusted on its own: it is trusted because the trailer block is the
/// one the anchor names.
#[allow(clippy::too_many_arguments)]
pub fn verify_setup_anchored(
    anchor: &SetupAnchor,
    trailer_block: &[u8],
    file: &dyn ReadAt,
    end: u64,
    clock: &ClockReading,
    codec: &dyn Codec,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<AnchoredSetup> {
    if anchor.is_placeholder() {
        return Err(Error::SetupAnchor("the anchor was never written"));
    }
    if hasher.sha256(trailer_block) != anchor.trailer {
        return Err(Error::SetupAnchor("trailer"));
    }
    let trailer = SetupTrailer::parse(trailer_block, end, hasher, verifier)?;
    let keys_bytes = read_part(file, trailer.keys, "keys", Limits::V1.keys_doc_bytes)?;
    if hasher.sha256(&keys_bytes) != anchor.keys {
        return Err(Error::SetupAnchor("key set"));
    }
    let manifest_bytes = read_part(
        file,
        trailer.manifest,
        "manifest",
        Limits::V1.manifest_doc_bytes,
    )?;
    if hasher.sha256(&manifest_bytes) != anchor.manifest {
        return Err(Error::SetupAnchor("manifest"));
    }
    let (setup, keys) = verify_parts(
        &trailer,
        &keys_bytes,
        &manifest_bytes,
        file,
        clock,
        codec,
        hasher,
        verifier,
    )?;
    Ok(AnchoredSetup {
        trailer,
        setup,
        keyset_version: keys.version(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_footer_and_the_magic_have_their_sizes() {
        assert_eq!(FOOTER_SIZE, 4 + 4 + 8 + 3 * 16 + TRAILER_MAGIC.len());
        assert!(!has_magic(&[0u8; 8]));
        assert_eq!(ANCHOR_SIZE, 104);
        assert_eq!(&SetupAnchor::PLACEHOLDER[..8], &ANCHOR_MAGIC);
        assert!(SetupAnchor::PLACEHOLDER[8..].iter().all(|&b| b == 0));
    }
}
