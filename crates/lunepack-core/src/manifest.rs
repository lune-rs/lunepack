//! The manifest, `<ver>/<target>.manifest.json` (FORMAT.md 8): one release's file tree for one
//! target, bound to the feed by size and hash.

use serde::{Deserialize, Serialize};

use crate::digest::{Sha256Digest, U53};
use crate::envelope::{OpenedEnvelope, PayloadKind};
use crate::error::{Error, FrameError, Result};
use crate::feed::{ArtifactRef, CheckedRef, FeedTargetEntry};
use crate::frame::{CheckedFrame, FrameDesc, check_file_frame, decode_verified};
use crate::fs::ReadAt;
use crate::ident::AppId;
use crate::keyset::VerifiedKeySet;
use crate::limits::Limits;
use crate::path::{EntryKind, RelPath, validate_tree};
use crate::target::Target;
use crate::traits::{Codec, Hasher, Verifier};
use crate::trust::{from_checked, parse_payload, present};
use crate::version::Version;

/// One manifest entry as written (FORMAT.md 8.1). Fields of another `type` are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryDoc {
    /// The entry's path (FORMAT.md 10.1).
    pub path: RelPath,
    /// `file`, `dir` or `symlink`.
    #[serde(rename = "type")]
    pub kind: String,
    /// `file`: byte size.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub size: Option<U53>,
    /// `file`: SHA-256 of the file's bytes.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub sha256: Option<Sha256Digest>,
    /// `file`: executable bit, required.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub exec: Option<bool>,
    /// `file`: the frame, present exactly when `size > 0`.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub frame: Option<FrameDesc>,
    /// `symlink`: the link text.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub target: Option<String>,
}

/// A manifest payload as written (FORMAT.md 8). The writer serialises whatever it is given;
/// [`verify_manifest`] checks every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestDocument {
    /// Must be 1.
    pub format: U53,
    /// Must be `"manifest"`.
    pub kind: String,
    /// Critical features; v1 accepts only an empty list.
    pub critical: Vec<String>,
    /// The app id.
    pub app_id: AppId,
    /// The release version, byte-equal to the feed's.
    pub version: String,
    /// The target id.
    pub target: String,
    /// When the manifest was written.
    pub issued: U53,
    /// The release's pack.
    pub pack: ArtifactRef,
    /// The entries.
    pub entries: Vec<EntryDoc>,
}

/// Reserved manifest fields v1 writers never write (FORMAT.md 8); a v1 reader rejects them.
#[derive(Deserialize)]
struct Reserved {
    #[serde(default, deserialize_with = "present")]
    install: Option<serde::de::IgnoredAny>,
    #[serde(default, deserialize_with = "present")]
    deltas: Option<serde::de::IgnoredAny>,
}

impl ManifestDocument {
    /// The payload bytes the writer signs: this document as JSON.
    pub fn to_payload(&self) -> Vec<u8> {
        // Plain strings, integers and booleans cannot fail to serialise.
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// A verified entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedEntry {
    /// A regular file.
    File {
        /// Its path.
        path: RelPath,
        /// Byte size.
        size: u64,
        /// SHA-256 of its bytes.
        sha256: Sha256Digest,
        /// Executable bit.
        exec: bool,
        /// Its checked frame; `None` for an empty file.
        frame: Option<CheckedFrame>,
    },
    /// A directory.
    Dir {
        /// Its path.
        path: RelPath,
    },
    /// A symlink (macOS and Linux targets only).
    Symlink {
        /// Its path.
        path: RelPath,
        /// The link text, checked by the tree rules.
        target: String,
    },
}

impl VerifiedEntry {
    /// The entry's path.
    pub fn path(&self) -> &RelPath {
        match self {
            VerifiedEntry::File { path, .. }
            | VerifiedEntry::Dir { path }
            | VerifiedEntry::Symlink { path, .. } => path,
        }
    }

    fn kind(&self) -> EntryKind<'_> {
        match self {
            VerifiedEntry::File { .. } => EntryKind::File,
            VerifiedEntry::Dir { .. } => EntryKind::Dir,
            VerifiedEntry::Symlink { target, .. } => EntryKind::Symlink { target },
        }
    }
}

/// A manifest that passed [`verify_manifest`]; there is no other constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    app_id: AppId,
    version: Version,
    target: Target,
    issued: u64,
    pack: CheckedRef,
    entries: Vec<VerifiedEntry>,
}

impl VerifiedManifest {
    /// The app id.
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    /// The release version.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The target.
    pub fn target(&self) -> Target {
        self.target
    }

    /// When the manifest was written; the next check's implausible-clock floor (FORMAT.md 11.3).
    pub fn issued(&self) -> u64 {
        self.issued
    }

    /// The pack reference.
    pub fn pack(&self) -> &CheckedRef {
        &self.pack
    }

    /// The entries in document order.
    pub fn entries(&self) -> &[VerifiedEntry] {
        &self.entries
    }
}

fn foreign(present: bool, what: &'static str) -> Result<()> {
    if present {
        Err(Error::Field(what))
    } else {
        Ok(())
    }
}

fn check_entry(doc: EntryDoc, pack_size: u64, empty_sha256: Sha256Digest) -> Result<VerifiedEntry> {
    match doc.kind.as_str() {
        "file" => {
            foreign(doc.target.is_some(), "target on a file entry")?;
            let size = doc
                .size
                .ok_or(Error::Field("file entry without size"))?
                .get();
            let sha256 = doc
                .sha256
                .ok_or(Error::Field("file entry without sha256"))?;
            let exec = doc.exec.ok_or(Error::Field("file entry without exec"))?;
            if size == 0 && sha256 != empty_sha256 {
                return Err(Error::Field(
                    "empty file whose sha256 is not that of no bytes",
                ));
            }
            let frame = check_file_frame(doc.frame.as_ref(), size, sha256, pack_size)?;
            Ok(VerifiedEntry::File {
                path: doc.path,
                size,
                sha256,
                exec,
                frame,
            })
        }
        "dir" => {
            foreign(
                doc.size.is_some()
                    || doc.sha256.is_some()
                    || doc.exec.is_some()
                    || doc.frame.is_some()
                    || doc.target.is_some(),
                "file or symlink field on a dir entry",
            )?;
            Ok(VerifiedEntry::Dir { path: doc.path })
        }
        "symlink" => {
            foreign(
                doc.size.is_some()
                    || doc.sha256.is_some()
                    || doc.exec.is_some()
                    || doc.frame.is_some(),
                "file field on a symlink entry",
            )?;
            let target = doc
                .target
                .ok_or(Error::Field("symlink entry without target"))?;
            Ok(VerifiedEntry::Symlink {
                path: doc.path,
                target,
            })
        }
        _ => Err(Error::Field("unknown entry type")),
    }
}

/// Verifies a manifest (FORMAT.md 8, 11.1 step 5) reached from `entry` of a verified feed. Order:
/// the bytes' length and SHA-256 equal the feed entry's reference **before** the envelope is
/// opened; the envelope meets the key set's release threshold (no key windows for manifests: the
/// feed binds the manifest by hash); only then the payload is parsed (format, kind, critical,
/// fields; reserved `install` and `deltas` rejected); at most 200,000 entries; app id equal to the
/// key set's and the feed's, version byte-equal (and so precedence-equal) to the feed entry's,
/// target equal to the feed entry's; the pack reference (FORMAT.md 7.1); every entry's fields, an
/// empty file's hash, every file frame against `pack.size` (FORMAT.md 9); the tree rules.
pub fn verify_manifest(
    keys: &VerifiedKeySet,
    entry: &FeedTargetEntry,
    bytes: &[u8],
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<VerifiedManifest> {
    entry.reference().check_bytes(bytes, hasher)?;
    let envelope = OpenedEnvelope::open(bytes, PayloadKind::Manifest, &Limits::V1)?;
    let payload = envelope.authenticate(keys.keys(), keys.threshold(), verifier)?;
    check_payload(
        payload,
        Expected {
            app_ids: [keys.app_id(), entry.app_id()],
            version_text: entry.version_text(),
            version: entry.version(),
            target: entry.target(),
        },
        hasher,
    )
}

/// Verifies a manifest carried in an offline payload, with no feed (M6-D4): the release this
/// installer was built for is `expect`, and the manifest's signatures stand in for the feed's
/// hash binding. Order (FORMAT.md 2.6, then 8): the size cap, strict JSON and the envelope; the
/// signatures meet the key set's release threshold counting only release keys whose window holds
/// `now` (Unix seconds; an offline first install has no floor time, so the windows always apply);
/// only then the payload is parsed (format, kind, critical, fields; reserved `install` and
/// `deltas` rejected); then exactly as [`verify_manifest`]: at most 200,000 entries, app id equal
/// to the key set's, version byte-equal to `expect`'s text (and so precedence-equal), target
/// equal, the pack reference, every entry and frame, the tree rules.
///
/// The key set's own expiry is [`verify_key_set`](crate::verify_key_set)'s check: a payload stops
/// installing at the key set's `expires` or at the end of its release keys' windows.
pub fn verify_payload_manifest(
    keys: &VerifiedKeySet,
    expect: (&Version, Target),
    bytes: &[u8],
    now: u64,
    hasher: &dyn Hasher,
    verifier: &dyn Verifier,
) -> Result<VerifiedManifest> {
    let envelope = OpenedEnvelope::open(bytes, PayloadKind::Manifest, &Limits::V1)?;
    let windows = keys.windows();
    let ring = keys
        .keys()
        .subset(|i| windows.get(i).is_some_and(|w| w.contains(now)));
    let payload = envelope.authenticate(&ring, keys.threshold(), verifier)?;
    let (version, target) = expect;
    let version_text = version.to_string();
    check_payload(
        payload,
        Expected {
            app_ids: [keys.app_id(), keys.app_id()],
            version_text: &version_text,
            version,
            target,
        },
        hasher,
    )
}

/// What an authenticated manifest payload must name.
struct Expected<'a> {
    /// Every app id it must equal.
    app_ids: [&'a AppId; 2],
    /// The version text it must equal byte for byte.
    version_text: &'a str,
    /// The version it must equal in precedence.
    version: &'a Version,
    /// The target it must equal.
    target: Target,
}

/// The checks after authentication, shared by [`verify_manifest`] and
/// [`verify_payload_manifest`].
fn check_payload(
    payload: &[u8],
    expect: Expected<'_>,
    hasher: &dyn Hasher,
) -> Result<VerifiedManifest> {
    let doc: ManifestDocument = parse_payload(payload, PayloadKind::Manifest)?;
    let reserved: Reserved = from_checked(payload)?;
    if reserved.install.is_some() || reserved.deltas.is_some() {
        return Err(Error::Field("reserved manifest field"));
    }

    let max = Limits::V1.manifest_entries;
    if doc.entries.len() > max {
        return Err(Error::TooMany {
            what: "entries",
            count: doc.entries.len(),
            max,
        });
    }
    if expect.app_ids.iter().any(|id| doc.app_id != **id) {
        return Err(Error::AppIdMismatch);
    }
    let version = Version::parse(&doc.version)?;
    if doc.version.as_bytes() != expect.version_text.as_bytes() || version != *expect.version {
        return Err(Error::VersionMismatch);
    }
    let target = Target::parse(&doc.target)?;
    if target != expect.target {
        return Err(Error::TargetMismatch {
            expected: expect.target.as_str(),
            found: target.as_str(),
        });
    }

    let pack = doc.pack.check()?;
    let empty = hasher.sha256(b"");
    let entries = doc
        .entries
        .into_iter()
        .map(|e| check_entry(e, pack.size(), empty))
        .collect::<Result<Vec<_>>>()?;
    validate_tree(entries.iter().map(|e| (e.path(), e.kind())), target)?;

    Ok(VerifiedManifest {
        app_id: doc.app_id,
        version,
        target,
        issued: doc.issued.get(),
        pack,
        entries,
    })
}

/// Reads one file entry of a verified manifest out of its pack and decodes it (FORMAT.md 13.6
/// steps 2–3), for a client that needs a file before any tree exists (the installer's update
/// config and icon).
///
/// - `entry_path` must name a file entry; an absent path, a directory or a symlink is
///   [`Error::Field`]. An empty file is no bytes, read from nothing.
/// - `max` caps the decoded size: an entry whose signed size is above it is [`Error::TooLarge`]
///   before any byte is read.
/// - The frame must lie inside `pack` as it is now (`pack.size()`), else
///   [`FrameError::OutOfPack`](crate::error::FrameError::OutOfPack); exactly `frame.length` bytes are read
///   at `frame.offset`, and a short read is an error.
/// - Then [`decode_verified`](crate::decode_verified): the frame's hash before the codec sees a
///   byte, then the decoded size and hash against the entry.
pub fn read_entry(
    manifest: &VerifiedManifest,
    entry_path: &RelPath,
    pack: &dyn ReadAt,
    codec: &dyn Codec,
    hasher: &dyn Hasher,
    max: u64,
) -> Result<Vec<u8>> {
    let entry = manifest
        .entries()
        .iter()
        .find(|e| e.path() == entry_path)
        .ok_or(Error::Field("no manifest entry at the path"))?;
    let VerifiedEntry::File { size, frame, .. } = entry else {
        return Err(Error::Field("the manifest entry is not a file"));
    };
    if *size > max {
        return Err(Error::TooLarge {
            what: "manifest entry",
            size: *size,
            cap: max,
        });
    }
    let Some(frame) = frame else {
        // `check_entry` bound an empty file to the hash of no bytes.
        return Ok(Vec::new());
    };
    let end = frame
        .offset()
        .checked_add(frame.length())
        .ok_or(FrameError::OutOfPack)?;
    if end > pack.size()? {
        return Err(FrameError::OutOfPack.into());
    }
    let length = usize::try_from(frame.length()).map_err(|_| FrameError::OutOfPack)?;
    let mut bytes = vec![0u8; length];
    pack.read_exact_at(frame.offset(), &mut bytes)?;
    let capacity = usize::try_from(*size).unwrap_or(0);
    let mut out = Vec::with_capacity(capacity);
    decode_verified(frame, &bytes, hasher, codec, &mut out)?;
    Ok(out)
}
