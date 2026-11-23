//! The manifest, `<ver>/<target>.manifest.json` (FORMAT.md 8): one release's file tree for one
//! target, bound to the feed by size and hash.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::digest::{Sha256Digest, U53};
use crate::envelope::{OpenedEnvelope, PayloadKind};
use crate::error::{Error, FrameError, Result, Untrusted};
use crate::feed::{ArtifactRef, CheckedRef, FeedTargetEntry};
use crate::frame::{
    CheckedFrame, FrameDesc, check_file_frame, decode_verified, is_patch_codec, patch_window,
};
use crate::fs::ReadAt;
use crate::ident::AppId;
use crate::keyset::VerifiedKeySet;
use crate::limits::Limits;
use crate::path::{EntryKind, RelPath, validate_tree};
use crate::target::Target;
use crate::traits::{Codec, CodecId, Hasher, Verifier};
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
    /// The deltas from earlier releases (FORMAT.md 9.3); absent when there are none, so a
    /// manifest without deltas is byte for byte what it was before deltas existed.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub deltas: Option<Vec<DeltaDoc>>,
}

/// One delta as written (FORMAT.md 9.3): the delta file of the patches from release `from`, as an
/// artifact reference (7.1), and its patches. [`verify_manifest`] checks every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaDoc {
    /// The base release's version text.
    pub from: String,
    /// The delta file, relative to the feed's directory.
    pub path: String,
    /// The delta file's exact byte length.
    pub size: U53,
    /// The delta file's SHA-256.
    pub sha256: Sha256Digest,
    /// The patches, each a byte range of the delta file.
    pub patches: Vec<PatchDoc>,
}

/// One patch as written (FORMAT.md 9.3): the file at `path` rebuilt from the base file of
/// `base_size` bytes and `base_sha256` by `codec`, from the delta file's bytes
/// `offset .. offset + length`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchDoc {
    /// The file entry it rebuilds.
    pub path: RelPath,
    /// The base file's size.
    pub base_size: U53,
    /// The base file's SHA-256.
    pub base_sha256: Sha256Digest,
    /// The codec id, compared byte for byte; kept as text so an unknown id is
    /// [`Error::UnknownCodec`].
    pub codec: String,
    /// Offset of the patch in the delta file.
    pub offset: U53,
    /// Patch length, at least 1.
    pub length: U53,
    /// SHA-256 of the patch's bytes.
    pub sha256: Sha256Digest,
}

/// Reserved manifest fields v1 writers never write (FORMAT.md 8); a v1 reader rejects them.
#[derive(Deserialize)]
struct Reserved {
    #[serde(default, deserialize_with = "present")]
    install: Option<serde::de::IgnoredAny>,
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

/// A patch that passed the checks of FORMAT.md 9.3, bound to the file entry it rebuilds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPatch {
    path: RelPath,
    base_size: u64,
    base_sha256: Sha256Digest,
    codec: CodecId,
    offset: u64,
    length: u64,
    sha256: Sha256Digest,
    size: u64,
    file_sha256: Sha256Digest,
    window: u64,
}

impl VerifiedPatch {
    /// The file entry's path.
    pub fn path(&self) -> &RelPath {
        &self.path
    }

    /// The base file's size, at least 1.
    pub fn base_size(&self) -> u64 {
        self.base_size
    }

    /// The base file's SHA-256 (never the patched file's).
    pub fn base_sha256(&self) -> Sha256Digest {
        self.base_sha256
    }

    /// The codec: `lzma2`, `bcj-x86+lzma2` or `bcj-arm64+lzma2`.
    pub fn codec(&self) -> CodecId {
        self.codec
    }

    /// Offset in the delta file.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Patch length, at least 1.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// The patch's signed SHA-256.
    pub fn sha256(&self) -> Sha256Digest {
        self.sha256
    }

    /// The patched file's size (the entry's), at least 1.
    pub fn file_size(&self) -> u64 {
        self.size
    }

    /// The patched file's SHA-256 (the entry's).
    pub fn file_sha256(&self) -> Sha256Digest {
        self.file_sha256
    }

    /// The LZMA2 window: `round_up(base_size + file_size, 4096)`, at most 128 MiB.
    pub fn window(&self) -> u64 {
        self.window
    }

    /// The writer's own descriptor of a patch it just encoded, for its round trip (D27) through
    /// [`decode_patch_verified`](crate::frame::decode_patch_verified) before the patch is kept:
    /// every value comes from the bytes in hand, not from a document. The window is computed here
    /// and must be within the format's cap.
    pub(crate) fn for_round_trip(
        path: RelPath,
        codec: CodecId,
        patch: (&[u8], Sha256Digest),
        base: (u64, Sha256Digest),
        file: (u64, Sha256Digest),
    ) -> Result<VerifiedPatch> {
        let window = patch_window(base.0, file.0)
            .filter(|w| *w <= Limits::V1.patch_window_bytes)
            .ok_or(Error::Field("patch window above 128 MiB"))?;
        Ok(VerifiedPatch {
            path,
            base_size: base.0,
            base_sha256: base.1,
            codec,
            offset: 0,
            length: patch.0.len() as u64,
            sha256: patch.1,
            size: file.0,
            file_sha256: file.1,
            window,
        })
    }
}

/// A delta that passed the checks of FORMAT.md 9.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelta {
    from: Version,
    from_text: String,
    file: CheckedRef,
    patches: Vec<VerifiedPatch>,
}

impl VerifiedDelta {
    /// The base release's version (precedence strictly below the manifest's).
    pub fn from(&self) -> &Version {
        &self.from
    }

    /// The base release's version text as written; a client matches it byte for byte against its
    /// installed version's text (FORMAT.md 9.3), since precedence ignores build metadata.
    pub fn from_text(&self) -> &str {
        &self.from_text
    }

    /// The delta file's reference.
    pub fn file(&self) -> &CheckedRef {
        &self.file
    }

    /// The patches in document order.
    pub fn patches(&self) -> &[VerifiedPatch] {
        &self.patches
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
    deltas: Vec<VerifiedDelta>,
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

    /// The deltas in document order; empty when the manifest has none.
    pub fn deltas(&self) -> &[VerifiedDelta] {
        &self.deltas
    }
}

fn foreign(present: bool, what: &'static str) -> Result<()> {
    if present {
        Err(Error::Field(what))
    } else {
        Ok(())
    }
}

pub(crate) fn check_entry(
    doc: EntryDoc,
    pack_size: u64,
    empty_sha256: Sha256Digest,
) -> Result<VerifiedEntry> {
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

/// Checks the `deltas` of a manifest of release `version` whose verified entries are `entries`
/// (FORMAT.md 9.3). Every rule fails the whole manifest:
///
/// - `deltas` present means 1 to 16 objects;
/// - `from` is a version (10.3) whose precedence is strictly below `version`, and no two deltas
///   have equal precedence;
/// - the delta file is an artifact reference (7.1) with `size >= 1`;
/// - `patches` has 1 to 200,000 objects; each `path` names a `file` entry of the manifest with
///   `size >= 1`, at most once per delta;
/// - `base_size >= 1`; `base_sha256` differs from the entry's `sha256`; `codec` is `lzma2`,
///   `bcj-x86+lzma2` or `bcj-arm64+lzma2` byte for byte (another id of 9.0 is
///   [`Error::Field`], an unknown one [`Error::UnknownCodec`]);
/// - `length >= 1` and `offset + length <= size` of the delta file, without overflow;
/// - the window `round_up(base_size + entry size, 4096)` is at most 128 MiB.
///
/// Patches may overlap or repeat inside a delta file, and bytes no patch covers are allowed.
pub(crate) fn check_deltas(
    deltas: Option<Vec<DeltaDoc>>,
    version: &Version,
    entries: &[VerifiedEntry],
) -> Result<Vec<VerifiedDelta>> {
    let Some(deltas) = deltas else {
        return Ok(Vec::new());
    };
    let limits = Limits::V1;
    if deltas.is_empty() {
        return Err(Error::Field("deltas without a delta"));
    }
    if deltas.len() > limits.deltas_per_manifest {
        return Err(Error::TooMany {
            what: "deltas",
            count: deltas.len(),
            max: limits.deltas_per_manifest,
        });
    }
    let files: BTreeMap<&RelPath, (u64, Sha256Digest)> = entries
        .iter()
        .filter_map(|e| match e {
            VerifiedEntry::File {
                path, size, sha256, ..
            } => Some((path, (*size, *sha256))),
            _ => None,
        })
        .collect();
    let mut out: Vec<VerifiedDelta> = Vec::with_capacity(deltas.len());
    for delta in deltas {
        let from = Version::parse(&delta.from)?;
        if from >= *version {
            return Err(Error::Field("delta from a version not below the release"));
        }
        if out.iter().any(|d| d.from == from) {
            return Err(Error::Field("two deltas from versions of equal precedence"));
        }
        let file = ArtifactRef {
            path: delta.path,
            size: delta.size,
            sha256: delta.sha256,
        }
        .check()?;
        if file.size() == 0 {
            return Err(Error::Field("empty delta file"));
        }
        if delta.patches.is_empty() {
            return Err(Error::Field("delta without a patch"));
        }
        if delta.patches.len() > limits.patches_per_delta {
            return Err(Error::TooMany {
                what: "patches",
                count: delta.patches.len(),
                max: limits.patches_per_delta,
            });
        }
        let mut seen = BTreeSet::new();
        let mut patches = Vec::with_capacity(delta.patches.len());
        for patch in delta.patches {
            let &(size, file_sha256) = files
                .get(&patch.path)
                .ok_or(Error::Field("patch for a path that is not a file entry"))?;
            if size == 0 {
                return Err(Error::Field("patch for an empty file"));
            }
            if !seen.insert(patch.path.clone()) {
                return Err(Error::Field("two patches for one file in a delta"));
            }
            let base_size = patch.base_size.get();
            if base_size == 0 {
                return Err(Error::Field("patch from an empty base"));
            }
            if patch.base_sha256 == file_sha256 {
                return Err(Error::Field("patch whose base is the file itself"));
            }
            let codec = CodecId::from_id(&patch.codec)
                .ok_or_else(|| Error::UnknownCodec(Untrusted::new(&patch.codec)))?;
            if !is_patch_codec(codec) {
                return Err(Error::Field("codec not allowed for a patch"));
            }
            let offset = patch.offset.get();
            let length = patch.length.get();
            if length == 0 {
                return Err(Error::Field("empty patch"));
            }
            if offset
                .checked_add(length)
                .is_none_or(|end| end > file.size())
            {
                return Err(Error::Field("patch outside its delta file"));
            }
            let window = patch_window(base_size, size)
                .filter(|w| *w <= limits.patch_window_bytes)
                .ok_or(Error::Field("patch window above 128 MiB"))?;
            patches.push(VerifiedPatch {
                path: patch.path,
                base_size,
                base_sha256: patch.base_sha256,
                codec,
                offset,
                length,
                sha256: patch.sha256,
                size,
                file_sha256,
                window,
            });
        }
        out.push(VerifiedDelta {
            from,
            from_text: delta.from,
            file,
            patches,
        });
    }
    Ok(out)
}

/// Verifies a manifest (FORMAT.md 8, 11.1 step 5) reached from `entry` of a verified feed. Order:
/// the bytes' length and SHA-256 equal the feed entry's reference **before** the envelope is
/// opened; the envelope meets the key set's release threshold (no key windows for manifests: the
/// feed binds the manifest by hash); only then the payload is parsed (format, kind, critical,
/// fields; reserved `install` rejected); at most 200,000 entries; app id equal to the key set's
/// and the feed's, version byte-equal (and so precedence-equal) to the feed entry's, target equal
/// to the feed entry's; the pack reference (FORMAT.md 7.1); every entry's fields, an empty file's
/// hash, every file frame against `pack.size` (FORMAT.md 9); the tree rules; the deltas
/// (FORMAT.md 9.3).
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
/// only then the payload is parsed (format, kind, critical, fields; reserved `install`
/// rejected); then exactly as [`verify_manifest`]: at most 200,000 entries, app id equal to the
/// key set's, version byte-equal to `expect`'s text (and so precedence-equal), target equal, the
/// pack reference, every entry and frame, the tree rules, the deltas.
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
    if reserved.install.is_some() {
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
    let deltas = check_deltas(doc.deltas, &version, &entries)?;

    Ok(VerifiedManifest {
        app_id: doc.app_id,
        version,
        target,
        issued: doc.issued.get(),
        pack,
        entries,
        deltas,
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
