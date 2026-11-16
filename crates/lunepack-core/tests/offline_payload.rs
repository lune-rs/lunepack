//! M6 step 6: the offline payload's manifest verification with no feed (M6-D4) and single-entry
//! reads before staging (FORMAT.md 13.6), with the testkit fakes.

use std::path::Path;

use lunepack_core::digest::U53;
use lunepack_core::error::FrameError;
use lunepack_core::path::RelPath;
use lunepack_core::{
    AppId, ClockReading, CodecId, Error, FsError, FsErrorKind, KeySetDocument, ManifestDocument,
    PayloadKind, ReadAt, RollbackFloor, Target, TrustedRoot, VerifiedKeySet, VerifiedManifest,
    Version, read_entry, verify_key_set, verify_payload_manifest,
};
use lunepack_testkit::{ChainFixture, FakeClock, FakeCodec, FakeHasher, PackBuilder, SUITE_T0};

const VERSION: &str = "1.2.0";
const DAY: u64 = 86_400;
/// Inside the fixture's release-key windows (`SUITE_T0 - 1 day .. SUITE_T0 + 1000 days`).
const NOW: u64 = SUITE_T0 + 3600;

fn data(n: usize, salt: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

fn pack(fx: &ChainFixture<'_>) -> PackBuilder {
    let mut p = PackBuilder::new();
    p.file(fx.hasher, "bin/app", &data(3000, 1), CodecId::BcjX86Lzma2)
        .file(fx.hasher, "share/README", &data(500, 3), CodecId::Stored)
        .file(fx.hasher, "share/empty", b"", CodecId::Stored)
        .file(fx.hasher, "data/blob", &data(700, 4), CodecId::Lzma2)
        .dir("share/doc")
        .symlink("lib/x.so", "x.so.1");
    p
}

fn version() -> Version {
    Version::parse(VERSION).unwrap()
}

/// A key set under `root` (root key 0) holding `keys`, with `threshold` and `expires`.
fn key_set(
    fx: &ChainFixture<'_>,
    root: &TrustedRoot,
    doc: KeySetDocument,
    now: u64,
) -> Result<VerifiedKeySet, Error> {
    let bytes = fx.envelope(PayloadKind::Keys, &doc.to_payload(), &[0]);
    verify_key_set(
        root,
        &bytes,
        &RollbackFloor::default(),
        &ClockReading::read(&FakeClock::new(now), None),
        fx.hasher,
        fx.verifier,
    )
}

fn signed(fx: &ChainFixture<'_>, doc: &ManifestDocument, seeds: &[u8]) -> Vec<u8> {
    fx.envelope(PayloadKind::Manifest, &doc.to_payload(), seeds)
}

fn verify(
    fx: &ChainFixture<'_>,
    keys: &VerifiedKeySet,
    bytes: &[u8],
    now: u64,
) -> Result<VerifiedManifest, Error> {
    verify_payload_manifest(
        keys,
        (&version(), Target::LinuxX86_64),
        bytes,
        now,
        fx.hasher,
        fx.verifier,
    )
}

#[test]
fn a_payload_manifest_signed_by_a_current_release_key_verifies_with_no_feed() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let p = pack(&fx);
    let bytes = signed(
        &fx,
        &fx.manifest_document(VERSION, Target::LinuxX86_64, &p),
        &[5],
    );
    let m = verify(&fx, &keys, &bytes, NOW).unwrap();
    assert_eq!(m.version().to_string(), VERSION);
    assert_eq!(m.target(), Target::LinuxX86_64);
    assert_eq!(m.entries().len(), 6);
    assert_eq!(m.pack().size(), p.bytes.len() as u64);
}

#[test]
fn a_wrong_key_or_too_few_keys_are_refused() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let doc = fx.manifest_document(VERSION, Target::LinuxX86_64, &pack(&fx));
    // The root key and a key the set does not list.
    for seeds in [&[0][..], &[6]] {
        let got = verify(&fx, &keys, &signed(&fx, &doc, seeds), NOW);
        assert!(matches!(got, Err(Error::Threshold { .. })), "{seeds:?}");
    }
    // Threshold 2: one key, or one key signing twice, is below it.
    let (_, keys2) = fx.verified_chain(&[5, 7], 2);
    for seeds in [&[5][..], &[5, 5]] {
        let got = verify(&fx, &keys2, &signed(&fx, &doc, seeds), NOW);
        assert!(
            matches!(got, Err(Error::Threshold { got: 1, need: 2 })),
            "{seeds:?}: {got:?}"
        );
    }
    verify(&fx, &keys2, &signed(&fx, &doc, &[5, 7]), NOW).unwrap();
}

#[test]
fn a_release_key_counts_only_inside_its_window() {
    let fx = ChainFixture::fake();
    let root = fx.trusted_root(1, 1, &[0]);
    let mut ks = fx.keyset_document(1, 1, None, 1, &[]);
    ks.keys = vec![fx.release_key(5, SUITE_T0, SUITE_T0 + 10 * DAY)];
    let keys = key_set(&fx, &root, ks, SUITE_T0).unwrap();
    let bytes = signed(
        &fx,
        &fx.manifest_document(VERSION, Target::LinuxX86_64, &pack(&fx)),
        &[5],
    );
    verify(&fx, &keys, &bytes, SUITE_T0).unwrap();
    verify(&fx, &keys, &bytes, SUITE_T0 + 10 * DAY - 1).unwrap();
    for now in [SUITE_T0 - 1, SUITE_T0 + 10 * DAY, SUITE_T0 + 400 * DAY] {
        let got = verify(&fx, &keys, &bytes, now);
        assert!(
            matches!(got, Err(Error::Threshold { .. })),
            "{now}: {got:?}"
        );
    }
}

#[test]
fn an_expired_key_set_stops_the_payload_before_its_manifest() {
    // P8: a setup file stops installing at its key set's `expires`.
    let fx = ChainFixture::fake();
    let root = fx.trusted_root(1, 1, &[0]);
    let expires = SUITE_T0 + 30 * DAY;
    let doc = fx.keyset_document(1, 1, Some(expires), 1, &[5]);
    key_set(&fx, &root, doc.clone(), expires - 1).unwrap();
    for now in [expires, expires + 400 * DAY] {
        let got = key_set(&fx, &root, doc.clone(), now);
        assert!(
            matches!(
                got,
                Err(Error::Expired {
                    what: "key set",
                    ..
                })
            ),
            "{now}: {got:?}"
        );
    }
}

#[test]
fn app_version_and_target_must_be_the_payloads() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let p = pack(&fx);
    // Another app id.
    let mut doc = fx.manifest_document(VERSION, Target::LinuxX86_64, &p);
    doc.app_id = AppId::parse("org.example.other").unwrap();
    let got = verify(&fx, &keys, &signed(&fx, &doc, &[5]), NOW);
    assert!(matches!(got, Err(Error::AppIdMismatch)), "{got:?}");
    // Equal precedence but other text, and other versions.
    for v in ["1.2.0+b", "1.2.1", "1.2.0-rc.1"] {
        let doc = fx.manifest_document(v, Target::LinuxX86_64, &p);
        let got = verify(&fx, &keys, &signed(&fx, &doc, &[5]), NOW);
        assert!(matches!(got, Err(Error::VersionMismatch)), "{v}: {got:?}");
    }
    // The other way round: the payload expects `1.0.0+b`, the manifest says `1.0.0`.
    let doc = fx.manifest_document("1.0.0", Target::LinuxX86_64, &p);
    let got = verify_payload_manifest(
        &keys,
        (&Version::parse("1.0.0+b").unwrap(), Target::LinuxX86_64),
        &signed(&fx, &doc, &[5]),
        NOW,
        fx.hasher,
        fx.verifier,
    );
    assert!(matches!(got, Err(Error::VersionMismatch)), "{got:?}");
    // Build metadata that matches byte for byte passes.
    let doc = fx.manifest_document("1.0.0+b", Target::LinuxX86_64, &p);
    verify_payload_manifest(
        &keys,
        (&Version::parse("1.0.0+b").unwrap(), Target::LinuxX86_64),
        &signed(&fx, &doc, &[5]),
        NOW,
        fx.hasher,
        fx.verifier,
    )
    .unwrap();
    // Another target.
    let doc = fx.manifest_document(VERSION, Target::LinuxAarch64, &p);
    let got = verify(&fx, &keys, &signed(&fx, &doc, &[5]), NOW);
    assert!(
        matches!(
            got,
            Err(Error::TargetMismatch {
                expected: "linux-x86_64",
                found: "linux-aarch64"
            })
        ),
        "{got:?}"
    );
}

#[test]
fn a_duplicate_key_reserved_fields_and_oversize_are_refused() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let doc = fx.manifest_document(VERSION, Target::LinuxX86_64, &pack(&fx));
    // A duplicate member in the signed payload: strict JSON refuses it after authentication.
    let payload = String::from_utf8(doc.to_payload()).unwrap();
    let dup = payload.replacen("{", "{\"kind\":\"manifest\",", 1);
    let got = verify(
        &fx,
        &keys,
        &fx.envelope(PayloadKind::Manifest, dup.as_bytes(), &[5]),
        NOW,
    );
    assert!(matches!(got, Err(Error::Json(_))), "{got:?}");
    // A duplicate member in the envelope itself, before any signature is checked.
    let bytes = String::from_utf8(signed(&fx, &doc, &[5])).unwrap();
    let dup = bytes.replacen("{", "{\"payloadType\":\"x\",", 1);
    let got = verify(&fx, &keys, dup.as_bytes(), NOW);
    assert!(matches!(got, Err(Error::Json(_))), "{got:?}");
    // Reserved members.
    for member in ["install", "deltas"] {
        let tampered = payload.replacen("{", &format!("{{\"{member}\":{{}},"), 1);
        let got = verify(
            &fx,
            &keys,
            &fx.envelope(PayloadKind::Manifest, tampered.as_bytes(), &[5]),
            NOW,
        );
        assert!(
            matches!(got, Err(Error::Field("reserved manifest field"))),
            "{member}: {got:?}"
        );
    }
    // Over the manifest cap: refused by size before parsing.
    let big = vec![b' '; 64 * 1024 * 1024 + 1];
    let got = verify(&fx, &keys, &big, NOW);
    assert!(
        matches!(
            got,
            Err(Error::TooLarge {
                what: "manifest",
                ..
            })
        ),
        "{got:?}"
    );
}

#[test]
fn entries_and_tree_rules_apply_as_for_a_feed_manifest() {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let mut doc = fx.manifest_document(VERSION, Target::LinuxX86_64, &pack(&fx));
    doc.entries[0].exec = None;
    let got = verify(&fx, &keys, &signed(&fx, &doc, &[5]), NOW);
    assert!(
        matches!(got, Err(Error::Field("file entry without exec"))),
        "{got:?}"
    );
    let mut doc = fx.manifest_document(VERSION, Target::LinuxX86_64, &pack(&fx));
    let first = doc.entries[0].clone();
    doc.entries.push(first);
    let got = verify(&fx, &keys, &signed(&fx, &doc, &[5]), NOW);
    assert!(matches!(got, Err(Error::Tree(_))), "{got:?}");
    let mut doc = fx.manifest_document(VERSION, Target::LinuxX86_64, &pack(&fx));
    doc.pack.size = U53::new(1).unwrap();
    let got = verify(&fx, &keys, &signed(&fx, &doc, &[5]), NOW);
    assert!(
        matches!(got, Err(Error::Frame(FrameError::OutOfPack))),
        "{got:?}"
    );
}

// ---- read_entry ----------------------------------------------------------------------------------

/// A pack in memory.
struct Bytes(Vec<u8>);

impl ReadAt for Bytes {
    fn size(&self) -> Result<u64, FsError> {
        Ok(self.0.len() as u64)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
        let start = usize::try_from(offset).unwrap();
        match self.0.get(start..start + buf.len()) {
            Some(src) => {
                buf.copy_from_slice(src);
                Ok(())
            }
            None => Err(FsError::new(FsErrorKind::Other, Path::new("pack"), None)),
        }
    }
}

/// A pack whose `size` claims more than it holds (a file shrunk after it was measured).
struct Lying(Vec<u8>, u64);

impl ReadAt for Lying {
    fn size(&self) -> Result<u64, FsError> {
        Ok(self.1)
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), FsError> {
        Bytes(self.0.clone()).read_exact_at(offset, buf)
    }
}

fn verified(fx: &ChainFixture<'_>, p: &PackBuilder) -> VerifiedManifest {
    let (_, keys) = fx.verified_chain(&[5], 1);
    let bytes = signed(
        fx,
        &fx.manifest_document(VERSION, Target::LinuxX86_64, p),
        &[5],
    );
    verify(fx, &keys, &bytes, NOW).unwrap()
}

fn path(text: &str) -> RelPath {
    RelPath::parse(text).unwrap()
}

#[test]
fn read_entry_returns_the_signed_file() {
    let fx = ChainFixture::fake();
    let p = pack(&fx);
    let m = verified(&fx, &p);
    let codec = FakeCodec::new();
    for (name, want) in [
        ("bin/app", data(3000, 1)),
        ("share/README", data(500, 3)),
        ("data/blob", data(700, 4)),
        ("share/empty", Vec::new()),
    ] {
        let got = read_entry(
            &m,
            &path(name),
            &Bytes(p.bytes.clone()),
            &codec,
            &FakeHasher,
            1 << 20,
        )
        .unwrap();
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn read_entry_refuses_dirs_symlinks_and_absent_paths() {
    let fx = ChainFixture::fake();
    let p = pack(&fx);
    let m = verified(&fx, &p);
    for (name, want) in [
        ("share/doc", "the manifest entry is not a file"),
        ("lib/x.so", "the manifest entry is not a file"),
        ("share/none", "no manifest entry at the path"),
    ] {
        let got = read_entry(
            &m,
            &path(name),
            &Bytes(p.bytes.clone()),
            &FakeCodec::new(),
            &FakeHasher,
            1 << 20,
        );
        assert!(
            matches!(got, Err(Error::Field(text)) if text == want),
            "{name}: {got:?}"
        );
    }
}

#[test]
fn read_entry_checks_the_frame_hash_before_decoding() {
    let fx = ChainFixture::fake();
    let p = pack(&fx);
    let m = verified(&fx, &p);
    let lunepack_core::VerifiedEntry::File {
        frame: Some(frame), ..
    } = &m.entries()[0]
    else {
        panic!("bin/app is a file with a frame");
    };
    let mut bytes = p.bytes.clone();
    bytes[(frame.offset() + frame.length() / 2) as usize] ^= 0x01;
    // A codec that panics when called: the hash check must come first.
    let codec = FakeCodec::with_fault(lunepack_testkit::Fault::PanicIfCalled);
    let got = read_entry(
        &m,
        &path("bin/app"),
        &Bytes(bytes),
        &codec,
        &FakeHasher,
        1 << 20,
    );
    assert!(
        matches!(got, Err(Error::Frame(FrameError::FrameHash))),
        "{got:?}"
    );
}

#[test]
fn read_entry_refuses_a_truncated_pack() {
    let fx = ChainFixture::fake();
    let p = pack(&fx);
    let m = verified(&fx, &p);
    let mut short = p.bytes.clone();
    short.truncate(short.len() - 1);
    // The last file's frame ends at the pack's end.
    let last = m
        .entries()
        .iter()
        .filter_map(|e| match e {
            lunepack_core::VerifiedEntry::File {
                path,
                frame: Some(f),
                ..
            } => Some((path.clone(), f.offset() + f.length())),
            _ => None,
        })
        .max_by_key(|(_, end)| *end)
        .unwrap();
    assert_eq!(last.1, p.bytes.len() as u64);
    let got = read_entry(
        &m,
        &last.0,
        &Bytes(short.clone()),
        &FakeCodec::new(),
        &FakeHasher,
        1 << 20,
    );
    assert!(
        matches!(got, Err(Error::Frame(FrameError::OutOfPack))),
        "{got:?}"
    );
    // A pack that claims its full size but reads short: the short read is an error.
    let got = read_entry(
        &m,
        &last.0,
        &Lying(short, p.bytes.len() as u64),
        &FakeCodec::new(),
        &FakeHasher,
        1 << 20,
    );
    assert!(matches!(got, Err(Error::Fs(_))), "{got:?}");
}

#[test]
fn read_entry_caps_the_decoded_size_before_reading() {
    let fx = ChainFixture::fake();
    let p = pack(&fx);
    let m = verified(&fx, &p);
    // An empty pack: a cap that is checked first never reaches the read.
    let got = read_entry(
        &m,
        &path("bin/app"),
        &Bytes(Vec::new()),
        &FakeCodec::new(),
        &FakeHasher,
        2999,
    );
    assert!(
        matches!(
            got,
            Err(Error::TooLarge {
                size: 3000,
                cap: 2999,
                ..
            })
        ),
        "{got:?}"
    );
    let got = read_entry(
        &m,
        &path("bin/app"),
        &Bytes(p.bytes.clone()),
        &FakeCodec::new(),
        &FakeHasher,
        3000,
    )
    .unwrap();
    assert_eq!(got.len(), 3000);
}
