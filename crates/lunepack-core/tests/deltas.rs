//! M12 step 1: the manifest's `deltas` (FORMAT.md 9.3), written by the core's `ReleaseLayout` and
//! verified by `verify_manifest`: one accepted manifest with two deltas, then one rejection per
//! reader rule, each from the writer's document with one field changed.

use lunepack_core::digest::U53;
use lunepack_core::error::PackError;
use lunepack_core::path::RelPath;
use lunepack_core::{
    AppId, Channel, ClockReading, CodecId, DeltaPatch, Error, FeedTargetEntry, FinishedRelease,
    Hasher, MAX_PATCH_WINDOW, ManifestDocument, PayloadKind, ReleaseLayout, RollbackFloor,
    Sha256Digest, Target, VerifiedKeySet, VerifiedManifest, pack_file, patch_window, verify_feed,
    verify_manifest,
};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeCodec, FakeHasher, SUITE_APP_ID, SUITE_CHANNEL, SUITE_T0,
};

const VERSION: &str = "1.2.0";
const TARGET: Target = Target::LinuxX86_64;
const APP_SIZE: u64 = 3000;

fn data(n: usize, salt: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

fn rel(text: &str) -> RelPath {
    RelPath::parse(text).unwrap()
}

fn sha(bytes: &[u8]) -> Sha256Digest {
    FakeHasher.sha256(bytes)
}

/// The release's tree: two non-empty files, an empty file, a directory and a symlink.
fn tree_layout() -> ReleaseLayout {
    let mut l = ReleaseLayout::new(AppId::parse(SUITE_APP_ID).unwrap(), VERSION, TARGET).unwrap();
    let codec = FakeCodec::new();
    for (path, exec, bytes) in [
        ("bin/app", true, data(APP_SIZE as usize, 1)),
        ("lib/x.so.1", false, data(2000, 2)),
        ("share/empty", false, Vec::new()),
    ] {
        let packed = pack_file(&bytes, &codec, &codec, &FakeHasher).unwrap();
        l.add_file(rel(path), exec, &packed).unwrap();
    }
    l.add_dir(rel("share/doc")).unwrap();
    l.add_symlink(rel("lib/x.so"), "x.so.1").unwrap();
    l
}

fn patch(codec: CodecId, bytes: &[u8], base: &[u8]) -> DeltaPatch {
    DeltaPatch {
        codec,
        bytes: bytes.to_vec(),
        base_size: base.len() as u64,
        base_sha256: sha(base),
    }
}

/// The writer's release with two deltas: from 1.0.0 (one patch) and from 1.1.0 (two patches),
/// added lowest first and in reverse path order, so the writer's ordering shows.
fn release() -> FinishedRelease {
    let mut l = tree_layout();
    l.add_delta(
        "1.0.0",
        vec![(
            rel("bin/app"),
            patch(CodecId::Lzma2, b"patch of app from 1.0.0", b"app 1.0.0"),
        )],
    )
    .unwrap();
    l.add_delta(
        "1.1.0",
        vec![
            (
                rel("lib/x.so.1"),
                patch(CodecId::Lzma2, b"patch of lib from 1.1.0!", b"lib 1.1.0"),
            ),
            (
                rel("bin/app"),
                patch(
                    CodecId::BcjX86Lzma2,
                    b"patch of app from 1.1.0",
                    b"app 1.1.0",
                ),
            ),
        ],
    )
    .unwrap();
    l.finish_release(SUITE_T0, &FakeHasher).unwrap()
}

fn entry_for(fx: &ChainFixture<'_>, keys: &VerifiedKeySet, manifest: &[u8]) -> FeedTargetEntry {
    let doc = fx.feed_document(
        1,
        None,
        vec![fx.release(VERSION, &[(TARGET, manifest)], None)],
    );
    let bytes = fx.envelope(PayloadKind::Feed, &doc.to_payload(), &[5]);
    let feed = verify_feed(
        keys,
        &bytes,
        &AppId::parse(SUITE_APP_ID).unwrap(),
        &Channel::parse(SUITE_CHANNEL).unwrap(),
        &RollbackFloor::default(),
        &ClockReading::read(&FakeClock::new(SUITE_T0), None),
        fx.verifier,
    )
    .unwrap();
    feed.target_entry(0, TARGET).unwrap()
}

/// Signs `payload` with release key 5 and verifies it through a feed that references it.
fn verify_payload(payload: &[u8]) -> Result<VerifiedManifest, Error> {
    let fx = ChainFixture::fake();
    let (_, keys) = fx.verified_chain(&[5], 1);
    let bytes = fx.envelope(PayloadKind::Manifest, payload, &[5]);
    let entry = entry_for(&fx, &keys, &bytes);
    verify_manifest(&keys, &entry, &bytes, fx.hasher, fx.verifier)
}

fn verify_doc(doc: &ManifestDocument) -> Result<VerifiedManifest, Error> {
    verify_payload(&doc.to_payload())
}

/// The writer's document with one change.
fn edited(edit: impl FnOnce(&mut ManifestDocument)) -> ManifestDocument {
    let mut doc = release().manifest;
    edit(&mut doc);
    doc
}

/// `r` is the field error `rule`: the rule under test, not an earlier one.
fn field(r: Result<VerifiedManifest, Error>, rule: &str) {
    assert!(
        matches!(&r, Err(Error::Field(msg)) if *msg == rule),
        "want {rule:?}: {r:?}"
    );
}

#[test]
fn a_manifest_with_two_deltas_is_accepted() {
    let rel_ = release();
    let m = verify_doc(&rel_.manifest).unwrap();
    let deltas = m.deltas();
    assert_eq!(deltas.len(), 2);
    // Highest base first.
    assert_eq!(deltas[0].from_text(), "1.1.0");
    assert_eq!(deltas[1].from_text(), "1.0.0");
    assert_eq!(rel_.deltas.len(), 2);
    for (d, file) in deltas.iter().zip(&rel_.deltas) {
        assert_eq!(
            d.file().path(),
            format!("1.2.0/linux-x86_64.from-{}.delta", d.from_text())
        );
        assert_eq!(file.path, d.file().path());
        assert_eq!(d.file().size(), file.bytes.len() as u64);
        assert_eq!(d.file().sha256(), sha(&file.bytes));
        // Patches in entry order, back to back from offset 0, each hash its own bytes.
        let mut next = 0;
        for p in d.patches() {
            assert_eq!(p.offset(), next);
            let bytes = &file.bytes[p.offset() as usize..(p.offset() + p.length()) as usize];
            assert_eq!(p.sha256(), sha(bytes));
            assert_eq!(
                p.window(),
                patch_window(p.base_size(), p.file_size()).unwrap()
            );
            next += p.length();
        }
        assert_eq!(next, file.bytes.len() as u64);
    }
    let paths: Vec<&str> = deltas[0]
        .patches()
        .iter()
        .map(|p| p.path().as_str())
        .collect();
    assert_eq!(paths, ["bin/app", "lib/x.so.1"]);
    let app = &deltas[0].patches()[0];
    assert_eq!(app.codec(), CodecId::BcjX86Lzma2);
    assert_eq!(app.base_size(), 9);
    assert_eq!(app.base_sha256(), sha(b"app 1.1.0"));
    assert_eq!(app.file_size(), APP_SIZE);
    assert_eq!(app.window(), 4096);
    // The patch carries the entry's own size and hash.
    let entry_sha = m
        .entries()
        .iter()
        .find_map(|e| match e {
            lunepack_core::VerifiedEntry::File { path, sha256, .. }
                if path.as_str() == "bin/app" =>
            {
                Some(*sha256)
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(app.file_sha256(), entry_sha);
}

/// The payload `ReleaseLayout::finish` wrote for `tree_layout()` before deltas existed (captured
/// from the writer at 5c6fb4c): a layout with no delta writes exactly these bytes.
const NO_DELTA_PAYLOAD: &str = include_str!("golden/manifest-no-deltas.json");

#[test]
fn a_layout_without_deltas_writes_the_manifest_of_before() {
    let (doc, pack) = tree_layout().finish(SUITE_T0, &FakeHasher).unwrap();
    let payload = doc.to_payload();
    assert_eq!(
        String::from_utf8(payload.clone()).unwrap(),
        NO_DELTA_PAYLOAD.trim_end()
    );
    assert!(!String::from_utf8_lossy(&payload).contains("deltas"));
    let release = tree_layout().finish_release(SUITE_T0, &FakeHasher).unwrap();
    assert_eq!(release.manifest.to_payload(), payload);
    assert_eq!(release.pack, pack);
    assert!(release.deltas.is_empty());
    assert!(verify_doc(&doc).unwrap().deltas().is_empty());
    // `finish` never drops a delta file.
    let mut l = tree_layout();
    l.add_delta(
        "1.0.0",
        vec![(rel("bin/app"), patch(CodecId::Lzma2, b"p", b"old"))],
    )
    .unwrap();
    assert!(matches!(
        l.finish(SUITE_T0, &FakeHasher),
        Err(Error::Pack(PackError::Invariant(_)))
    ));
}

#[test]
fn the_delta_list_and_its_from_versions() {
    field(
        verify_doc(&edited(|d| d.deltas = Some(Vec::new()))),
        "deltas without a delta",
    );
    let r = verify_doc(&edited(|d| {
        let deltas = d.deltas.as_mut().unwrap();
        let first = deltas[0].clone();
        deltas.clear();
        for i in 1..=17 {
            let mut x = first.clone();
            x.from = format!("0.0.{i}");
            deltas.push(x);
        }
    }));
    assert!(
        matches!(
            r,
            Err(Error::TooMany {
                what: "deltas",
                count: 17,
                max: 16
            })
        ),
        "{r:?}"
    );
    // Sixteen are allowed.
    verify_doc(&edited(|d| {
        let deltas = d.deltas.as_mut().unwrap();
        let first = deltas[0].clone();
        deltas.clear();
        for i in 1..=16 {
            let mut x = first.clone();
            x.from = format!("0.0.{i}");
            deltas.push(x);
        }
    }))
    .unwrap();
    let r = verify_doc(&edited(|d| {
        d.deltas.as_mut().unwrap()[0].from = "1.1".into()
    }));
    assert!(matches!(r, Err(Error::Version(_))), "{r:?}");
    for from in ["1.2.0", "1.2.0+build.7", "1.3.0"] {
        field(
            verify_doc(&edited(|d| {
                d.deltas.as_mut().unwrap()[0].from = from.into()
            })),
            "delta from a version not below the release",
        );
    }
    // Two deltas whose `from` differ only in build metadata have equal precedence.
    field(
        verify_doc(&edited(|d| {
            d.deltas.as_mut().unwrap()[1].from = "1.1.0+other".into();
        })),
        "two deltas from versions of equal precedence",
    );
    // Build metadata alone is kept as written: a client matches the text byte for byte.
    let m = verify_doc(&edited(|d| {
        d.deltas.as_mut().unwrap()[0].from = "1.1.0+b.1".into()
    }))
    .unwrap();
    assert_eq!(m.deltas()[0].from_text(), "1.1.0+b.1");
}

#[test]
fn the_delta_file_reference() {
    let r = verify_doc(&edited(|d| {
        d.deltas.as_mut().unwrap()[0].path = "1.2.0/linux x86_64.delta".into();
    }));
    assert!(matches!(r, Err(Error::ReferenceChar)), "{r:?}");
    let r = verify_doc(&edited(|d| {
        d.deltas.as_mut().unwrap()[0].path = "../x.delta".into()
    }));
    assert!(matches!(r, Err(Error::Path(_))), "{r:?}");
    field(
        verify_doc(&edited(|d| {
            d.deltas.as_mut().unwrap()[0].size = U53::new(0).unwrap()
        })),
        "empty delta file",
    );
}

#[test]
fn the_patch_list() {
    field(
        verify_doc(&edited(|d| d.deltas.as_mut().unwrap()[0].patches.clear())),
        "delta without a patch",
    );
    // More than 200,000 patches: through the writer, whose own check is the reader's (a document
    // that large exceeds the manifest's byte cap before it reaches the rule).
    let mut l = tree_layout();
    let one = (rel("bin/app"), patch(CodecId::Lzma2, b"p", b"old"));
    l.add_delta("1.0.0", vec![one; 200_001]).unwrap();
    let r = l.finish_release(SUITE_T0, &FakeHasher);
    assert!(
        matches!(
            r,
            Err(Error::TooMany {
                what: "patches",
                count: 200_001,
                max: 200_000
            })
        ),
        "{:?}",
        r.err()
    );
    for (path, rule) in [
        ("share/doc", "patch for a path that is not a file entry"),
        ("lib/x.so", "patch for a path that is not a file entry"),
        ("share/empty", "patch for an empty file"),
        ("bin/other", "patch for a path that is not a file entry"),
    ] {
        field(
            verify_doc(&edited(|d| {
                d.deltas.as_mut().unwrap()[0].patches[0].path = rel(path);
            })),
            rule,
        );
    }
    field(
        verify_doc(&edited(|d| {
            let p = &mut d.deltas.as_mut().unwrap()[0].patches;
            p[1].path = p[0].path.clone();
        })),
        "two patches for one file in a delta",
    );
    // The same file in two deltas is fine (the accepted release has it).
}

#[test]
fn the_patch_fields() {
    let doc = release().manifest;
    let app_sha = doc
        .entries
        .iter()
        .find(|e| e.path.as_str() == "bin/app")
        .and_then(|e| e.sha256)
        .unwrap();
    let delta_size = doc.deltas.as_ref().unwrap()[0].size.get();
    let p0 = |edit: &dyn Fn(&mut lunepack_core::PatchDoc)| {
        verify_doc(&edited(|d| {
            edit(&mut d.deltas.as_mut().unwrap()[0].patches[0])
        }))
    };
    field(
        p0(&|p| p.base_size = U53::new(0).unwrap()),
        "patch from an empty base",
    );
    field(
        p0(&|p| p.base_sha256 = app_sha),
        "patch whose base is the file itself",
    );
    for codec in ["stored", "bcj2"] {
        field(
            p0(&|p| p.codec = codec.into()),
            "codec not allowed for a patch",
        );
    }
    for codec in ["LZMA2", "zstd", "lzma2 "] {
        let r = p0(&|p| p.codec = codec.into());
        assert!(matches!(r, Err(Error::UnknownCodec(_))), "{codec}: {r:?}");
    }
    for codec in ["lzma2", "bcj-x86+lzma2", "bcj-arm64+lzma2"] {
        p0(&|p| p.codec = codec.into()).unwrap();
    }
    field(p0(&|p| p.length = U53::new(0).unwrap()), "empty patch");
    field(
        p0(&|p| p.offset = U53::new(delta_size).unwrap()),
        "patch outside its delta file",
    );
    field(
        p0(&|p| {
            p.offset = U53::new(1).unwrap();
            p.length = U53::new(delta_size).unwrap();
        }),
        "patch outside its delta file",
    );
    field(
        p0(&|p| {
            p.offset = U53::new(U53::MAX.get()).unwrap();
            p.length = U53::new(U53::MAX.get()).unwrap();
        }),
        "patch outside its delta file",
    );
    // Patches may overlap or repeat, and bytes no patch covers are allowed.
    verify_doc(&edited(|d| {
        let p = &mut d.deltas.as_mut().unwrap()[0].patches;
        p[1].offset = p[0].offset;
        p[1].length = p[0].length;
    }))
    .unwrap();
}

#[test]
fn the_patch_window_is_at_most_128_mib() {
    assert_eq!(MAX_PATCH_WINDOW, 134_217_728);
    // `base_size + size` of exactly 128 MiB: the window is 128 MiB.
    let at_cap = MAX_PATCH_WINDOW - APP_SIZE;
    assert_eq!(patch_window(at_cap, APP_SIZE), Some(MAX_PATCH_WINDOW));
    let m = verify_doc(&edited(|d| {
        d.deltas.as_mut().unwrap()[0].patches[0].base_size = U53::new(at_cap).unwrap();
    }))
    .unwrap();
    assert_eq!(m.deltas()[0].patches()[0].window(), MAX_PATCH_WINDOW);
    // One byte more rounds up past the cap.
    field(
        verify_doc(&edited(|d| {
            d.deltas.as_mut().unwrap()[0].patches[0].base_size = U53::new(at_cap + 1).unwrap();
        })),
        "patch window above 128 MiB",
    );
    field(
        verify_doc(&edited(|d| {
            d.deltas.as_mut().unwrap()[0].patches[0].base_size = U53::MAX;
        })),
        "patch window above 128 MiB",
    );
    assert_eq!(patch_window(u64::MAX, 1), None);
    assert_eq!(patch_window(u64::MAX - 1, 0), None);
    assert_eq!(patch_window(1, 0), Some(4096));
    assert_eq!(patch_window(4096, 0), Some(4096));
}

#[test]
fn unknown_members_are_ignored_and_duplicates_and_nulls_rejected() {
    let text = String::from_utf8(release().manifest.to_payload()).unwrap();
    for (from, to) in [
        ("\"base_size\"", "\"note\":{\"x\":1},\"base_size\""),
        ("\"patches\"", "\"note\":\"x\",\"patches\""),
    ] {
        let edited = text.replacen(from, to, 1);
        assert_ne!(edited, text);
        verify_payload(edited.as_bytes()).unwrap();
    }
    for (from, to) in [
        ("\"base_size\"", "\"length\":1,\"base_size\""),
        ("\"patches\"", "\"from\":\"0.1.0\",\"patches\""),
        ("\"deltas\":[", "\"deltas\":null,\"x\":["),
        ("\"base_size\"", "\"codec\":null,\"base_size\""),
    ] {
        let edited = text.replacen(from, to, 1);
        assert_ne!(edited, text);
        let r = verify_payload(edited.as_bytes());
        assert!(
            matches!(r, Err(Error::Schema(_)) | Err(Error::Json(_))),
            "{to}: {r:?}"
        );
    }
    // An uppercase digest is not a digest.
    let sha = release().manifest.deltas.unwrap()[0].patches[0].base_sha256;
    let hex = format!("{sha}");
    assert_eq!(hex.len(), 64, "Display is the hex form");
    let upper = text.replacen(&hex, &hex.to_uppercase(), 1);
    assert_ne!(upper, text);
    let r = verify_payload(upper.as_bytes());
    assert!(matches!(r, Err(Error::Schema(_))), "{r:?}");
}

#[test]
fn install_stays_reserved() {
    let text = String::from_utf8(release().manifest.to_payload()).unwrap();
    let edited = text.replacen("\"issued\"", "\"install\":{},\"issued\"", 1);
    field(verify_payload(edited.as_bytes()), "reserved manifest field");
}
