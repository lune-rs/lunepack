//! M12 step 3 with the real codec: a release written by the core's `ReleaseLayout` with a delta
//! made by `LzmaCodec::encode_patch`, verified through a signed feed, staged by the core's `stage`
//! from patch sources against the current tree, on the testkit's `MemFs`.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::{
    AppId, CancelToken, Channel, ClockReading, CodecId, DeltaPatch, Encoder, FileKind, Fs, Hasher,
    PatchSource, PayloadKind, RelPath, ReleaseLayout, RollbackFloor, SourceFor, StageEnv,
    StageError, StageInput, Target, VerifiedManifest, pack_file, stage, verify_feed,
    verify_manifest,
};
use lunepack_testkit::{
    ChainFixture, FakeClock, FakeHasher, MemFs, SUITE_APP_ID, SUITE_CHANNEL, SUITE_T0,
};

const VERSION: &str = "2.0.0";
const FROM: &str = "1.0.0";
const TARGET: Target = Target::LinuxX86_64;

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect()
}

fn put(fs: &dyn Fs, path: &Path, bytes: &[u8]) {
    fs.create_dir_all(path.parent().unwrap()).unwrap();
    if fs.symlink_metadata(path).unwrap().is_some() {
        fs.remove_file(path).unwrap();
    }
    let mut w = fs.create_new(path).unwrap();
    w.write_all(bytes).unwrap();
    w.sync().unwrap();
}

/// One patched file: its path, the base (in the current tree), the new bytes and the patch.
struct Patched {
    path: String,
    base: Vec<u8>,
    new: Vec<u8>,
    patch: Vec<u8>,
}

/// The release: "bin/app" (a BCJ x86 patch from 1.0.0) and "share/data" (a plain one).
fn release(fx: &ChainFixture<'_>) -> (VerifiedManifest, Vec<Patched>) {
    let mut layout =
        ReleaseLayout::new(AppId::parse(SUITE_APP_ID).unwrap(), VERSION, TARGET).unwrap();
    let mut files = Vec::new();
    let mut patches = Vec::new();
    for (path, len, seed, codec) in [
        ("bin/app", 200_000, 1, CodecId::BcjX86Lzma2),
        ("share/data", 120_000, 2, CodecId::Lzma2),
    ] {
        let base = noise(len, seed);
        let mut new = base.clone();
        new[len / 3..len / 3 + 512].copy_from_slice(&noise(512, seed + 10));
        new.extend_from_slice(&noise(1000, seed + 20));
        let packed = pack_file(&new, &LzmaCodec, &LzmaCodec, &FakeHasher).unwrap();
        layout
            .add_file(RelPath::parse(path).unwrap(), false, &packed)
            .unwrap();
        let patch = LzmaCodec.encode_patch(codec, &base, &new).unwrap().bytes;
        patches.push((
            RelPath::parse(path).unwrap(),
            DeltaPatch {
                codec,
                bytes: patch.clone(),
                base_size: base.len() as u64,
                base_sha256: FakeHasher.sha256(&base),
            },
        ));
        files.push(Patched {
            path: path.to_owned(),
            base,
            new,
            patch,
        });
    }
    layout.add_delta(FROM, patches).unwrap();
    let finished = layout.finish_release(SUITE_T0, &FakeHasher).unwrap();

    let (_, keys) = fx.verified_chain(&[5], 1);
    let bytes = fx.envelope(PayloadKind::Manifest, &finished.manifest.to_payload(), &[5]);
    let feed_doc = fx.feed_document(
        1,
        None,
        vec![fx.release(VERSION, &[(TARGET, &bytes)], None)],
    );
    let feed_bytes = fx.envelope(PayloadKind::Feed, &feed_doc.to_payload(), &[5]);
    let feed = verify_feed(
        &keys,
        &feed_bytes,
        &AppId::parse(SUITE_APP_ID).unwrap(),
        &Channel::parse(SUITE_CHANNEL).unwrap(),
        &RollbackFloor::default(),
        &ClockReading::read(&FakeClock::new(SUITE_T0), None),
        fx.verifier,
    )
    .unwrap();
    let entry = feed.target_entry(0, TARGET).unwrap();
    let m = verify_manifest(&keys, &entry, &bytes, fx.hasher, fx.verifier).unwrap();
    (m, files)
}

fn versions() -> PathBuf {
    PathBuf::from("/data/versions")
}

/// Whether any `.lptmp` file is left under `dir`.
fn any_tmp(fs: &dyn Fs, dir: &Path) -> bool {
    fs.list_dir(dir).unwrap().iter().any(|e| match e.kind {
        FileKind::Dir => any_tmp(fs, &dir.join(&e.name)),
        _ => e.name.to_string_lossy().ends_with(".lptmp"),
    })
}

/// Writes the bases (the first one with a byte changed when `damage`) and patches into `fs`, and
/// returns the patch sources in manifest order.
fn world(fs: &dyn Fs, m: &VerifiedManifest, files: &[Patched], damage: bool) -> Vec<SourceFor> {
    let current = versions().join(FROM);
    let delta = &m.deltas()[0];
    m.entries()
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let desc = delta
                .patches()
                .iter()
                .find(|p| p.path() == e.path())
                .unwrap()
                .clone();
            let f = files.iter().find(|f| f.path == e.path().as_str()).unwrap();
            let mut base = f.base.clone();
            if damage && i == 0 {
                base[100] ^= 1;
            }
            let patch = PathBuf::from(format!("/data/cache/patch-{i}"));
            put(fs, &current.join(&f.path), &base);
            put(fs, &patch, &f.patch);
            SourceFor::Patch(PatchSource {
                patch,
                base: current.join(&f.path),
                desc,
            })
        })
        .collect()
}

#[test]
fn patch_sources_stage_with_the_lzma_codec() {
    let fx = ChainFixture::fake();
    let (m, files) = release(&fx);
    let cancel = CancelToken::new();
    for damage in [false, true] {
        let fs = MemFs::new();
        let input = StageInput {
            manifest: &m,
            versions_dir: versions(),
            sources: world(&fs, &m, &files, damage),
        };
        let env = StageEnv {
            fs: &fs,
            codec: &LzmaCodec,
            hasher: &FakeHasher,
            workers: 2,
            budget_bytes: 256 << 20,
            cancel: &cancel,
            progress: &|_| {},
        };
        match (damage, stage(&input, &env)) {
            (false, Ok(staged)) => {
                for f in &files {
                    let got = fs.read_capped(&staged.tree.join(&f.path), 1 << 20).unwrap();
                    assert_eq!(got, f.new, "{}", f.path);
                }
            }
            // A base with one byte changed is NeedFetch for that path alone.
            (true, Err(StageError::NeedFetch(list))) => {
                assert_eq!(list, [m.entries()[0].path().clone()]);
                assert!(!any_tmp(&fs, &versions()));
            }
            (damage, other) => panic!("damage {damage}: {other:?}"),
        }
    }
}
