//! Stable-toolchain replay of the codec crate's fuzz harnesses (M13 step 2): the committed seeds
//! under `fuzz/seeds/codec` and `fuzz/seeds/patch` are exactly what this crate's own encoder makes,
//! every seed runs through its harness as expected (a `bad-` seed is refused for the reason its
//! name gives), and random and mutated inputs never panic. The libFuzzer targets in `fuzz/` call
//! the same harnesses (`lunepack_codec_lzma::fuzz`).
//!
//! To rewrite the committed seeds after an encoder change:
//! `LUNEPACK_WRITE_SEEDS=1 cargo test -p lunepack-codec-lzma --test fuzz_replay committed_seeds`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use lunepack_codec_lzma::LzmaCodec;
use lunepack_codec_lzma::fuzz::{
    HARNESSES, PATCH_EXPLICIT_WINDOW, accepts, codec_verdict, patch_verdict,
};
use lunepack_core::{CodecId, Encoder};
use lunepack_testkit::replay::{mutated_seeds, random_inputs, seed_neighbourhood};

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

fn seed_dir(harness: &str) -> PathBuf {
    fuzz_dir().join("seeds").join(harness)
}

/// One seed input of one harness (the shape of `lunepack_testkit::Seed`).
#[derive(Debug, Clone)]
struct Seed {
    harness: &'static str,
    name: String,
    bytes: Vec<u8>,
    accepted: bool,
    /// For a `bad-` seed: text its refusal contains.
    reason: Option<&'static str>,
}

// ---- the seed writers ------------------------------------------------------------------------------

/// Selector bytes of `codec`: the index in `fuzz::IDS`.
fn selector(id: CodecId) -> u8 {
    match id {
        CodecId::Stored => 0,
        CodecId::Lzma2 => 1,
        CodecId::BcjX86Lzma2 => 2,
        CodecId::BcjArm64Lzma2 => 3,
        CodecId::Bcj2 => 4,
    }
}

/// A `codec` input: selector, output size, one header per stream, the streams' bytes.
fn frame_input(id: CodecId, output_size: u32, streams: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut out = vec![selector(id)];
    out.extend_from_slice(&output_size.to_be_bytes());
    for (i, (dict, decoded, bytes)) in streams.iter().enumerate() {
        out.extend_from_slice(&dict.to_be_bytes());
        out.extend_from_slice(&decoded.to_be_bytes());
        if i + 1 < streams.len() {
            out.extend_from_slice(
                &u16::try_from(bytes.len())
                    .expect("a short stream")
                    .to_be_bytes(),
            );
        }
    }
    for (_, _, bytes) in streams {
        out.extend_from_slice(bytes);
    }
    out
}

/// A `patch` input: selector, base length, base size, output size, an explicit window or none,
/// the base, the patch.
fn patch_input(
    id: CodecId,
    base: &[u8],
    base_size: u32,
    output_size: u32,
    window: Option<u32>,
    patch: &[u8],
) -> Vec<u8> {
    let mut out = vec![
        selector(id)
            | if window.is_some() {
                PATCH_EXPLICIT_WINDOW
            } else {
                0
            },
    ];
    out.extend_from_slice(
        &u16::try_from(base.len())
            .expect("a short base")
            .to_be_bytes(),
    );
    out.extend_from_slice(&base_size.to_be_bytes());
    out.extend_from_slice(&output_size.to_be_bytes());
    if let Some(w) = window {
        out.extend_from_slice(&w.to_be_bytes());
    }
    out.extend_from_slice(base);
    out.extend_from_slice(patch);
    out
}

/// Deterministic, compressible bytes with x86-like call opcodes and ARM64-like `bl` words in them.
fn sample(len: usize, salt: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x = 0x2545_f491u32 ^ salt;
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        match x % 5 {
            0 => out.extend_from_slice(&[0xe8, (x >> 8) as u8, (x >> 16) as u8, 0, 0]),
            1 => out.extend_from_slice(&[(x >> 8) as u8, (x >> 16) as u8, 0x00, 0x94]),
            2 => out.extend_from_slice(b"lunepack "),
            3 => out.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5]),
            _ => out.push((x >> 24) as u8),
        }
    }
    out.truncate(len);
    out
}

fn seeds() -> Vec<Seed> {
    let mut out = Vec::new();
    let mut add = |harness, name: &str, bytes: Vec<u8>, reason: Option<&'static str>| {
        out.push(Seed {
            harness,
            name: name.to_owned(),
            bytes,
            accepted: reason.is_none(),
            reason,
        });
    };
    let data = sample(3000, 1);
    let size = u32::try_from(data.len()).unwrap();

    // `codec`: one round trip per codec id.
    let enc = |id| LzmaCodec.encode(id, &data).expect("encode");
    let stored = enc(CodecId::Stored);
    add(
        "codec",
        "ok-stored",
        frame_input(CodecId::Stored, size, &[(0, size, &stored.bytes)]),
        None,
    );
    let mut lzma2_frame = None;
    for (name, id) in [
        ("ok-lzma2", CodecId::Lzma2),
        ("ok-bcj-x86-lzma2", CodecId::BcjX86Lzma2),
        ("ok-bcj-arm64-lzma2", CodecId::BcjArm64Lzma2),
    ] {
        let f = enc(id);
        let dict = f.dict_size.expect("an LZMA2 dictionary");
        add(
            "codec",
            name,
            frame_input(id, size, &[(dict, size, &f.bytes)]),
            None,
        );
        if id == CodecId::Lzma2 {
            lzma2_frame = Some((dict, f.bytes));
        }
    }
    let bcj2 = enc(CodecId::Bcj2);
    let parts = bcj2.streams.expect("four streams");
    let mut at = 0usize;
    let mut slices = Vec::new();
    for s in &parts {
        let len = usize::try_from(s.length).unwrap();
        slices.push((
            s.dict_size.unwrap_or(0),
            u32::try_from(s.decoded_size).unwrap(),
            &bcj2.bytes[at..at + len],
        ));
        at += len;
    }
    assert_eq!(at, bcj2.bytes.len());
    add(
        "codec",
        "ok-bcj2",
        frame_input(CodecId::Bcj2, size, &slices),
        None,
    );

    // `codec`: refusals.
    let (dict, lzma2) = lzma2_frame.expect("the lzma2 frame");
    add(
        "codec",
        "bad-truncated-stream",
        frame_input(
            CodecId::Lzma2,
            size,
            &[(dict, size, &lzma2[..lzma2.len() / 2])],
        ),
        Some("decoder failed"),
    );
    let mut flipped = lzma2.clone();
    // 0x03 is no LZMA2 control byte (0x00 end, 0x01 and 0x02 stored chunks, 0x80.. LZMA chunks).
    flipped[0] = 0x03;
    add(
        "codec",
        "bad-corrupt-chunk-header",
        frame_input(CodecId::Lzma2, size, &[(dict, size, &flipped)]),
        Some("decoder failed"),
    );
    add(
        "codec",
        "bad-wrong-declared-size",
        frame_input(CodecId::Lzma2, size + 1, &[(dict, size + 1, &lzma2)]),
        Some("decoded to 3000 bytes, the descriptor says 3001"),
    );
    add(
        "codec",
        "bad-dict-over-cap",
        frame_input(CodecId::Lzma2, size, &[(32 << 20, size, &lzma2)]),
        Some("dict_size is outside the format's range"),
    );

    // `patch`: one round trip per patch codec.
    let base = sample(2500, 2);
    let mut new = base.clone();
    new.splice(1200..1210, sample(40, 3));
    let base_size = u32::try_from(base.len()).unwrap();
    let new_size = u32::try_from(new.len()).unwrap();
    let mut lzma2_patch = None;
    for (name, id) in [
        ("ok-lzma2", CodecId::Lzma2),
        ("ok-bcj-x86-lzma2", CodecId::BcjX86Lzma2),
        ("ok-bcj-arm64-lzma2", CodecId::BcjArm64Lzma2),
    ] {
        let p = LzmaCodec
            .encode_patch(id, &base, &new)
            .expect("patch")
            .bytes;
        add(
            "patch",
            name,
            patch_input(id, &base, base_size, new_size, None, &p),
            None,
        );
        if id == CodecId::Lzma2 {
            lzma2_patch = Some(p);
        }
    }
    let p = lzma2_patch.expect("the lzma2 patch");
    add(
        "patch",
        "bad-truncated-stream",
        patch_input(
            CodecId::Lzma2,
            &base,
            base_size,
            new_size,
            None,
            &p[..p.len() / 2],
        ),
        Some("decoder failed"),
    );
    let mut flipped = p.clone();
    flipped[0] = 0x03;
    add(
        "patch",
        "bad-corrupt-chunk-header",
        patch_input(CodecId::Lzma2, &base, base_size, new_size, None, &flipped),
        Some("decoder failed"),
    );
    add(
        "patch",
        "bad-wrong-declared-size",
        patch_input(CodecId::Lzma2, &base, base_size, new_size + 1, None, &p),
        Some("decoded to 2530 bytes, the descriptor says 2531"),
    );
    add(
        "patch",
        "bad-window-over-cap",
        patch_input(
            CodecId::Lzma2,
            &base,
            base_size,
            new_size,
            Some(256 << 20),
            &p,
        ),
        Some("the patch window is not the format's"),
    );
    add(
        "patch",
        "bad-stored-patch",
        patch_input(CodecId::Stored, &base, base_size, new_size, None, &new),
        Some("is not supported"),
    );
    out
}

fn seeds_of(harness: &str) -> Vec<Seed> {
    seeds()
        .into_iter()
        .filter(|s| s.harness == harness)
        .collect()
}

fn run(harness: &str, data: &[u8]) -> bool {
    accepts(harness, data).unwrap_or_else(|| panic!("no harness named {harness}"))
}

fn verdict(harness: &str, data: &[u8]) -> Result<(), String> {
    match harness {
        "codec" => codec_verdict(data),
        "patch" => patch_verdict(data),
        other => panic!("no harness named {other}"),
    }
}

// ---- the replay ------------------------------------------------------------------------------------

#[test]
fn committed_seeds_match_the_writer() {
    let write = std::env::var_os("LUNEPACK_WRITE_SEEDS").is_some();
    let mut problems = Vec::new();
    let mut expected: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for seed in &seeds() {
        expected
            .entry(seed.harness)
            .or_default()
            .insert(seed.name.clone());
        let path = seed_dir(seed.harness).join(&seed.name);
        if write {
            fs::create_dir_all(seed_dir(seed.harness)).expect("create seed dir");
            fs::write(&path, &seed.bytes).expect("write seed");
            continue;
        }
        match fs::read(&path) {
            Ok(committed) if committed == seed.bytes => {}
            Ok(_) => problems.push(format!(
                "{}/{} differs from the writer",
                seed.harness, seed.name
            )),
            Err(_) => problems.push(format!("{}/{} is not committed", seed.harness, seed.name)),
        }
    }
    for (harness, _) in HARNESSES {
        let names = expected.get(harness).cloned().unwrap_or_default();
        assert!(!names.is_empty(), "harness {harness} has no seeds");
        if let Ok(dir) = fs::read_dir(seed_dir(harness)) {
            for entry in dir.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !names.contains(&name) {
                    problems.push(format!(
                        "{harness}/{name} is committed but no writer makes it"
                    ));
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "seeds out of date (rerun with LUNEPACK_WRITE_SEEDS=1):\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_harness_has_a_fuzz_target_and_both_kinds_of_seed() {
    for (harness, _) in HARNESSES {
        let target = fuzz_dir()
            .join("fuzz_targets")
            .join(format!("{harness}.rs"));
        let source = fs::read_to_string(&target).unwrap_or_else(|e| {
            panic!("no fuzz target for {harness} at {}: {e}", target.display())
        });
        assert!(
            source.contains(&format!("lunepack_codec_lzma::fuzz::{harness}(")),
            "{} does not call lunepack_codec_lzma::fuzz::{harness}",
            target.display()
        );
        let seeds = seeds_of(harness);
        assert!(
            seeds.iter().any(|s| s.accepted),
            "{harness}: no accepted seed"
        );
        assert!(
            seeds.iter().any(|s| !s.accepted),
            "{harness}: no rejected seed"
        );
    }
}

/// Every codec id of the closed set is reachable from `codec` (an accepted seed each) and from
/// `patch` (an accepted seed for the three patch ids, the codec's own refusal for the other two).
#[test]
fn every_codec_id_is_reachable() {
    let names: BTreeSet<String> = seeds_of("codec")
        .into_iter()
        .filter(|s| s.accepted)
        .map(|s| s.name)
        .collect();
    let want: BTreeSet<String> = [
        "ok-stored",
        "ok-lzma2",
        "ok-bcj-x86-lzma2",
        "ok-bcj-arm64-lzma2",
        "ok-bcj2",
    ]
    .map(str::to_owned)
    .into();
    assert_eq!(names, want);
    for seed in seeds_of("codec").iter().filter(|s| s.accepted) {
        assert_eq!(codec_verdict(&seed.bytes), Ok(()), "codec/{}", seed.name);
    }
    let accepted = seeds_of("patch").iter().filter(|s| s.accepted).count();
    assert_eq!(accepted, 3);
    // The other two ids reach the decoder and are refused there.
    let ok = seeds_of("patch")
        .into_iter()
        .find(|s| s.name == "ok-lzma2")
        .expect("the lzma2 patch seed");
    for sel in [0u8, 4] {
        let mut data = ok.bytes.clone();
        data[0] = sel;
        let err = patch_verdict(&data).expect_err("not a patch codec");
        assert!(err.contains("is not supported"), "selector {sel}: {err}");
    }
    // The selector's high bits other than the explicit-window bit are ignored; the window is
    // then the format's.
    let mut data = ok.bytes.clone();
    data[0] |= 0x08;
    assert_eq!(patch_verdict(&data), Ok(()));
}

#[test]
fn committed_seeds_run_as_expected() {
    for (harness, _) in HARNESSES {
        let expected: BTreeMap<String, Seed> = seeds_of(harness)
            .into_iter()
            .map(|s| (s.name.clone(), s))
            .collect();
        let mut seen = 0;
        for entry in fs::read_dir(seed_dir(harness)).expect("seed dir").flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let bytes = fs::read(entry.path()).expect("read seed");
            let got = run(harness, &bytes);
            let seed = expected
                .get(&name)
                .unwrap_or_else(|| panic!("{harness}/{name}: no writer makes it"));
            assert_eq!(
                got, seed.accepted,
                "{harness}/{name}: accepted = {got}, expected {}",
                seed.accepted
            );
            let result = verdict(harness, &bytes);
            match (seed.accepted, seed.reason) {
                (true, None) => assert_eq!(result, Ok(()), "{harness}/{name}"),
                (false, Some(reason)) => {
                    let err = result.expect_err(&name);
                    assert!(
                        err.contains(reason),
                        "{harness}/{name}: refused with {err:?}, expected a reason containing {reason:?}"
                    );
                }
                other => panic!("{harness}/{name}: {other:?}"),
            }
            seen += 1;
        }
        assert_eq!(seen, expected.len(), "{harness}: committed seeds");
    }
}

/// The two cap cases are refused by the codec's own check, whatever the stream says: a
/// dictionary over 16 MiB (any size above the cap, a power of two or not) and a window over
/// 128 MiB (a window that is the format's window of the sizes, at the cap and above it).
#[test]
fn the_caps_are_the_codecs_own_refusal() {
    let lzma2 = seeds_of("codec")
        .into_iter()
        .find(|s| s.name == "ok-lzma2")
        .expect("the lzma2 seed");
    // Header: selector, output size (4), then the stream's dictionary size.
    for dict in [(16u32 << 20) + 1, 32 << 20, 1 << 30, u32::MAX] {
        let mut data = lzma2.bytes.clone();
        data[5..9].copy_from_slice(&dict.to_be_bytes());
        let err = codec_verdict(&data).expect_err("a dictionary over the cap");
        assert!(err.contains("dict_size is outside"), "{dict}: {err}");
    }
    let patch = seeds_of("patch")
        .into_iter()
        .find(|s| s.name == "ok-lzma2")
        .expect("the lzma2 patch seed");
    // Header: selector, base length (2), base size (4), output size (4).
    for window in [(128u32 << 20) + 4096, 256 << 20, u32::MAX] {
        let mut data = patch.bytes.clone();
        data[0] |= PATCH_EXPLICIT_WINDOW;
        data.splice(11..11, window.to_be_bytes());
        let err = patch_verdict(&data).expect_err("a window over the cap");
        assert!(err.contains("the patch window is not"), "{window}: {err}");
    }
}

/// Every single-byte change, every truncation and every one-byte insertion of every seed (strided
/// for the largest seeds so the whole test stays quick).
#[test]
fn seed_neighbourhoods_do_not_panic() {
    for (harness, _) in HARNESSES {
        for seed in seeds_of(harness) {
            seed_neighbourhood(&seed.bytes, |data| {
                run(harness, data);
            });
        }
    }
}

fn replay_harness(harness: &str) {
    random_inputs(harness, |data| {
        run(harness, data);
    });
    mutated_seeds(
        harness,
        seeds_of(harness).into_iter().map(|s| s.bytes).collect(),
        |data| {
            run(harness, data);
        },
    );
}

#[test]
fn codec() {
    replay_harness("codec");
}

#[test]
fn patch() {
    replay_harness("patch");
}

#[test]
fn the_replay_list_covers_every_harness() {
    let all: BTreeSet<&str> = HARNESSES.iter().map(|(n, _)| *n).collect();
    assert_eq!(all, BTreeSet::from(["codec", "patch"]));
}
