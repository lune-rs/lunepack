//! M12 step 2: delta patches through the LZMA codec (FORMAT.md 9.3): round trips of the three
//! patch codecs on generated data (a base and a modified copy), and the decoder's refusals.

use std::io::{self, Write};

use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::error::CodecError;
use lunepack_core::frame::{MAX_PATCH_WINDOW, patch_window};
use lunepack_core::{Codec, CodecId, Encoder, Error, PatchView};

const PATCH_CODECS: [CodecId; 3] = [CodecId::Lzma2, CodecId::BcjX86Lzma2, CodecId::BcjArm64Lzma2];

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 32) as u8).collect()
    }
}

/// x86-like code: filler and CALL/JMP opcodes with small relative operands.
fn x86_like(len: usize, rng: &mut XorShift) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.push(0x48 + (rng.next() >> 61) as u8);
        out.push(if rng.next() & 1 == 0 { 0xE8 } else { 0xE9 });
        out.extend_from_slice(&((rng.next() >> 48) as u32 & 0xFFFF).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The base and a modified copy: a few spans overwritten, one inserted and one removed, so the
/// new file shares most of its bytes with the base at shifted positions.
fn pair(len: usize, seed: u64) -> (Vec<u8>, Vec<u8>) {
    let mut rng = XorShift(seed);
    let base = x86_like(len, &mut rng);
    let mut new = base.clone();
    for at in [len / 7, len / 3, len / 2] {
        let span = rng.bytes(64);
        new[at..at + 64].copy_from_slice(&span);
    }
    new.splice(len / 4..len / 4, rng.bytes(300));
    new.drain(len * 3 / 4..len * 3 / 4 + 200);
    (base, new)
}

fn view<'a>(codec: CodecId, input: &'a [u8], base: &[u8], output_size: u64) -> PatchView<'a> {
    PatchView {
        codec,
        input,
        base_size: base.len() as u64,
        output_size,
        window: patch_window(base.len() as u64, output_size).unwrap(),
    }
}

fn decode(view: &PatchView<'_>, base: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    LzmaCodec.decode_patch(view, base, &mut out)?;
    Ok(out)
}

#[test]
fn patches_round_trip_and_are_much_smaller_than_frames() {
    let (base, new) = pair(256 * 1024, 7);
    for codec in PATCH_CODECS {
        let patch = LzmaCodec.encode_patch(codec, &base, &new).unwrap();
        assert_eq!(patch.codec, codec);
        let again = LzmaCodec.encode_patch(codec, &base, &new).unwrap();
        assert_eq!(patch, again, "{codec:?}: deterministic");
        let v = view(codec, &patch.bytes, &base, new.len() as u64);
        let mut out = Vec::new();
        let report = LzmaCodec.decode_patch(&v, &base, &mut out).unwrap();
        assert_eq!(out, new, "{codec:?}: round trip");
        assert_eq!(report.consumed, vec![patch.bytes.len() as u64]);
        // The generated operands are relative and do not move with the insertion, so BCJ's
        // absolute addresses differ after it: only the plain codec is held to a tenth here.
        let frame = LzmaCodec.encode(codec, &new).unwrap();
        let ratio = if codec == CodecId::Lzma2 { 10 } else { 1 };
        assert!(
            patch.bytes.len() * ratio < frame.bytes.len(),
            "{codec:?}: patch {} vs frame {}",
            patch.bytes.len(),
            frame.bytes.len()
        );
    }
}

#[test]
fn small_and_unrelated_inputs_round_trip() {
    let mut rng = XorShift(11);
    for (base, new) in [
        (vec![1u8], vec![2u8]),
        (rng.bytes(1), rng.bytes(5000)),
        (rng.bytes(70_000), rng.bytes(3)),
        (rng.bytes(4096), rng.bytes(4096)),
    ] {
        for codec in PATCH_CODECS {
            let patch = LzmaCodec.encode_patch(codec, &base, &new).unwrap();
            let v = view(codec, &patch.bytes, &base, new.len() as u64);
            assert_eq!(decode(&v, &base).unwrap(), new, "{codec:?} {}", base.len());
        }
    }
}

#[test]
fn a_wrong_base_never_panics_and_changes_what_it_feeds() {
    // A base with one byte flipped: decoding never panics, and a flip in bytes the patch copies
    // from changes the output or fails. A byte the patch never reads (the encoder found no match
    // there) decodes to the file unchanged, which is right: the core's file hash decides.
    let (base, new) = pair(64 * 1024, 3);
    for codec in PATCH_CODECS {
        let patch = LzmaCodec.encode_patch(codec, &base, &new).unwrap();
        let v = view(codec, &patch.bytes, &base, new.len() as u64);
        let mut changed = 0;
        let positions: Vec<usize> = (0..64).map(|k| k * base.len() / 64 + 5).collect();
        for &at in &positions {
            let mut wrong = base.clone();
            wrong[at] ^= 0x01;
            if decode(&v, &wrong).map_or(true, |out| out != new) {
                changed += 1;
            }
        }
        // The plain codec copies from the whole base; BCJ's matches end at the insertion (the
        // generated operands do not move with it), so only the base's first quarter feeds it.
        let want = if codec == CodecId::Lzma2 { 48 } else { 8 };
        assert!(
            changed >= want,
            "{codec:?}: only {changed} of {} flips changed the output",
            positions.len()
        );
    }
}

#[test]
fn truncated_and_trailing_patches_are_errors() {
    let (base, new) = pair(64 * 1024, 5);
    for codec in PATCH_CODECS {
        let patch = LzmaCodec.encode_patch(codec, &base, &new).unwrap();
        let n = new.len() as u64;
        let short = &patch.bytes[..patch.bytes.len() - 1];
        assert!(
            decode(&view(codec, short, &base, n), &base).is_err(),
            "{codec:?}: short"
        );
        let mut long = patch.bytes.clone();
        long.push(0);
        let r = decode(&view(codec, &long, &base, n), &base);
        assert!(
            matches!(r, Err(Error::Codec(CodecError::Corrupt(_)))),
            "{codec:?}: trailing: {r:?}"
        );
    }
}

/// Counts the bytes written.
struct Count(u64);

impl Write for Count {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_output_stops_at_the_signed_size() {
    let (base, new) = pair(64 * 1024, 9);
    for codec in PATCH_CODECS {
        let patch = LzmaCodec.encode_patch(codec, &base, &new).unwrap();
        let fewer = new.len() as u64 - 1;
        let mut out = Count(0);
        let r = LzmaCodec.decode_patch(&view(codec, &patch.bytes, &base, fewer), &base, &mut out);
        assert!(
            matches!(r, Err(Error::Codec(CodecError::StreamSize { .. }))),
            "{codec:?}: {r:?}"
        );
        assert!(out.0 <= fewer, "{codec:?}: wrote {} > {fewer}", out.0);
        // One more than the file: a short output.
        let more = new.len() as u64 + 1;
        let r = decode(&view(codec, &patch.bytes, &base, more), &base);
        assert!(r.is_err(), "{codec:?}: a short output decoded");
    }
}

#[test]
fn the_view_is_checked_before_anything_is_decoded() {
    let (base, new) = pair(16 * 1024, 13);
    let patch = LzmaCodec.encode_patch(CodecId::Lzma2, &base, &new).unwrap();
    let n = new.len() as u64;
    let good = view(CodecId::Lzma2, &patch.bytes, &base, n);
    for codec in [CodecId::Stored, CodecId::Bcj2] {
        let r = decode(&PatchView { codec, ..good }, &base);
        assert!(
            matches!(r, Err(Error::Codec(CodecError::Unsupported(c))) if c == codec),
            "{codec:?}: {r:?}"
        );
    }
    let corrupt = |v: PatchView<'_>, base: &[u8], what: &str| {
        let r = decode(&v, base);
        assert!(
            matches!(r, Err(Error::Codec(CodecError::Corrupt(_)))),
            "{what}: {r:?}"
        );
    };
    corrupt(good, &base[1..], "a base shorter than base_size");
    corrupt(
        PatchView {
            window: good.window + 4096,
            ..good
        },
        &base,
        "a window that is not the format's",
    );
    corrupt(
        PatchView {
            window: good.window - 4096,
            ..good
        },
        &base,
        "a window below the sizes",
    );
    // A window above 128 MiB is refused from the sizes alone: no base of that size is needed.
    let huge = PatchView {
        codec: CodecId::Lzma2,
        input: &patch.bytes,
        base_size: MAX_PATCH_WINDOW,
        output_size: 1,
        window: patch_window(MAX_PATCH_WINDOW, 1).unwrap(),
    };
    corrupt(huge, &base, "base length differs first");
    // The encoder refuses the same window.
    let r = LzmaCodec.encode_patch(
        CodecId::Lzma2,
        &[0u8; 1],
        &vec![0u8; MAX_PATCH_WINDOW as usize],
    );
    assert!(r.is_err(), "an encode above the window cap");
    for codec in [CodecId::Stored, CodecId::Bcj2] {
        let r = LzmaCodec.encode_patch(codec, &base, &new);
        assert!(
            matches!(r, Err(Error::Codec(CodecError::Unsupported(c))) if c == codec),
            "{codec:?}"
        );
    }
    assert!(LzmaCodec.encode_patch(CodecId::Lzma2, &[], &new).is_err());
    assert!(LzmaCodec.encode_patch(CodecId::Lzma2, &base, &[]).is_err());
}

#[test]
fn the_window_cap_is_checked_on_the_view() {
    // `check` refuses a window above the cap even when it matches the sizes.
    let base = [7u8; 16];
    let v = PatchView {
        codec: CodecId::Lzma2,
        input: &[0],
        base_size: 16,
        output_size: MAX_PATCH_WINDOW,
        window: patch_window(16, MAX_PATCH_WINDOW).unwrap(),
    };
    assert!(v.window > MAX_PATCH_WINDOW);
    let r = v.check(base.len());
    assert!(
        matches!(r, Err(Error::Codec(CodecError::Corrupt(_)))),
        "{r:?}"
    );
    let at_cap = PatchView {
        output_size: MAX_PATCH_WINDOW - 16,
        window: MAX_PATCH_WINDOW,
        ..v
    };
    assert_eq!(at_cap.check(base.len()).unwrap(), MAX_PATCH_WINDOW as u32);
}
