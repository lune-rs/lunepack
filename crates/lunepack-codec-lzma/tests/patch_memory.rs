//! Patch decoder heap peak (M12 step 2, M12-D7): `patch_decoder_memory` (core, `frame.rs`) is the
//! budget the stage charges per patch; this test pins the measured peak of one
//! `Codec::decode_patch` below it, at a 64 MiB window, for bases from small to nearly the whole
//! window, and checks the budget's headroom over the worst measurement.
//!
//! The counting allocator (`peak_alloc`) counts a `realloc` as a new block while the old one is
//! still live. `lzma-rust2` 0.25 starts a patch's window as a copy of the base and grows it
//! geometrically (at least doubling) up to the window, so the last growth holds the old block
//! (anything from half the window to just under it) and the whole window at once: the peak is
//! below two windows, whatever the base's size. For the BCJ ids the filtered copy of the base
//! exists only while the reader is made (it copies it), before any growth.
//!
//! As in `memory.rs`, the patch is not made by the encoder (preset 9e over a 64 MiB window takes
//! minutes in a debug build): it is a real patch head (props, LZMA state) encoded against the
//! base's tail, then stored chunks (control byte 2, no dictionary reset) up to the file's size,
//! then the end marker. The decoded bytes are not checked here; `tests/patch.rs` and the contract
//! suite do that. One test on purpose: the allocator counters are process-wide.

use std::hint::black_box;
use std::io::{self, Write};

use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::frame::{patch_decoder_memory, patch_window};
use lunepack_core::{Codec, CodecId, Encoder, PatchView};
use peak_alloc::PeakAlloc;

#[global_allocator]
static ALLOC: PeakAlloc = PeakAlloc;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const WINDOW: usize = 64 * MIB;
/// Real encoder output at the head of every patch.
const HEAD: usize = 32 * KIB;

fn measure<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let base = ALLOC.current_usage();
    ALLOC.reset_peak_usage();
    let result = f();
    let peak = ALLOC.peak_usage().saturating_sub(base);
    (result, peak)
}

struct Sink;

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Filler bytes: one pseudo-random 64 KiB block, repeated.
fn filler(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    let block: Vec<u8> = (0..64 * KIB)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    block.iter().copied().cycle().take(len).collect()
}

/// A patch stream decoding to `size` bytes against `base`: a real patch head against the base's
/// last 64 KiB (so no dictionary reset and LZMA state live), then stored chunks, then the end.
fn patch_stream(codec: CodecId, base: &[u8], size: usize) -> Vec<u8> {
    let tail = &base[base.len().saturating_sub(64 * KIB)..];
    let head = filler(HEAD.min(size), 99);
    let mut stream = LzmaCodec
        .encode_patch(codec, tail, &head)
        .expect("encode the head")
        .bytes;
    assert_eq!(stream.pop(), Some(0), "an LZMA2 stream ends with 0");
    let rest = filler(size - head.len(), 7);
    for chunk in rest.chunks(64 * KIB) {
        let n = u16::try_from(chunk.len() - 1).expect("at most 64 KiB");
        stream.push(2);
        stream.extend_from_slice(&n.to_be_bytes());
        stream.extend_from_slice(chunk);
    }
    stream.push(0);
    stream
}

#[test]
fn patch_decoder_peak_is_within_patch_decoder_memory() {
    let (_, calibration) = measure(|| black_box(vec![0u8; 8 * MIB]));
    println!("calibration (8 MiB Vec): {calibration} bytes");
    assert!(
        (8 * MIB..8 * MIB + 64 * KIB).contains(&calibration),
        "the counting allocator reads {calibration} for an 8 MiB allocation"
    );

    let mut worst_seen = 0u64;
    let mut budget_at_worst = 0u64;
    // (base size, codecs): every case has a 64 MiB window.
    let cases: [(usize, &[CodecId]); 4] = [
        (MIB, &[CodecId::Lzma2]),
        (
            WINDOW / 2 - 4 * KIB,
            &[CodecId::Lzma2, CodecId::BcjX86Lzma2],
        ),
        (WINDOW / 2, &[CodecId::Lzma2, CodecId::BcjArm64Lzma2]),
        (WINDOW - MIB, &[CodecId::Lzma2, CodecId::BcjX86Lzma2]),
    ];
    for (base_size, codecs) in cases {
        let base = filler(base_size, 3);
        let size = WINDOW - base_size;
        for &codec in codecs {
            let stream = patch_stream(codec, &base, size);
            let window = patch_window(base_size as u64, size as u64).expect("window");
            assert_eq!(window, WINDOW as u64);
            let view = PatchView {
                codec,
                input: &stream,
                base_size: base_size as u64,
                output_size: size as u64,
                window,
            };
            let (report, peak) = measure(|| LzmaCodec.decode_patch(&view, &base, &mut Sink));
            let report = report.expect("the patch decodes");
            assert_eq!(report.consumed, vec![stream.len() as u64]);
            let peak = peak as u64;
            let budget = patch_decoder_memory(codec, window);
            println!(
                "{codec:?}, base {base_size} bytes: peak {peak} bytes, \
                 patch_decoder_memory {budget} bytes"
            );
            assert!(
                peak <= budget,
                "{codec:?}, base {base_size}: peak {peak} exceeds {budget}"
            );
            if peak > worst_seen {
                worst_seen = peak;
                budget_at_worst = budget;
            }
        }
    }
    // The budget is two windows plus the codec's overhead constant. Measured (debug build,
    // 2026-11-24): a 1 MiB base peaks at 100,794,403 bytes, a base just under half the window
    // at 134,340,643 (two windows and 127 KiB), a base of nearly the whole window at
    // 133,300,259; the BCJ ids add 4 KiB. The constant keeps at least 25 % headroom over what
    // the worst case needed beyond two windows.
    let two_windows = 2 * WINDOW as u64;
    let over = worst_seen.saturating_sub(two_windows);
    let constant = budget_at_worst - two_windows;
    println!("worst peak {worst_seen} bytes; beyond two windows {over}; constant {constant}");
    assert!(
        constant * 4 >= over * 5,
        "the overhead constant {constant} has less than 25 % headroom over {over}"
    );
}
