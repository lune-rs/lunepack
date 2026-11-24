//! Patch encoder heap peak (M12 step 2, M12-D7): `Encoder::encode_patch_memory` is what the pack
//! stage charges per patch candidate; this test pins the measured peak of one real
//! `encode_patch` at a 64 MiB window below it, with the headroom stated.
//!
//! Measured (2026-11-24, release): `lzma2` 772,565,077 bytes against an estimate of 839,846,972
//! (8.7 % headroom), the same for a 60 MiB base and a 4 MiB file; `bcj-x86+lzma2` 806,119,509
//! with a 32 MiB file and 776,730,709 with a 4 MiB one against 906,955,836 (the BCJ extra grows
//! with the file and is bounded by one window, so its worst case is about 840 MB, 8 % below).
//!
//! Release-only: preset 9e over a 64 MiB window takes minutes in a debug build. Run it with
//! `cargo test -p lunepack-codec-lzma --locked --release --test patch_encode_memory`. One test on
//! purpose: the allocator counters are process-wide.

use std::hint::black_box;

use lunepack_codec_lzma::LzmaCodec;
use lunepack_core::frame::patch_window;
use lunepack_core::{CodecId, Encoder};
use peak_alloc::PeakAlloc;

#[global_allocator]
static ALLOC: PeakAlloc = PeakAlloc;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

fn measure<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let base = ALLOC.current_usage();
    ALLOC.reset_peak_usage();
    let result = f();
    let peak = ALLOC.peak_usage().saturating_sub(base);
    (result, peak)
}

/// Pseudo-random bytes (incompressible on their own, so the encoder works the whole window).
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

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "release only: run with --release (preset 9e over a 64 MiB window is minutes in debug)"
)]
fn patch_encoder_peak_is_within_encode_patch_memory() {
    let (_, calibration) = measure(|| black_box(vec![0u8; 8 * MIB]));
    assert!(
        (8 * MIB..8 * MIB + 64 * KIB).contains(&calibration),
        "the counting allocator reads {calibration} for an 8 MiB allocation"
    );
    // (base, new) with a window of 64 MiB less 4 KiB: half and half, then nearly all base.
    for (base_len, new_len) in [(32 * MIB, 32 * MIB - 4096), (60 * MIB, 4 * MIB - 4096)] {
        let base = noise(base_len, 5);
        let mut new = base[..new_len].to_vec();
        new[KIB..KIB + 4096].copy_from_slice(&noise(4096, 9));
        let window = patch_window(base.len() as u64, new.len() as u64).expect("window");
        assert_eq!(window, 64 * MIB as u64 - 4096);
        for codec in [CodecId::Lzma2, CodecId::BcjX86Lzma2] {
            let (patch, peak) = measure(|| LzmaCodec.encode_patch(codec, &base, &new));
            let patch = patch.expect("encode");
            let peak = peak as u64;
            let budget = LzmaCodec.encode_patch_memory(codec, window);
            println!(
                "{codec:?}, base {base_len}, new {new_len}: patch {} bytes, peak {peak} bytes, \
                 encode_patch_memory {budget} bytes",
                patch.bytes.len()
            );
            assert!(peak <= budget, "{codec:?}: peak {peak} exceeds {budget}");
        }
    }
}
