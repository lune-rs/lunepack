//! Fuzz entry points for the real LZMA decoders (M13 step 2): `fn(&[u8])` harnesses that build a
//! [`FrameView`] or a [`PatchView`] from the input and call [`LzmaCodec`] directly, without the
//! frame-hash check the core puts in front of a decoder, so the decoder sees attacker bytes. Hidden
//! from the docs; not part of the API. The layouts are in `fuzz/README.md`.
//!
//! The harness hands the dictionary size, the window and the declared sizes to the codec as the
//! input gives them, so the codec's own checks are what refuses a dictionary over 16 MiB or a
//! window over 128 MiB. Only the declared decoded sizes are reduced to at most [`MAX_OUTPUT`]
//! (modulo, so the call is never skipped), to keep one run short.
//!
//! The sink counts and discards. After the call the harness asserts that the decoder wrote no more
//! than the declared output size and that an `Ok` report matches what was written: a violation is
//! a panic, which is a finding.
//!
//! Every harness must return for any input without panicking, over-allocating or looping. The
//! `bool` of [`accepts`] says whether the decoder returned `Ok`; it exists for the seed tests and
//! is ignored by the fuzz targets.

use std::error::Error as _;
use std::io::{self, Write};

use lunepack_core::frame::patch_window;
use lunepack_core::{Codec, CodecId, DecodeReport, PatchView, StreamView};

use crate::LzmaCodec;

/// Largest declared decoded size the harness passes on: 4 MiB.
pub const MAX_OUTPUT: u64 = 4 << 20;

/// A harness entry point.
pub type Harness = fn(&[u8]);

/// Every harness of this crate by name.
pub const HARNESSES: &[(&str, Harness)] = &[("codec", codec), ("patch", patch)];

/// The codec ids in the order a selector byte picks them (modulo 5).
const IDS: [CodecId; 5] = [
    CodecId::Stored,
    CodecId::Lzma2,
    CodecId::BcjX86Lzma2,
    CodecId::BcjArm64Lzma2,
    CodecId::Bcj2,
];

/// Bits of a `patch` selector byte: the low three pick the codec, this one says that a window
/// follows the sizes instead of being computed from them.
pub const PATCH_EXPLICIT_WINDOW: u8 = 0x80;

/// Runs the harness `name` and reports whether the decoder accepted `data` (`None`: no such
/// harness).
pub fn accepts(name: &str, data: &[u8]) -> Option<bool> {
    Some(match name {
        "codec" => codec_verdict(data).is_ok(),
        "patch" => patch_verdict(data).is_ok(),
        _ => return None,
    })
}

/// The `codec` harness: the decoder's verdict on `data` as a frame.
pub fn codec(data: &[u8]) {
    let _ = codec_verdict(data);
}

/// The `patch` harness: the decoder's verdict on `data` as a delta patch.
pub fn patch(data: &[u8]) {
    let _ = patch_verdict(data);
}

/// The sink: counts the bytes and drops them.
#[derive(Default)]
struct Sink {
    written: u64,
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An error and its causes, outermost first.
fn chain(e: &lunepack_core::Error) -> String {
    let mut text = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        let c_text = c.to_string();
        // A transparent wrapper repeats its cause's text.
        if !text.ends_with(&c_text) {
            text.push_str(": ");
            text.push_str(&c_text);
        }
        cause = c.source();
    }
    text
}

/// Big-endian reads over the input; a short input is the reader's `Err`.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("the input is shorter than its header".to_owned());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Up to `n` bytes (what is left, when less).
    fn up_to(&mut self, n: usize) -> &'a [u8] {
        let n = n.min(self.0.len());
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        head
    }

    fn rest(&mut self) -> &'a [u8] {
        self.up_to(usize::MAX)
    }
}

/// A declared size reduced into `0..=MAX_OUTPUT`.
fn reduce(declared: u32) -> u64 {
    u64::from(declared) % (MAX_OUTPUT + 1)
}

/// What the sink saw against what the decoder said.
fn check_report(
    declared: u64,
    sink: &Sink,
    result: &Result<DecodeReport, lunepack_core::Error>,
    inputs: &[usize],
) {
    assert!(
        sink.written <= declared,
        "the decoder wrote {} bytes, the declared output is {declared}",
        sink.written
    );
    if let Ok(report) = result {
        assert_eq!(
            sink.written, declared,
            "an Ok report with {} bytes written, the declared output is {declared}",
            sink.written
        );
        assert_eq!(
            report.consumed.len(),
            inputs.len(),
            "an Ok report has one entry per stream"
        );
        for (consumed, len) in report.consumed.iter().zip(inputs) {
            assert!(
                *consumed <= *len as u64,
                "an Ok report consumed {consumed} bytes of a {len} byte stream"
            );
        }
    }
}

/// The `codec` harness: `Ok` when [`LzmaCodec::decode`] accepts `data`, else the error's text (a
/// header the harness cannot read included). For the seed tests, which assert the reason a `bad-`
/// seed is refused for.
///
/// Layout: selector byte (codec id, modulo 5: stored, lzma2, bcj-x86+lzma2, bcj-arm64+lzma2,
/// bcj2), output size (u32 BE), then one stream header per stream (one stream; four for bcj2):
/// dictionary size (u32 BE), decoded size (u32 BE), and, for every stream but the last, its
/// encoded length (u16 BE). The streams' bytes follow in order, the last one taking the rest.
/// The dictionary of a `stored` stream and of bcj2's fourth stream is read and not passed on.
pub fn codec_verdict(data: &[u8]) -> Result<(), String> {
    let mut r = Reader(data);
    let id = IDS[usize::from(r.u8()?) % IDS.len()];
    let output_size = reduce(r.u32()?);
    let count = if id == CodecId::Bcj2 { 4 } else { 1 };
    let mut heads = Vec::with_capacity(count);
    for i in 0..count {
        let dict = r.u32()?;
        let decoded = reduce(r.u32()?);
        let len = if i + 1 < count {
            Some(usize::from(r.u16()?))
        } else {
            None
        };
        // A stored stream and the RC stream of bcj2 have no dictionary.
        let has_dict = id != CodecId::Stored && !(id == CodecId::Bcj2 && i == 3);
        heads.push((has_dict.then_some(dict), decoded, len));
    }
    let streams: Vec<StreamView<'_>> = heads
        .iter()
        .map(|&(dict_size, decoded_size, len)| StreamView {
            input: match len {
                Some(n) => r.up_to(n),
                None => r.rest(),
            },
            decoded_size,
            dict_size,
        })
        .collect();
    let frame = lunepack_core::FrameView {
        codec: id,
        output_size,
        streams: &streams,
    };
    let mut sink = Sink::default();
    let result = LzmaCodec.decode(&frame, &mut sink);
    let lens: Vec<usize> = streams.iter().map(|s| s.input.len()).collect();
    check_report(output_size, &sink, &result, &lens);
    result.map(|_| ()).map_err(|e| chain(&e))
}

/// The `patch` harness: `Ok` when [`LzmaCodec::decode_patch`] accepts `data`, else the error's
/// text (a header the harness cannot read included). For the seed tests.
///
/// Layout: selector byte (the low three bits the codec id, modulo 5, in the order of `codec`;
/// [`PATCH_EXPLICIT_WINDOW`] set: a window follows the sizes), base length (u16 BE, the bytes of
/// the base that follow the header), declared base size (u32 BE), declared output size (u32 BE),
/// the window (u32 BE, only with the explicit bit; otherwise the format's window of the two
/// sizes). The base bytes follow, then the patch's bytes up to the end. The base length and the
/// declared base size are separate so that the codec's own comparison is reached.
pub fn patch_verdict(data: &[u8]) -> Result<(), String> {
    let mut r = Reader(data);
    let selector = r.u8()?;
    let codec = IDS[usize::from(selector & 7) % IDS.len()];
    let base_len = usize::from(r.u16()?);
    let base_size = u64::from(r.u32()?);
    let output_size = reduce(r.u32()?);
    let window = if selector & PATCH_EXPLICIT_WINDOW != 0 {
        u64::from(r.u32()?)
    } else {
        patch_window(base_size, output_size).unwrap_or(u64::MAX)
    };
    let base = r.up_to(base_len);
    let view = PatchView {
        codec,
        input: r.rest(),
        base_size,
        output_size,
        window,
    };
    let mut sink = Sink::default();
    let result = LzmaCodec.decode_patch(&view, base, &mut sink);
    check_report(output_size, &sink, &result, &[view.input.len()]);
    if let Ok(report) = &result {
        assert_eq!(
            report.consumed,
            [view.input.len() as u64],
            "an Ok patch consumed all of its input"
        );
    }
    result.map(|_| ()).map_err(|e| chain(&e))
}
