# Fuzz targets

libFuzzer targets over the untrusted-input harnesses of `lunepack_core::fuzz` (envelopes, root,
key set, feed, manifest, a manifest's deltas, paths, trees, version/target/id rules, strict JSON, frames, HTTP response
headers, the setup-file locator and trailer, the service protocol, the UI frames) and of
`lunepack_codec_lzma::fuzz` (the real LZMA frame and delta-patch decoders: `codec`, `patch`). Each
target calls one harness; a harness must return for any input without panicking.

This directory is outside the Cargo workspace (root `exclude`) and has its own committed
`Cargo.lock`, which the boundary check holds to crates.io plus this repository's own crates. It is
not part of the gate: libFuzzer needs a nightly toolchain and a C++ build. The gate instead replays
the committed seeds and random and mutated inputs on stable:

    cargo test -p lunepack-testkit --locked --test fuzz_replay

## Run

    cargo install cargo-fuzz --locked
    cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target> -- -max_total_time=60

Targets: `envelope`, `root`, `keys`, `feed`, `manifest`, `deltas`, `path`, `tree`, `rules`, `json`, `frame`, `http`,
`state`, `update_config`, `setup`, `service`, `ui`, `codec`, `patch`.
If AddressSanitizer does not work on your host, add `-s none`. `corpus/` and `artifacts/` are
local and gitignored; a crash lands in `artifacts/<target>/`.

## Seeds

`seeds/<target>/` holds the committed inputs, written by the real writers over the testkit fakes
(`lunepack_testkit::fuzz_seeds`); `ok-*` seeds go all the way through their harness, `bad-*` seeds
are rejected on purpose. Envelope seeds carry dummy signatures, and no secret is involved. A test
regenerates them in memory and fails if a committed file differs. To rewrite them after a writer
change:

    LUNEPACK_WRITE_SEEDS=1 cargo test -p lunepack-testkit --test fuzz_replay committed_seeds

The `codec` and `patch` seeds are written by the codec crate's own encoder and replayed by its own
test (the testkit does not depend on the codec crate); rewrite them with:

    LUNEPACK_WRITE_SEEDS=1 cargo test -p lunepack-codec-lzma --test fuzz_replay committed_seeds

and replay them on stable with `cargo test -p lunepack-codec-lzma --locked --test fuzz_replay`.

A crash found by libFuzzer: minimise it, keep the input as a seed, add it to the replay test as a
regression case and fix the parser.

## Inputs

- `envelope`: the bytes are an envelope, tried as each of the four kinds.
- `root`, `keys`, `feed`, `manifest`: the bytes are a payload; the harness signs it with a built-in
  fake key and runs the real verification function (`advance_root`, `verify_key_set`,
  `verify_feed`, `verify_manifest`).
- `deltas`: the bytes are the JSON value of the `deltas` member of a manifest (FORMAT.md 9.3). The
  harness splices them into a fixed valid manifest of `org.example.hello` 1.0.0 for `linux-x86_64`
  (files `bin/app` of 300 bytes, `lib/x.so.1` of 200, an empty `share/empty`, and the link
  `lib/x.so`), signs it and runs the same `verify_manifest` call as `manifest`. A patch can name
  those files; the seeds carry their sizes and hashes.
- `path`: one entry path. `tree`: lines `f <path>`, `d <path>`, `l <path>><link target>`.
- `rules`: text through the version, target, app id, channel, algorithm, codec, hex, base64 and
  reference rules. `json`: the strict JSON pre-pass.
- `frame`: 50 header bytes (u16 BE descriptor length, u64 BE file size, u64 BE pack size, 32 bytes
  file SHA-256), the frame descriptor JSON, then the frame bytes.
- `http`: 35 parameter bytes (flags: bit 0 a range was requested, bit 1 it has a last byte; u64 BE
  first, last, signed pack size and expected body length; u16 BE status), then one `name: value`
  header line per newline. The harness runs the response header rules, the `Content-Range` and
  `Content-Length` checks and the document check.
- `update_config`: the bytes are an update-config document (FORMAT.md 13); an accepted one must
  round-trip through the writer to the same value and canonical bytes.
- `setup`: the bytes are a whole executable. The harness runs the PE reader, the setup locator (the
  trailer at the end of the file or before a signed PE's certificate table) and parses the trailer
  it finds with the fake scheme.
- `service`: the first byte selects the side of a service-protocol connection (M10-D1): even, a
  server for app `org.example.hello` reading the client's hello, requests and their data frames;
  odd, a client reading the server's hello and answers. The rest is the peer's byte stream. Accepted:
  every frame was valid and the stream ended on a frame boundary.
- `ui`: the first byte selects the direction of the UI protocol (M6-D2): even, the engine's frames, decoded
  and applied to a reducer that answers every prompt with its first fitting choice; odd, the UI's frames,
  decoded and checked against a reducer at the install welcome prompt. The rest is the byte stream.
  Accepted: every frame was valid (and, from the engine, in order) and the stream ended on a frame
  boundary. The seeds include the administrator command at its cap and the refusals around it.
- `codec`: the bytes are one frame handed to the real decoder (`LzmaCodec::decode`) without the
  frame-hash check. Big-endian layout: a selector byte (the codec, modulo 5: 0 `stored`, 1 `lzma2`,
  2 `bcj-x86+lzma2`, 3 `bcj-arm64+lzma2`, 4 `bcj2`), the output size (u32), then one stream header
  per stream (one stream; four for `bcj2`): dictionary size (u32), decoded size (u32) and, for
  every stream but the last, its encoded length (u16). The streams' bytes follow in order, the last
  one taking the rest. The dictionary of a `stored` stream and of `bcj2`'s fourth (RC) stream is
  read and not passed on. The dictionary size goes to the codec as given (the codec refuses one
  that is not a power of two between 4 KiB and 16 MiB before it allocates); the declared sizes are
  reduced modulo 4 MiB + 1, so a run decodes at most 4 MiB. The sink counts and drops the bytes;
  the harness panics if the decoder wrote more than the output size, or if an `Ok` report does not
  match the bytes written and the streams.
- `patch`: the bytes are one delta patch handed to `LzmaCodec::decode_patch` (FORMAT.md 9.3).
  Layout: a selector byte (the low three bits the codec as in `codec`, so `stored` and `bcj2` reach
  the codec's own refusal; bit 7 set: the window is given), the length of the base bytes (u16),
  the declared base size (u32), the declared output size (u32, reduced like the sizes of `codec`),
  the window (u32, only with bit 7; otherwise the format's window of the two sizes), then the base
  bytes and the patch's bytes up to the end. A window that is not the format's, or is over
  128 MiB, is refused by the codec before it allocates. The sink and the panics are as in `codec`;
  an `Ok` patch must also have consumed all of its input.
