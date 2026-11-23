# Fuzz targets

libFuzzer targets over the untrusted-input harnesses of `lunepack_core::fuzz` (envelopes, root,
key set, feed, manifest, paths, trees, version/target/id rules, strict JSON, frames, HTTP response
headers, the setup-file locator and trailer, the service protocol, the UI frames). Each target
calls one harness; a harness must return for any input without panicking.

This directory is outside the Cargo workspace (root `exclude`) and has its own committed
`Cargo.lock`, which the boundary check holds to crates.io plus this repository's own crates. It is
not part of the gate: libFuzzer needs a nightly toolchain and a C++ build. The gate instead replays
the committed seeds and random and mutated inputs on stable:

    cargo test -p lunepack-testkit --locked --test fuzz_replay

## Run

    cargo install cargo-fuzz --locked
    cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target> -- -max_total_time=60

Targets: `envelope`, `root`, `keys`, `feed`, `manifest`, `path`, `tree`, `rules`, `json`, `frame`, `http`,
`state`, `update_config`, `setup`, `service`, `ui`.
If AddressSanitizer does not work on your host, add `-s none`. `corpus/` and `artifacts/` are
local and gitignored; a crash lands in `artifacts/<target>/`.

## Seeds

`seeds/<target>/` holds the committed inputs, written by the real writers over the testkit fakes
(`lunepack_testkit::fuzz_seeds`); `ok-*` seeds go all the way through their harness, `bad-*` seeds
are rejected on purpose. Envelope seeds carry dummy signatures, and no secret is involved. A test
regenerates them in memory and fails if a committed file differs. To rewrite them after a writer
change:

    LUNEPACK_WRITE_SEEDS=1 cargo test -p lunepack-testkit --test fuzz_replay committed_seeds

A crash found by libFuzzer: minimise it, keep the input as a seed, add it to the replay test as a
regression case and fix the parser.

## Inputs

- `envelope`: the bytes are an envelope, tried as each of the four kinds.
- `root`, `keys`, `feed`, `manifest`: the bytes are a payload; the harness signs it with a built-in
  fake key and runs the real verification function (`advance_root`, `verify_key_set`,
  `verify_feed`, `verify_manifest`).
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
