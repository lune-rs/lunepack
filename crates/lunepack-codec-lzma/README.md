# lunepack-codec-lzma

The codec adapter of lunepack: decodes and encodes LZMA2, with the BCJ filters, over the pure-Rust `lzma-rust2` crate. Decoding allocates only what the signed sizes in a release allow.

Part of lunepack; applications normally use the `lunepack` facade crate.

Part of [lunepack](https://github.com/lune-rs/lunepack), a pure-Rust installer, packager and auto-updater framework.

Licensed under either of MIT or Apache-2.0, at your option.
