# lunepack

The Rust API an application depends on to update itself: check a release feed, download resumably, verify signatures and hashes, stage a new version tree, then apply it and restart. A builder wires the default adapters (filesystem, HTTP, LZMA2, crypto, the OS of the build); each can be replaced.

Packaging and signing releases is the job of the `lunepack-cli` crate (the `lunepack` command).

Part of [lunepack](https://github.com/lune-rs/lunepack), a pure-Rust installer, packager and auto-updater framework.

Licensed under either of MIT or Apache-2.0, at your option.
