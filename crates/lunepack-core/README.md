# lunepack-core

The pure logic of lunepack: the signed document formats, the trust chain, version and channel rules, the update engine, and the traits behind everything external (filesystem, network, codecs, signatures, the OS). It does no I/O and has no clock or randomness of its own.

Most applications depend on the `lunepack` facade crate instead of this one. Its API is an internal contract of one lunepack release, not a stable interface.

Part of [lunepack](https://github.com/lune-rs/lunepack), a pure-Rust installer, packager and auto-updater framework.

Licensed under either of MIT or Apache-2.0, at your option.
