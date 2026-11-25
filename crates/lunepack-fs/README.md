# lunepack-fs

The filesystem adapter of lunepack: the core's filesystem trait over `std`, the OS advisory lock, and the place and exchange primitives the updater needs. The few `unsafe` blocks are single libc calls with a `SAFETY` comment.

Part of lunepack; applications normally use the `lunepack` facade crate.

Part of [lunepack](https://github.com/lune-rs/lunepack), a pure-Rust installer, packager and auto-updater framework.

Licensed under either of MIT or Apache-2.0, at your option.
