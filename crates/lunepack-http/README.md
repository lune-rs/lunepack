# lunepack-http

The release-source adapter of lunepack: HTTP and HTTPS through ureq with rustls, the platform certificate verifier as the only trust source, and a source that reads a local directory for mirrors and tests. It also holds the object-store adapters a publisher uploads through: an S3-compatible store signed with SigV4 (Cloudflare R2 first) and a local-directory store.

Part of lunepack; applications normally use the `lunepack` facade crate.

Part of [lunepack](https://github.com/lune-rs/lunepack), a pure-Rust installer, packager and auto-updater framework.

Licensed under either of MIT or Apache-2.0, at your option.
