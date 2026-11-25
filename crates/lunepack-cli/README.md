# lunepack-cli

The `lunepack` command: package an application's releases and signed feeds, build installers, and manage the keys that sign them.

    cargo install lunepack-cli --locked

The command reference is in the repository: https://github.com/lune-rs/lunepack/blob/main/docs/CLI.md. The prebuilt runtime, service, stub and installer binaries that `pack` places in a release are not on crates.io; they come from the project's GitHub releases or from a checkout.

Part of [lunepack](https://github.com/lune-rs/lunepack), a pure-Rust installer, packager and auto-updater framework.

Licensed under either of MIT or Apache-2.0, at your option.
