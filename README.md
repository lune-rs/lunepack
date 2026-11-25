# lunepack

A pure-Rust installer, packager and auto-updater framework. It packages an app's build output into a signed
release that any static host can serve, builds installers for Windows, macOS and Linux, ships full and delta
updates, and applies an update and restarts the app, with a rollback when the new version does not confirm
that it works. It is built first for Lunegit, a desktop git client, and is meant for other apps too, in any
language.

Status: version 0.1.0, prepared for its first release; nothing has been published yet, so until then
the crates and the prebuilt binaries are built from a checkout. The format is specified and frozen from the
first published release ([`docs/FORMAT.md`](docs/FORMAT.md)).

## What is in it

| | |
| --- | --- |
| `lunepack` (the `lunepack-cli` crate) | the publisher's command line: `init`, `keys`, `pack`, `feed`, `verify`, `inspect`, `setup` and `prebuilt` |
| `lunepack` (the facade crate) | the Rust API an app uses to check for, download, verify and stage an update, and to apply it and restart |
| `lunepack-runtime` | a small static program that sits beside an app and does the same through a command line, so an app in any language can update itself |
| installers and an update window | per-user and per-machine installs on Windows, macOS and Linux; a privileged update service for installs for all users |
| `examples/dotnet` | a .NET app that installs and updates itself through the runtime's command line only |

Signing is done with the publisher's own keys; an update is accepted only when the chain from the root key
compiled into the app to the files on disk verifies. What that does and does not defend against is in the
[threat model](docs/THREAT-MODEL.md).

## Where to start

- [`docs/GETTING-STARTED.md`](docs/GETTING-STARTED.md): from nothing to an installed Rust app that updates
  itself.
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md): the same for an app in any language, with the .NET example.
- [`docs/KEY-CEREMONY.md`](docs/KEY-CEREMONY.md): making and keeping the signing keys, rotating and revoking
  them, and what a leak costs.
- Reference: [`docs/CLI.md`](docs/CLI.md) (the packager), [`docs/RUNTIME.md`](docs/RUNTIME.md) (the runtime's
  command line, output and exit codes), [`docs/FORMAT.md`](docs/FORMAT.md) (the documents and how a client
  checks them), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (the crates and the rules between them).
- [`SECURITY.md`](SECURITY.md): how to report a vulnerability, and how to check the prebuilt binaries you
  download. [`docs/RELEASING.md`](docs/RELEASING.md) is the maintainer's runbook for a release.

Identifiers such as `D19` or `M9-D8` in these documents refer to the project's internal decision log, which
is not part of this repository; where a rule matters, the document states it.

## Install

```sh
cargo install lunepack-cli --locked   # installs the `lunepack` command
```

(once the first release is published.) The prebuilt runtime, window program, update service and Windows
stubs that a packager places into an app are downloaded with `lunepack prebuilt fetch`, which checks them
against hashes compiled into the command line, or built from a checkout with `scripts/build-runtime.sh`
([`docs/CLI.md`](docs/CLI.md)). A Rust app depends on the `lunepack` crate.

## Build and test

Rust 1.99.1 is pinned in `rust-toolchain.toml` and installed by rustup on first use.

```sh
cargo build --workspace --locked
cargo test --workspace --locked
./scripts/gate.sh   # everything the gate runs, stage by stage
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
