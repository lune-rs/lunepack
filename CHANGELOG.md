# Changelog

All notable changes to lunepack are listed here, newest first. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Crates are released together at one version.

## [Unreleased] - 0.1.0

The first version meant for publication; nothing has been published yet.

### Added

- The `lunepack` facade crate and the crates behind it (`lunepack-core`, `lunepack-crypto`,
  `lunepack-fs`, `lunepack-http`, `lunepack-codec-lzma`, `lunepack-os-linux`, `lunepack-os-macos`,
  `lunepack-os-windows`) and the `lunepack-cli` crate, which installs the `lunepack` command, are
  prepared for crates.io, with a README, description, keywords and categories each.
- Packaging a release, signed feeds, full and delta updates, installers for Windows, macOS and Linux
  (per-user and per-machine), the update runtime with its command line, and the update service.
- A third-party notices file generated from the dependencies of the shipped binaries, checked by the
  gate and placed by `lunepack pack` as `lunepack-NOTICES.txt` beside the runtime.
- A .NET example application that updates itself through the runtime's command line only.
