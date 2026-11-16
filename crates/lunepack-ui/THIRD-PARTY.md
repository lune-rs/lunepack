# Third-party material in `lunepack-ui`

The `lunepack-ui` binary embeds the files below through `lunepack-ui-luneui`. Rust dependencies keep
their own licenses (`cargo metadata` lists them); this file names what is bundled as a file.

## RznSans (fonts)

- Files: `RznSans-Regular.ttf` and `RznSans-Medium.ttf` (version 1.007), in
  `crates/lunepack-ui-luneui/assets/fonts/`, compiled into the binary with `include_bytes!`
  (`crates/lunepack-ui-luneui/src/lib.rs`). The only font the screens use.
- License: SIL Open Font License, Version 1.1. The full text, with the copyright line and the
  Reserved Font Name `RznSans`, is `crates/lunepack-ui-luneui/assets/fonts/OFL.txt`, which stays
  beside the fonts.
- The fonts are bundled, unmodified, with the software and are not sold by themselves. A
  distribution of the `lunepack-ui` binary must carry this notice and the license text with it;
  `pack --ui` places only the binary, so shipping them with a release belongs to the release
  workflow (M13).
- The OFL covers the font binaries only, not lunepack's source, which is under the repository's own
  licenses (`LICENSE-MIT`, `LICENSE-APACHE`).
