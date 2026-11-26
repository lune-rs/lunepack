//! `ffi-header [--check]`: the C header of `lunepack-ffi` (M14-D8), generated from its source by
//! cbindgen as a library (no build script: the library's own build graph does not include it).
//!
//! The checked-in header is the generator's exact output; `--check` fails, naming the file, when
//! it differs, and a unit test makes the same comparison on every OS through `cargo test`.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow};

/// The generated header, relative to the workspace root.
pub const OUTPUT: &str = "crates/lunepack-ffi/include/lunepack.h";

/// The binding crate, relative to the workspace root.
const CRATE: &str = "crates/lunepack-ffi";

/// The header's bytes for the workspace rooted at `root`: LF line ends, and no path, date or host
/// (`cbindgen.toml` holds the settings).
pub fn generate(root: &Path) -> Result<Vec<u8>> {
    let krate = root.join(CRATE);
    let config = cbindgen::Config::from_file(krate.join("cbindgen.toml"))
        .map_err(|e| anyhow!("cannot read {CRATE}/cbindgen.toml: {e}"))?;
    let bindings = cbindgen::Builder::new()
        .with_config(config)
        .with_src(krate.join("src").join("lib.rs"))
        .generate()
        .map_err(|e| anyhow!("cbindgen failed: {e}"))?;
    let mut out = Vec::new();
    bindings.write(&mut out);
    Ok(out)
}

/// Runs the task: writes the header, or with `--check` compares it with the checked-in one.
pub fn main(args: impl IntoIterator<Item = String>) -> ExitCode {
    let mut check = false;
    for arg in args {
        match arg.as_str() {
            "--check" => check = true,
            other => {
                eprintln!("ffi-header: unknown argument `{other}`; usage: ffi-header [--check]");
                return ExitCode::from(2);
            }
        }
    }
    match run(check) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("ffi-header: error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(check: bool) -> Result<ExitCode> {
    let root = std::env::current_dir()?;
    let fresh = generate(&root)?;
    let target = root.join(OUTPUT);
    if check {
        let committed = fs::read(&target).with_context(|| {
            format!("cannot read {OUTPUT}; run `cargo run -p xtask -- ffi-header`")
        })?;
        return Ok(if committed == fresh {
            println!("ffi-header: ok ({OUTPUT} is current)");
            ExitCode::SUCCESS
        } else {
            println!(
                "ffi-header: {OUTPUT} is stale; run `cargo run -p xtask -- ffi-header` and commit the result"
            );
            ExitCode::from(1)
        });
    }
    if let Some(dir) = target.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    fs::write(&target, &fresh).with_context(|| format!("cannot write {OUTPUT}"))?;
    println!("ffi-header: wrote {OUTPUT} ({} bytes)", fresh.len());
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits in the workspace root")
    }

    /// The same generation as `ffi-header`, compared byte for byte with the checked-in header.
    /// Runs on every OS through `cargo test --workspace`.
    #[test]
    fn the_checked_in_header_is_the_generators_exact_output() {
        let fresh = generate(root()).expect("generate");
        let committed = fs::read(root().join(OUTPUT)).expect("the checked-in header");
        assert!(
            committed == fresh,
            "{OUTPUT} differs from the generator's output: run `cargo run -p xtask -- ffi-header`"
        );
    }

    #[test]
    fn the_output_is_lf_only_and_names_no_path_date_or_host() {
        let fresh = generate(root()).expect("generate");
        let text = String::from_utf8(fresh).expect("UTF-8");
        assert!(!text.contains('\r'), "CR in the header");
        for needle in [
            "/Users/",
            "/home/",
            "C:\\",
            "\\\\",
            env!("CARGO_MANIFEST_DIR"),
        ] {
            assert!(!text.contains(needle), "the header contains {needle:?}");
        }
        // No timestamp: cbindgen writes none, and the banner is fixed text.
        assert!(text.starts_with("/* SPDX-License-Identifier: MIT OR Apache-2.0 */\n"));
        assert!(text.contains("do not edit"));
        // Two runs give the same bytes.
        assert_eq!(text.as_bytes(), generate(root()).expect("again").as_slice());
    }
}
