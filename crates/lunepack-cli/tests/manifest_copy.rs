//! The CLI's `res/windows.manifest` is a copy of the shared one (the crate is published and
//! `../lunepack-os-windows/res` is not in its package; build.rs says why). In a checkout the two
//! must stay byte-equal. Not in a package: `exclude = ["/tests"]`.

use std::path::PathBuf;

#[test]
fn the_cli_manifest_is_the_shared_manifest() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let own = root.join("res").join("windows.manifest");
    let shared = root
        .join("..")
        .join("lunepack-os-windows")
        .join("res")
        .join("windows.manifest");
    let a = std::fs::read(&own).unwrap_or_else(|e| panic!("read {}: {e}", own.display()));
    let b = std::fs::read(&shared).unwrap_or_else(|e| panic!("read {}: {e}", shared.display()));
    assert!(
        a == b,
        "{} differs from {}: copy the shared manifest over it",
        own.display(),
        shared.display()
    );
}
