//! The CLI's own PE image carries the Windows hardening (M7-D10): no C-runtime DLL import,
//! `DependentLoadFlags` of `LOAD_LIBRARY_SEARCH_SYSTEM32`, `advapi32.dll` delay-loaded (its
//! `cryptbase` forwarder would otherwise load from the application directory before `main`), and
//! an embedded manifest with `asInvoker` and `longPathAware`. The test reads the binary cargo built
//! for it (`CARGO_BIN_EXE_lunepack`), so it fails when `.cargo/config.toml`'s `+crt-static` is
//! overridden by a `RUSTFLAGS` environment variable. Empty off Windows.
//!
//! The reader is the core's `pe` module, the one the packager checks every Windows binary with.

#![cfg(windows)]

use lunepack_core::pe::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, PeImage, SUBSYSTEM_CONSOLE, is_c_runtime, manifest_is_hardened,
};

const IMAGE: &str = env!("CARGO_BIN_EXE_lunepack");

#[test]
fn the_cli_image_is_hardened() {
    let bytes = std::fs::read(IMAGE).expect("read the lunepack binary");
    let pe = PeImage::parse(&bytes).expect("the lunepack binary reads as a PE image");
    let imports: Vec<&str> = pe.all_imports().collect();
    let crt: Vec<&&str> = imports.iter().filter(|n| is_c_runtime(n)).collect();
    assert!(
        crt.is_empty(),
        "C runtime imports: {crt:?} (all: {imports:?})"
    );
    assert!(!pe.imports.is_empty(), "the reader found no imports at all");
    assert_eq!(
        pe.dependent_load_flags,
        Some(LOAD_LIBRARY_SEARCH_SYSTEM32),
        "DependentLoadFlags"
    );
    assert!(
        !pe.imports
            .iter()
            .any(|n| n.eq_ignore_ascii_case("advapi32.dll")),
        "advapi32.dll must not be a static import: {:?}",
        pe.imports
    );
    assert!(
        pe.delay_imports
            .iter()
            .any(|n| n.eq_ignore_ascii_case("advapi32.dll")),
        "advapi32.dll must be delay-loaded: {:?}",
        pe.delay_imports
    );
    assert_eq!(
        pe.headers.subsystem, SUBSYSTEM_CONSOLE,
        "the CLI is a console program"
    );
    let manifest = pe.manifest.as_deref().expect("an embedded RT_MANIFEST");
    assert!(
        manifest_is_hardened(manifest),
        "the manifest requests asInvoker and sets longPathAware to true"
    );
}
