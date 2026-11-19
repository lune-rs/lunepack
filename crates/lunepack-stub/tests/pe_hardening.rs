//! Both stub images carry the Windows hardening (M7-D10, P6a): no C-runtime DLL import,
//! `DependentLoadFlags` of `LOAD_LIBRARY_SEARCH_SYSTEM32`, an embedded manifest with `asInvoker`
//! and `longPathAware`; the GUI stub is a GUI-subsystem binary (2) and the console stub a
//! console one (3). The test reads the binaries cargo built for it (`CARGO_BIN_EXE_<name>`), so it
//! fails when `.cargo/config.toml`'s `+crt-static` is overridden by a `RUSTFLAGS` environment
//! variable. Empty off Windows. The reader is the core's `pe` module.

#![cfg(windows)]

use lunepack_core::pe::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, PeImage, SUBSYSTEM_CONSOLE, SUBSYSTEM_GUI, is_c_runtime,
    manifest_is_hardened,
};
use lunepack_core::{Target, check_pe_stub};

#[cfg(target_arch = "x86_64")]
const TARGET: Target = Target::WindowsX86_64;
#[cfg(target_arch = "aarch64")]
const TARGET: Target = Target::WindowsAarch64;

fn assert_hardened(path: &str, subsystem: u16) {
    let bytes = std::fs::read(path).expect("read the stub binary");
    let pe = PeImage::parse(&bytes).expect("the stub binary reads as a PE image");
    let imports: Vec<&str> = pe.all_imports().collect();
    assert!(!imports.is_empty(), "the reader found no imports at all");
    let crt: Vec<&&str> = imports.iter().filter(|n| is_c_runtime(n)).collect();
    assert!(
        crt.is_empty(),
        "C runtime imports: {crt:?} (all: {imports:?})"
    );
    assert_eq!(
        pe.dependent_load_flags,
        Some(LOAD_LIBRARY_SEARCH_SYSTEM32),
        "DependentLoadFlags"
    );
    assert_eq!(pe.headers.subsystem, subsystem, "subsystem");
    let manifest = pe.manifest.as_deref().expect("an embedded RT_MANIFEST");
    assert!(
        manifest_is_hardened(manifest),
        "the manifest requests asInvoker and sets longPathAware to true"
    );
    // The packager's own check (M7-D10) accepts it as the stub of its subsystem.
    assert_eq!(
        check_pe_stub(&bytes, TARGET, subsystem == SUBSYSTEM_CONSOLE),
        Ok(())
    );
}

#[test]
fn the_gui_stub_image_is_hardened() {
    assert_hardened(env!("CARGO_BIN_EXE_lunepack-stub"), SUBSYSTEM_GUI);
}

#[test]
fn the_console_stub_image_is_hardened() {
    assert_hardened(
        env!("CARGO_BIN_EXE_lunepack-stub-console"),
        SUBSYSTEM_CONSOLE,
    );
}
