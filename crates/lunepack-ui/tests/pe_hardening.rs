//! The UI's own PE image carries the Windows hardening (M7-D10, P6a): no C-runtime DLL
//! import, `DependentLoadFlags` of `LOAD_LIBRARY_SEARCH_SYSTEM32`, an embedded manifest with
//! `asInvoker` and `longPathAware`, and the GUI subsystem (M7-D6). The test reads the binary cargo
//! built for it (`CARGO_BIN_EXE_lunepack-ui`), so it fails when `.cargo/config.toml`'s
//! `+crt-static` is overridden by a `RUSTFLAGS` environment variable. Empty off Windows.
//!
//! The reader is the core's `pe` module, the one the packager checks every Windows binary with.

#![cfg(windows)]

use lunepack_core::pe::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, PeImage, SUBSYSTEM_GUI, is_c_runtime, manifest_is_hardened,
};
use lunepack_core::{Target, check_ui_image};

const IMAGE: &str = env!("CARGO_BIN_EXE_lunepack-ui");
#[cfg(target_arch = "x86_64")]
const TARGET: Target = Target::WindowsX86_64;
#[cfg(target_arch = "aarch64")]
const TARGET: Target = Target::WindowsAarch64;

#[test]
fn the_ui_image_is_hardened() {
    let bytes = std::fs::read(IMAGE).expect("read the UI binary");
    let pe = PeImage::parse(&bytes).expect("the UI binary reads as a PE image");
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
    assert_eq!(
        pe.headers.subsystem, SUBSYSTEM_GUI,
        "the UI is a GUI-subsystem binary"
    );
    let manifest = pe.manifest.as_deref().expect("an embedded RT_MANIFEST");
    assert!(
        manifest_is_hardened(manifest),
        "the manifest requests asInvoker and sets longPathAware to true"
    );
    // The packager's own check (M7-D10) accepts it.
    assert_eq!(check_ui_image(&bytes, TARGET), Ok(()));
}

#[test]
fn the_reader_lists_the_imports_of_a_known_system_image() {
    // The control: a reader that found no imports would pass the test above for the wrong reason.
    // `kernel32.dll` is known to import `ntdll.dll`.
    let system = std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
        .join("System32")
        .join("kernel32.dll");
    let bytes = std::fs::read(system).expect("read kernel32.dll");
    let pe = PeImage::parse(&bytes).expect("kernel32.dll reads as a PE image");
    assert!(
        pe.imports
            .iter()
            .any(|n| n.eq_ignore_ascii_case("ntdll.dll")),
        "kernel32.dll must import ntdll.dll, got {:?}",
        pe.imports
    );
}
