//! Windows hardening for the two stub binaries (M7-D10): a load-config `DependentLoadFlags` of
//! `LOAD_LIBRARY_SEARCH_SYSTEM32` for its static imports, and the one shared manifest
//! (`asInvoker`, `longPathAware`, Windows 10/11 `supportedOS`) embedded. Only the MSVC linker on
//! Windows, and only the binaries: nothing is added for other targets, tests or examples.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("lunepack-os-windows")
            .join("res")
            .join("windows.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let windows_msvc = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if !windows_msvc {
        return;
    }
    println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
}
