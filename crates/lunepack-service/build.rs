//! Windows hardening for the service binary (M7-D10, as the stub and the runtime): a load-config
//! `DependentLoadFlags` of `LOAD_LIBRARY_SEARCH_SYSTEM32` for its static imports, and the one
//! shared manifest (`asInvoker`, `longPathAware`, Windows 10/11 `supportedOS`) embedded. Only the
//! MSVC linker on Windows, and only the binary: nothing is added for other targets or tests.
//!
//! `advapi32.dll` is delay-loaded, as in the runtime: the service control manager, the registry
//! and the security descriptors all live there, and a delay-loaded `advapi32` is first loaded by
//! its first call, after `main` has limited the search to System32 (`harden_dll_search`). The
//! packager's image check refuses a static `advapi32.dll` import.

// The build script reads cargo's own variables; the ban on environment reads is for the service
// program, which runs as LocalSystem (clippy.toml).
#![allow(clippy::disallowed_methods)]

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
    println!("cargo:rustc-link-arg-bins=/DELAYLOAD:advapi32.dll");
    println!("cargo:rustc-link-arg-bins=delayimp.lib");
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
}
