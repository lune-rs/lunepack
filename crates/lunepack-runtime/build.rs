//! Windows hardening for this binary (M7-D10): a load-config `DependentLoadFlags` of
//! `LOAD_LIBRARY_SEARCH_SYSTEM32` for its static imports, and the one shared manifest
//! (`asInvoker`, `longPathAware`, Windows 10/11 `supportedOS`) embedded. Only the MSVC linker on
//! Windows, and only the binaries and the examples (the end-to-end stand-in UI, which a `windows-*`
//! pack holds to the runtime's own image rules): nothing is added for other targets or tests.
//!
//! `advapi32.dll` is delay-loaded. Its `SystemFunction036` (`RtlGenRandom`, imported by
//! `getrandom` 0.2 through `ring`) is a forwarder to `cryptbase.dll`, which is not a KnownDLL, and
//! the loader resolves a static import's forwarder by the default search order, application
//! directory first, before `main` runs; `DependentLoadFlags` does not cover it. A `cryptbase.dll`
//! planted beside a `Setup.exe` in Downloads would run. Delay-loaded, `advapi32` is first loaded by
//! its first call, after `main` has limited the search to System32 (`harden_dll_search`). The
//! packager refuses a static `advapi32.dll` import.

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
    for kind in ["bins", "examples"] {
        println!("cargo:rustc-link-arg-{kind}=/DEPENDENTLOADFLAG:0x800");
        println!("cargo:rustc-link-arg-{kind}=/DELAYLOAD:advapi32.dll");
        println!("cargo:rustc-link-arg-{kind}=delayimp.lib");
        println!("cargo:rustc-link-arg-{kind}=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-{kind}=/MANIFESTINPUT:{}",
            manifest.display()
        );
    }
}
