//! Build script of the C library: the macOS install name of the cdylib, and the target triple the
//! tests need to compile a C file for the same target.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // The target triple, for the C example's compile-and-run test (M14 step 5).
    let target = std::env::var("TARGET").expect("cargo sets TARGET for a build script");
    println!("cargo:rustc-env=LUNEPACK_FFI_TARGET={target}");
    // A macOS cdylib otherwise records an absolute build path as its install name, which a C app
    // beside a copy of the library could not load. `@rpath` lets the app choose where to look.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/liblunepack_ffi.dylib");
    }
}
