//! C ABI over the `lunepack` facade (M14).
//!
//! A C-callable library for an app that updates itself: the running app's own updater (check,
//! download, stage) and the lifecycle calls. Each function is a thin wrapper over a facade call the
//! runtime's command line already uses; this crate adds no logic and constructs no adapter.
//!
//! Conventions (M14-D3 to D7): every fallible function returns an `int32_t` status, handles are
//! opaque and released by their `_free`, strings are UTF-8, and no panic crosses the boundary.
//! The header `include/lunepack.h` is generated (`cargo run -p xtask -- ffi-header`).

// A C ABI needs `no_mangle` symbols and raw pointers, which the crate-level `deny` refuses; each
// module that does so lifts it for itself, with a `// SAFETY:` comment on every unsafe block.

/// The version of the C ABI (M14-D7). Within a version changes are additive only: new functions,
/// statuses, phases, sources, reasons, flag bits, and fields appended to library-allocated structs.
/// Removing or re-meaning anything bumps it.
pub const ABI_VERSION: u32 = 1;

/// The ABI version this library implements, the value of `LUNEPACK_ABI_VERSION` in the header.
#[allow(unsafe_code)] // `no_mangle` is an unsafe attribute; the function itself has no unsafe code.
#[unsafe(no_mangle)]
pub extern "C" fn lunepack_abi_version() -> u32 {
    ABI_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_abi_version_is_one() {
        assert_eq!(lunepack_abi_version(), 1);
    }
}
