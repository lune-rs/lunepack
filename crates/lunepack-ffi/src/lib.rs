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

mod cancel;
mod guard;
mod status;

pub use cancel::{
    LunepackCancelToken, lunepack_cancel_token_cancel, lunepack_cancel_token_free,
    lunepack_cancel_token_is_cancelled, lunepack_cancel_token_new,
};
pub use status::{LunepackStatus, lunepack_last_error_reason, lunepack_status_name};

use std::ffi::c_char;

use lunepack::{Phase, Source};

/// The version of the C ABI (M14-D7), `LUNEPACK_ABI_VERSION` in the header; compare it with
/// `lunepack_abi_version()`. Within a version changes are additive only: new functions,
/// statuses, phases, sources, reasons, flag bits, and fields appended to library-allocated structs.
/// Removing or re-meaning anything bumps it.
pub const LUNEPACK_ABI_VERSION: u32 = 1;

/// The ABI version this library implements.
#[allow(unsafe_code)] // `no_mangle` is an unsafe attribute; the function itself has no unsafe code.
#[unsafe(no_mangle)]
pub extern "C" fn lunepack_abi_version() -> u32 {
    LUNEPACK_ABI_VERSION
}

/// The library's own version, as text (`"0.1.0"`): static, NUL-terminated.
#[allow(unsafe_code)] // `no_mangle` is an unsafe attribute; the function itself has no unsafe code.
#[unsafe(no_mangle)]
pub extern "C" fn lunepack_library_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// The phase of an operation, as a progress event reports it. A number this library does not
/// know (a phase a later version adds) is `LUNEPACK_PHASE_UNKNOWN`.
pub type LunepackPhase = i32;
/// Fetching and verifying the signed documents.
pub const LUNEPACK_PHASE_CHECK: LunepackPhase = 0;
/// Finding files of the current tree that the new version keeps unchanged.
pub const LUNEPACK_PHASE_SCAN: LunepackPhase = 1;
/// Fetching pack bytes into the cache.
pub const LUNEPACK_PHASE_DOWNLOAD: LunepackPhase = 2;
/// Building and verifying the new version tree.
pub const LUNEPACK_PHASE_STAGE: LunepackPhase = 3;
/// Installing the first version.
pub const LUNEPACK_PHASE_INSTALL: LunepackPhase = 4;
/// Waiting for the app to exit before an apply.
pub const LUNEPACK_PHASE_WAIT: LunepackPhase = 5;
/// Committing the staged version and switching `current` to it.
pub const LUNEPACK_PHASE_APPLY: LunepackPhase = 6;
/// Launching the new version.
pub const LUNEPACK_PHASE_LAUNCH: LunepackPhase = 7;
/// Waiting for the new version to confirm its health.
pub const LUNEPACK_PHASE_CONFIRM: LunepackPhase = 8;
/// Rolling a version that failed its health check back to the previous one.
pub const LUNEPACK_PHASE_ROLLBACK: LunepackPhase = 9;
/// Removing the install.
pub const LUNEPACK_PHASE_UNINSTALL: LunepackPhase = 10;
/// Proving a bundle the user placed equal to its signed release before adopting it.
pub const LUNEPACK_PHASE_ADOPT: LunepackPhase = 11;
/// A phase this library version does not know.
pub const LUNEPACK_PHASE_UNKNOWN: LunepackPhase = -1;

/// Where the bytes of one file come from. A number this library does not know is
/// `LUNEPACK_SOURCE_UNKNOWN`.
pub type LunepackSource = i32;
/// Copied from the current tree, hash-checked against the manifest.
pub const LUNEPACK_SOURCE_UNCHANGED: LunepackSource = 0;
/// A single frame fetched with an HTTP Range request.
pub const LUNEPACK_SOURCE_RANGE: LunepackSource = 1;
/// Taken from the full pack.
pub const LUNEPACK_SOURCE_FULL_PACK: LunepackSource = 2;
/// A delta patch against the current file (reserved).
pub const LUNEPACK_SOURCE_PATCH: LunepackSource = 3;
/// A source this library version does not know.
pub const LUNEPACK_SOURCE_UNKNOWN: LunepackSource = -1;

/// Every phase and its name, in number order.
const PHASE_NAMES: &[(LunepackPhase, &std::ffi::CStr)] = &[
    (LUNEPACK_PHASE_CHECK, c"check"),
    (LUNEPACK_PHASE_SCAN, c"scan"),
    (LUNEPACK_PHASE_DOWNLOAD, c"download"),
    (LUNEPACK_PHASE_STAGE, c"stage"),
    (LUNEPACK_PHASE_INSTALL, c"install"),
    (LUNEPACK_PHASE_WAIT, c"wait"),
    (LUNEPACK_PHASE_APPLY, c"apply"),
    (LUNEPACK_PHASE_LAUNCH, c"launch"),
    (LUNEPACK_PHASE_CONFIRM, c"confirm"),
    (LUNEPACK_PHASE_ROLLBACK, c"rollback"),
    (LUNEPACK_PHASE_UNINSTALL, c"uninstall"),
    (LUNEPACK_PHASE_ADOPT, c"adopt"),
];

/// Every source and its name, in number order.
const SOURCE_NAMES: &[(LunepackSource, &std::ffi::CStr)] = &[
    (LUNEPACK_SOURCE_UNCHANGED, c"unchanged"),
    (LUNEPACK_SOURCE_RANGE, c"range"),
    (LUNEPACK_SOURCE_FULL_PACK, c"full_pack"),
    (LUNEPACK_SOURCE_PATCH, c"patch"),
];

/// The number of a facade phase; a phase a later facade adds is `LUNEPACK_PHASE_UNKNOWN`.
#[allow(dead_code)] // the progress bridge of the next step is its caller.
pub(crate) fn phase_number(phase: Phase) -> LunepackPhase {
    match phase {
        Phase::Check => LUNEPACK_PHASE_CHECK,
        Phase::Scan => LUNEPACK_PHASE_SCAN,
        Phase::Download => LUNEPACK_PHASE_DOWNLOAD,
        Phase::Stage => LUNEPACK_PHASE_STAGE,
        Phase::Install => LUNEPACK_PHASE_INSTALL,
        Phase::Wait => LUNEPACK_PHASE_WAIT,
        Phase::Apply => LUNEPACK_PHASE_APPLY,
        Phase::Launch => LUNEPACK_PHASE_LAUNCH,
        Phase::Confirm => LUNEPACK_PHASE_CONFIRM,
        Phase::Rollback => LUNEPACK_PHASE_ROLLBACK,
        Phase::Uninstall => LUNEPACK_PHASE_UNINSTALL,
        Phase::Adopt => LUNEPACK_PHASE_ADOPT,
        _ => LUNEPACK_PHASE_UNKNOWN,
    }
}

/// The number of a facade source; a source a later facade adds is `LUNEPACK_SOURCE_UNKNOWN`.
#[allow(dead_code)] // the progress bridge of the next step is its caller.
pub(crate) fn source_number(source: Source) -> LunepackSource {
    match source {
        Source::Unchanged => LUNEPACK_SOURCE_UNCHANGED,
        Source::Range => LUNEPACK_SOURCE_RANGE,
        Source::FullPack => LUNEPACK_SOURCE_FULL_PACK,
        Source::Patch => LUNEPACK_SOURCE_PATCH,
        _ => LUNEPACK_SOURCE_UNKNOWN,
    }
}

fn name_in(table: &[(i32, &'static std::ffi::CStr)], number: i32) -> *const c_char {
    table
        .iter()
        .find(|(n, _)| *n == number)
        .map_or(std::ptr::null(), |(_, name)| name.as_ptr())
}

/// The name of a phase (`"check"`, `"download"`, ...): static; NULL for a number this library does
/// not know.
#[allow(unsafe_code)] // `no_mangle` is an unsafe attribute; the function itself has no unsafe code.
#[unsafe(no_mangle)]
pub extern "C" fn lunepack_phase_name(phase: LunepackPhase) -> *const c_char {
    guard::quiet(std::ptr::null(), || name_in(PHASE_NAMES, phase))
}

/// The name of a source (`"unchanged"`, `"range"`, `"full_pack"`, `"patch"`): static; NULL for a
/// number this library does not know.
#[allow(unsafe_code)] // `no_mangle` is an unsafe attribute; the function itself has no unsafe code.
#[unsafe(no_mangle)]
pub extern "C" fn lunepack_source_name(source: LunepackSource) -> *const c_char {
    guard::quiet(std::ptr::null(), || name_in(SOURCE_NAMES, source))
}

/// Plumbing the runtime's drift test uses; not part of the C ABI and free to change.
#[doc(hidden)]
pub mod unstable_internals {
    pub use crate::status::*;
}

#[cfg(test)]
#[allow(unsafe_code)] // reads the static strings the entry points return
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn text(p: *const c_char) -> Option<String> {
        // SAFETY: a non-NULL result is a static NUL-terminated string.
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned())
    }

    #[test]
    fn the_abi_version_is_one() {
        assert_eq!(lunepack_abi_version(), 1);
    }

    #[test]
    fn the_library_version_is_the_crate_version() {
        assert_eq!(
            text(lunepack_library_version()).as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn phase_and_source_names_follow_the_facade() {
        for phase in [Phase::Check, Phase::Download, Phase::Adopt, Phase::Rollback] {
            let name = text(lunepack_phase_name(phase_number(phase))).expect("a phase name");
            assert_eq!(name, format!("{phase:?}").to_lowercase());
        }
        assert_eq!(text(lunepack_phase_name(LUNEPACK_PHASE_UNKNOWN)), None);
        assert_eq!(text(lunepack_phase_name(99)), None);
        for (source, name) in [
            (Source::Unchanged, "unchanged"),
            (Source::Range, "range"),
            (Source::FullPack, "full_pack"),
            (Source::Patch, "patch"),
        ] {
            assert_eq!(
                text(lunepack_source_name(source_number(source))).as_deref(),
                Some(name)
            );
        }
        assert_eq!(text(lunepack_source_name(LUNEPACK_SOURCE_UNKNOWN)), None);
    }
}
