//! Statuses (M14-D3): the C ABI's error numbers are the runtime's exit-code numbers and `kind`
//! names (`docs/RUNTIME.md`, "Exit codes") for the same class, plus `usage` and `internal`.
//!
//! The class of a facade error cannot be shared with the runtime (its `Kind` lives in a binary
//! crate), so [`Fail::of`] repeats the runtime's mapping, and a unit test in the runtime
//! (`modes.rs`) holds the two equal. The facade's `Display` text is never used: it may carry paths
//! or OS text, which no output of lunepack shows (D42).

#![allow(unsafe_code)] // `no_mangle` is an unsafe attribute; the bodies hold only checked code.

use std::ffi::{CStr, c_char};

use lunepack::{Error, ServiceReason};

use crate::guard;

/// The result of a function: `LUNEPACK_STATUS_OK` or a status number. Callers tolerate numbers
/// they do not know; `lunepack_status_name` names the ones this library does.
pub type LunepackStatus = i32;

/// Success.
pub const LUNEPACK_STATUS_OK: LunepackStatus = 0;
/// A bad argument (a NULL where a value is required, text that is not UTF-8, a value outside its
/// set, an unknown flag bit) or a call made from inside a progress callback.
pub const LUNEPACK_STATUS_USAGE: LunepackStatus = 2;
/// The tree is not installed, or there is no install state.
pub const LUNEPACK_STATUS_NOT_INSTALLED: LunepackStatus = 3;
/// Another lunepack operation holds the install lock.
pub const LUNEPACK_STATUS_BUSY: LunepackStatus = 4;
/// The operation was cancelled.
pub const LUNEPACK_STATUS_CANCELLED: LunepackStatus = 5;
/// The update is no longer applicable.
pub const LUNEPACK_STATUS_STALE: LunepackStatus = 6;
/// A document, hash or signature was refused.
pub const LUNEPACK_STATUS_VERIFY: LunepackStatus = 7;
/// The transport failed.
pub const LUNEPACK_STATUS_TRANSPORT: LunepackStatus = 8;
/// A filesystem operation failed.
pub const LUNEPACK_STATUS_FS: LunepackStatus = 9;
/// The install state store failed or is too new.
pub const LUNEPACK_STATUS_STATE: LunepackStatus = 10;
/// A download ended early; the part is kept and the next call resumes it.
pub const LUNEPACK_STATUS_INCOMPLETE: LunepackStatus = 11;
/// Nothing usable is staged.
pub const LUNEPACK_STATUS_NOTHING_STAGED: LunepackStatus = 12;
/// The update config is missing or unusable.
pub const LUNEPACK_STATUS_UPDATE_CONFIG: LunepackStatus = 14;
/// The staged version is not the expected one.
pub const LUNEPACK_STATUS_UNEXPECTED_VERSION: LunepackStatus = 15;
/// The health token does not match.
pub const LUNEPACK_STATUS_TOKEN_MISMATCH: LunepackStatus = 16;
/// The install is per machine and the call is the privileged engine's.
pub const LUNEPACK_STATUS_MACHINE_SCOPE: LunepackStatus = 17;
/// Not supported on this platform.
pub const LUNEPACK_STATUS_UNSUPPORTED: LunepackStatus = 18;
/// A process operation failed.
pub const LUNEPACK_STATUS_PROCESS: LunepackStatus = 19;
/// There is no previous version to roll back to.
pub const LUNEPACK_STATUS_ROLLBACK_UNAVAILABLE: LunepackStatus = 22;
/// The install already has a current version.
pub const LUNEPACK_STATUS_ALREADY_INSTALLED: LunepackStatus = 23;
/// The desktop integration failed or is in the way.
pub const LUNEPACK_STATUS_INTEGRATION: LunepackStatus = 24;
/// The install root holds files lunepack did not make.
pub const LUNEPACK_STATUS_INSTALL_MISMATCH: LunepackStatus = 26;
/// The channel offers no release for this install.
pub const LUNEPACK_STATUS_NO_RELEASE: LunepackStatus = 27;
/// The app is somewhere lunepack does not update (macOS); `lunepack_last_error_reason` names why.
pub const LUNEPACK_STATUS_UNSUPPORTED_LOCATION: LunepackStatus = 28;
/// The publisher policy refused the update; `lunepack_last_error_reason` names why.
pub const LUNEPACK_STATUS_PUBLISHER_MISMATCH: LunepackStatus = 29;
/// The update service of a machine install cannot be used; `lunepack_last_error_reason` names why.
pub const LUNEPACK_STATUS_SERVICE_UNAVAILABLE: LunepackStatus = 32;
/// An administrator's policy switched self-update off.
pub const LUNEPACK_STATUS_DISABLED_BY_POLICY: LunepackStatus = 33;
/// A directory of the machine install is not protected as it must be.
pub const LUNEPACK_STATUS_NOT_PROTECTED: LunepackStatus = 35;
/// A caught panic, a worker failure, or an error this library version does not know.
pub const LUNEPACK_STATUS_INTERNAL: LunepackStatus = 70;

/// Every status and its name (the runtime's `kind` name), in number order.
const STATUS_NAMES: &[(LunepackStatus, &CStr)] = &[
    (LUNEPACK_STATUS_OK, c"ok"),
    (LUNEPACK_STATUS_USAGE, c"usage"),
    (LUNEPACK_STATUS_NOT_INSTALLED, c"not_installed"),
    (LUNEPACK_STATUS_BUSY, c"busy"),
    (LUNEPACK_STATUS_CANCELLED, c"cancelled"),
    (LUNEPACK_STATUS_STALE, c"stale"),
    (LUNEPACK_STATUS_VERIFY, c"verify"),
    (LUNEPACK_STATUS_TRANSPORT, c"transport"),
    (LUNEPACK_STATUS_FS, c"fs"),
    (LUNEPACK_STATUS_STATE, c"state"),
    (LUNEPACK_STATUS_INCOMPLETE, c"incomplete"),
    (LUNEPACK_STATUS_NOTHING_STAGED, c"nothing_staged"),
    (LUNEPACK_STATUS_UPDATE_CONFIG, c"update_config"),
    (LUNEPACK_STATUS_UNEXPECTED_VERSION, c"unexpected_version"),
    (LUNEPACK_STATUS_TOKEN_MISMATCH, c"token_mismatch"),
    (LUNEPACK_STATUS_MACHINE_SCOPE, c"machine_scope"),
    (LUNEPACK_STATUS_UNSUPPORTED, c"unsupported"),
    (LUNEPACK_STATUS_PROCESS, c"process"),
    (
        LUNEPACK_STATUS_ROLLBACK_UNAVAILABLE,
        c"rollback_unavailable",
    ),
    (LUNEPACK_STATUS_ALREADY_INSTALLED, c"already_installed"),
    (LUNEPACK_STATUS_INTEGRATION, c"integration"),
    (LUNEPACK_STATUS_INSTALL_MISMATCH, c"install_mismatch"),
    (LUNEPACK_STATUS_NO_RELEASE, c"no_release"),
    (
        LUNEPACK_STATUS_UNSUPPORTED_LOCATION,
        c"unsupported_location",
    ),
    (LUNEPACK_STATUS_PUBLISHER_MISMATCH, c"publisher_mismatch"),
    (LUNEPACK_STATUS_SERVICE_UNAVAILABLE, c"service_unavailable"),
    (LUNEPACK_STATUS_DISABLED_BY_POLICY, c"disabled_by_policy"),
    (LUNEPACK_STATUS_NOT_PROTECTED, c"not_protected"),
    (LUNEPACK_STATUS_INTERNAL, c"internal"),
];

/// The reasons of `unsupported_location` (macOS, M8-D4).
const PLACE_REASONS: &[&CStr] = &[
    c"translocated",
    c"read_only",
    c"other_volume",
    c"not_owned",
    c"not_writable",
];

/// The reasons of `publisher_mismatch` (M9-D9): every outcome the facade names.
const PUBLISHER_REASONS: &[&CStr] = &[
    c"different",
    c"installed_unsigned",
    c"installed_invalid",
    c"candidate_unsigned",
    c"candidate_invalid",
    c"os",
];

/// The reasons of `service_unavailable` (M10-D13).
const SERVICE_REASONS: &[&CStr] = &[
    c"not_installed",
    c"disabled",
    c"start_failed",
    c"untrusted",
    c"timeout",
    c"protocol",
    c"unsupported",
];

/// A failed call: its status and, for the three classes that have one, the reason name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fail {
    status: LunepackStatus,
    reason: Option<&'static CStr>,
}

impl Fail {
    /// A bad argument or a reentrant call.
    pub const fn usage() -> Fail {
        Fail::plain(LUNEPACK_STATUS_USAGE)
    }

    /// A caught panic or an error this library does not know.
    pub const fn internal() -> Fail {
        Fail::plain(LUNEPACK_STATUS_INTERNAL)
    }

    const fn plain(status: LunepackStatus) -> Fail {
        Fail {
            status,
            reason: None,
        }
    }

    fn with_reason(status: LunepackStatus, table: &[&'static CStr], name: &str) -> Fail {
        Fail {
            status,
            reason: table
                .iter()
                .copied()
                .find(|r| r.to_bytes() == name.as_bytes()),
        }
    }

    /// The status number.
    pub const fn status(&self) -> LunepackStatus {
        self.status
    }

    /// The reason name, for `unsupported_location`, `publisher_mismatch` and
    /// `service_unavailable`.
    pub const fn reason(&self) -> Option<&'static CStr> {
        self.reason
    }

    /// The class of a facade error: the same number and reason as the runtime's `Kind::of` gives
    /// it. An error this version does not know is `internal`, never `ok`.
    pub fn of(e: &Error) -> Fail {
        use lunepack::Error as E;
        match e {
            E::NotInstalled => Fail::plain(LUNEPACK_STATUS_NOT_INSTALLED),
            E::Busy => Fail::plain(LUNEPACK_STATUS_BUSY),
            E::Cancelled => Fail::plain(LUNEPACK_STATUS_CANCELLED),
            E::Stale => Fail::plain(LUNEPACK_STATUS_STALE),
            E::MachineScope => Fail::plain(LUNEPACK_STATUS_MACHINE_SCOPE),
            E::VersionDirCollision => Fail::plain(LUNEPACK_STATUS_FS),
            E::StateTooNew => Fail::plain(LUNEPACK_STATUS_STATE),
            E::Verify(_) => Fail::plain(LUNEPACK_STATUS_VERIFY),
            E::Transport(_) => Fail::plain(LUNEPACK_STATUS_TRANSPORT),
            E::Fs(_) => Fail::plain(LUNEPACK_STATUS_FS),
            E::State(_) => Fail::plain(LUNEPACK_STATUS_STATE),
            E::Incomplete => Fail::plain(LUNEPACK_STATUS_INCOMPLETE),
            E::NeedFetchExhausted(_) => Fail::plain(LUNEPACK_STATUS_VERIFY),
            E::Config(_) | E::NoUpdateConfig | E::UpdateConfig(_) => {
                Fail::plain(LUNEPACK_STATUS_UPDATE_CONFIG)
            }
            E::Unsupported => Fail::plain(LUNEPACK_STATUS_UNSUPPORTED),
            E::NothingStaged => Fail::plain(LUNEPACK_STATUS_NOTHING_STAGED),
            E::UnexpectedVersion => Fail::plain(LUNEPACK_STATUS_UNEXPECTED_VERSION),
            E::AlreadyInstalled => Fail::plain(LUNEPACK_STATUS_ALREADY_INSTALLED),
            E::ForeignInstallRoot => Fail::plain(LUNEPACK_STATUS_INSTALL_MISMATCH),
            E::TokenMismatch => Fail::plain(LUNEPACK_STATUS_TOKEN_MISMATCH),
            E::Process(_) => Fail::plain(LUNEPACK_STATUS_PROCESS),
            E::Integration(_) => Fail::plain(LUNEPACK_STATUS_INTEGRATION),
            E::RollbackUnavailable => Fail::plain(LUNEPACK_STATUS_ROLLBACK_UNAVAILABLE),
            E::NoRelease => Fail::plain(LUNEPACK_STATUS_NO_RELEASE),
            // A reason this version does not know is `internal`, as in the runtime.
            E::UnsupportedLocation { reason } => {
                let fail = Fail::with_reason(
                    LUNEPACK_STATUS_UNSUPPORTED_LOCATION,
                    PLACE_REASONS,
                    reason.as_str(),
                );
                if fail.reason.is_some() {
                    fail
                } else {
                    Fail::internal()
                }
            }
            E::PublisherMismatch { reason } => Fail::with_reason(
                LUNEPACK_STATUS_PUBLISHER_MISMATCH,
                PUBLISHER_REASONS,
                reason.code(),
            ),
            E::DisabledByPolicy => Fail::plain(LUNEPACK_STATUS_DISABLED_BY_POLICY),
            E::ServiceUnavailable { reason } => {
                // A reason a later facade adds is `protocol`, as in the runtime.
                let name = match reason {
                    ServiceReason::NotInstalled => "not_installed",
                    ServiceReason::Disabled => "disabled",
                    ServiceReason::StartFailed => "start_failed",
                    ServiceReason::Untrusted => "untrusted",
                    ServiceReason::Timeout => "timeout",
                    _ => "protocol",
                };
                Fail::with_reason(LUNEPACK_STATUS_SERVICE_UNAVAILABLE, SERVICE_REASONS, name)
            }
            E::ServiceUnsupported => Fail::with_reason(
                LUNEPACK_STATUS_SERVICE_UNAVAILABLE,
                SERVICE_REASONS,
                "unsupported",
            ),
            // The service's own refusals, by the code's wire name: a refused document is
            // `verify`, a tree that is not protected as it must be is `not_protected`; the rest
            // carries no class of its own.
            E::ServiceRefused { code, .. } => match code.as_str() {
                "verify_failed" | "not_in_manifest" | "size_mismatch" | "hash_mismatch"
                | "pending_exists" | "bad_full" => Fail::plain(LUNEPACK_STATUS_VERIFY),
                "not_protected" => Fail::plain(LUNEPACK_STATUS_NOT_PROTECTED),
                _ => Fail::internal(),
            },
            // WorkerPanicked, and any variant a later facade adds (the enum is non-exhaustive).
            _ => Fail::internal(),
        }
    }
}

/// The name of a publisher finding (`different`, `candidate_unsigned`, ...), the same text the
/// runtime's `publisher` member and the `publisher_mismatch` reason carry.
pub(crate) fn publisher_name(finding: lunepack::PublisherOutcome) -> Option<&'static CStr> {
    PUBLISHER_REASONS
        .iter()
        .copied()
        .find(|r| r.to_bytes() == finding.code().as_bytes())
}

/// Every status number and name this library defines, for the runtime's drift test.
pub fn status_table() -> impl Iterator<Item = (LunepackStatus, &'static str)> {
    STATUS_NAMES
        .iter()
        .map(|(n, name)| (*n, name.to_str().unwrap_or_default()))
}

/// Every reason name of a status that has reasons, for the runtime's drift test.
pub fn reason_table(status: LunepackStatus) -> &'static [&'static CStr] {
    match status {
        LUNEPACK_STATUS_UNSUPPORTED_LOCATION => PLACE_REASONS,
        LUNEPACK_STATUS_PUBLISHER_MISMATCH => PUBLISHER_REASONS,
        LUNEPACK_STATUS_SERVICE_UNAVAILABLE => SERVICE_REASONS,
        _ => &[],
    }
}

/// The name of a status number: `"ok"` for 0, the runtime's `kind` name for the others, NULL for
/// a number this library does not know. The string is static.
#[unsafe(no_mangle)]
pub extern "C" fn lunepack_status_name(status: LunepackStatus) -> *const c_char {
    guard::quiet(std::ptr::null(), || {
        STATUS_NAMES
            .iter()
            .find(|(n, _)| *n == status)
            .map_or(std::ptr::null(), |(_, name)| name.as_ptr())
    })
}

/// The reason name of the calling thread's last failed call, for `unsupported_location`,
/// `publisher_mismatch` and `service_unavailable`; NULL when the last call had none, or succeeded.
/// Every status-returning function clears it on entry. The string is static.
#[unsafe(no_mangle)]
pub extern "C" fn lunepack_last_error_reason() -> *const c_char {
    guard::quiet(std::ptr::null(), || {
        guard::last_reason().map_or(std::ptr::null(), CStr::as_ptr)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_of(status: LunepackStatus) -> Option<String> {
        let p = lunepack_status_name(status);
        // SAFETY: a non-NULL result is a static NUL-terminated string.
        (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_owned())
    }

    #[test]
    fn status_names_cover_the_table_and_unknown_numbers_have_none() {
        assert_eq!(name_of(0).as_deref(), Some("ok"));
        assert_eq!(name_of(2).as_deref(), Some("usage"));
        assert_eq!(name_of(14).as_deref(), Some("update_config"));
        assert_eq!(name_of(70).as_deref(), Some("internal"));
        for n in [1, 13, 20, 21, 25, 30, 31, 34, 36, 69, 71, -1, i32::MAX] {
            assert_eq!(name_of(n), None, "{n}");
        }
        let mut numbers: Vec<_> = status_table().map(|(n, _)| n).collect();
        let len = numbers.len();
        numbers.sort_unstable();
        numbers.dedup();
        assert_eq!(numbers.len(), len, "numbers are unique");
        assert!(numbers.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn an_unknown_error_is_internal_and_never_ok() {
        assert_eq!(
            Fail::of(&Error::WorkerPanicked).status(),
            LUNEPACK_STATUS_INTERNAL
        );
        assert_eq!(
            Fail::of(&Error::NoRelease).status(),
            LUNEPACK_STATUS_NO_RELEASE
        );
        assert_eq!(Fail::of(&Error::NoRelease).reason(), None);
    }

    #[test]
    fn publisher_and_service_reasons_are_named() {
        let f = Fail::of(&Error::PublisherMismatch {
            reason: lunepack::PublisherOutcome::CandidateUnsigned,
        });
        assert_eq!(f.status(), LUNEPACK_STATUS_PUBLISHER_MISMATCH);
        assert_eq!(f.reason(), Some(c"candidate_unsigned"));
        let f = Fail::of(&Error::ServiceUnavailable {
            reason: ServiceReason::Timeout,
        });
        assert_eq!(f.status(), LUNEPACK_STATUS_SERVICE_UNAVAILABLE);
        assert_eq!(f.reason(), Some(c"timeout"));
        let f = Fail::of(&Error::ServiceUnsupported);
        assert_eq!(f.reason(), Some(c"unsupported"));
    }
}
