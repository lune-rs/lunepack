//! What a `WinVerifyTrust` answer means for a publisher check (M9-D8, M9-R1-D2, M9-R1-D3): the
//! allowlist of statuses that are a verdict about the file. Everything else is a local fault, so a
//! sharing violation, a scanner's lock, an I/O error or an unknown status never marks a release bad.
//!
//! Pure integers, so it is tested on every host; a Windows-only test pins each constant to
//! `windows-sys`'s.

/// `TRUST_E_NOSIGNATURE`.
pub(crate) const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
/// `TRUST_E_SUBJECT_FORM_UNKNOWN`.
pub(crate) const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
/// `TRUST_E_PROVIDER_UNKNOWN`.
pub(crate) const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
/// `TRUST_E_BAD_DIGEST`.
pub(crate) const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
/// `CERT_E_UNTRUSTEDROOT`.
pub(crate) const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
/// `CERT_E_CHAINING`.
pub(crate) const CERT_E_CHAINING: u32 = 0x800B_010A;
/// `TRUST_E_EXPLICIT_DISTRUST`.
pub(crate) const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
/// `CERT_E_REVOKED`.
pub(crate) const CERT_E_REVOKED: u32 = 0x800B_010C;
/// `CERT_E_EXPIRED`.
pub(crate) const CERT_E_EXPIRED: u32 = 0x800B_0101;

/// What the status says about the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The signature verifies and chains to a trusted root.
    Trusted,
    /// The file has no Authenticode signature (a catalog signature counts as none: lunepack does
    /// not consult catalogs).
    Unsigned,
    /// A signature the file does not satisfy: altered bytes, an untrusted or broken chain, an
    /// explicit distrust, a revocation.
    Invalid,
    /// The signature is valid but a certificate has expired and nothing timestamped it. The
    /// caller decides (M9-R1-D3): a candidate is invalid, the installed tree's subject is still
    /// its baseline.
    Expired,
    /// Anything else: the check could not be made.
    Os,
}

/// Classifies `status` (what `WinVerifyTrust` returned) with `last_error` (`GetLastError()` read
/// right after it). `TRUST_E_NOSIGNATURE` is "unsigned" only when the last error says the file has
/// no signature or its form is unknown; with any other last error it is an unknown failure.
pub(crate) fn classify(status: u32, last_error: u32) -> Verdict {
    match status {
        0 => Verdict::Trusted,
        TRUST_E_NOSIGNATURE => match last_error {
            TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
                Verdict::Unsigned
            }
            _ => Verdict::Os,
        },
        TRUST_E_BAD_DIGEST
        | CERT_E_UNTRUSTEDROOT
        | CERT_E_CHAINING
        | TRUST_E_EXPLICIT_DISTRUST
        | CERT_E_REVOKED => Verdict::Invalid,
        CERT_E_EXPIRED => Verdict::Expired,
        _ => Verdict::Os,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_listed_statuses_are_verdicts_about_the_file() {
        assert_eq!(classify(0, 0), Verdict::Trusted);
        // A trusted answer is trusted whatever the stale last error holds.
        assert_eq!(classify(0, TRUST_E_NOSIGNATURE), Verdict::Trusted);
        for last in [
            TRUST_E_NOSIGNATURE,
            TRUST_E_SUBJECT_FORM_UNKNOWN,
            TRUST_E_PROVIDER_UNKNOWN,
        ] {
            assert_eq!(classify(TRUST_E_NOSIGNATURE, last), Verdict::Unsigned);
        }
        // No signature, but a last error that says something else went wrong: a local fault.
        for last in [0, 5, 32, 33, 0x8009_2003] {
            assert_eq!(
                classify(TRUST_E_NOSIGNATURE, last),
                Verdict::Os,
                "{last:#x}"
            );
        }
        for status in [
            TRUST_E_BAD_DIGEST,
            CERT_E_UNTRUSTEDROOT,
            CERT_E_CHAINING,
            TRUST_E_EXPLICIT_DISTRUST,
            CERT_E_REVOKED,
        ] {
            assert_eq!(classify(status, 0), Verdict::Invalid, "{status:#x}");
        }
        assert_eq!(classify(CERT_E_EXPIRED, 0), Verdict::Expired);
    }

    #[test]
    fn everything_else_is_a_local_fault() {
        // A sharing violation, a lock violation, access denied, file not found, an I/O error as
        // HRESULTs, `CRYPT_E_FILE_ERROR`, `TRUST_E_SUBJECT_NOT_TRUSTED`, `E_OUTOFMEMORY` and a few
        // more, none of which says anything about the file's own signature.
        for status in [
            0x8007_0020_u32,
            0x8007_0021,
            0x8007_0005,
            0x8007_0002,
            0x8007_001F,
            0x8009_2003,
            0x800B_0004,
            0x8007_000E,
            0x800B_010F,
            0x8000_4005,
            1,
            u32::MAX,
        ] {
            assert_eq!(classify(status, 0), Verdict::Os, "{status:#x}");
            assert_eq!(
                classify(status, TRUST_E_NOSIGNATURE),
                Verdict::Os,
                "{status:#x}"
            );
        }
    }
}
