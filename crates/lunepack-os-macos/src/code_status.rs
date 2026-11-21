//! What a Security.framework status means for a publisher check (M9-D7, M9-R1-D2): the allowlist of
//! statuses that are a verdict about the code, and nothing else. Every other status, a missing or
//! unreadable file included, is a local fault, so it never marks a release bad.
//!
//! Plain integers, so it is tested on every host; each value is the one in `Security/CSCommon.h`
//! (checked against the SDK on a Mac when this was written) and a macOS test pins it against the
//! framework's own behaviour.

/// `errSecCSUnsigned`: the code object is not signed at all.
pub(crate) const ERR_SEC_CS_UNSIGNED: i32 = -67062;
/// `errSecCSReqFailed`: the code does not satisfy the requirement.
pub(crate) const ERR_SEC_CS_REQ_FAILED: i32 = -67050;

/// The statuses that say the code's own bytes or signature are wrong (`Security/CSCommon.h`).
/// A name the SDK lacks is not here: it falls to a local fault.
pub(crate) const INVALID_SET: [(&str, i32); 16] = [
    ("errSecCSSignatureFailed", -67061),
    ("errSecCSSignatureInvalid", -67045),
    ("errSecCSBadResource", -67054),
    ("errSecCSResourcesNotSealed", -67057),
    ("errSecCSResourcesNotFound", -67056),
    ("errSecCSResourcesInvalid", -67055),
    ("errSecCSResourceDirectoryFailed", -67023),
    ("errSecCSResourceRulesInvalid", -67053),
    ("errSecCSBadNestedCode", -67021),
    // Not in the sketch: a bundle sealed with nested code that is now unsigned is the same finding
    // as nested code that was modified, and a definitive one about the bundle's own contents.
    ("errSecCSUnsignedNestedCode", -67022),
    ("errSecCSInfoPlistFailed", -67030),
    ("errSecCSUnsealedAppRoot", -67014),
    ("errSecCSUnsealedFrameworkRoot", -67008),
    ("errSecCSBadMainExecutable", -67010),
    ("errSecCSBadBundleFormat", -67028),
    ("errSecCSInvalidSymlink", -67003),
];

/// What a status says about the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// `errSecSuccess`.
    Ok,
    /// The code is not signed at all.
    Unsigned,
    /// The code does not satisfy the requirement (a different publisher, when the requirement is
    /// the installed bundle's designated requirement).
    ReqFailed,
    /// The signature or the sealed contents do not verify.
    Invalid,
    /// Anything else: the check could not be made.
    Os,
}

/// Classifies the status of a validity check.
pub(crate) fn classify(status: i32) -> Verdict {
    match status {
        0 => Verdict::Ok,
        ERR_SEC_CS_UNSIGNED => Verdict::Unsigned,
        ERR_SEC_CS_REQ_FAILED => Verdict::ReqFailed,
        s if INVALID_SET.iter().any(|(_, v)| *v == s) => Verdict::Invalid,
        _ => Verdict::Os,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_listed_statuses_are_verdicts() {
        assert_eq!(classify(0), Verdict::Ok);
        assert_eq!(classify(ERR_SEC_CS_UNSIGNED), Verdict::Unsigned);
        assert_eq!(classify(ERR_SEC_CS_REQ_FAILED), Verdict::ReqFailed);
        for (name, status) in INVALID_SET {
            assert_eq!(classify(status), Verdict::Invalid, "{name}");
        }
    }

    #[test]
    fn the_invalid_set_has_distinct_values_and_no_other_verdict_in_it() {
        let mut seen = std::collections::BTreeSet::new();
        for (name, status) in INVALID_SET {
            assert!(seen.insert(status), "{name} repeats a value");
            assert!(![0, ERR_SEC_CS_UNSIGNED, ERR_SEC_CS_REQ_FAILED].contains(&status));
        }
    }

    #[test]
    fn everything_else_is_a_local_fault() {
        // Code not found on disk, unreadable, a bad object, an internal error, a keychain or
        // database fault, a cancelled operation, an untrusted signer, memory, an unknown number.
        for status in [
            -67068, // errSecCSStaticCodeNotFound
            -67060, // errSecCSSignatureNotVerifiable
            -67049, // errSecCSBadObjectFormat
            -67048, // errSecCSInternalError
            -67033, // errSecCSDBDenied
            -67032, // errSecCSDBAccess
            -67006, // errSecCSCancelled
            -66996, // errSecCSSignatureUntrusted
            -108,   // memFullErr
            -25293, // errSecAuthFailed
            1,
            i32::MIN,
            i32::MAX,
        ] {
            assert_eq!(classify(status), Verdict::Os, "{status}");
        }
    }
}
