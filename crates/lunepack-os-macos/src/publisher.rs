//! The publisher-continuity check on macOS (M9-D7, M9-D10, M9-R1-D2): [`MacPublisherCheck`].
//!
//! The rule is Sparkle's: the candidate bundle must be valid (`SecStaticCodeCheckValidity` with
//! strict validation, nested code, every architecture and restricted symlinks, and no network) and
//! must satisfy the installed bundle's own designated requirement. The requirement is only ever
//! copied out of the installed signature by Security; no requirement text is assembled from
//! strings. An ad-hoc signature (its designated requirement is a cdhash, so every rebuild would be
//! "different") counts as unsigned on either side. Nothing in a tree is executed, and no
//! `Info.plist` is read by lunepack.
//!
//! Only the statuses [`crate::code_status`] lists are verdicts about the code; every other status,
//! and every file-system or CoreFoundation failure, is [`PublisherError::Os`]: a local fault is
//! retried later and never marks a version bad. The installed bundle is examined first.
//!
//! CoreFoundation ownership: the `Copy` calls return +1 references and are wrapped under the create
//! rule at once; a dictionary lookup is +0 and wrapped under the get rule, so every object is
//! released exactly once.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::Path;

use core_foundation::base::{CFType, CFTypeRef, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFStringRef;
use core_foundation::url::CFURL;
use lunepack_core::{PublisherCheck, PublisherError, SignedTree};
use security_framework::os::macos::code_signing::{Flags, SecRequirement, SecStaticCode};

use crate::code_status::{Verdict, classify};

/// `kSecCSSigningInformation`: ask for the signing information (`SecCode.h`).
const SIGNING_INFORMATION: u32 = 1 << 1;
/// `kSecCodeSignatureAdhoc` (`CSCommon.h`).
const SIGNATURE_ADHOC: i64 = 0x0002;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    /// `kSecCodeInfoFlags`: a CFNumber, the code's signature flags.
    static kSecCodeInfoFlags: CFStringRef;

    fn SecStaticCodeCheckValidity(
        code: *const c_void,
        flags: u32,
        requirement: *const c_void,
    ) -> i32;

    fn SecCodeCopyDesignatedRequirement(
        code: *const c_void,
        flags: u32,
        requirement: *mut *const c_void,
    ) -> i32;

    fn SecCodeCopySigningInformation(
        code: *const c_void,
        flags: u32,
        information: *mut *const c_void,
    ) -> i32;
}

/// The [`PublisherCheck`] of macOS.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacPublisherCheck;

/// What looking at the installed bundle found.
enum Ident {
    /// Not signed, or signed ad hoc: no publisher.
    Unsigned,
    Invalid,
    Os,
    /// Valid and signed by an identity: its designated requirement.
    Signed(SecRequirement),
}

/// The flags every validity check uses (M9-D7). `NO_NETWORK_ACCESS` keeps the check offline.
fn strict() -> Flags {
    Flags::CHECK_ALL_ARCHITECTURES
        | Flags::CHECK_NESTED_CODE
        | Flags::STRICT_VALIDATE
        | Flags::RESTRICT_SYMLINKS
        | Flags::NO_NETWORK_ACCESS
}

/// Why a bundle is not a signed one, from [`open_signed`].
enum NotSigned {
    Unsigned,
    Invalid,
    Os,
}

/// The status of `SecStaticCodeCheckValidity(code, flags, requirement)`, `requirement` absent when
/// null.
fn validity(code: &SecStaticCode, flags: Flags) -> i32 {
    // SAFETY: `code` is a live SecStaticCode for the whole call; a null requirement is the
    // documented way to ask for validity alone.
    unsafe {
        SecStaticCodeCheckValidity(
            code.as_concrete_TypeRef().cast::<c_void>(),
            flags.bits(),
            std::ptr::null(),
        )
    }
}

/// The static code at `root` once its own signature is known to be there: a cheap check of the
/// signature alone, with no requirement and no nested code, which is what tells an unsigned bundle
/// from a signed one with a missing part.
fn open_signed(root: &Path) -> Result<SecStaticCode, NotSigned> {
    let Some(url) = CFURL::from_path(root, true) else {
        return Err(NotSigned::Os);
    };
    let code = match SecStaticCode::from_path(&url, Flags::NONE) {
        Ok(code) => code,
        Err(e) => {
            return Err(match classify(e.code()) {
                Verdict::Unsigned => NotSigned::Unsigned,
                // Anything else at this point (not found, not readable) says nothing about the
                // code's signature.
                _ => NotSigned::Os,
            });
        }
    };
    match classify(validity(&code, Flags::BASIC_VALIDATE_ONLY)) {
        Verdict::Ok => Ok(code),
        Verdict::Unsigned => Err(NotSigned::Unsigned),
        Verdict::Invalid => Err(NotSigned::Invalid),
        Verdict::ReqFailed | Verdict::Os => Err(NotSigned::Os),
    }
}

/// The installed bundle: the whole tree is validated (strict, nested, every architecture), and its
/// designated requirement is copied out.
fn installed_identity(root: &Path) -> Ident {
    let code = match open_signed(root) {
        Ok(code) => code,
        Err(NotSigned::Unsigned) => return Ident::Unsigned,
        Err(NotSigned::Invalid) => return Ident::Invalid,
        Err(NotSigned::Os) => return Ident::Os,
    };
    // This is what tells an invalid signature from a different publisher, and, now that the bundle
    // is known to be signed, an unsigned part inside it (`errSecCSUnsigned` again) is an invalid
    // bundle, not an unsigned one.
    match classify(validity(&code, strict())) {
        Verdict::Ok => {}
        Verdict::Unsigned | Verdict::Invalid => return Ident::Invalid,
        // A requirement was not asked for, so a failed requirement is not a verdict here.
        Verdict::ReqFailed | Verdict::Os => return Ident::Os,
    }
    match signature_flags(&code) {
        Some(flags) if flags & SIGNATURE_ADHOC != 0 => return Ident::Unsigned,
        Some(_) => {}
        None => return Ident::Os,
    }
    match designated_requirement(&code) {
        Some(requirement) => Ident::Signed(requirement),
        None => Ident::Os,
    }
}

/// Whether the candidate bundle at `root` satisfies `requirement`. The tree is validated (strict,
/// nested, every architecture) once, without the requirement, which is what tells a damaged tree
/// from a different publisher; the requirement is then checked alone (`BASIC_VALIDATE_ONLY` skips
/// the validation already done, not the requirement), and no designated requirement is copied out
/// of the candidate.
fn candidate_satisfies(root: &Path, requirement: &SecRequirement) -> Result<bool, PublisherError> {
    let code = match open_signed(root) {
        Ok(code) => code,
        Err(NotSigned::Unsigned) => return Err(PublisherError::CandidateUnsigned),
        Err(NotSigned::Invalid) => return Err(PublisherError::CandidateInvalid),
        Err(NotSigned::Os) => return Err(PublisherError::Os),
    };
    // Now that the bundle is known to be signed, an unsigned part inside it (`errSecCSUnsigned`
    // again) is an invalid bundle, not an unsigned one.
    match classify(validity(&code, strict())) {
        Verdict::Ok => {}
        Verdict::Unsigned | Verdict::Invalid => return Err(PublisherError::CandidateInvalid),
        // A requirement was not asked for, so a failed requirement is not a verdict here.
        Verdict::ReqFailed | Verdict::Os => return Err(PublisherError::Os),
    }
    match signature_flags(&code) {
        Some(flags) if flags & SIGNATURE_ADHOC != 0 => {
            return Err(PublisherError::CandidateUnsigned);
        }
        Some(_) => {}
        None => return Err(PublisherError::Os),
    }
    let status = match code.check_validity(
        Flags::BASIC_VALIDATE_ONLY | Flags::NO_NETWORK_ACCESS,
        requirement,
    ) {
        Ok(()) => 0,
        Err(e) => e.code(),
    };
    match classify(status) {
        Verdict::Ok => Ok(true),
        Verdict::ReqFailed => Ok(false),
        Verdict::Invalid | Verdict::Unsigned => Err(PublisherError::CandidateInvalid),
        Verdict::Os => Err(PublisherError::Os),
    }
}

/// The `kSecCodeInfoFlags` of `code`, `None` when Security does not give them.
fn signature_flags(code: &SecStaticCode) -> Option<i64> {
    let mut info: *const c_void = std::ptr::null();
    // SAFETY: `code` is live; `info` is a valid out-pointer for one reference, written only on
    // success.
    let status = unsafe {
        SecCodeCopySigningInformation(
            code.as_concrete_TypeRef().cast::<c_void>(),
            SIGNING_INFORMATION,
            &mut info,
        )
    };
    if status != 0 || info.is_null() {
        return None;
    }
    // SAFETY: on success the call returned a +1 `CFDictionary` (create rule), which this wrapper
    // now owns and releases.
    let dict: CFDictionary<*const c_void, *const c_void> =
        unsafe { CFDictionary::wrap_under_create_rule(info.cast()) };
    // SAFETY: `kSecCodeInfoFlags` is a constant CFString the framework exports; it is only read.
    let key = unsafe { kSecCodeInfoFlags };
    let value = dict.find(key.cast::<c_void>())?;
    // SAFETY: the dictionary owns the value (+0): wrapping it under the get rule retains it for
    // the wrapper's life, and `downcast` checks that it really is a CFNumber.
    let value = unsafe { CFType::wrap_under_get_rule(*value as CFTypeRef) };
    value.downcast::<CFNumber>()?.to_i64()
}

/// The designated requirement of `code`, copied out of its signature by Security.
fn designated_requirement(code: &SecStaticCode) -> Option<SecRequirement> {
    let mut requirement: *const c_void = std::ptr::null();
    // SAFETY: `code` is live; `requirement` is a valid out-pointer for one reference, written only
    // on success.
    let status = unsafe {
        SecCodeCopyDesignatedRequirement(
            code.as_concrete_TypeRef().cast::<c_void>(),
            0,
            &mut requirement,
        )
    };
    if status != 0 || requirement.is_null() {
        return None;
    }
    // SAFETY: on success the call returned a +1 `SecRequirement` (create rule), which this wrapper
    // now owns and releases.
    Some(unsafe { SecRequirement::wrap_under_create_rule(requirement.cast_mut().cast()) })
}

impl PublisherCheck for MacPublisherCheck {
    fn same_publisher(
        &self,
        installed: &SignedTree,
        candidate: &SignedTree,
    ) -> Result<bool, PublisherError> {
        let requirement = match installed_identity(&installed.root) {
            Ident::Signed(requirement) => requirement,
            Ident::Unsigned => return Err(PublisherError::InstalledUnsigned),
            Ident::Invalid => return Err(PublisherError::InstalledInvalid),
            Ident::Os => return Err(PublisherError::Os),
        };
        candidate_satisfies(&candidate.root, &requirement)
    }
}
