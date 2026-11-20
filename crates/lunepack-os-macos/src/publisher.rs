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

/// What looking at one bundle found.
enum Ident {
    /// Not signed, or signed ad hoc: no publisher.
    Unsigned,
    Invalid,
    Os,
    /// Valid and signed by an identity: the code and its designated requirement.
    Signed(SecStaticCode, SecRequirement),
}

/// The flags every validity check uses (M9-D7). `NO_NETWORK_ACCESS` keeps the check offline.
fn strict() -> Flags {
    Flags::CHECK_ALL_ARCHITECTURES
        | Flags::CHECK_NESTED_CODE
        | Flags::STRICT_VALIDATE
        | Flags::RESTRICT_SYMLINKS
        | Flags::NO_NETWORK_ACCESS
}

fn identity(root: &Path) -> Ident {
    let Some(url) = CFURL::from_path(root, true) else {
        return Ident::Os;
    };
    let code = match SecStaticCode::from_path(&url, Flags::NONE) {
        Ok(code) => code,
        Err(e) => {
            return match classify(e.code()) {
                Verdict::Unsigned => Ident::Unsigned,
                // Anything else at this point (not found, not readable) says nothing about the
                // code's signature.
                _ => Ident::Os,
            };
        }
    };
    // Is the bundle itself signed? A cheap check of the signature alone, with no requirement: it
    // is what tells an unsigned bundle from a signed one with a missing part.
    // SAFETY: `code` is a live SecStaticCode for the whole call; a null requirement is the
    // documented way to ask for validity alone.
    let status = unsafe {
        SecStaticCodeCheckValidity(
            code.as_concrete_TypeRef().cast::<c_void>(),
            Flags::BASIC_VALIDATE_ONLY.bits(),
            std::ptr::null(),
        )
    };
    match classify(status) {
        Verdict::Ok => {}
        Verdict::Unsigned => return Ident::Unsigned,
        Verdict::Invalid => return Ident::Invalid,
        Verdict::ReqFailed | Verdict::Os => return Ident::Os,
    }
    // Then the whole tree: strict, nested, every architecture. This is what tells an invalid
    // signature from a different publisher, and, now that the bundle is known to be signed, an
    // unsigned part inside it (`errSecCSUnsigned` again) is an invalid bundle, not an unsigned one.
    // SAFETY: as above.
    let status = unsafe {
        SecStaticCodeCheckValidity(
            code.as_concrete_TypeRef().cast::<c_void>(),
            strict().bits(),
            std::ptr::null(),
        )
    };
    match classify(status) {
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
        Some(requirement) => Ident::Signed(code, requirement),
        None => Ident::Os,
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
        let requirement = match identity(&installed.root) {
            Ident::Signed(_, requirement) => requirement,
            Ident::Unsigned => return Err(PublisherError::InstalledUnsigned),
            Ident::Invalid => return Err(PublisherError::InstalledInvalid),
            Ident::Os => return Err(PublisherError::Os),
        };
        let code = match identity(&candidate.root) {
            Ident::Signed(code, _) => code,
            Ident::Unsigned => return Err(PublisherError::CandidateUnsigned),
            Ident::Invalid => return Err(PublisherError::CandidateInvalid),
            Ident::Os => return Err(PublisherError::Os),
        };
        let status = match code.check_validity(strict(), &requirement) {
            Ok(()) => 0,
            Err(e) => e.code(),
        };
        match classify(status) {
            Verdict::Ok => Ok(true),
            Verdict::ReqFailed => Ok(false),
            Verdict::Invalid => Err(PublisherError::CandidateInvalid),
            Verdict::Unsigned => Err(PublisherError::CandidateUnsigned),
            Verdict::Os => Err(PublisherError::Os),
        }
    }
}
