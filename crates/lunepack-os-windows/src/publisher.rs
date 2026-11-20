//! The publisher-continuity check on Windows (M9-D8, M9-R1-D2, M9-R1-D3): [`WinPublisherCheck`].
//!
//! Every file is verified with `WinVerifyTrust` (`WINTRUST_ACTION_GENERIC_VERIFY_V2`, no UI, no
//! revocation, cache-only URL retrieval: the network is never used). The installed entry and the
//! candidate entry must both verify, and their leaf signers' subject names must be byte-equal as
//! DER (`CERT_INFO.Subject`: no string is parsed, no thumbprint is compared, so a renewed
//! certificate of the same subject is the same publisher). Every other PE file of the candidate
//! must verify under any trusted publisher.
//!
//! Only the statuses [`crate::trust_status`] lists are verdicts about a file; every other status,
//! and every error met while walking, opening or reading a file, is [`PublisherError::Os`]: a local
//! fault is retried later and never marks a version bad. The installed tree is examined first. A
//! catalog-signed file counts as unsigned; a dual-signed file is judged by its primary signature.
//!
//! The provider state of `WinVerifyTrust` is closed by a guard on every path, after the subject
//! bytes have been copied out of it.

#![allow(unsafe_code)]

use std::fs::{self, File};
use std::io::Read as _;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use lunepack_core::codesign::PLAN_HEAD_BYTES;
use lunepack_core::path::MAX_PATH_DEPTH;
use lunepack_core::pe::{PeError, PeHeaders};
use lunepack_core::{PublisherCheck, PublisherError, SignedTree};
use windows_sys::Win32::Foundation::{GetLastError, HWND, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};

use crate::trust_status::{Verdict, classify};

/// `FILE_ATTRIBUTE_REPARSE_POINT`: a symlink, a junction or any other reparse point.
const REPARSE_POINT: u32 = 0x400;
/// Longest subject name read, in bytes; a certificate subject is far below this.
const MAX_SUBJECT_BYTES: usize = 4096;

/// The [`PublisherCheck`] of Windows.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinPublisherCheck;

/// What verifying one file found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileSig {
    /// Verified; the leaf signer's DER subject.
    Trusted(Vec<u8>),
    Unsigned,
    Invalid,
    /// A certificate has expired and no timestamp covers it; the subject, when the provider data
    /// still holds it.
    Expired(Option<Vec<u8>>),
    Os,
}

/// Closes the `WinVerifyTrust` state when dropped.
struct StateGuard {
    data: *mut WINTRUST_DATA,
    action: *mut windows_sys::core::GUID,
}

impl Drop for StateGuard {
    fn drop(&mut self) {
        // SAFETY: `data` and `action` point at locals of `verify_file` that outlive this guard
        // (they are declared before it); `WTD_STATEACTION_CLOSE` is the documented way to release
        // the state a `WTD_STATEACTION_VERIFY` call made, and is harmless when none was made.
        unsafe {
            (*self.data).dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(
                INVALID_HANDLE_VALUE as HWND,
                self.action,
                self.data.cast::<core::ffi::c_void>(),
            );
        }
    }
}

/// Verifies the file at `path`.
fn verify_file(path: &Path) -> FileSig {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return FileSig::Os;
    }
    wide.push(0);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: core::ptr::null_mut(),
        pgKnownSubject: core::ptr::null_mut(),
    };
    // SAFETY: `WINTRUST_DATA` is a plain C struct of integers, pointers and a union of pointers;
    // all-zero is its documented initial state, and the fields that matter are set below.
    let mut data: WINTRUST_DATA = unsafe { core::mem::zeroed() };
    data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    // No network, ever: no revocation check, and a certificate's URLs are read from the cache only.
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let guard = StateGuard {
        data: &mut data,
        action: &mut action,
    };
    // SAFETY: `data` is initialised as above, `file` and `wide` outlive the call and the guard
    // (declared before it), `action` is a valid GUID, and `INVALID_HANDLE_VALUE` as the window
    // means no UI.
    let status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE as HWND,
            guard.action,
            guard.data.cast::<core::ffi::c_void>(),
        )
    };
    // SAFETY: `GetLastError` reads the calling thread's last-error value; nothing ran in between.
    let last = unsafe { GetLastError() };
    let verdict = classify(status as u32, last);
    // SAFETY: `guard.data` points at `data`, alive for this whole function, and nothing writes
    // through any pointer while this shared view is read.
    let state = unsafe { &*guard.data };
    match verdict {
        Verdict::Trusted => match subject_of(state) {
            Some(subject) => FileSig::Trusted(subject),
            None => FileSig::Os,
        },
        Verdict::Expired => FileSig::Expired(subject_of(state)),
        Verdict::Unsigned => FileSig::Unsigned,
        Verdict::Invalid => FileSig::Invalid,
        Verdict::Os => FileSig::Os,
    }
    // `guard` drops here, after the subject bytes were copied out.
}

/// The DER subject of the primary signer's leaf certificate, copied out of the provider state.
fn subject_of(data: &WINTRUST_DATA) -> Option<Vec<u8>> {
    // SAFETY: `hWVTStateData` is the state handle `WinVerifyTrust` filled in; the helper returns
    // null when there is no provider data, and the pointer it returns stays valid until the state
    // is closed, which the caller's guard does only after this function returns.
    let prov = unsafe { WTHelperProvDataFromStateData(data.hWVTStateData) };
    if prov.is_null() {
        return None;
    }
    // SAFETY: `prov` is valid (above); index 0, not a counter signer, is the primary signer; null
    // means no such signer.
    let signer = unsafe { WTHelperGetProvSignerFromChain(prov, 0, 0, 0) };
    if signer.is_null() {
        return None;
    }
    // SAFETY: `signer` is a valid `CRYPT_PROVIDER_SGNR` (above); its chain array has `csCertChain`
    // elements when non-null, and element 0 is the leaf. Each pointer is null-checked before it is
    // followed, and every structure lives in the provider state, valid until the guard drops.
    unsafe {
        let signer = &*signer;
        if signer.csCertChain == 0 || signer.pasCertChain.is_null() {
            return None;
        }
        let leaf = (*signer.pasCertChain).pCert;
        if leaf.is_null() || (*leaf).pCertInfo.is_null() {
            return None;
        }
        let name = &(*(*leaf).pCertInfo).Subject;
        let len = name.cbData as usize;
        if name.pbData.is_null() || len == 0 || len > MAX_SUBJECT_BYTES {
            return None;
        }
        Some(core::slice::from_raw_parts(name.pbData, len).to_vec())
    }
}

/// `MZ` with `PE\0\0` where `e_lfanew` points, inside `head` (the core's `sign_plan` rule for a
/// file whose headers do not parse).
fn has_pe_signature(head: &[u8]) -> bool {
    let Some(raw) = head.get(0x3C..0x40) else {
        return false;
    };
    let lfanew = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    head.starts_with(b"MZ")
        && lfanew
            .checked_add(4)
            .and_then(|end| head.get(lfanew..end))
            .is_some_and(|sig| sig == b"PE\0\0")
}

/// Whether `file` is a PE image (the core reader decides, never the name: a DLL renamed `.dat` is
/// still loadable). `Err` is a local fault.
fn is_pe(file: &Path, len: u64) -> Result<bool, PublisherError> {
    let mut head = Vec::new();
    File::open(file)
        .and_then(|f| f.take(PLAN_HEAD_BYTES as u64).read_to_end(&mut head))
        .map_err(|_| PublisherError::Os)?;
    Ok(match PeHeaders::parse(&head, len) {
        Ok(_) => true,
        Err(PeError::NotPe) => false,
        Err(_) => has_pe_signature(&head),
    })
}

/// The files of the tree at `root`, sorted by path: regular files only. A reparse point, a
/// directory that cannot be listed or nesting beyond the format's limit is a local fault: the walk
/// must not leave the tree or give up quietly.
fn files_of(root: &Path) -> Result<Vec<(String, PathBuf, u64)>, PublisherError> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), String::new(), 0usize)];
    while let Some((dir, prefix, depth)) = stack.pop() {
        if depth >= MAX_PATH_DEPTH {
            return Err(PublisherError::Os);
        }
        for entry in fs::read_dir(&dir).map_err(|_| PublisherError::Os)? {
            let entry = entry.map_err(|_| PublisherError::Os)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| PublisherError::Os)?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).map_err(|_| PublisherError::Os)?;
            if meta.file_attributes() & REPARSE_POINT != 0 {
                return Err(PublisherError::Os);
            }
            let rel = format!("{prefix}{name}");
            if meta.is_dir() {
                stack.push((path, format!("{rel}/"), depth + 1));
            } else if meta.is_file() {
                out.push((rel, path, meta.len()));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn entry_path(tree: &SignedTree) -> PathBuf {
    let mut path = tree.root.clone();
    for part in tree.entry.components() {
        path.push(part);
    }
    path
}

/// The installed tree's baseline subject (M9-D8, M9-R1-D3).
fn installed_subject(tree: &SignedTree) -> Result<Vec<u8>, PublisherError> {
    match verify_file(&entry_path(tree)) {
        FileSig::Trusted(subject) | FileSig::Expired(Some(subject)) => Ok(subject),
        // An expired signature is never a permanent block (M9-R1-D3): when the provider data is
        // gone there is no baseline, which is not a refusal under `enforce`.
        FileSig::Unsigned | FileSig::Expired(None) => Err(PublisherError::InstalledUnsigned),
        FileSig::Invalid => Err(PublisherError::InstalledInvalid),
        FileSig::Os => Err(PublisherError::Os),
    }
}

impl PublisherCheck for WinPublisherCheck {
    fn same_publisher(
        &self,
        installed: &SignedTree,
        candidate: &SignedTree,
    ) -> Result<bool, PublisherError> {
        let baseline = installed_subject(installed)?;
        // Every PE of the candidate first: an unsigned DLL refuses even when the entry matches.
        for (_, path, len) in files_of(&candidate.root)? {
            if !is_pe(&path, len)? {
                continue;
            }
            match verify_file(&path) {
                FileSig::Trusted(_) => {}
                FileSig::Unsigned => return Err(PublisherError::CandidateUnsigned),
                // An expired candidate (no timestamp) is a packaging mistake (M9-R1-D3).
                FileSig::Invalid | FileSig::Expired(_) => {
                    return Err(PublisherError::CandidateInvalid);
                }
                FileSig::Os => return Err(PublisherError::Os),
            }
        }
        match verify_file(&entry_path(candidate)) {
            FileSig::Trusted(subject) => Ok(subject == baseline),
            FileSig::Unsigned => Err(PublisherError::CandidateUnsigned),
            FileSig::Invalid | FileSig::Expired(_) => Err(PublisherError::CandidateInvalid),
            FileSig::Os => Err(PublisherError::Os),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_status as t;
    use windows_sys::Win32::Foundation as f;

    /// Each local constant is the one Windows defines.
    #[test]
    fn the_status_constants_are_windows_own() {
        for (mine, theirs) in [
            (t::TRUST_E_NOSIGNATURE, f::TRUST_E_NOSIGNATURE),
            (
                t::TRUST_E_SUBJECT_FORM_UNKNOWN,
                f::TRUST_E_SUBJECT_FORM_UNKNOWN,
            ),
            (t::TRUST_E_PROVIDER_UNKNOWN, f::TRUST_E_PROVIDER_UNKNOWN),
            (t::TRUST_E_BAD_DIGEST, f::TRUST_E_BAD_DIGEST),
            (t::CERT_E_UNTRUSTEDROOT, f::CERT_E_UNTRUSTEDROOT),
            (t::CERT_E_CHAINING, f::CERT_E_CHAINING),
            (t::TRUST_E_EXPLICIT_DISTRUST, f::TRUST_E_EXPLICIT_DISTRUST),
            (t::CERT_E_REVOKED, f::CERT_E_REVOKED),
            (t::CERT_E_EXPIRED, f::CERT_E_EXPIRED),
        ] {
            assert_eq!(mine, theirs as u32);
        }
    }

    /// A missing file and a directory are a local fault, never "unsigned".
    #[test]
    fn a_file_that_cannot_be_opened_is_a_local_fault() {
        let dir = std::env::temp_dir();
        assert_eq!(
            verify_file(&dir.join("lunepack-no-such-file.exe")),
            FileSig::Os
        );
        assert_eq!(verify_file(&dir), FileSig::Os);
    }

    /// A signed system binary verifies and gives a subject; a plain text file is unsigned.
    #[test]
    fn a_system_binary_is_trusted_and_a_text_file_is_no_verdict() {
        let notepad = Path::new(&std::env::var_os("SystemRoot").expect("SystemRoot"))
            .join("System32")
            .join("notepad.exe");
        // Some Windows builds sign system files by catalog only; the premise is checked first.
        match verify_file(&notepad) {
            FileSig::Trusted(subject) => assert!(!subject.is_empty()),
            FileSig::Unsigned => eprintln!("skipped: notepad.exe is catalog-signed here"),
            other => panic!("notepad.exe: {other:?}"),
        }
        let dir = std::env::temp_dir().join(format!("lunepack-wintrust-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let text = dir.join("a.txt");
        fs::write(&text, b"not a PE file").unwrap();
        // Probed on Windows 11: a file of a form Windows cannot sign (a text file) is answered
        // with `TRUST_E_SUBJECT_FORM_UNKNOWN` as the status itself, not with a no-signature status;
        // that is not on the allowlist, so it is a local fault, never a verdict about the file.
        assert_eq!(verify_file(&text), FileSig::Os);
        let _ = fs::remove_dir_all(&dir);
    }
}
