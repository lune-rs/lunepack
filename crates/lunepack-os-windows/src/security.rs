//! Protected directories, descriptor checks and token queries of the per-machine install
//! (M10-D9): [`WindowsProtect`] (the core's `Protect` port), the descriptor reader
//! [`read_descriptor`] that both the check and the tests use, [`standing`] and
//! [`current_user_sid`].
//!
//! # The rules
//!
//! A directory the engine creates under Program Files gets an explicit, protected descriptor, passed
//! to the create call itself (nothing is applied afterwards): owner Administrators; full control
//! for LocalSystem and Administrators; for [`DirClass::MachineTree`] also read and execute for
//! Users and all application packages; every entry inheritable; no CREATOR OWNER or CREATOR GROUP
//! entry. [`WindowsProtect::check`] re-reads a directory through a handle opened without following
//! a reparse point and passes it only when [`judge`] accepts what it read:
//!
//! - the owner is LocalSystem, Administrators or TrustedInstaller (the set T);
//! - a DACL is present;
//! - every ACE is judged by type: deny types are skipped (they only remove rights), plain allow
//!   and allow-callback ACEs are judged, any other type fails;
//! - an allow entry for a SID in T passes whatever its mask; one for any other SID passes only
//!   when its mask is within the read class R (rights as an allow-list, so an unknown bit, a
//!   generic write, `MAXIMUM_ALLOWED` and `ACCESS_SYSTEM_SECURITY` fail). Inherit-only entries are
//!   judged the same, and CREATOR OWNER and CREATOR GROUP get no exception: a child made inside
//!   by an account outside T would receive the grant;
//! - [`DirClass::AdminOnly`] additionally has no allow entry for a SID outside T at all.
//!
//! The real Program Files folder fails this check when it carries the inheritable CREATOR OWNER
//! full-control entry, which is intended: the engine only checks the directories it created.
//!
//! No function here reads an environment variable. Every handle and every buffer the system
//! allocates is released by a guard on every path.

use lunepack_core::DirClass;

/// LocalSystem.
pub const SID_SYSTEM: &str = "S-1-5-18";
/// The built-in Administrators group.
pub const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
/// TrustedInstaller (`NT SERVICE\TrustedInstaller`).
pub const SID_TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// The built-in Users group.
pub const SID_USERS: &str = "S-1-5-32-545";
/// All application packages.
pub const SID_ALL_APP_PACKAGES: &str = "S-1-15-2-1";
/// CREATOR OWNER.
pub const SID_CREATOR_OWNER: &str = "S-1-3-0";
/// CREATOR GROUP.
pub const SID_CREATOR_GROUP: &str = "S-1-3-1";
/// Everyone.
pub const SID_EVERYONE: &str = "S-1-1-0";

/// `ACCESS_ALLOWED_ACE_TYPE`.
pub const ACE_ALLOWED: u8 = 0;
/// `ACCESS_DENIED_ACE_TYPE`.
pub const ACE_DENIED: u8 = 1;
/// `ACCESS_ALLOWED_CALLBACK_ACE_TYPE`.
pub const ACE_ALLOWED_CALLBACK: u8 = 9;
/// `ACCESS_DENIED_CALLBACK_ACE_TYPE`.
pub const ACE_DENIED_CALLBACK: u8 = 10;
/// `ACCESS_DENIED_OBJECT_ACE_TYPE`.
const ACE_DENIED_OBJECT: u8 = 6;
/// `ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE`.
const ACE_DENIED_CALLBACK_OBJECT: u8 = 12;

/// The ACE flag `INHERIT_ONLY_ACE`.
pub const INHERIT_ONLY_ACE: u8 = 0x08;

// The read class R (M10-D9): list/read data, read EA, traverse, read attributes, read control,
// synchronize and the generic read and execute rights.
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_EXECUTE: u32 = 0x0000_0020;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
/// Every right an unprivileged principal may hold on a protected directory.
pub const READ_CLASS: u32 = FILE_READ_DATA
    | FILE_READ_EA
    | FILE_EXECUTE
    | FILE_READ_ATTRIBUTES
    | READ_CONTROL
    | SYNCHRONIZE
    | GENERIC_READ
    | GENERIC_EXECUTE;

/// One entry of a DACL as read back: the ACE type, the trustee's SID as text (empty for a type
/// whose layout is not read), the access mask and the ACE flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// The ACE type (`ACCESS_ALLOWED_ACE_TYPE` is 0).
    pub kind: u8,
    /// The trustee, in the `S-1-...` form; empty when the type is not one this module reads.
    pub sid: String,
    /// The access mask.
    pub mask: u32,
    /// The ACE flags (`OBJECT_INHERIT_ACE` 0x1, `CONTAINER_INHERIT_ACE` 0x2, `INHERIT_ONLY_ACE` 0x8, ...).
    pub flags: u8,
}

/// The owner and the DACL of a directory as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    /// The owner's SID as text.
    pub owner: String,
    /// The DACL's entries in order; `None` when the DACL is absent (a NULL DACL grants everyone
    /// everything).
    pub entries: Option<Vec<Ace>>,
}

/// Why a directory is not protected as its class says, or could not be read. Carries no path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckError {
    /// The path does not exist.
    NotFound,
    /// The path is not a directory, or is a reparse point.
    NotDirectory,
    /// The owner is not LocalSystem, Administrators or TrustedInstaller.
    Owner,
    /// The DACL is absent.
    NoDacl,
    /// Someone outside the administrators holds a write-class (or any non-read) right.
    ForeignWrite,
    /// An admin-only directory grants a principal outside the administrators some right.
    ForeignAccess,
    /// An entry of a type the check does not judge, or a malformed entry.
    UnknownAce,
    /// The system refused to read the descriptor (a fixed description).
    Os(&'static str),
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::NotFound => f.write_str("the directory does not exist"),
            CheckError::NotDirectory => f.write_str("not a real directory"),
            CheckError::Owner => f.write_str("the owner is not an administrator"),
            CheckError::NoDacl => f.write_str("the directory has no DACL"),
            CheckError::ForeignWrite => {
                f.write_str("a principal outside the administrators holds a write right")
            }
            CheckError::ForeignAccess => {
                f.write_str("a principal outside the administrators holds a right")
            }
            CheckError::UnknownAce => f.write_str("an entry of an unjudged type"),
            CheckError::Os(what) => write!(f, "could not read the descriptor: {what}"),
        }
    }
}

impl std::error::Error for CheckError {}

fn in_t(sid: &str) -> bool {
    sid == SID_SYSTEM || sid == SID_ADMINISTRATORS || sid == SID_TRUSTED_INSTALLER
}

fn is_deny(kind: u8) -> bool {
    matches!(
        kind,
        ACE_DENIED | ACE_DENIED_OBJECT | ACE_DENIED_CALLBACK | ACE_DENIED_CALLBACK_OBJECT
    )
}

/// Judges what was read from a directory against `class` (rules 2 to 7 of the module docs; the
/// real-directory rule is the reader's). Pure.
pub fn judge(descriptor: &Descriptor, class: DirClass) -> Result<(), CheckError> {
    if !in_t(&descriptor.owner) {
        return Err(CheckError::Owner);
    }
    let Some(entries) = &descriptor.entries else {
        return Err(CheckError::NoDacl);
    };
    for ace in entries {
        if is_deny(ace.kind) {
            continue;
        }
        if ace.kind != ACE_ALLOWED && ace.kind != ACE_ALLOWED_CALLBACK {
            return Err(CheckError::UnknownAce);
        }
        if in_t(&ace.sid) {
            continue;
        }
        if ace.mask & !READ_CLASS != 0 {
            return Err(CheckError::ForeignWrite);
        }
        if class == DirClass::AdminOnly {
            return Err(CheckError::ForeignAccess);
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) use ffi::{
    HandleGuard, LocalGuard, handle_descriptor, handle_owner, sd_descriptor, wide,
};
#[cfg(windows)]
pub use ffi::{WindowsProtect, check_dir, current_user_sid, read_descriptor, standing};

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use lunepack_core::{DirClass, FsError, Protect, ProtectError, Standing};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS,
        ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_OWNER, ERROR_PATH_NOT_FOUND,
        ERROR_PRIVILEGE_NOT_HELD, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SE_OBJECT_TYPE,
    };
    use windows_sys::Win32::Security::{
        ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CheckTokenMembership, CreateWellKnownSid,
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetLengthSid,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, IsValidSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TokenElevationType, TokenElevationTypeFull, TokenUser,
        WinBuiltinAdministratorsSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{Ace, CheckError, Descriptor, judge};

    /// `TokenElevationTypeDefault`: no split token.
    const ELEVATION_DEFAULT: i32 = 1;

    /// Closes a handle when dropped.
    pub(crate) struct HandleGuard(pub(crate) HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            // SAFETY: the handle was returned by a successful open call, is owned by this guard
            // alone, and is closed exactly once here.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Frees a `LocalAlloc` buffer the system allocated for us when dropped.
    pub(crate) struct LocalGuard(pub(crate) *mut c_void);

    impl Drop for LocalGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer is a buffer the system allocated with `LocalAlloc` for a
                // call that documents `LocalFree` as the release, owned by this guard alone and
                // freed exactly once here.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    /// `path` as a NUL-terminated UTF-16 string; an interior NUL is refused.
    fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
        let mut units: Vec<u16> = path.as_os_str().encode_wide().collect();
        if units.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a path with an interior NUL",
            ));
        }
        units.push(0);
        Ok(units)
    }

    pub(crate) fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The text form of the SID `sid`.
    fn sid_to_string(sid: PSID) -> Result<String, CheckError> {
        let mut raw: *mut u16 = null_mut();
        // SAFETY: `sid` points at a SID the caller validated; `raw` is a valid out pointer. On
        // success the system hands over a NUL-terminated string it allocated with `LocalAlloc`.
        if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
            return Err(CheckError::Os("sid to text"));
        }
        let _free = LocalGuard(raw.cast());
        // SAFETY: `raw` is non-null and NUL-terminated (the call succeeded), so scanning for the
        // terminator and reading that many `u16`s stays inside the allocation, which the guard
        // keeps alive until the end of this function.
        let units = unsafe {
            let mut len = 0usize;
            while *raw.add(len) != 0 {
                len += 1;
            }
            std::slice::from_raw_parts(raw, len)
        };
        Ok(String::from_utf16_lossy(units))
    }

    /// Reads the owner and the DACL of the directory `path` through a handle opened without
    /// following a reparse point. A path that is not a directory, or is a reparse point, is
    /// [`CheckError::NotDirectory`].
    pub fn read_descriptor(path: &Path) -> Result<Descriptor, CheckError> {
        let wide = wide_path(path).map_err(|_| CheckError::NotFound)?;
        // SAFETY: `wide` is a NUL-terminated `u16` buffer that outlives the call; the security
        // attributes and the template handle are null. `FILE_FLAG_OPEN_REPARSE_POINT` opens a
        // link itself, never its target; `FILE_FLAG_BACKUP_SEMANTICS` is what opening a
        // directory needs. Only read-control and attribute rights are asked for.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                READ_CONTROL | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            // SAFETY: `GetLastError` takes no argument.
            return Err(match unsafe { GetLastError() } {
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => CheckError::NotFound,
                _ => CheckError::Os("open"),
            });
        }
        let handle = HandleGuard(handle);

        // SAFETY: an all-zero `BY_HANDLE_FILE_INFORMATION` is a valid value (plain integers).
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `handle` is an open handle; `info` is a valid out pointer for the call.
        if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
            return Err(CheckError::Os("file information"));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(CheckError::NotDirectory);
        }

        handle_descriptor(handle.0, SE_FILE_OBJECT)
    }

    /// Reads the owner and the DACL of the object behind `handle` (opened with read-control
    /// access) as an object of type `object`.
    pub(crate) fn handle_descriptor(
        handle: HANDLE,
        object: SE_OBJECT_TYPE,
    ) -> Result<Descriptor, CheckError> {
        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `handle` is an open handle with read-control access (the caller's contract); the
        // three out pointers are valid and the others null, as the call allows for the requested
        // information. On success `owner` and `dacl` point into the descriptor `sd`, which the
        // guard below releases.
        let code = unsafe {
            GetSecurityInfo(
                handle,
                object,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        };
        let _sd = LocalGuard(sd);
        if code != 0 {
            return Err(CheckError::Os("security info"));
        }
        if owner.is_null() {
            return Err(CheckError::Owner);
        }
        let owner = sid_to_string(owner)?;
        Ok(Descriptor {
            owner,
            entries: dacl_entries(dacl)?,
        })
    }

    /// The owner of the object behind `handle` (opened with read-control access) as SID text.
    /// Reads only the owner, nothing else of the descriptor.
    pub(crate) fn handle_owner(
        handle: HANDLE,
        object: SE_OBJECT_TYPE,
    ) -> Result<String, CheckError> {
        let mut owner: PSID = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: as in `handle_descriptor`, with only the owner asked for and its out pointer
        // given; `owner` points into `sd`, which the guard releases after the conversion.
        let code = unsafe {
            GetSecurityInfo(
                handle,
                object,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            )
        };
        let _sd = LocalGuard(sd);
        if code != 0 {
            return Err(CheckError::Os("security info"));
        }
        if owner.is_null() {
            return Err(CheckError::Owner);
        }
        sid_to_string(owner)
    }

    /// Reads the owner and the DACL of the in-memory descriptor `sd` (self-relative or absolute,
    /// valid for the duration of the call).
    pub(crate) fn sd_descriptor(sd: PSECURITY_DESCRIPTOR) -> Result<Descriptor, CheckError> {
        let mut owner: PSID = null_mut();
        let mut defaulted = 0;
        // SAFETY: `sd` is a valid security descriptor (the caller's contract); the out pointers
        // are valid. `owner` points into `sd`.
        if unsafe { GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) } == 0 {
            return Err(CheckError::Os("descriptor owner"));
        }
        if owner.is_null() {
            return Err(CheckError::Owner);
        }
        let owner = sid_to_string(owner)?;
        let mut present = 0;
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: as above; `dacl` points into `sd` when present.
        if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) } == 0 {
            return Err(CheckError::Os("descriptor dacl"));
        }
        if present == 0 {
            return Ok(Descriptor {
                owner,
                entries: None,
            });
        }
        Ok(Descriptor {
            owner,
            entries: dacl_entries(dacl)?,
        })
    }

    /// The entries of `dacl` (a valid ACL kept alive by the caller); `None` for a null DACL.
    fn dacl_entries(dacl: *mut ACL) -> Result<Option<Vec<Ace>>, CheckError> {
        if dacl.is_null() {
            return Ok(None);
        }
        // SAFETY: an all-zero `ACL_SIZE_INFORMATION` is a valid value (plain integers).
        let mut size: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: `dacl` is a valid ACL kept alive by the caller; `size` is a valid buffer of
        // exactly the length passed, for the class asked.
        let ok = unsafe {
            GetAclInformation(
                dacl,
                (&raw mut size).cast::<c_void>(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        if ok == 0 {
            return Err(CheckError::Os("acl information"));
        }
        let mut entries = Vec::with_capacity(size.AceCount as usize);
        for index in 0..size.AceCount {
            entries.push(read_ace(dacl, index)?);
        }
        Ok(Some(entries))
    }

    /// Reads entry `index` of `dacl`. A type whose layout is not the plain allow or deny one is
    /// returned with an empty SID and the mask read from the common prefix.
    fn read_ace(dacl: *mut ACL, index: u32) -> Result<Ace, CheckError> {
        let mut raw: *mut c_void = null_mut();
        // SAFETY: `dacl` is a valid ACL kept alive by the caller and `index` is below its ACE
        // count; `raw` is a valid out pointer. The returned pointer points inside the ACL.
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
            return Err(CheckError::UnknownAce);
        }
        let bytes = raw.cast::<u8>();
        // SAFETY: every ACE starts with a four-byte `ACE_HEADER` (type, flags, `u16` size) inside
        // the ACL; the reads are unaligned-safe and stay within those four bytes.
        let (kind, flags, ace_size) = unsafe {
            (
                bytes.read_unaligned(),
                bytes.add(1).read_unaligned(),
                u16::from_le_bytes([bytes.add(2).read_unaligned(), bytes.add(3).read_unaligned()]),
            )
        };
        let layout_known = matches!(
            kind,
            super::ACE_ALLOWED
                | super::ACE_DENIED
                | super::ACE_ALLOWED_CALLBACK
                | super::ACE_DENIED_CALLBACK
        );
        // A header, a mask and a smallest SID (8 bytes) must fit in the entry.
        if ace_size < 16 {
            return Err(CheckError::UnknownAce);
        }
        // SAFETY: the entry is at least 16 bytes (checked), so the mask at offset 4 is inside it.
        let mask = unsafe { bytes.add(4).cast::<u32>().read_unaligned() };
        if !layout_known {
            return Ok(Ace {
                kind,
                sid: String::new(),
                mask,
                flags,
            });
        }
        // SAFETY: for these four types the SID starts at offset 8 of the entry (after the header
        // and the mask), inside the entry (checked above).
        let sid = unsafe { bytes.add(8) }.cast::<c_void>();
        // SAFETY: `sid` points at least 8 readable bytes inside the entry; `IsValidSid` checks the
        // revision and sub-authority count and reads no more than the SID's own length, which is
        // compared with the room left in the entry before the string conversion reads it.
        let valid = unsafe { IsValidSid(sid) } != 0
            && (unsafe { GetLengthSid(sid) } as usize) <= usize::from(ace_size) - 8;
        if !valid {
            return Err(CheckError::UnknownAce);
        }
        Ok(Ace {
            kind,
            sid: sid_to_string(sid)?,
            mask,
            flags,
        })
    }

    /// Whether the directory `path` is protected as `class` says.
    pub fn check_dir(path: &Path, class: DirClass) -> Result<(), CheckError> {
        judge(&read_descriptor(path)?, class)
    }

    /// The security descriptor in SDDL form of a directory of `class`: owner Administrators, a
    /// protected DACL, every entry inheritable to files and directories.
    fn sddl(class: DirClass) -> &'static str {
        match class {
            DirClass::MachineTree => {
                "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)(A;OICI;FRFX;;;S-1-15-2-1)"
            }
            DirClass::AdminOnly => "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            // `DirClass` is not `non_exhaustive`, but a new class must get its own descriptor.
            #[allow(unreachable_patterns)]
            _ => "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
        }
    }

    /// The core's [`Protect`] port over the Windows security descriptors.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct WindowsProtect;

    impl Protect for WindowsProtect {
        fn create_dir(&self, path: &Path, class: DirClass) -> Result<(), ProtectError> {
            let wide_path = wide_path(path)
                .map_err(|e| ProtectError::Fs(FsError::from_io(path, e).during("create_dir")))?;
            let sddl = wide(sddl(class));
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            // SAFETY: `sddl` is a NUL-terminated `u16` buffer that outlives the call; `sd` is a
            // valid out pointer and the size out pointer is null (not wanted). On success `sd` is
            // a `LocalAlloc` buffer the guard below frees.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(ProtectError::Os("descriptor"));
            }
            let _sd = LocalGuard(sd);
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            // SAFETY: `wide_path` is a NUL-terminated `u16` buffer and `attributes` a valid
            // `SECURITY_ATTRIBUTES` whose descriptor `sd` stays allocated; both outlive the call.
            // The descriptor is applied by the create call itself, atomically; an existing entry
            // of any kind fails the call and is not touched.
            if unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) } != 0 {
                return Ok(());
            }
            // SAFETY: `GetLastError` takes no argument.
            let code = unsafe { GetLastError() };
            Err(match code {
                ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS => ProtectError::Exists,
                ERROR_INVALID_OWNER | ERROR_PRIVILEGE_NOT_HELD => {
                    ProtectError::Os("the owner cannot be set")
                }
                ERROR_ACCESS_DENIED => ProtectError::Os("access denied"),
                _ => ProtectError::Fs(
                    FsError::from_io(path, io::Error::from_raw_os_error(code as i32))
                        .during("create_dir"),
                ),
            })
        }

        fn check(&self, path: &Path, class: DirClass) -> Result<(), ProtectError> {
            check_dir(path, class).map_err(|e| match e {
                CheckError::NotFound => ProtectError::NotFound,
                CheckError::Os(what) => ProtectError::Os(what),
                _ => ProtectError::NotProtected,
            })
        }
    }

    /// The current process token, opened for queries.
    fn process_token() -> Option<HandleGuard> {
        let mut token: HANDLE = null_mut();
        // SAFETY: the pseudo handle of the current process needs no release; `token` is a valid
        // out pointer, and a handle it receives is owned by the guard.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        (ok != 0).then_some(HandleGuard(token))
    }

    /// The current process's standing (M10-D15), from its token only: `UacElevated` when the
    /// token's elevation type is Full; `Admin` when the type is Default and the Administrators
    /// group is enabled in it; otherwise `Standard`. Any failure to read it is `Standard`.
    pub fn standing() -> Standing {
        let Some(token) = process_token() else {
            return Standing::Standard;
        };
        let mut kind: i32 = 0;
        let mut returned = 0u32;
        // SAFETY: `token` is an open token with query access; `kind` is a buffer of exactly the
        // size passed, for `TokenElevationType`, which writes one `TOKEN_ELEVATION_TYPE` (an
        // `i32`); `returned` is a valid out pointer.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenElevationType,
                (&raw mut kind).cast::<c_void>(),
                std::mem::size_of::<i32>() as u32,
                &mut returned,
            )
        };
        if ok == 0 {
            return Standing::Standard;
        }
        if kind == TokenElevationTypeFull {
            return Standing::UacElevated;
        }
        if kind != ELEVATION_DEFAULT {
            return Standing::Standard;
        }
        let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut len = SECURITY_MAX_SID_SIZE;
        // SAFETY: `sid` is a buffer of `len` bytes, the size of the largest SID; the domain SID
        // argument is null as the well-known type needs none.
        let made = unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                null_mut(),
                sid.as_mut_ptr().cast::<c_void>(),
                &mut len,
            )
        };
        if made == 0 {
            return Standing::Standard;
        }
        let mut member = 0i32;
        // SAFETY: a null token asks about the calling thread's effective token (the process token
        // here, with no impersonation); `sid` is the valid SID just built; `member` is a valid out
        // pointer. A group that is only deny-only in the token is reported as not a member.
        let ok = unsafe {
            CheckTokenMembership(null_mut(), sid.as_mut_ptr().cast::<c_void>(), &mut member)
        };
        if ok != 0 && member != 0 {
            Standing::Admin
        } else {
            Standing::Standard
        }
    }

    /// The current user's SID as text (`S-1-5-21-...`), read from the process token.
    pub fn current_user_sid() -> io::Result<String> {
        let token = process_token().ok_or_else(io::Error::last_os_error)?;
        let mut needed = 0u32;
        // SAFETY: a null buffer of length 0 is the documented way to ask for the size; `needed` is
        // a valid out pointer.
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed) };
        // SAFETY: `GetLastError` takes no argument.
        if needed == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::last_os_error());
        }
        // A `u64` backing keeps the buffer aligned for the `TOKEN_USER` it receives.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let mut returned = 0u32;
        // SAFETY: `buffer` holds at least `needed` bytes, the size the first call asked for;
        // `returned` is a valid out pointer.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast::<c_void>(),
                needed,
                &mut returned,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call succeeded, so the buffer starts with a `TOKEN_USER` whose SID pointer
        // points into the same buffer, which stays alive until the end of this function.
        let sid = unsafe {
            (*buffer
                .as_ptr()
                .cast::<windows_sys::Win32::Security::TOKEN_USER>())
            .User
            .Sid
        };
        sid_to_string(sid).map_err(|e| io::Error::other(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(sid: &str, mask: u32, flags: u8) -> Ace {
        Ace {
            kind: ACE_ALLOWED,
            sid: sid.to_owned(),
            mask,
            flags,
        }
    }

    fn tree() -> Descriptor {
        Descriptor {
            owner: SID_ADMINISTRATORS.to_owned(),
            entries: Some(vec![
                allow(SID_SYSTEM, 0x1f01ff, 0x03),
                allow(SID_ADMINISTRATORS, 0x1f01ff, 0x03),
                allow(SID_USERS, 0x1200a9, 0x03),
                allow(SID_ALL_APP_PACKAGES, 0x1200a9, 0x03),
            ]),
        }
    }

    fn with(mut d: Descriptor, extra: Ace) -> Descriptor {
        d.entries.as_mut().unwrap().push(extra);
        d
    }

    #[test]
    fn a_machine_tree_descriptor_passes_as_a_tree_and_fails_as_admin_only() {
        assert_eq!(judge(&tree(), DirClass::MachineTree), Ok(()));
        assert_eq!(
            judge(&tree(), DirClass::AdminOnly),
            Err(CheckError::ForeignAccess)
        );
        let admin = Descriptor {
            owner: SID_SYSTEM.to_owned(),
            entries: Some(vec![
                allow(SID_SYSTEM, 0x1f01ff, 3),
                allow(SID_ADMINISTRATORS, 0x1f01ff, 3),
            ]),
        };
        assert_eq!(judge(&admin, DirClass::AdminOnly), Ok(()));
    }

    #[test]
    fn the_owner_and_the_dacl_are_required() {
        let mut d = tree();
        d.owner = "S-1-5-21-1-2-3-1001".to_owned();
        assert_eq!(judge(&d, DirClass::MachineTree), Err(CheckError::Owner));
        let mut d = tree();
        d.owner = SID_TRUSTED_INSTALLER.to_owned();
        assert_eq!(judge(&d, DirClass::MachineTree), Ok(()));
        let mut d = tree();
        d.entries = None;
        assert_eq!(judge(&d, DirClass::MachineTree), Err(CheckError::NoDacl));
    }

    #[test]
    fn a_foreign_write_class_right_fails_whatever_the_flags_and_the_sid() {
        // modify, write DAC for Everyone, inherit-only Users write, inherit-only CREATOR OWNER
        // full control, CREATOR GROUP generic write, generic all, maximum allowed, system security.
        for (sid, mask, flags) in [
            (SID_USERS, 0x1301bf, 0x03),
            (SID_EVERYONE, 0x40000, 0x03),
            (SID_USERS, 0x2, INHERIT_ONLY_ACE | 0x03),
            (SID_CREATOR_OWNER, 0x1f01ff, INHERIT_ONLY_ACE | 0x03),
            (SID_CREATOR_GROUP, 0x4000_0000, 0x03),
            ("S-1-5-21-1-2-3-1001", 0x1000_0000, 0),
            (SID_USERS, 0x0200_0000, 0),
            (SID_USERS, 0x0100_0000, 0),
            (SID_USERS, 0x0000_0100 | 0x0004_0000, 0),
        ] {
            assert_eq!(
                judge(
                    &with(tree(), allow(sid, mask, flags)),
                    DirClass::MachineTree
                ),
                Err(CheckError::ForeignWrite),
                "{sid} {mask:#x} {flags:#x}"
            );
        }
    }

    #[test]
    fn a_deny_entry_is_skipped_and_an_object_entry_fails() {
        for kind in [ACE_DENIED, 6, ACE_DENIED_CALLBACK, 12] {
            let deny = Ace {
                kind,
                sid: SID_USERS.to_owned(),
                mask: 0x1f01ff,
                flags: 0,
            };
            assert_eq!(
                judge(&with(tree(), deny), DirClass::MachineTree),
                Ok(()),
                "{kind}"
            );
        }
        for kind in [2u8, 3, 4, 5, 7, 8, 11, 13, 17, 200] {
            let odd = Ace {
                kind,
                sid: String::new(),
                mask: 1,
                flags: 0,
            };
            assert_eq!(
                judge(&with(tree(), odd), DirClass::MachineTree),
                Err(CheckError::UnknownAce),
                "{kind}"
            );
        }
        let callback = Ace {
            kind: ACE_ALLOWED_CALLBACK,
            sid: SID_USERS.to_owned(),
            mask: 0x2,
            flags: 0,
        };
        assert_eq!(
            judge(&with(tree(), callback), DirClass::MachineTree),
            Err(CheckError::ForeignWrite)
        );
    }

    #[test]
    fn an_allow_entry_for_a_trusted_sid_passes_whatever_its_mask() {
        let d = with(tree(), allow(SID_TRUSTED_INSTALLER, 0xffff_ffff, 0x03));
        assert_eq!(judge(&d, DirClass::MachineTree), Ok(()));
    }

    #[test]
    fn the_read_class_is_exactly_the_listed_rights() {
        assert_eq!(READ_CLASS, 0xA012_00A9);
    }
}
