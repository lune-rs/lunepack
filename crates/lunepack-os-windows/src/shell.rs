//! Small shell and user32 helpers the Windows integration, the runtime and the facade share
//! (M7): known folders, a message box, the process's app user model id and the foreground right
//! for a child. Safe wrappers; off Windows each returns `Unsupported`.

use std::io;
use std::path::PathBuf;

/// The icon of a [`message_box`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    /// An information icon (`MB_ICONINFORMATION`).
    Info,
    /// A warning icon (`MB_ICONWARNING`).
    Warning,
    /// An error icon (`MB_ICONERROR`).
    Error,
}

/// The user's per-user program files folder (`FOLDERID_UserProgramFiles`, by default
/// `%LOCALAPPDATA%\Programs`), the parent of a per-user install root (M7-D2). The folder may not
/// exist yet (a fresh profile): the path is returned unverified and an install creates it with the
/// root.
pub fn user_program_files() -> io::Result<PathBuf> {
    imp::known_folder(imp::Folder::UserProgramFiles)
}

/// The user's Start-menu programs folder (`FOLDERID_Programs`), where the shortcut goes (M7-D15).
pub fn start_menu_programs() -> io::Result<PathBuf> {
    imp::known_folder(imp::Folder::Programs)
}

/// Shows a modal message box with an OK button and no owner window, and returns when it is
/// closed. For a GUI-subsystem process that has no console to print an error on.
pub fn message_box(title: &str, text: &str, kind: MessageKind) -> io::Result<()> {
    imp::message_box(title, text, kind)
}

/// Sets this process's explicit app user model id (`SetCurrentProcessExplicitAppUserModelID`,
/// M7-D9), which the taskbar groups windows by and which a Start-menu shortcut carries. Call it
/// before the first window exists. Rejects an id that is empty, has an interior NUL, or is over
/// 128 UTF-16 units (the system's limit is 128 including the terminator).
pub fn set_process_aumid(aumid: &str) -> io::Result<()> {
    if aumid.is_empty() || aumid.contains('\0') || aumid.encode_utf16().count() > 127 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid app user model id",
        ));
    }
    imp::set_process_aumid(aumid)
}

/// This process's explicit app user model id (`GetCurrentProcessExplicitAppUserModelID`), read
/// back: `Ok(None)` when none was set. For tests and diagnostics.
pub fn process_aumid() -> io::Result<Option<String>> {
    imp::process_aumid()
}

/// Lets the process `pid` bring a window to the foreground (`AllowSetForegroundWindow`), so an
/// app a launcher just started is not hidden behind the launcher's own window.
pub fn allow_set_foreground(pid: u32) -> io::Result<()> {
    imp::allow_set_foreground(pid)
}

#[cfg(windows)]
mod imp {
    use super::MessageKind;
    use std::ffi::OsString;
    use std::io;
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::PathBuf;

    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_Programs, FOLDERID_UserProgramFiles, GetCurrentProcessExplicitAppUserModelID,
        KF_FLAG_DONT_VERIFY, SHGetKnownFolderPath, SetCurrentProcessExplicitAppUserModelID,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AllowSetForegroundWindow, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK,
        MB_SETFOREGROUND, MessageBoxW,
    };

    pub(super) enum Folder {
        UserProgramFiles,
        Programs,
    }

    /// A NUL-terminated UTF-16 copy of `s`.
    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    /// `E_FAIL`, which `GetCurrentProcessExplicitAppUserModelID` returns when no id was set.
    const E_FAIL_NOT_SET: i32 = 0x8000_4005_u32 as i32;

    fn hresult(code: i32) -> io::Result<()> {
        if code >= 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(code))
        }
    }

    #[allow(unsafe_code)]
    pub(super) fn known_folder(folder: Folder) -> io::Result<PathBuf> {
        let id = match folder {
            Folder::UserProgramFiles => &FOLDERID_UserProgramFiles,
            Folder::Programs => &FOLDERID_Programs,
        };
        let mut raw: *mut u16 = std::ptr::null_mut();
        // SAFETY: `id` is a valid `GUID` reference for the call; the flags are
        // `KF_FLAG_DONT_VERIFY` (the path is returned whether or not the folder exists, as on a
        // fresh profile where `%LOCALAPPDATA%\Programs` is not created yet; nothing is created) and
        // the token is null (the current user); `raw` is a valid out pointer. On success the system
        // hands over a NUL-terminated string that this function frees with `CoTaskMemFree` after
        // copying it; on failure `raw` may still need freeing, which is also done (a null pointer
        // is accepted by `CoTaskMemFree`).
        let code = unsafe {
            SHGetKnownFolderPath(
                id,
                KF_FLAG_DONT_VERIFY as u32,
                std::ptr::null_mut(),
                &mut raw,
            )
        };
        let result = if code >= 0 && !raw.is_null() {
            // SAFETY: `raw` is non-null and NUL-terminated (the call succeeded), so scanning for
            // the terminator and reading that many `u16`s stays inside the allocation.
            let units = unsafe {
                let mut len = 0usize;
                while *raw.add(len) != 0 {
                    len += 1;
                }
                std::slice::from_raw_parts(raw, len)
            };
            Ok(PathBuf::from(OsString::from_wide(units)))
        } else if code >= 0 {
            Err(io::Error::other("the shell returned no folder"))
        } else {
            Err(io::Error::from_raw_os_error(code))
        };
        // SAFETY: `raw` is null or the allocation the shell made for this call, freed once.
        unsafe { CoTaskMemFree(raw.cast()) };
        result
    }

    #[allow(unsafe_code)]
    pub(super) fn message_box(title: &str, text: &str, kind: MessageKind) -> io::Result<()> {
        let icon = match kind {
            MessageKind::Info => MB_ICONINFORMATION,
            MessageKind::Warning => MB_ICONWARNING,
            MessageKind::Error => MB_ICONERROR,
        };
        let title = wide(title);
        let text = wide(text);
        // SAFETY: both strings are NUL-terminated `u16` buffers that outlive the call; a null
        // owner window is allowed.
        let shown = unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                title.as_ptr(),
                MB_OK | icon | MB_SETFOREGROUND,
            )
        };
        if shown == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[allow(unsafe_code)]
    pub(super) fn set_process_aumid(aumid: &str) -> io::Result<()> {
        let id = wide(aumid);
        // SAFETY: `id` is a NUL-terminated `u16` buffer that outlives the call.
        hresult(unsafe { SetCurrentProcessExplicitAppUserModelID(id.as_ptr()) })
    }

    #[allow(unsafe_code)]
    pub(super) fn process_aumid() -> io::Result<Option<String>> {
        let mut raw: *mut u16 = std::ptr::null_mut();
        // SAFETY: `raw` is a valid out pointer. On success the system hands over a NUL-terminated
        // string it allocated (freed below with `CoTaskMemFree`); on failure `raw` is left null or
        // untouched, and `CoTaskMemFree` accepts null.
        let code = unsafe { GetCurrentProcessExplicitAppUserModelID(&mut raw) };
        let result = if code >= 0 && !raw.is_null() {
            // SAFETY: `raw` is non-null and NUL-terminated (the call succeeded), so scanning for
            // the terminator and reading that many `u16`s stays inside the allocation.
            let units = unsafe {
                let mut len = 0usize;
                while *raw.add(len) != 0 {
                    len += 1;
                }
                std::slice::from_raw_parts(raw, len)
            };
            Ok(Some(String::from_utf16_lossy(units)))
        } else if code == E_FAIL_NOT_SET {
            Ok(None)
        } else {
            Err(io::Error::from_raw_os_error(code))
        };
        // SAFETY: `raw` is null or the allocation the shell made for this call, freed once.
        unsafe { CoTaskMemFree(raw.cast()) };
        result
    }

    #[allow(unsafe_code)]
    pub(super) fn allow_set_foreground(pid: u32) -> io::Result<()> {
        // SAFETY: the call takes a process id by value and no pointer.
        if unsafe { AllowSetForegroundWindow(pid) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::MessageKind;
    use std::io;
    use std::path::PathBuf;

    pub(super) enum Folder {
        UserProgramFiles,
        Programs,
    }

    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    pub(super) fn known_folder(_folder: Folder) -> io::Result<PathBuf> {
        unsupported()
    }

    pub(super) fn message_box(_title: &str, _text: &str, _kind: MessageKind) -> io::Result<()> {
        unsupported()
    }

    pub(super) fn set_process_aumid(_aumid: &str) -> io::Result<()> {
        unsupported()
    }

    pub(super) fn process_aumid() -> io::Result<Option<String>> {
        unsupported()
    }

    pub(super) fn allow_set_foreground(_pid: u32) -> io::Result<()> {
        unsupported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_windows_every_helper_is_unsupported() {
        if cfg!(windows) {
            return;
        }
        let kind = |e: io::Error| e.kind();
        assert_eq!(
            user_program_files().map_err(kind),
            Err(io::ErrorKind::Unsupported)
        );
        assert_eq!(
            start_menu_programs().map_err(kind),
            Err(io::ErrorKind::Unsupported)
        );
        assert_eq!(
            message_box("t", "x", MessageKind::Info).map_err(kind),
            Err(io::ErrorKind::Unsupported)
        );
        assert_eq!(
            set_process_aumid("com.example.app").map_err(kind),
            Err(io::ErrorKind::Unsupported)
        );
        assert_eq!(
            process_aumid().map_err(kind),
            Err(io::ErrorKind::Unsupported)
        );
        assert_eq!(
            allow_set_foreground(1).map_err(kind),
            Err(io::ErrorKind::Unsupported)
        );
    }

    #[test]
    fn an_invalid_aumid_is_refused_before_any_call() {
        for bad in ["", "a\0b", &"a".repeat(128)] {
            assert_eq!(
                set_process_aumid(bad).map_err(|e| e.kind()),
                Err(io::ErrorKind::InvalidInput),
                "{bad:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_known_folders_are_absolute_and_the_programs_folder_exists() {
        for folder in [user_program_files(), start_menu_programs()] {
            let path = folder.expect("known folder");
            assert!(path.is_absolute(), "{path:?}");
        }
        // `FOLDERID_UserProgramFiles` is returned unverified: a fresh profile has no such folder yet.
        assert!(start_menu_programs().expect("programs").is_dir());
    }
}
