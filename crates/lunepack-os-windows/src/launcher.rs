//! Two helpers for the launcher stub (M7-D7): this process's command line exactly as the system
//! holds it, and ignoring Ctrl+C and Ctrl+Break in this process only. Safe wrappers; off Windows
//! each returns `Unsupported`.

use std::io;

/// This process's whole command line as UTF-16 units (`GetCommandLineW`), without the
/// terminating NUL: the bytes a launcher passes on, unparsed.
pub fn raw_command_line() -> io::Result<Vec<u16>> {
    imp::raw_command_line()
}

/// Makes this process ignore Ctrl+C and Ctrl+Break (a console control handler that reports them
/// handled; every other event goes to the default handler). Unlike `SetConsoleCtrlHandler(NULL,
/// TRUE)`, the ignore is not inherited: a child started afterwards on the same console still gets
/// both events and decides for itself. For a console launcher that waits for its child.
pub fn ignore_console_interrupts() -> io::Result<()> {
    imp::ignore_console_interrupts()
}

#[cfg(windows)]
mod imp {
    use std::io;

    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::Environment::GetCommandLineW;
    use windows_sys::core::BOOL;

    #[allow(unsafe_code)]
    pub(super) fn raw_command_line() -> io::Result<Vec<u16>> {
        // SAFETY: `GetCommandLineW` takes no argument and returns a pointer to the process's
        // command line, a NUL-terminated string owned by the system for the process's lifetime.
        let raw = unsafe { GetCommandLineW() };
        if raw.is_null() {
            return Err(io::Error::other("no command line"));
        }
        // SAFETY: `raw` is non-null and NUL-terminated, so scanning for the terminator and reading
        // that many `u16`s stays inside the string, which nothing frees while the process runs.
        let units = unsafe {
            let mut len = 0usize;
            while *raw.add(len) != 0 {
                len += 1;
            }
            std::slice::from_raw_parts(raw, len)
        };
        Ok(units.to_vec())
    }

    /// Reports Ctrl+C and Ctrl+Break handled; anything else falls through to the next handler.
    extern "system" fn swallow_interrupts(event: u32) -> BOOL {
        BOOL::from(event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT)
    }

    #[allow(unsafe_code)]
    pub(super) fn ignore_console_interrupts() -> io::Result<()> {
        // SAFETY: the handler is a plain function with the `PHANDLER_ROUTINE` signature that
        // touches no state, valid for the whole process lifetime; adding it has no other effect.
        let ok = unsafe { SetConsoleCtrlHandler(Some(swallow_interrupts), 1) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io;

    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, "Windows only")
    }

    pub(super) fn raw_command_line() -> io::Result<Vec<u16>> {
        Err(unsupported())
    }

    pub(super) fn ignore_console_interrupts() -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn the_raw_command_line_names_this_test_binary() {
        let line = String::from_utf16(&super::raw_command_line().unwrap()).unwrap();
        let exe = std::env::current_exe().unwrap();
        let stem = exe.file_stem().unwrap().to_str().unwrap();
        assert!(line.contains(stem), "{line}");
    }

    #[cfg(windows)]
    #[test]
    fn interrupts_can_be_ignored() {
        super::ignore_console_interrupts().unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn both_are_unsupported_off_windows() {
        assert!(super::raw_command_line().is_err());
        assert!(super::ignore_console_interrupts().is_err());
    }
}
