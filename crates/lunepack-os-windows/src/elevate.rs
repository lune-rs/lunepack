//! The hand-off to an elevated child (M10-D15): [`WindowsElevation`], the core's `Elevation` over
//! `ShellExecuteExW` with the verb `runas`.
//!
//! The program is always an absolute path the caller names; the arguments are joined into one
//! command line with the `CommandLineToArgvW` quoting rules ([`join_args`]); the child's window is
//! hidden and its working folder is the program's own folder. Nothing but the child's process
//! handle comes back: no environment, no inherited handle. The user declining the prompt is
//! `Declined`; any other failure is a typed error. This module never starts a window of its own
//! and never reads an environment variable.

/// One argument as `CommandLineToArgvW` reads it back: unchanged when it holds no space, tab,
/// newline, vertical tab or quote and is not empty; otherwise in double quotes with every quote
/// escaped and the backslashes before a quote (or before the closing quote) doubled.
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return arg.to_owned();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// The arguments joined into one command-line tail, each quoted by [`quote_arg`]. `None` when an
/// argument holds a NUL.
pub fn join_args(args: &[String]) -> Option<String> {
    if args.iter().any(|a| a.contains('\0')) {
        return None;
    }
    Some(
        args.iter()
            .map(|a| quote_arg(a))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

#[cfg(windows)]
pub use ffi::WindowsElevation;

#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi {
    use std::os::windows::ffi::OsStrExt as _;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{
        ERROR_CANCELLED, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Com::{
        COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, INFINITE, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
        ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    use std::path::Path;
    use std::time::Duration;

    use lunepack_core::{Elevated, ElevatedChild, Elevation, ElevationError, Standing};

    use crate::security::{HandleGuard, standing};

    /// The core's `Elevation` for Windows.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct WindowsElevation;

    /// The elevated child: its process handle, closed on drop.
    struct Child(HandleGuard);

    // SAFETY: a process handle is a kernel handle usable from any thread; this wrapper owns it
    // alone and every use goes through `&mut` of its owner.
    unsafe impl Send for Child {}

    impl Child {
        /// Waits up to `limit` (`None` is forever) and returns the exit code, or `None` when the
        /// time ran out first.
        fn wait_for(&mut self, limit: Option<Duration>) -> Result<Option<i32>, ElevationError> {
            let millis = limit.map_or(INFINITE, |d| {
                u32::try_from(d.as_millis())
                    .unwrap_or(INFINITE - 1)
                    .min(INFINITE - 1)
            });
            // SAFETY: the handle is an open process handle with synchronize access.
            let waited = unsafe { WaitForSingleObject((self.0).0, millis) };
            if waited != WAIT_OBJECT_0 {
                return if limit.is_some() && waited == WAIT_TIMEOUT {
                    Ok(None)
                } else {
                    Err(ElevationError::Failed("wait for the elevated process"))
                };
            }
            let mut code = 0u32;
            // SAFETY: the handle is an open process handle with query access; `code` is writable.
            if unsafe { GetExitCodeProcess((self.0).0, &mut code) } == 0 {
                return Err(ElevationError::Failed(
                    "read the elevated process's exit code",
                ));
            }
            Ok(Some(i32::from_ne_bytes(code.to_ne_bytes())))
        }
    }

    impl ElevatedChild for Child {
        fn wait(&mut self) -> Result<i32, ElevationError> {
            self.wait_for(None)?
                .ok_or(ElevationError::Failed("wait for the elevated process"))
        }
    }

    /// Initialises COM on this thread for the call, as `ShellExecuteExW` asks, and undoes it.
    struct ComScope(bool);

    impl ComScope {
        fn new() -> ComScope {
            // SAFETY: a null reserved pointer and the apartment flags; the result says whether a
            // matching `CoUninitialize` is owed (`S_OK` or `S_FALSE`).
            let hr = unsafe {
                CoInitializeEx(
                    null(),
                    (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
                )
            };
            ComScope(hr >= 0)
        }
    }

    impl Drop for ComScope {
        fn drop(&mut self) {
            if self.0 {
                // SAFETY: balances the successful `CoInitializeEx` on this thread.
                unsafe { CoUninitialize() };
            }
        }
    }

    fn wide_path(path: &Path) -> Option<Vec<u16>> {
        let mut units: Vec<u16> = path.as_os_str().encode_wide().collect();
        if units.contains(&0) {
            return None;
        }
        units.push(0);
        Some(units)
    }

    impl Elevation for WindowsElevation {
        fn standing(&self) -> Standing {
            standing()
        }

        fn run_elevated(&self, exe: &Path, args: &[String]) -> Result<Elevated, ElevationError> {
            const BAD: ElevationError = ElevationError::Failed("the program path is not usable");
            if !exe.is_absolute() || exe.file_name().is_none() {
                return Err(BAD);
            }
            let file = wide_path(exe).ok_or(BAD)?;
            let folder = wide_path(exe.parent().ok_or(BAD)?).ok_or(BAD)?;
            let parameters: Vec<u16> = super::join_args(args)
                .ok_or(ElevationError::Failed("an argument holds a NUL"))?
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let verb: Vec<u16> = "runas\0".encode_utf16().collect();
            let _com = ComScope::new();
            // SAFETY: an all-zero `SHELLEXECUTEINFOW` is valid (null pointers, zero masks); the
            // fields set below are the ones the call reads.
            let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
            info.hwnd = null_mut();
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = parameters.as_ptr();
            info.lpDirectory = folder.as_ptr();
            info.nShow = SW_HIDE;
            // SAFETY: `info` is a valid `SHELLEXECUTEINFOW` whose string fields point to
            // NUL-terminated `u16` buffers (`verb`, `file`, `parameters`, `folder`) that outlive
            // the call; the call returns a process handle in `hProcess` that this function then
            // owns.
            let ok = unsafe { ShellExecuteExW(&mut info) };
            if ok == 0 {
                // SAFETY: `GetLastError` takes no argument.
                return if unsafe { GetLastError() } == ERROR_CANCELLED {
                    Ok(Elevated::Declined)
                } else {
                    Err(ElevationError::Failed("start the elevated process"))
                };
            }
            let process: HANDLE = info.hProcess;
            if process.is_null() {
                return Err(ElevationError::Failed("no process handle came back"));
            }
            Ok(Elevated::Started(Box::new(Child(HandleGuard(process)))))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::windows::io::IntoRawHandle as _;
        use std::process::Command;

        fn child_of(args: &[&str]) -> Child {
            let child = Command::new("cmd.exe")
                .args(args)
                .spawn()
                .expect("start cmd");
            Child(HandleGuard(child.into_raw_handle()))
        }

        #[test]
        fn the_child_reports_its_exit_code() {
            let mut child = child_of(&["/c", "exit", "7"]);
            assert_eq!(child.wait(), Ok(7));
        }

        #[test]
        fn a_timed_wait_gives_up_while_the_child_runs_and_then_sees_the_end() {
            let mut child = child_of(&["/c", "ping -n 4 127.0.0.1 >nul & exit 3"]);
            assert_eq!(child.wait_for(Some(Duration::from_millis(100))), Ok(None));
            assert_eq!(child.wait_for(Some(Duration::from_secs(30))), Ok(Some(3)));
        }

        /// The system's own parser reads back what `join_args` wrote: the independent instrument
        /// for the quoting rules.
        #[test]
        fn the_systems_parser_reads_back_every_joined_argument() {
            use windows_sys::Win32::Foundation::LocalFree;
            use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

            let args: Vec<String> = [
                "plain",
                "",
                "two words",
                r"C:\a b\c",
                r"C:\a b\",
                r#"say "hi""#,
                r#"a\"b"#,
                r"back\slash\\",
                "tab\there",
                r#"\\"x y\\"#,
                "--for-sid=S-1-5-21-1-2-3-1001",
            ]
            .iter()
            .map(|a| (*a).to_owned())
            .collect();
            let line: Vec<u16> = std::iter::once("prog ".to_owned())
                .chain(std::iter::once(
                    super::super::join_args(&args).expect("joined"),
                ))
                .collect::<String>()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut count = 0i32;
            // SAFETY: `line` is NUL-terminated and outlives the call; `count` is writable.
            let argv = unsafe { CommandLineToArgvW(line.as_ptr(), &mut count) };
            assert!(!argv.is_null());
            let mut got = Vec::new();
            for i in 1..usize::try_from(count).expect("count") {
                // SAFETY: `argv` holds `count` valid NUL-terminated strings until `LocalFree`.
                let units = unsafe {
                    let p = *argv.add(i);
                    let mut n = 0;
                    while *p.add(n) != 0 {
                        n += 1;
                    }
                    std::slice::from_raw_parts(p, n)
                };
                got.push(String::from_utf16(units).expect("utf16"));
            }
            // SAFETY: `argv` came from `CommandLineToArgvW`, freed once with `LocalFree`.
            unsafe { LocalFree(argv.cast()) };
            assert_eq!(got, args);
        }

        #[test]
        fn a_relative_or_odd_program_path_is_refused_before_anything_runs() {
            let e = WindowsElevation;
            for bad in [r"x.exe", r"bin\x.exe", r"C:", ""] {
                assert!(
                    matches!(
                        e.run_elevated(Path::new(bad), &[]),
                        Err(ElevationError::Failed(_))
                    ),
                    "{bad:?}"
                );
            }
            assert!(matches!(
                e.run_elevated(
                    Path::new(r"C:\Windows\System32\cmd.exe"),
                    &["a\0b".to_owned()]
                ),
                Err(ElevationError::Failed(_))
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_follows_the_command_line_rules() {
        let cases: &[(&str, &str)] = &[
            ("plain", "plain"),
            ("", r#""""#),
            ("two words", r#""two words""#),
            (r"C:\a b\c", r#""C:\a b\c""#),
            (r"C:\a b\", r#""C:\a b\\""#),
            (r#"say "hi""#, r#""say \"hi\"""#),
            (r#"a\"b"#, r#""a\\\"b""#),
            (r"back\slash", r"back\slash"),
            ("tab\there", "\"tab\there\""),
        ];
        for (arg, want) in cases {
            assert_eq!(quote_arg(arg), *want, "{arg:?}");
        }
        assert_eq!(
            join_args(&["--mode".to_owned(), "a b".to_owned()]).as_deref(),
            Some(r#"--mode "a b""#)
        );
        assert_eq!(join_args(&["a\0".to_owned()]), None);
        assert_eq!(join_args(&[]).as_deref(), Some(""));
    }
}
