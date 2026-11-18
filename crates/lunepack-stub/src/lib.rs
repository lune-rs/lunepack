//! The Windows launcher stub (M7-D7, launch contract v1).
//!
//! The stub sits at `R\<entry file name>` and starts the installed app's current version:
//! it takes `R` from its own resolved path and from nothing else, reads the install through
//! `lunepack_core::launch_target` (the newest record's current version, that version's config,
//! its entry), and starts the entry with its own command-line tail passed on byte for byte, its
//! environment and working directory unchanged, and no job object.
//!
//! - GUI variant (`lunepack-stub`): starts the app, lets it take the foreground, exits 0.
//! - Console variant (`lunepack-stub-console`): the app inherits the console and the three
//!   standard handles; the stub ignores Ctrl+C and Ctrl+Break itself (the app still gets them),
//!   waits, and exits with the app's 32-bit exit code.
//! - Reserved: a command line of exactly `--lunepack-uninstall`, optionally followed by `/S` or
//!   `--silent`, starts the current version's runtime as `uninstall [--silent]` and exits 0.
//! - Failures exit 90–95 (`lunepack_core::StubError`) with a fixed message: a message box (GUI) or
//!   one stderr line (console). No path or value read from the install is shown.
//!
//! Off Windows both binaries print one line and exit 2, so the workspace builds everywhere.

use std::ffi::OsString;

/// Which launcher runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// The GUI-subsystem launcher: does not wait for the app.
    Gui,
    /// The console launcher: waits and passes on the app's exit code.
    Console,
}

/// The reserved argument of the launch contract.
pub const UNINSTALL_ARG: &str = "--lunepack-uninstall";

/// The exit code off Windows.
pub const EXIT_UNSUPPORTED: i32 = 2;

/// What the stub's arguments (without argv\[0\]) ask for: `Some(silent)` for the reserved
/// uninstall command line (exactly [`UNINSTALL_ARG`], optionally followed by `/S` or `--silent`),
/// `None` for anything else, which goes to the app unchanged.
pub fn reserved_uninstall(args: &[OsString]) -> Option<bool> {
    match args {
        [only] if only == UNINSTALL_ARG => Some(false),
        [first, mode] if first == UNINSTALL_ARG && (mode == "/S" || mode == "--silent") => {
            Some(true)
        }
        _ => None,
    }
}

/// The command-line tail after argv\[0\], as the stub passes it on: argv\[0\] follows the
/// `CommandLineToArgvW` rule (from a leading `"` to the next `"`, or to the end when there is
/// none; otherwise to the first space or tab), and the spaces and tabs after it are dropped. The
/// rest is returned as is, never parsed or re-quoted.
pub fn command_line_tail(line: &[u16]) -> &[u16] {
    const QUOTE: u16 = b'"' as u16;
    const SPACE: u16 = b' ' as u16;
    const TAB: u16 = b'\t' as u16;
    let end = if line.first() == Some(&QUOTE) {
        line[1..]
            .iter()
            .position(|&c| c == QUOTE)
            .map_or(line.len(), |at| at + 2)
    } else {
        line.iter()
            .position(|&c| c == SPACE || c == TAB)
            .unwrap_or(line.len())
    };
    let rest = &line[end..];
    let skip = rest
        .iter()
        .position(|&c| c != SPACE && c != TAB)
        .unwrap_or(rest.len());
    &rest[skip..]
}

/// Runs the launcher and returns the process exit code.
pub fn run(variant: Variant) -> i32 {
    imp::run(variant)
}

#[cfg(windows)]
mod imp {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt as _;
    use std::os::windows::process::CommandExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use lunepack_core::{FileKind, Fs, LaunchTarget, StubError, launch_target};
    use lunepack_crypto::Sha256Hasher;
    use lunepack_fs::StdFs;
    use lunepack_os_windows::{MessageKind, message_box};

    use super::{Variant, command_line_tail, reserved_uninstall};

    /// The title of the GUI variant's message box: fixed text.
    const TITLE: &str = "App launcher";

    pub(super) fn run(variant: Variant) -> i32 {
        match launch(variant) {
            Ok(code) => code,
            Err(error) => {
                report(variant, error);
                i32::from(error.code())
            }
        }
    }

    fn report(variant: Variant, error: StubError) {
        match variant {
            // Best effort: with no desktop to show it on there is only the exit code.
            Variant::Gui => {
                let _ = message_box(TITLE, error.message(), MessageKind::Error);
            }
            Variant::Console => eprintln!("{}", error.message()),
        }
    }

    /// `R`: the directory of this executable's final path (`GetModuleFileNameW`, then the final
    /// path of that file). Nothing else names it.
    fn install_root() -> Result<PathBuf, StubError> {
        let exe = std::env::current_exe().map_err(|_| StubError::NotInstalled)?;
        let exe = std::fs::canonicalize(exe).map_err(|_| StubError::NotInstalled)?;
        exe.parent()
            .map(Path::to_path_buf)
            .ok_or(StubError::NotInstalled)
    }

    /// `path` without the `\\?\` prefix the final path carries, when the rest is a plain drive
    /// path short enough for every API (`X:\...`, under 260 units): the started app then sees an
    /// ordinary argv\[0\]. Anything else stays verbatim.
    fn display_form(path: &Path) -> PathBuf {
        let text = path.as_os_str().to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            let bytes = rest.as_bytes();
            let drive = bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\';
            if drive && rest.encode_utf16().count() < 260 && !text.contains('\u{FFFD}') {
                return PathBuf::from(rest);
            }
        }
        path.to_path_buf()
    }

    fn launch(variant: Variant) -> Result<i32, StubError> {
        let root = install_root()?;
        let fs = StdFs::new();
        let target = launch_target(&fs, &Sha256Hasher, &root)?;
        let args: Vec<OsString> = std::env::args_os().skip(1).collect();
        if let Some(silent) = reserved_uninstall(&args) {
            return uninstall(&fs, &target, silent);
        }
        let line = lunepack_os_windows::raw_command_line().map_err(|_| StubError::Launch)?;
        let tail = command_line_tail(&line);

        let mut command = Command::new(display_form(&target.entry_path));
        if !tail.is_empty() {
            command.raw_arg(OsString::from_wide(tail));
        }
        match variant {
            Variant::Gui => {
                let child = command.spawn().map_err(|_| StubError::Launch)?;
                // Best effort: without it the app may open behind the window it was started from.
                let _ = lunepack_os_windows::allow_set_foreground(child.id());
                Ok(0)
            }
            Variant::Console => {
                // Best effort: a stub with no console has no interrupt to ignore.
                let _ = lunepack_os_windows::ignore_console_interrupts();
                let mut child = command.spawn().map_err(|_| StubError::Launch)?;
                let status = child.wait().map_err(|_| StubError::Launch)?;
                // On Windows every exit status has a code: the full 32-bit value, passed on.
                Ok(status.code().unwrap_or(i32::from(StubError::Launch.code())))
            }
        }
    }

    /// The reserved argument: the current version's runtime (a regular file, not a link) runs
    /// `uninstall [--silent]`, detached from this process's standard handles; the stub does not
    /// wait, so it holds nothing under `R` while the uninstall runs.
    fn uninstall(fs: &dyn Fs, target: &LaunchTarget, silent: bool) -> Result<i32, StubError> {
        match fs.symlink_metadata(&target.runtime_path) {
            Ok(Some(meta)) if meta.kind == FileKind::File => {}
            Ok(Some(meta)) if meta.kind == FileKind::Symlink => return Err(StubError::Link),
            _ => return Err(StubError::Entry),
        }
        let mut command = Command::new(display_form(&target.runtime_path));
        command.arg("uninstall");
        if silent {
            command.arg("--silent");
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| StubError::Launch)?;
        Ok(0)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{EXIT_UNSUPPORTED, Variant};

    pub(super) fn run(_variant: Variant) -> i32 {
        eprintln!("the stub runs on Windows only");
        EXIT_UNSUPPORTED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn tail(s: &str) -> String {
        String::from_utf16(command_line_tail(&wide(s))).unwrap()
    }

    #[test]
    fn argv0_ends_at_the_closing_quote_or_the_first_blank() {
        assert_eq!(
            tail(r#""C:\My App\app.exe" a "b c" d\"e \\""#),
            r#"a "b c" d\"e \\""#
        );
        assert_eq!(tail(r"C:\app.exe a b"), "a b");
        assert_eq!(tail("C:\\app.exe\t \tx  "), "x  ");
        assert_eq!(tail(r#""C:\a b\app.exe""#), "");
        assert_eq!(tail(r"C:\app.exe"), "");
        assert_eq!(tail(""), "");
        // An unclosed quote: argv[0] is the whole line.
        assert_eq!(tail(r#""C:\a b\app.exe x"#), "");
        // Text right after the closing quote starts the tail (the quote ends argv[0]).
        assert_eq!(tail(r#""C:\app.exe"x y"#), "x y");
        // Non-ASCII is passed through unit for unit.
        assert_eq!(tail("app.exe é 😀"), "é 😀");
    }

    #[test]
    fn only_the_exact_reserved_command_lines_are_reserved() {
        let os = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            reserved_uninstall(&os(&["--lunepack-uninstall"])),
            Some(false)
        );
        assert_eq!(
            reserved_uninstall(&os(&["--lunepack-uninstall", "/S"])),
            Some(true)
        );
        assert_eq!(
            reserved_uninstall(&os(&["--lunepack-uninstall", "--silent"])),
            Some(true)
        );
        for other in [
            &[][..],
            &["--lunepack-uninstall", "/s"][..],
            &["--lunepack-uninstall", "--silent", "x"][..],
            &["x", "--lunepack-uninstall"][..],
            &["/S", "--lunepack-uninstall"][..],
            &["--LUNEPACK-UNINSTALL"][..],
            &["--lunepack-uninstall=1"][..],
        ] {
            assert_eq!(reserved_uninstall(&os(other)), None, "{other:?}");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_stub_refuses_with_exit_2() {
        assert_eq!(run(Variant::Gui), EXIT_UNSUPPORTED);
        assert_eq!(run(Variant::Console), EXIT_UNSUPPORTED);
    }
}
