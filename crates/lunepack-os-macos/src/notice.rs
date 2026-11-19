//! A native alert on macOS (M8-D11): for an interactive install or uninstall that ended without a
//! UI that showed its outcome.
//!
//! The alert is shown by `/usr/bin/osascript` running one fixed script. The title, the text and the
//! kind reach it only as arguments (`on run argv`), never inside the script's source, so no string
//! can change what the script does. The alert dismisses itself after [`GIVE_UP_SECS`] seconds, and
//! the process is killed [`KILL_GRACE`] after that, so the call returns within a bounded time
//! whatever the window server does. The caller decides whether showing it is allowed (only when
//! the session is provably interactive, M7-F14's rule).

use std::io;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The program that shows the alert.
const OSASCRIPT: &str = "/usr/bin/osascript";

/// How long the alert stays up before it dismisses itself.
pub const GIVE_UP_SECS: u64 = 120;

/// How long past the alert's own timeout the process may run before it is killed.
const KILL_GRACE: Duration = Duration::from_secs(5);

/// The only script this module ever runs. Its three arguments are the title, the text and the
/// kind (`info`, `warning` or `error`); the kind picks one of three fixed branches.
pub const SCRIPT: &str = "on run argv\n\
    set theTitle to item 1 of argv\n\
    set theText to item 2 of argv\n\
    set theKind to item 3 of argv\n\
    if theKind is \"error\" then\n\
    display alert theTitle message theText as critical giving up after 120\n\
    else if theKind is \"warning\" then\n\
    display alert theTitle message theText as warning giving up after 120\n\
    else\n\
    display alert theTitle message theText as informational giving up after 120\n\
    end if\n\
    end run";

/// What kind of outcome the alert reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    /// A normal end.
    Info,
    /// Something to look at.
    Warning,
    /// A failure.
    Error,
}

impl NoticeKind {
    const fn word(self) -> &'static str {
        match self {
            NoticeKind::Info => "info",
            NoticeKind::Warning => "warning",
            NoticeKind::Error => "error",
        }
    }
}

/// The arguments of the `osascript` run for `title`, `text` and `kind`: `-e`, the fixed script,
/// `--` (so an argument that starts with a dash is not an option), then the three strings.
pub fn notice_args(title: &str, text: &str, kind: NoticeKind) -> Vec<String> {
    vec![
        "-e".to_owned(),
        SCRIPT.to_owned(),
        "--".to_owned(),
        title.to_owned(),
        text.to_owned(),
        kind.word().to_owned(),
    ]
}

/// Shows the alert and returns when it is dismissed, when it gives up (after [`GIVE_UP_SECS`]), or
/// when the process has been killed ([`GIVE_UP_SECS`] plus a few seconds at the most). An error
/// means no alert could be shown (no window server, `osascript` missing or failed).
pub fn notice(title: &str, text: &str, kind: NoticeKind) -> io::Result<()> {
    let args = notice_args(title, text, kind);
    run_bounded(
        OSASCRIPT,
        &args,
        Duration::from_secs(GIVE_UP_SECS) + KILL_GRACE,
    )
}

/// Runs `program` with `args` (no shell, no streams) and kills it when it has not ended within
/// `limit`. `Ok` only for a normal exit with status 0.
fn run_bounded(program: &str, args: &[String], limit: Duration) -> io::Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let start = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) if status.success() => return Ok(()),
            Some(_) => return Err(io::Error::other("the alert could not be shown")),
            None if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(20)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the alert did not end in time",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_is_a_constant_and_strings_travel_as_arguments() {
        let evil = "a\" & (do shell script \"x\") \\ end tell\nend run";
        let args = notice_args(evil, "text \" \\ end tell", NoticeKind::Error);
        assert_eq!(args[0], "-e");
        assert_eq!(
            args[1], SCRIPT,
            "the script text must not depend on the strings"
        );
        assert_eq!(args[2], "--");
        assert_eq!(args[3], evil);
        assert_eq!(args[4], "text \" \\ end tell");
        assert_eq!(args[5], "error");
        assert_eq!(args.len(), 6);
        for kind in [NoticeKind::Info, NoticeKind::Warning, NoticeKind::Error] {
            assert_eq!(notice_args("t", "x", kind)[1], SCRIPT);
        }
        // The script itself holds none of the caller's text and gives up after the constant.
        assert!(SCRIPT.contains(&format!("giving up after {GIVE_UP_SECS}")));
    }

    /// The real `osascript` hands the arguments to a script verbatim, an argument that starts
    /// with a dash and quotes, backslashes and `end tell` included. (A different script from the
    /// alert's, so no window opens.)
    #[test]
    fn osascript_passes_arguments_through_verbatim() {
        let evil = "-x \"q\" \\ end tell";
        let mut args = notice_args(evil, "two", NoticeKind::Info);
        args[1] = "on run argv\nreturn (item 1 of argv) & \"|\" & (item 2 of argv) & \"|\" & (item 3 of argv)\nend run"
            .to_owned();
        let out = Command::new(OSASCRIPT)
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .expect("run osascript");
        assert!(out.status.success(), "osascript failed");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim_end_matches('\n'),
            format!("{evil}|two|info")
        );
    }

    #[test]
    fn a_process_that_does_not_end_is_killed_at_the_limit() {
        let started = Instant::now();
        let err = run_bounded("/bin/sleep", &["30".to_owned()], Duration::from_millis(300))
            .expect_err("sleep outlives the limit");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn an_exit_status_and_a_missing_program_are_errors() {
        let limit = Duration::from_secs(5);
        assert!(run_bounded("/usr/bin/true", &[], limit).is_ok());
        assert!(run_bounded("/usr/bin/false", &[], limit).is_err());
        assert!(run_bounded("/nonexistent/osascript", &[], limit).is_err());
    }
}
