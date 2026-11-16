//! The reduce-motion reader (M6-D8): on Linux the desktop's animation switch, read with
//! `gsettings` (no shell). A desktop without it, or without `gsettings`, is unknown, which means
//! the full motion tier.

/// What `gsettings get org.gnome.desktop.interface enable-animations` printed, as a verdict for
/// reduced motion: `false` (animations off) is reduced motion, `true` is not; anything else is
/// unknown.
pub fn parse_enable_animations(output: &str) -> Option<bool> {
    match output.trim() {
        "false" => Some(true),
        "true" => Some(false),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
mod run {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// The most output read from the helper.
    const MAX_OUTPUT: u64 = 256;
    /// How long the helper may run before it is killed.
    const LIMIT: Duration = Duration::from_secs(2);

    /// Runs `program` with `args` (no shell, no stdin, no stderr) and returns at most
    /// [`MAX_OUTPUT`] bytes of its output when it exits successfully within [`LIMIT`]; kills it
    /// otherwise.
    pub(super) fn run_bounded(program: &str, args: &[&str]) -> Option<String> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut out = child.stdout.take()?;
        let reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = (&mut out).take(MAX_OUTPUT).read_to_end(&mut buf);
            buf
        });
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if start.elapsed() < LIMIT => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let bytes = reader.join().ok()?;
        status.filter(|s| s.success())?;
        String::from_utf8(bytes).ok()
    }
}

/// Whether the user asked for reduced motion; `None` when the setting cannot be read. `None`
/// means the full motion tier.
#[cfg(target_os = "linux")]
pub fn prefers_reduced_motion() -> Option<bool> {
    let out = run::run_bounded(
        "gsettings",
        &["get", "org.gnome.desktop.interface", "enable-animations"],
    )?;
    parse_enable_animations(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_parses_to_a_verdict() {
        assert_eq!(parse_enable_animations("false\n"), Some(true));
        assert_eq!(parse_enable_animations("true\n"), Some(false));
        assert_eq!(parse_enable_animations(""), None);
        assert_eq!(parse_enable_animations("'true'"), None);
        assert_eq!(
            parse_enable_animations("No such schema \"org.gnome.desktop.interface\""),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_missing_or_slow_helper_is_unknown_not_a_hang() {
        use std::time::{Duration, Instant};
        assert_eq!(run::run_bounded("/nonexistent/helper", &[]), None);
        let started = Instant::now();
        assert_eq!(run::run_bounded("sleep", &["30"]), None);
        assert!(started.elapsed() < Duration::from_secs(6));
        assert_eq!(
            run::run_bounded("echo", &["true"]).as_deref(),
            Some("true\n")
        );
        // The real reader answers (or says unknown) without panicking.
        let _ = prefers_reduced_motion();
    }
}
