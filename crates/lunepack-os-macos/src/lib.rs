//! macOS install, shortcut, autostart and process-restart adapter.
//!
//! It holds `MacProcess` (the core's `Process` over libproc and kqueue, M8 step 3),
//! `MacIntegration` (the autostart LaunchAgent, M8-D12), `notice` (a native alert through
//! `osascript`, M8-D11) and the reduce-motion reader (M6-D8): [`prefers_reduced_motion`] runs `defaults`
//! (no shell) to read the "Reduce motion" accessibility setting, so the runtime's graph gets no
//! window-stack library.
//!
//! The per-machine ports (M11): [`MacProtect`] (protected directories), [`LaunchdRegistrar`] (the
//! socket-activated LaunchDaemon), [`ActivatedListener`] and [`UnixConnector`] (the service's
//! socket, both ends), [`FilePolicy`] (the administrator's policy file), [`MacMachineIntegration`]
//! (the start-at-sign-in entry for every user) and [`MacElevation`] (the standing; no prompt of
//! our own, D38 (a)).

#[cfg(any(target_os = "macos", test))]
mod code_status;
#[cfg(target_os = "macos")]
mod integration;
#[cfg(target_os = "macos")]
mod launchd;
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub mod libproc;
#[cfg(target_os = "macos")]
mod notice;
#[cfg(target_os = "macos")]
mod policy;
#[cfg(target_os = "macos")]
mod process;
#[cfg(target_os = "macos")]
mod protect;
#[cfg(target_os = "macos")]
mod publisher;
#[cfg(target_os = "macos")]
mod socket;

#[cfg(target_os = "macos")]
pub use integration::{MacEnv, MacIntegration, MacMachineIntegration};
#[cfg(target_os = "macos")]
pub use launchd::{LAUNCHCTL, LaunchdRegistrar, SELF_TEST_LIMIT, daemon_plist};
#[cfg(target_os = "macos")]
pub use notice::{NoticeKind, notice};
#[cfg(target_os = "macos")]
pub use policy::{FilePolicy, MAX_POLICY_BYTES, POLICY_DIR};
#[cfg(target_os = "macos")]
pub use process::MacProcess;
#[cfg(target_os = "macos")]
pub use protect::{MacProtect, class_mode};
#[cfg(target_os = "macos")]
pub use publisher::MacPublisherCheck;
#[cfg(target_os = "macos")]
pub use socket::{
    ActivatedListener, ActivationError, CONNECT_RETRY, UnixConnector, UnixDuplex, check_listener,
    peer_uid,
};

/// [`Elevation`](lunepack_core::Elevation) on macOS (D38 (a)): the standing from the effective
/// uid (0 is an administrator's), and no prompt of lunepack's own, so a hand-off is
/// [`ElevationError::NoAgent`](lunepack_core::ElevationError::NoAgent): the caller shows the
/// command to run as an administrator, or opens the installer package.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, Default)]
pub struct MacElevation;

#[cfg(target_os = "macos")]
impl lunepack_core::Elevation for MacElevation {
    fn standing(&self) -> lunepack_core::Standing {
        if effective_uid() == 0 {
            lunepack_core::Standing::Admin
        } else {
            lunepack_core::Standing::Standard
        }
    }

    fn run_elevated(
        &self,
        _exe: &std::path::Path,
        _args: &[String],
    ) -> Result<lunepack_core::Elevated, lunepack_core::ElevationError> {
        Err(lunepack_core::ElevationError::NoAgent)
    }
}

/// The effective uid of this process.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid(2) takes no arguments, cannot fail and touches no memory.
    unsafe { libc::geteuid() }
}

/// Sets this process's file-creation mask to `0o022` and returns the previous one.
///
/// Every process that stands as root when it creates the files of a machine install calls this
/// first (M11-D7): the installer package's postinstall and a root shell may carry any mask, and
/// what the staging, the machine record and the app bundle are made with must not depend on it.
/// `0o022` leaves every tree readable by everyone and writable by nobody but root; the protected
/// directories get their exact modes from `Protect` regardless.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub fn set_root_umask() -> u32 {
    // SAFETY: umask(2) has no preconditions and cannot fail; it only changes this process's mask.
    u32::from(unsafe { libc::umask(0o022) })
}

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The most output read from the helper.
const MAX_OUTPUT: u64 = 256;
/// How long the helper may run before it is killed.
const LIMIT: Duration = Duration::from_secs(2);

/// What `defaults read com.apple.universalaccess reduceMotion` printed, as a verdict: `1` is
/// reduced motion, `0` is not; anything else is unknown.
pub fn parse_reduce_motion(output: &str) -> Option<bool> {
    match output.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// Whether the user asked for reduced motion; `None` when the setting cannot be read (and
/// always off macOS). `None` means the full motion tier.
pub fn prefers_reduced_motion() -> Option<bool> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let out = run_bounded(
        "/usr/bin/defaults",
        &["read", "com.apple.universalaccess", "reduceMotion"],
    )?;
    parse_reduce_motion(&out)
}

/// Runs `program` with `args` (no shell, no stdin, no stderr), reads at most [`MAX_OUTPUT`] bytes
/// of its output and returns them when it exits successfully within [`LIMIT`]; kills it otherwise.
fn run_bounded(program: &str, args: &[&str]) -> Option<String> {
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
            Ok(None) if start.elapsed() < LIMIT => std::thread::sleep(Duration::from_millis(10)),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_setting_parses_to_a_verdict() {
        assert_eq!(parse_reduce_motion("1\n"), Some(true));
        assert_eq!(parse_reduce_motion("0\n"), Some(false));
        assert_eq!(parse_reduce_motion(""), None);
        assert_eq!(parse_reduce_motion("2"), None);
        assert_eq!(
            parse_reduce_motion("The domain/default pair does not exist"),
            None
        );
    }

    // Uses /bin/sleep, /usr/bin/false and /bin/echo, which exist only on Unix.
    #[cfg(unix)]
    #[test]
    fn a_missing_or_slow_helper_is_unknown_not_a_hang() {
        assert_eq!(run_bounded("/nonexistent/helper", &[]), None);
        let started = Instant::now();
        assert_eq!(run_bounded("/bin/sleep", &["30"]), None);
        assert!(started.elapsed() < Duration::from_secs(6));
        assert_eq!(run_bounded("/usr/bin/false", &[]), None);
        assert_eq!(run_bounded("/bin/echo", &["1"]).as_deref(), Some("1\n"));
    }

    #[test]
    fn the_real_reader_answers_without_panicking() {
        let value = prefers_reduced_motion();
        if cfg!(not(target_os = "macos")) {
            assert_eq!(value, None);
        }
    }
}
