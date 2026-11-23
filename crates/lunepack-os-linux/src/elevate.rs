//! The hand-off to an administrator on Linux (M11-D9): `pkexec`, whose polkit agent asks for an
//! administrator's password. The child's standard output is a pipe the caller reads the event
//! lines from (pkexec keeps the caller's stdout and passes the child's exit code through);
//! standard input is `/dev/null`.
//!
//! pkexec answers a declined or dismissed prompt with exit code 126 and a missing agent with 127,
//! both only when it ends: [`PkexecChild::wait`] turns them into [`ElevationError::Declined`] and
//! [`ElevationError::NoAgent`]. A missing `/usr/bin/pkexec` is [`ElevationError::NoAgent`] at
//! once; the caller then shows the `sudo` command instead.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

use lunepack_core::{Elevated, ElevatedChild, Elevation, ElevationError, Standing};

/// Where pkexec is; nothing else is tried (no `PATH`).
pub const PKEXEC: &str = "/usr/bin/pkexec";
/// pkexec's exit code for a declined or dismissed authentication.
pub const PKEXEC_DECLINED: i32 = 126;
/// pkexec's exit code when no authentication agent could ask.
pub const PKEXEC_NO_AGENT: i32 = 127;

/// Whether `path` is a regular file owned by root that neither its group nor others may write.
pub(crate) fn root_tool(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
}

/// The effective uid of this process.
#[allow(unsafe_code)]
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Sets this process's file-creation mask to `0o022` and returns the previous one.
///
/// Every process that stands as root when it creates the files of a machine install calls this
/// first (M11-D7): pkexec keeps the caller's mask and a root shell may carry a hardened or a
/// permissive one, and what the staging, the machine record and the integration entries are made
/// with must not depend on it. `0o022` leaves every tree readable by everyone and writable by
/// nobody but root; the protected directories get their exact modes from `Protect` regardless.
#[allow(unsafe_code, clippy::useless_conversion)]
pub fn set_root_umask() -> u32 {
    // SAFETY: `umask` has no preconditions and cannot fail; it only changes this process's mask.
    u32::from(unsafe { libc::umask(0o022) })
}

/// [`Elevation`] through pkexec.
#[derive(Debug, Clone)]
pub struct PkexecElevation {
    pkexec: PathBuf,
    /// Whether the tool must be a root-owned file (false only in tests, which run a fake).
    require_root_tool: bool,
}

impl Default for PkexecElevation {
    fn default() -> Self {
        PkexecElevation::new()
    }
}

impl PkexecElevation {
    /// [`PKEXEC`].
    pub fn new() -> PkexecElevation {
        PkexecElevation {
            pkexec: PathBuf::from(PKEXEC),
            require_root_tool: true,
        }
    }

    /// For tests: `pkexec` stands for pkexec, whoever owns it. Never used by a composition root.
    #[doc(hidden)]
    pub fn for_tests(pkexec: PathBuf) -> PkexecElevation {
        PkexecElevation {
            pkexec,
            require_root_tool: false,
        }
    }
}

/// A child started through pkexec.
#[derive(Debug)]
pub struct PkexecChild {
    child: Child,
    stdout: Option<ChildStdout>,
}

impl ElevatedChild for PkexecChild {
    fn wait(&mut self) -> Result<i32, ElevationError> {
        let status = self
            .child
            .wait()
            .map_err(|_| ElevationError::Failed("wait for pkexec"))?;
        match status.code() {
            Some(PKEXEC_DECLINED) => Err(ElevationError::Declined),
            Some(PKEXEC_NO_AGENT) => Err(ElevationError::NoAgent),
            Some(code) => Ok(code),
            None => Err(ElevationError::Failed("pkexec ended by a signal")),
        }
    }

    fn take_output(&mut self) -> Option<Box<dyn Read + Send>> {
        self.stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>)
    }
}

impl Elevation for PkexecElevation {
    fn standing(&self) -> Standing {
        if effective_uid() == 0 {
            Standing::Admin
        } else {
            Standing::Standard
        }
    }

    fn run_elevated(&self, exe: &Path, args: &[String]) -> Result<Elevated, ElevationError> {
        if !exe.is_absolute() {
            return Err(ElevationError::Failed(
                "the program is not an absolute path",
            ));
        }
        let usable = if self.require_root_tool {
            root_tool(&self.pkexec)
        } else {
            self.pkexec.is_file()
        };
        if !usable {
            return Err(ElevationError::NoAgent);
        }
        let mut child = Command::new(&self.pkexec)
            .arg(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ElevationError::NoAgent,
                _ => ElevationError::Failed("start pkexec"),
            })?;
        let stdout = child.stdout.take();
        Ok(Elevated::Started(Box::new(PkexecChild { child, stdout })))
    }
}
