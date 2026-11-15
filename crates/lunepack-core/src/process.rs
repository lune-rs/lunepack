//! Processes behind a trait (hard rule 3): the runtime and the facade start the app, wait for the
//! process that asked for an update to end, supervise a launched version and ask whether a version
//! tree is still in use, all through [`Process`]. The Linux implementation is in
//! `lunepack-os-linux`; the testkit's `FakeProcess` scripts every answer.
//!
//! A process is named by a [`ProcessId`]: the pid and the process's start time, so a pid that the
//! OS has reused for another process is never mistaken for the original.
//!
//! No error from this module carries a path beyond a file name, or any argument or environment
//! value: a [`SpawnSpec`] can hold a health token, and neither its `Debug` nor a [`ProcessError`]
//! ever shows one.

// `Duration` is a plain value (no clock is read); the purity test forbids `std::time` as a whole.
use core::time::Duration;
use std::error::Error as StdError;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::{Result, Untrusted};

/// A process, named so that a reused pid cannot be mistaken for it: the pid and the process's
/// start time in the OS's own unit (clock ticks since boot on Linux; the pair is only compared for
/// equality, never interpreted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessId {
    /// The process id.
    pub pid: u32,
    /// The process's start time.
    pub start_ticks: u64,
}

/// A program to start. The program runs without a shell; each argument reaches it as one
/// argument, as given.
#[derive(Clone, PartialEq, Eq)]
pub struct SpawnSpec {
    /// The program, an absolute path (a relative path is refused).
    pub program: PathBuf,
    /// Its arguments, without the program name.
    pub args: Vec<OsString>,
    /// Environment variables to set (they replace an inherited value of the same name).
    pub env_set: Vec<(OsString, OsString)>,
    /// Environment variables to remove from the inherited environment.
    pub env_remove: Vec<OsString>,
}

impl SpawnSpec {
    /// A spec for `program` with no arguments and the inherited environment.
    pub fn new(program: impl Into<PathBuf>) -> SpawnSpec {
        SpawnSpec {
            program: program.into(),
            args: Vec::new(),
            env_set: Vec::new(),
            env_remove: Vec::new(),
        }
    }
}

impl fmt::Debug for SpawnSpec {
    /// Shows the program's file name, the number of arguments and the names (never the values) of
    /// the variables set or removed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let program = self
            .program
            .file_name()
            .map(|n| Untrusted::new(&n.to_string_lossy()).to_string())
            .unwrap_or_default();
        let name_of = |k: &OsString| Untrusted::new(&k.to_string_lossy()).to_string();
        let set: Vec<String> = self.env_set.iter().map(|(k, _)| name_of(k)).collect();
        let removed: Vec<String> = self.env_remove.iter().map(name_of).collect();
        f.debug_struct("SpawnSpec")
            .field("program", &program)
            .field("args", &self.args.len())
            .field("env_set", &set)
            .field("env_remove", &removed)
            .finish()
    }
}

/// How a process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// Exit status 0.
    Success,
    /// A non-zero exit status.
    Failure(i32),
    /// Ended by a signal (its number).
    Signal(i32),
}

/// What [`Process::wait_exit`] saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The process is gone, a zombie, or no longer the process the id names.
    Exited,
    /// The timeout ran out with the process still running.
    TimedOut,
}

/// What went wrong, in terms a caller can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProcessErrorKind {
    /// The program, or a process the operation needs, does not exist.
    NotFound,
    /// The OS refused (permissions).
    PermissionDenied,
    /// The request is not acceptable: for example a program that is not an absolute path.
    InvalidRequest,
    /// The OS could not start the program.
    SpawnFailed,
    /// Information about a process could not be read (or parsed).
    Unreadable,
    /// This platform has no implementation.
    Unsupported,
    /// Anything else; the cause is in [`ProcessError::source`].
    Other,
}

impl ProcessErrorKind {
    /// A fixed description.
    pub const fn describe(self) -> &'static str {
        match self {
            ProcessErrorKind::NotFound => "not found",
            ProcessErrorKind::PermissionDenied => "permission denied",
            ProcessErrorKind::InvalidRequest => "invalid request",
            ProcessErrorKind::SpawnFailed => "could not start",
            ProcessErrorKind::Unreadable => "process information unreadable",
            ProcessErrorKind::Unsupported => "not supported on this platform",
            ProcessErrorKind::Other => "process operation failed",
        }
    }
}

/// A process operation failed. `Display` and `Debug` show the kind, the operation and the file
/// name of the program only.
pub struct ProcessError {
    /// The failure class.
    pub kind: ProcessErrorKind,
    /// The underlying error, kept as the cause (hard rule 4).
    pub source: Option<io::Error>,
    op: &'static str,
    name: String,
}

impl ProcessError {
    /// An error of `kind` for operation `op` (`"spawn"`, `"wait"`, ...).
    pub fn new(kind: ProcessErrorKind, op: &'static str) -> ProcessError {
        ProcessError {
            kind,
            source: None,
            op,
            name: String::new(),
        }
    }

    /// Names the program the operation was about; only its file name is kept.
    #[must_use]
    pub fn about(mut self, program: &Path) -> ProcessError {
        self.name = program
            .file_name()
            .map(|n| Untrusted::new(&n.to_string_lossy()).to_string())
            .unwrap_or_default();
        self
    }

    /// Keeps `source` as the cause.
    #[must_use]
    pub fn caused_by(mut self, source: io::Error) -> ProcessError {
        self.source = Some(source);
        self
    }

    /// Classifies an `io::Error` of operation `op` (`NotFound`, `PermissionDenied`; anything else
    /// is [`ProcessErrorKind::Other`]) and keeps it as the cause.
    pub fn from_io(op: &'static str, err: io::Error) -> ProcessError {
        let kind = match err.kind() {
            io::ErrorKind::NotFound => ProcessErrorKind::NotFound,
            io::ErrorKind::PermissionDenied => ProcessErrorKind::PermissionDenied,
            _ => ProcessErrorKind::Other,
        };
        ProcessError::new(kind, op).caused_by(err)
    }

    /// The operation that failed.
    pub fn operation(&self) -> &'static str {
        self.op
    }

    /// The OS error code of the cause, if any.
    pub fn os_code(&self) -> Option<i32> {
        self.source.as_ref().and_then(io::Error::raw_os_error)
    }

    /// The file name of the program the error is about (escaped, possibly empty).
    pub fn file_name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "process: {} ({})", self.kind.describe(), self.op)?;
        if !self.name.is_empty() {
            write!(f, ": {}", self.name)?;
        }
        Ok(())
    }
}

impl fmt::Debug for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The cause is shown by kind and OS code only: an OS error message can name a full path.
        f.debug_struct("ProcessError")
            .field("kind", &self.kind)
            .field("op", &self.op)
            .field("name", &self.name)
            .field("source_kind", &self.source.as_ref().map(io::Error::kind))
            .field("os_code", &self.os_code())
            .finish()
    }
}

impl StdError for ProcessError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|e| e as &(dyn StdError + 'static))
    }
}

/// A process this one started with [`Process::spawn_child`].
pub trait Child: Send {
    /// The child's id.
    fn id(&self) -> ProcessId;

    /// `Some(how it ended)` once the child has ended (it is reaped; later calls give the same
    /// answer), `None` while it runs. Does not block.
    fn try_wait(&mut self) -> Result<Option<ExitKind>>;

    /// Ends the child and only the child: asks it to stop (SIGTERM on Linux), waits up to `grace`
    /// for it to exit, then kills it. Returns once the child is gone and reaped; a child that
    /// already ended is not an error. The exit is then reported by [`Child::try_wait`].
    fn terminate(&mut self, grace: Duration) -> Result<()>;
}

/// Starting, watching and ending processes, and asking which ones use a directory. Object-safe
/// and `Send + Sync`.
pub trait Process: Send + Sync {
    /// The resolved path (symlinks followed) of the running executable.
    fn current_exe(&self) -> Result<PathBuf>;

    /// This process's id.
    fn current(&self) -> Result<ProcessId>;

    /// The parent process, or `None` when the parent is pid 1 or gone (the process was adopted).
    fn parent(&self) -> Result<Option<ProcessId>>;

    /// Starts `spec` in a new session with its standard streams null, and does not wait for it. The program outlives this process.
    fn spawn_detached(&self, spec: &SpawnSpec) -> Result<()>;

    /// Starts `spec` as a child of this process, standard streams null. The caller reaps it
    /// through the returned [`Child`].
    fn spawn_child(&self, spec: &SpawnSpec) -> Result<Box<dyn Child>>;

    /// Waits up to `timeout` for the process `id` to end. It only waits: it never signals, and
    /// never reaps a process that is not its own child. An id whose pid is gone, is a zombie, or
    /// now belongs to a process with another start time counts as ended.
    fn wait_exit(&self, id: &ProcessId, timeout: Duration) -> Result<WaitOutcome>;

    /// Whether any process other than those in `exclude` is running with the tree at `tree` in
    /// use (its executable, working directory, mapped files or open files lie under it). A process
    /// that cannot be inspected counts as in use.
    fn tree_in_use(&self, tree: &Path, exclude: &[ProcessId]) -> Result<bool>;
}
