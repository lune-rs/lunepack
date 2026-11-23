//! [`LinuxProcess`]: the core's [`Process`] over `std::process` and `/proc`.
//!
//! - Programs start through `std::process::Command` with an absolute path: no shell and no `PATH`
//!   lookup. `env_remove` is applied before `env_set`, so a variable in both lists ends up set.
//! - A piped child (`ChildStdio::Piped`, M6-D1) gets anonymous pipes from `std`, which creates the
//!   parent's ends close-on-exec: no process this one starts afterwards inherits them (the app the
//!   runtime relaunches must not hold the UI's channel). Its error stream stays null. A detached
//!   spawn refuses pipes.
//! - A detached program leads a new session (`setsid` between fork and exec) with its standard
//!   streams on `/dev/null`, so neither a hangup of the caller's terminal or process group nor a
//!   reader of the caller's pipes waits for it.
//! - Waiting polls `/proc/<pid>/stat` every 100 ms by the liveness rule in [`crate::procfs`]
//!   (gone, another start time, or a zombie counts as exited). It never signals or reaps.
//! - Only an own child is ever signalled ([`Child::terminate`]), and only before it is reaped, so
//!   its pid cannot have been reused.

use core::time::Duration;
use std::io::{self, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use lunepack_core::{
    Child, ChildStdio, Error, ExitKind, Process, ProcessError, ProcessErrorKind, ProcessId,
    SpawnSpec, WaitOutcome,
};

use crate::procfs::{self, Probe};

/// How often [`Process::wait_exit`] looks at the process it waits for.
const WAIT_POLL: Duration = Duration::from_millis(100);
/// How often [`Child::terminate`] looks at the child during the grace period.
const TERMINATE_POLL: Duration = Duration::from_millis(10);

/// The Linux [`Process`].
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxProcess {
    _private: (),
}

impl LinuxProcess {
    /// The process adapter.
    pub fn new() -> LinuxProcess {
        LinuxProcess { _private: () }
    }

    /// The id of the running process `pid` (its pid and start time), or `None` when no such
    /// process runs (gone, or a zombie). Used to name a wait target given only by its pid.
    pub fn process_id(&self, pid: u32) -> Result<Option<ProcessId>, Error> {
        match procfs::probe(pid).map_err(|e| unreadable("process id", e))? {
            Probe::Running(stat) => Ok(Some(ProcessId {
                pid,
                start_ticks: stat.start_ticks,
            })),
            Probe::Gone | Probe::Dead(_) => Ok(None),
        }
    }
}

fn unreadable(op: &'static str, err: io::Error) -> Error {
    ProcessError::new(ProcessErrorKind::Unreadable, op)
        .caused_by(err)
        .into()
}

fn spawn_error(err: io::Error, program: &Path) -> Error {
    let kind = match err.kind() {
        io::ErrorKind::NotFound => ProcessErrorKind::NotFound,
        io::ErrorKind::PermissionDenied => ProcessErrorKind::PermissionDenied,
        io::ErrorKind::InvalidInput => ProcessErrorKind::InvalidRequest,
        _ => ProcessErrorKind::SpawnFailed,
    };
    ProcessError::new(kind, "spawn")
        .about(program)
        .caused_by(err)
        .into()
}

/// The command for `spec`: the error stream null, the others null or piped as the spec says.
fn command(spec: &SpawnSpec) -> Result<Command, Error> {
    if !spec.program.is_absolute() {
        return Err(ProcessError::new(ProcessErrorKind::InvalidRequest, "spawn")
            .about(&spec.program)
            .into());
    }
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args);
    for name in &spec.env_remove {
        cmd.env_remove(name);
    }
    for (name, value) in &spec.env_set {
        cmd.env(name, value);
    }
    let piped = || match spec.stdio {
        ChildStdio::Piped => Stdio::piped(),
        _ => Stdio::null(),
    };
    cmd.stdin(piped()).stdout(piped()).stderr(Stdio::null());
    Ok(cmd)
}

/// Makes `cmd` start its program in a new session.
#[allow(unsafe_code)]
fn new_session(cmd: &mut Command) {
    // SAFETY: the closure runs in the forked child before exec, where only async-signal-safe
    // calls are allowed. It calls setsid(2), which is async-signal-safe, and on failure reads
    // errno through `io::Error::last_os_error` (no allocation, no lock). It touches no memory of
    // the parent and holds no lock.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Sends SIGTERM to `pid`, an own child that has not been reaped yet.
#[allow(unsafe_code)]
fn send_sigterm(pid: u32) -> io::Result<()> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
    if pid <= 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a process"));
    }
    // SAFETY: kill(2) takes two integers and touches no memory. `pid` is positive, so it names
    // one process, never a group; it is this process's own child, not yet reaped (the caller
    // checked), so the pid cannot have been reused by another process.
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc == -1 {
        let err = io::Error::last_os_error();
        // ESRCH: it is a zombie already; the caller reaps it.
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(err);
        }
    }
    Ok(())
}

impl Process for LinuxProcess {
    fn current_exe(&self) -> Result<PathBuf, Error> {
        let exe = std::fs::read_link("/proc/self/exe").map_err(|e| unreadable("current exe", e))?;
        if !exe.is_absolute() {
            return Err(ProcessError::new(ProcessErrorKind::Unreadable, "current exe").into());
        }
        Ok(exe)
    }

    fn current(&self) -> Result<ProcessId, Error> {
        let stat = procfs::read_stat(None)
            .map_err(|e| unreadable("current", e))?
            .ok_or_else(|| {
                Error::from(ProcessError::new(ProcessErrorKind::Unreadable, "current"))
            })?;
        Ok(ProcessId {
            pid: std::process::id(),
            start_ticks: stat.start_ticks,
        })
    }

    fn parent(&self) -> Result<Option<ProcessId>, Error> {
        let ppid = std::os::unix::process::parent_id();
        // 0: the parent is outside this pid namespace.
        if ppid <= 1 {
            return Ok(None);
        }
        let id = self.process_id(ppid)?;
        // Still its child after the read: then the parent has not been reaped, so `ppid` cannot
        // have been reused and the start time read is the parent's.
        if std::os::unix::process::parent_id() != ppid {
            return Ok(None);
        }
        Ok(id)
    }

    fn spawn_detached(&self, spec: &SpawnSpec) -> Result<(), Error> {
        if spec.stdio != ChildStdio::Null {
            // Nobody would own the pipes of a program that outlives this process.
            return Err(ProcessError::new(ProcessErrorKind::InvalidRequest, "spawn")
                .about(&spec.program)
                .into());
        }
        let mut cmd = command(spec)?;
        new_session(&mut cmd);
        // The handle is dropped without waiting: the program outlives this process.
        cmd.spawn()
            .map(drop)
            .map_err(|e| spawn_error(e, &spec.program))
    }

    fn spawn_child(&self, spec: &SpawnSpec) -> Result<Box<dyn Child>, Error> {
        let mut child = command(spec)?
            .spawn()
            .map_err(|e| spawn_error(e, &spec.program))?;
        let pid = child.id();
        // Not yet reaped, so `/proc/<pid>` exists (running or a zombie) and is this child.
        let start = match procfs::probe(pid) {
            Ok(Probe::Running(stat) | Probe::Dead(stat)) => Ok(stat.start_ticks),
            Ok(Probe::Gone) => Err(io::Error::from(io::ErrorKind::NotFound)),
            Err(e) => Err(e),
        };
        match start {
            Ok(start_ticks) => {
                let stdin = child.stdin.take();
                let stdout = child.stdout.take();
                Ok(Box::new(LinuxChild {
                    child,
                    id: ProcessId { pid, start_ticks },
                    done: None,
                    stdin,
                    stdout,
                }))
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(unreadable("spawn", e))
            }
        }
    }

    fn wait_exit(&self, id: &ProcessId, timeout: Duration) -> Result<WaitOutcome, Error> {
        let deadline = Instant::now().checked_add(timeout);
        loop {
            if procfs::has_exited(id).map_err(|e| unreadable("wait", e))? {
                return Ok(WaitOutcome::Exited);
            }
            let remaining = match deadline {
                Some(deadline) => deadline.saturating_duration_since(Instant::now()),
                None => WAIT_POLL,
            };
            if remaining.is_zero() {
                return Ok(WaitOutcome::TimedOut);
            }
            std::thread::sleep(remaining.min(WAIT_POLL));
        }
    }

    fn tree_in_use(&self, tree: &Path, exclude: &[ProcessId]) -> Result<bool, Error> {
        let tree = std::fs::canonicalize(tree).map_err(|e| ProcessError::from_io("in use", e))?;
        procfs::tree_in_use(&tree, exclude).map_err(|e| unreadable("in use", e))
    }

    /// Every user's processes (M11-D13): the root engine must not delete a tree another user
    /// runs. The rules are the per-user scan's, without its skip of other uids.
    fn tree_in_use_strict(&self, tree: &Path, exclude: &[ProcessId]) -> Result<bool, Error> {
        let tree = std::fs::canonicalize(tree).map_err(|e| ProcessError::from_io("in use", e))?;
        procfs::tree_in_use_strict(&tree, exclude).map_err(|e| unreadable("in use", e))
    }
}

/// A child started by [`LinuxProcess::spawn_child`].
struct LinuxChild {
    child: std::process::Child,
    id: ProcessId,
    done: Option<ExitKind>,
    /// The parent's end of the child's input pipe, until the caller takes it.
    stdin: Option<std::process::ChildStdin>,
    /// The parent's end of the child's output pipe, until the caller takes it.
    stdout: Option<std::process::ChildStdout>,
}

fn exit_kind(status: std::process::ExitStatus) -> ExitKind {
    match (status.code(), status.signal()) {
        (Some(0), _) => ExitKind::Success,
        (Some(code), _) => ExitKind::Failure(code),
        (None, Some(signal)) => ExitKind::Signal(signal),
        // A wait reports only an exit or a signal; nothing else reaches here.
        (None, None) => ExitKind::Failure(-1),
    }
}

impl Child for LinuxChild {
    fn id(&self) -> ProcessId {
        self.id
    }

    fn try_wait(&mut self) -> Result<Option<ExitKind>, Error> {
        if self.done.is_none() {
            let status = self
                .child
                .try_wait()
                .map_err(|e| ProcessError::from_io("wait", e))?;
            self.done = status.map(exit_kind);
        }
        Ok(self.done)
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        self.stdin
            .take()
            .map(|p| Box::new(p) as Box<dyn Write + Send>)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>)
    }

    fn terminate(&mut self, grace: Duration) -> Result<(), Error> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        // Not reaped (try_wait just said so): the pid is still this child's.
        send_sigterm(self.id.pid).map_err(|e| ProcessError::from_io("terminate", e))?;
        let deadline = Instant::now().checked_add(grace);
        loop {
            if self.try_wait()?.is_some() {
                return Ok(());
            }
            let remaining = match deadline {
                Some(deadline) => deadline.saturating_duration_since(Instant::now()),
                None => TERMINATE_POLL,
            };
            if remaining.is_zero() {
                break;
            }
            std::thread::sleep(remaining.min(TERMINATE_POLL));
        }
        // std's kill sends SIGKILL to the unreaped child; then reap it.
        self.child
            .kill()
            .map_err(|e| ProcessError::from_io("terminate", e))?;
        let status = self
            .child
            .wait()
            .map_err(|e| ProcessError::from_io("terminate", e))?;
        self.done = Some(exit_kind(status));
        Ok(())
    }
}
