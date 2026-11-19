//! [`MacProcess`]: the core's [`Process`] over `std::process`, libproc and kqueue.
//!
//! - Programs start through `std::process::Command` with an absolute path: no shell and no `PATH`
//!   lookup. `env_remove` is applied before `env_set`, so a variable in both lists ends up set.
//! - A piped child (`ChildStdio::Piped`) gets anonymous pipes from `std`, which creates the parent's
//!   ends close-on-exec: no process this one starts afterwards inherits them. Its error stream
//!   stays null. A detached spawn refuses pipes.
//! - A detached program leads a new session (`setsid` between fork and exec) with its standard
//!   streams on `/dev/null`.
//! - A process is named by its pid and its start time in microseconds (`PROC_PIDTBSDINFO`); a pid
//!   with another start time, a zombie and a pid that is gone all count as exited.
//! - Waiting for a process that is not our child registers a kqueue `EVFILT_PROC`/`NOTE_EXIT`
//!   watch after checking the start time (and checks it again once registered, so a reused pid is
//!   never watched); it wakes at least once a second to look again, and falls back to polling when
//!   the watch cannot be registered. It never signals or reaps.
//! - Only an own child is ever signalled ([`Child::terminate`]), and only before it is reaped, so
//!   its pid cannot have been reused.
//! - The in-use scan reads, for every process of the same user, its executable path, its working
//!   directory and its open vnode files, through libproc, and compares them with the tree's own
//!   path as the kernel names it (M5-D9; the premise that a tree moved by a swap is reported under
//!   its new path is a test of this crate). Gap: files only mapped into a process (a library it
//!   loaded from the tree) are not read.
//! - A background start (`spawn_app_background`, M8-D13) asks LaunchServices to start the app
//!   without activating it: `/usr/bin/open -g -n -W <bundle> --args <args>`, run as our own child
//!   (no shell), the spec's environment changes applied to `open`'s own environment, which `open`
//!   hands to the app (a health token never appears on a command line). The app is identified
//!   only as exactly one new process of this user whose executable is the entry and that started
//!   after the spawn, within [`IDENTIFY_WINDOW`]; zero or several is "unidentified", never a
//!   guess, and an unidentified app is never signalled. When the bundle's `Info.plist` cannot be
//!   read, or names another executable than the entry, the start falls back to a child start.

#![allow(unsafe_code)]

use core::time::Duration;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use lunepack_core::{
    Child, ChildStdio, Error, ExitKind, Process, ProcessError, ProcessErrorKind, ProcessId,
    SpawnSpec, WaitOutcome,
};

use crate::libproc;

/// How often [`Process::wait_exit`] looks again at a process it watches with kqueue, and how often
/// it looks at one it polls.
const WAIT_SLICE: Duration = Duration::from_millis(500);
/// How often a wait with no working kqueue watch looks at the process.
const WAIT_POLL: Duration = Duration::from_millis(100);
/// How often [`Child::terminate`] looks at the child during the grace period.
const TERMINATE_POLL: Duration = Duration::from_millis(10);
/// How long after a background start its app may be identified (M8-D13).
const IDENTIFY_WINDOW: Duration = Duration::from_secs(10);
/// LaunchServices' command-line front end.
const OPEN: &str = "/usr/bin/open";
/// The property-list tool that reads a bundle's executable name.
const PLUTIL: &str = "/usr/bin/plutil";

/// The macOS [`Process`].
#[derive(Debug, Clone, Copy, Default)]
pub struct MacProcess {
    _private: (),
}

impl MacProcess {
    /// The process adapter.
    pub fn new() -> MacProcess {
        MacProcess { _private: () }
    }

    /// The id of the running process `pid` (its pid and start time), or `None` when no such
    /// process runs (gone, or a zombie). Used to name a wait target given only by its pid.
    pub fn process_id(&self, pid: u32) -> Result<Option<ProcessId>, Error> {
        match libproc::bsd_info(pid).map_err(|e| unreadable("process id", e))? {
            Some(info) if !info.zombie => Ok(Some(ProcessId {
                pid,
                start_ticks: info.start_micros,
            })),
            _ => Ok(None),
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

/// Sends `signal` to the process `id` names, a process that is not our child, only after looking
/// again that it is still that process (same pid and start time, not a zombie). `Ok(false)` when
/// it has ended (nothing was sent).
fn signal_identified(id: &ProcessId, signal: libc::c_int) -> io::Result<bool> {
    let pid = libc::pid_t::try_from(id.pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pid out of range"))?;
    if pid <= 1 || has_exited(id)? {
        return Ok(false);
    }
    // SAFETY: kill(2) takes two integers and touches no memory. `pid` is above 1, so it names
    // one process, never a group or every process; it was identified as the app this process
    // started (M8-D13) and was looked at again just now with its start time, so it is that
    // process unless the pid was reused in the instant between the look and the call.
    let rc = unsafe { libc::kill(pid, signal) };
    if rc == -1 {
        let err = io::Error::last_os_error();
        return if err.raw_os_error() == Some(libc::ESRCH) {
            Ok(false)
        } else {
            Err(err)
        };
    }
    Ok(true)
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid(2) takes no arguments, cannot fail and touches no memory.
    unsafe { libc::geteuid() }
}

/// Whether the process `id` names has ended: gone, a zombie, or now another process (another start
/// time).
fn has_exited(id: &ProcessId) -> io::Result<bool> {
    Ok(match libproc::bsd_info(id.pid)? {
        None => true,
        Some(info) => info.zombie || info.start_micros != id.start_ticks,
    })
}

/// A kqueue watching one process for its exit.
struct ExitWatch {
    queue: OwnedFd,
}

impl ExitWatch {
    /// Watches `pid`. `Ok(None)`: no such process (it has exited).
    fn new(pid: u32) -> io::Result<Option<ExitWatch>> {
        // SAFETY: kqueue(2) takes no arguments; the descriptor it returns is owned by nobody else.
        let fd = unsafe { libc::kqueue() };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a new, open descriptor that nothing else owns or closes.
        let queue = unsafe { OwnedFd::from_raw_fd(fd) };
        let change = libc::kevent {
            ident: pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: `fd` is a kqueue; `change` is one valid change record that lives through the
        // call; no event list is passed (size 0), so nothing is written; a null timeout is not
        // used because no events are waited for.
        let rc = unsafe {
            libc::kevent(
                std::os::fd::AsRawFd::as_raw_fd(&queue),
                &change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if rc == -1 {
            let err = io::Error::last_os_error();
            return if err.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(err)
            };
        }
        Ok(Some(ExitWatch { queue }))
    }

    /// Waits up to `timeout` for the exit event; `true` when it came.
    fn wait(&self, timeout: Duration) -> io::Result<bool> {
        let ts = libc::timespec {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_nsec: libc::c_long::from(timeout.subsec_nanos() as i32),
        };
        let mut event = libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: the descriptor is a kqueue open for the whole call; no changes are passed; the
        // event list is one writable record, the size passed; `ts` is a valid timeout that lives
        // through the call.
        let rc = unsafe {
            libc::kevent(
                std::os::fd::AsRawFd::as_raw_fd(&self.queue),
                std::ptr::null(),
                0,
                &mut event,
                1,
                &ts,
            )
        };
        match rc {
            -1 => {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    Ok(false)
                } else {
                    Err(err)
                }
            }
            0 => Ok(false),
            _ => Ok(true),
        }
    }
}

impl Process for MacProcess {
    fn current_exe(&self) -> Result<PathBuf, Error> {
        let exe = std::env::current_exe().map_err(|e| unreadable("current exe", e))?;
        let exe = std::fs::canonicalize(exe).map_err(|e| unreadable("current exe", e))?;
        if !exe.is_absolute() {
            return Err(ProcessError::new(ProcessErrorKind::Unreadable, "current exe").into());
        }
        Ok(exe)
    }

    fn current(&self) -> Result<ProcessId, Error> {
        self.process_id(std::process::id())?
            .ok_or_else(|| Error::from(ProcessError::new(ProcessErrorKind::Unreadable, "current")))
    }

    fn parent(&self) -> Result<Option<ProcessId>, Error> {
        let ppid = std::os::unix::process::parent_id();
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
        // Not yet reaped, so the pid exists (running or a zombie) and is this child.
        match libproc::bsd_info(pid) {
            Ok(Some(info)) => {
                let stdin = child.stdin.take();
                let stdout = child.stdout.take();
                Ok(Box::new(MacChild {
                    child,
                    id: ProcessId {
                        pid,
                        start_ticks: info.start_micros,
                    },
                    done: None,
                    stdin,
                    stdout,
                }))
            }
            // libproc answers nothing for a process that has already ended and is not reaped yet
            // (it exited before the first look): its start time is unknown (0). Such an id counts
            // as exited at once, which is true, and the pid cannot be reused before it is reaped.
            Ok(None) => {
                let stdin = child.stdin.take();
                let stdout = child.stdout.take();
                Ok(Box::new(MacChild {
                    child,
                    id: ProcessId {
                        pid,
                        start_ticks: 0,
                    },
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

    fn spawn_app_background(&self, spec: &SpawnSpec) -> Result<Box<dyn Child>, Error> {
        if !spec.program.is_absolute() {
            return Err(ProcessError::new(ProcessErrorKind::InvalidRequest, "spawn")
                .about(&spec.program)
                .into());
        }
        match background_plan(spec) {
            Some(plan) => start_background(spec, plan),
            // Not an app LaunchServices can start as this entry: the focus is not protected, the
            // update is (M8-D13).
            None => self.spawn_child(spec),
        }
    }

    fn wait_exit(&self, id: &ProcessId, timeout: Duration) -> Result<WaitOutcome, Error> {
        let deadline = Instant::now().checked_add(timeout);
        let wait_err = |e| unreadable("wait", e);
        if has_exited(id).map_err(wait_err)? {
            return Ok(WaitOutcome::Exited);
        }
        // Register the watch, then look again: a process that ended or a pid that was reused in
        // between is caught here, so the watch is on the process the id names.
        let watch = match ExitWatch::new(id.pid) {
            Ok(Some(watch)) => Some(watch),
            Ok(None) => return Ok(WaitOutcome::Exited),
            Err(_) => None,
        };
        loop {
            if has_exited(id).map_err(wait_err)? {
                return Ok(WaitOutcome::Exited);
            }
            let remaining = match deadline {
                Some(deadline) => deadline.saturating_duration_since(Instant::now()),
                None => WAIT_SLICE,
            };
            if remaining.is_zero() {
                return Ok(WaitOutcome::TimedOut);
            }
            match &watch {
                Some(watch) => {
                    if watch.wait(remaining.min(WAIT_SLICE)).map_err(wait_err)? {
                        return Ok(WaitOutcome::Exited);
                    }
                }
                None => std::thread::sleep(remaining.min(WAIT_POLL)),
            }
        }
    }

    fn tree_in_use(&self, tree: &Path, exclude: &[ProcessId]) -> Result<bool, Error> {
        // The tree as the kernel names it, so the comparison with the kernel's paths is exact.
        let tree = std::fs::canonicalize(tree).map_err(|e| ProcessError::from_io("in use", e))?;
        let tree = libproc::kernel_path(&tree).map_err(|e| ProcessError::from_io("in use", e))?;
        scan(&tree, exclude).map_err(|e| unreadable("in use", e))
    }
}

/// Whether any process of this user other than those in `exclude` has its executable, working
/// directory or an open file under `tree`. A process of this user that cannot be read counts as in
/// use, unless it has ended meanwhile (M5-D9); any other error answers `true` (fail closed).
fn scan(tree: &Path, exclude: &[ProcessId]) -> io::Result<bool> {
    let my_uid = effective_uid();
    for pid in libproc::list_pids()? {
        let info = match libproc::bsd_info(pid) {
            Ok(Some(info)) => info,
            Ok(None) => continue,
            // Another user's process: the kernel refuses its details to everyone but that user
            // and root, and it is not ours to scan (`PROC_PIDTBSDINFO` is a same-user call).
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => continue,
            // Anything else: whose process this is cannot be told: fail closed.
            Err(_) => return Ok(true),
        };
        if info.uid != my_uid || info.zombie {
            continue;
        }
        let id = ProcessId {
            pid,
            start_ticks: info.start_micros,
        };
        if exclude.contains(&id) {
            continue;
        }
        match process_uses_tree(pid, tree) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            // Unreadable: fine only if the process ended (or the pid was reused) meanwhile.
            Err(_) => {
                if !has_exited(&id).unwrap_or(false) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Reads the three sources of process `pid` in turn. The executable path must be readable. The
/// working directory and the open files may be refused by the kernel (`EPERM`) for a process of
/// this user that the system protects by design (Apple's own daemons, such as `progressd`: their
/// descriptor list is denied to every ordinary process): such a process is judged by what is
/// readable of it, its executable path and, when the kernel gives it, its working directory. That
/// is the macOS counterpart of Linux's non-dumpable process (M5-D9) and a recorded gap: a
/// protected process that runs outside the tree but holds a file inside it is not seen.
fn process_uses_tree(pid: u32, tree: &Path) -> io::Result<bool> {
    if libproc::exe_path(pid)?.is_some_and(|p| p.starts_with(tree)) {
        return Ok(true);
    }
    let by_design = |e: &io::Error| e.kind() == io::ErrorKind::PermissionDenied;
    match libproc::cwd_path(pid) {
        Ok(Some(p)) if p.starts_with(tree) => return Ok(true),
        Ok(_) => {}
        Err(e) if by_design(&e) => return Ok(false),
        Err(e) => return Err(e),
    }
    match libproc::fd_paths(pid) {
        Ok(paths) => Ok(paths.iter().any(|p| p.starts_with(tree))),
        Err(e) if by_design(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// A child started by [`MacProcess::spawn_child`].
struct MacChild {
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

impl Child for MacChild {
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

// ---- background start (M8-D13) -----------------------------------------------------------------

/// What a background start needs, read before it starts.
struct BackgroundPlan {
    /// The bundle `B` (three levels above the entry).
    bundle: PathBuf,
    /// The entry as the kernel names it (what `proc_pidpath` reports for the app).
    entry: PathBuf,
}

/// The plan for starting `spec` in the background, or `None` for the fallback: the entry is
/// `<B>/Contents/MacOS/<name>` with null standard streams, `B/Contents/Info.plist` names `<name>`
/// as `CFBundleExecutable` (read with a bounded `plutil`, no shell), and the entry exists.
fn background_plan(spec: &SpawnSpec) -> Option<BackgroundPlan> {
    if spec.stdio != ChildStdio::Null {
        return None;
    }
    let name = spec.program.file_name()?.to_str()?;
    let macos = spec.program.parent()?;
    let contents = macos.parent()?;
    if macos.file_name()? != "MacOS" || contents.file_name()? != "Contents" {
        return None;
    }
    let bundle = contents.parent()?.to_path_buf();
    let plist = contents.join("Info.plist");
    let out = crate::run_bounded(
        PLUTIL,
        &[
            "-extract",
            "CFBundleExecutable",
            "raw",
            "-o",
            "-",
            plist.to_str()?,
        ],
    )?;
    if out.strip_suffix('\n').unwrap_or(&out) != name {
        return None;
    }
    let entry = std::fs::canonicalize(&spec.program).ok()?;
    let entry = libproc::kernel_path(&entry).ok()?;
    Some(BackgroundPlan { bundle, entry })
}

/// The pids of this user's processes whose executable is `entry`.
fn running_from(entry: &Path) -> io::Result<Vec<(u32, u64)>> {
    let me = effective_uid();
    let mut out = Vec::new();
    for pid in libproc::list_pids()? {
        let Ok(Some(info)) = libproc::bsd_info(pid) else {
            continue;
        };
        if info.uid != me || info.zombie {
            continue;
        }
        if libproc::exe_path(pid).ok().flatten().as_deref() == Some(entry) {
            out.push((pid, info.start_micros));
        }
    }
    Ok(out)
}

/// Microseconds since the epoch, in the unit of `PROC_PIDTBSDINFO`'s start time.
fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

fn start_background(spec: &SpawnSpec, plan: BackgroundPlan) -> Result<Box<dyn Child>, Error> {
    // The instances already running from the entry are never the new one.
    let before: Vec<u32> = running_from(&plan.entry)
        .map_err(|e| unreadable("spawn", e))?
        .into_iter()
        .map(|(pid, _)| pid)
        .collect();
    let since = now_micros();
    let mut cmd = Command::new(OPEN);
    cmd.arg("-g")
        .arg("-n")
        .arg("-W")
        .arg(&plan.bundle)
        .arg("--args")
        .args(&spec.args);
    // The spec's environment goes to `open`'s own environment, which `open` hands to the app:
    // never `--env`, whose value `ps` would show.
    for name in &spec.env_remove {
        cmd.env_remove(name);
    }
    for (name, value) in &spec.env_set {
        cmd.env(name, value);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let open = cmd.spawn().map_err(|e| spawn_error(e, &spec.program))?;
    let open_id = ProcessId {
        pid: open.id(),
        start_ticks: libproc::bsd_info(open.id())
            .ok()
            .flatten()
            .map_or(0, |i| i.start_micros),
    };
    Ok(Box::new(BackgroundApp {
        open,
        open_id,
        open_status: None,
        entry: plan.entry,
        before,
        since,
        window_end: Instant::now() + IDENTIFY_WINDOW,
        app: None,
        unidentifiable: false,
        done: None,
    }))
}

/// An app started by [`MacProcess::spawn_app_background`]: our child `open -W`, and the app
/// itself once identified (not our child).
struct BackgroundApp {
    open: std::process::Child,
    open_id: ProcessId,
    /// `open`'s exit, once reaped.
    open_status: Option<ExitKind>,
    entry: PathBuf,
    /// The pids running from the entry before the start.
    before: Vec<u32>,
    /// When the start began (microseconds since the epoch).
    since: u64,
    window_end: Instant,
    /// The app, once identified.
    app: Option<ProcessId>,
    /// Several candidates were seen: the app is never identified.
    unidentifiable: bool,
    done: Option<ExitKind>,
}

impl BackgroundApp {
    /// Reaps `open` when it has exited (best effort).
    fn poll_open(&mut self) {
        if self.open_status.is_none()
            && let Ok(Some(status)) = self.open.try_wait()
        {
            self.open_status = Some(exit_kind(status));
        }
    }

    /// Looks for the app while the window is open: exactly one new process of this user from the
    /// entry that started after the start began. Several is final: never identified.
    fn identify(&mut self) {
        if self.app.is_some() || self.unidentifiable || Instant::now() >= self.window_end {
            return;
        }
        let Ok(found) = running_from(&self.entry) else {
            return;
        };
        let new: Vec<(u32, u64)> = found
            .into_iter()
            .filter(|(pid, start)| !self.before.contains(pid) && *start >= self.since)
            .collect();
        match new.as_slice() {
            [] => {}
            [(pid, start)] => {
                self.app = Some(ProcessId {
                    pid: *pid,
                    start_ticks: *start,
                });
            }
            _ => self.unidentifiable = true,
        }
    }

    /// Ends `open` (our child) and reaps it.
    fn end_open(&mut self, grace: Duration) -> Result<(), Error> {
        self.poll_open();
        if self.open_status.is_some() {
            return Ok(());
        }
        send_sigterm(self.open_id.pid).map_err(|e| ProcessError::from_io("terminate", e))?;
        let deadline = Instant::now() + grace.min(Duration::from_secs(2));
        while Instant::now() < deadline {
            self.poll_open();
            if self.open_status.is_some() {
                return Ok(());
            }
            std::thread::sleep(TERMINATE_POLL);
        }
        let _ = self.open.kill();
        let status = self
            .open
            .wait()
            .map_err(|e| ProcessError::from_io("terminate", e))?;
        self.open_status = Some(exit_kind(status));
        Ok(())
    }
}

impl Child for BackgroundApp {
    /// The app's id once identified; `open`'s until then.
    fn id(&self) -> ProcessId {
        self.app.unwrap_or(self.open_id)
    }

    fn try_wait(&mut self) -> Result<Option<ExitKind>, Error> {
        if self.done.is_some() {
            return Ok(self.done);
        }
        self.poll_open();
        self.identify();
        self.done = match (self.app, self.open_status) {
            // The app's own status is not observable (not our child).
            (Some(app), _) => has_exited(&app)
                .map_err(|e| unreadable("wait", e))?
                .then_some(ExitKind::Unknown),
            // The launch failed before the app was seen.
            (None, Some(ExitKind::Success)) => Some(ExitKind::Unknown),
            (None, Some(ExitKind::Failure(code))) => Some(ExitKind::Failure(code)),
            (None, Some(other)) => Some(other),
            (None, None) => None,
        };
        Ok(self.done)
    }

    fn terminate(&mut self, grace: Duration) -> Result<(), Error> {
        if self.try_wait()?.is_some() {
            return self.end_open(grace);
        }
        if let Some(app) = self.app {
            // Only the identified app, looked at again before every signal.
            let term = |sig| {
                signal_identified(&app, sig).map_err(|e| ProcessError::from_io("terminate", e))
            };
            if term(libc::SIGTERM)? {
                let deadline = Instant::now().checked_add(grace);
                loop {
                    if has_exited(&app).map_err(|e| unreadable("terminate", e))? {
                        break;
                    }
                    let remaining = match deadline {
                        Some(deadline) => deadline.saturating_duration_since(Instant::now()),
                        None => TERMINATE_POLL,
                    };
                    if remaining.is_zero() {
                        term(libc::SIGKILL)?;
                        break;
                    }
                    std::thread::sleep(remaining.min(TERMINATE_POLL));
                }
            }
        }
        // An unidentified app is never signalled: only `open` is ended.
        self.end_open(grace)?;
        self.done = Some(ExitKind::Unknown);
        Ok(())
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        None
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        None
    }
}
